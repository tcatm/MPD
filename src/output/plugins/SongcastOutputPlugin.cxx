/*
 * Copyright 2003-2016 The Music Player Daemon Project
 * http://www.musicpd.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include "SongcastOutputPlugin.hxx"
#include "../OutputAPI.hxx"
#include "../Wrapper.hxx"
#include "../Timer.hxx"
#include "pcm/PcmExport.hxx"
#include "config/ConfigError.hxx"
#include "util/Error.hxx"
#include "util/Manual.hxx"
#include "util/ConstBuffer.hxx"
#include "system/FatalError.hxx"
#include "Log.hxx"

#include <thread>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum State {WAITING, ALIVE};

class ExpiringTimer final {
public:
	ExpiringTimer(int timeout) {
		t = timeout;
	}

	void reset() {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);

		now.tv_sec += t;

		expiration = now;
		aimed = true;
	}

	bool expired() {
		if (!aimed)
			return false;

		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);

		return timespec_cmp(now, expiration) >= 0;
	}

private:
	int t;
	struct timespec expiration;
	bool aimed;

	int timespec_cmp(struct timespec a, struct timespec b) {
		if      (a.tv_sec  < b.tv_sec )	return (-1);
		else if (a.tv_sec  > b.tv_sec )	return (+1);
		else if (a.tv_nsec < b.tv_nsec)	return (-1);
		else if (a.tv_nsec > b.tv_nsec)	return (+1);

		return 0;
	}
};

struct SongcastOutput final {
	AudioOutput base;

	bool unicast;
	unsigned int preset;
	unsigned int channel;
	unsigned int latency;
	const char *zone;

	std::string ohz_uri;

	ohm1_audio frame;
	uint32_t framecounter;
	const char *codec = "PCM";
	size_t framesize;

	State state;
	ExpiringTimer alive_timer;

	struct sockaddr_in receiver;

	Manual<PcmExport> pcm_export;

	std::thread t;

  // TODO structs for track and metatext might be useful
	std::string track_sequence, track_uri, track_metadata, metatext_sequence, metatext;

	int ohz_fd;
	int ohm_fd;

	Timer *timer;

	SongcastOutput()
	  :alive_timer(10),
		 base(songcast_output_plugin) {}

	bool Initialize(const ConfigBlock &block, Error &error) {
		return base.Configure(block, error);
	}

	bool Configure(const ConfigBlock &block, Error &error);
	static SongcastOutput *Create(const ConfigBlock &block, Error &error);

	bool Enable(Error &error);
	void Disable();

	bool Open(AudioFormat &audio_format, Error &error);
	void Close();

	unsigned Delay() const;
	void SendTag(const Tag &tag);
	size_t Play(const void *chunk, size_t size, Error &error);
	void Cancel();

	void ohz_thread();
	void handle_ohz();
	void handle_ohm();
};

SongcastOutput *
SongcastOutput::Create(const ConfigBlock &block, Error &error)
{
	auto *so = new SongcastOutput();

	if (!so->Initialize(block, error)) {
		delete so;
		return nullptr;
	}

	if (!so->Configure(block, error)) {
		delete so;
		return nullptr;
	}

	return so;
}

inline bool
SongcastOutput::Configure(const ConfigBlock &block, Error &error)
{
	preset = block.GetBlockValue("preset", 0u);
	unicast = block.GetBlockValue("unicast", false);
	channel = block.GetBlockValue("multicast_channel", 4u); // TODO replace with random default value
	latency = block.GetBlockValue("latency", 300u); // milliseconds
	zone = block.GetBlockValue("zone", "mpd");

	ohz_uri = "ohz://239.255.255.250:51972/" + std::string(zone);

	return true;
}

inline bool
SongcastOutput::Enable(Error &error)
{
	pcm_export.Construct();

	framecounter = 0;

	// Open socket for OHZ
	struct ip_mreq mreq = {
		mreq.imr_multiaddr.s_addr = inet_addr("239.255.255.250"),
		mreq.imr_interface = {}
	};

	ohz_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (ohz_fd <= 0)
		return false;

	struct sockaddr_in src = {};
	src.sin_family = AF_INET;
	src.sin_port = htons(51972);
	src.sin_addr.s_addr = htonl(INADDR_ANY);

	int one = 1;

	if (setsockopt(ohz_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		goto fail_ohz;

	if (bind(ohz_fd, (struct sockaddr *) &src, sizeof(src)) < 0)
		goto fail_ohz;

	if (setsockopt(ohz_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		goto fail_ohz;

	// Open socket for OHM/OHU
	ohm_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (ohm_fd <= 0)
		goto fail_ohz;

	if (!unicast) {
		if (setsockopt(ohm_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
			goto fail_ohm;
	}

	src.sin_family = AF_INET;
	src.sin_port = unicast ? 0 : htons(51973);
	src.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(ohm_fd, (struct sockaddr *) &src, sizeof(src)) < 0)
		goto fail_ohm;

	if (!unicast) {
		mreq.imr_multiaddr.s_addr = inet_addr((std::string("239.255.") + std::to_string(channel)).c_str());
		if (setsockopt(ohm_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
			goto fail_ohm;

		receiver = {};
		receiver.sin_family = AF_INET;
		receiver.sin_port = htons(51973);
		receiver.sin_addr = mreq.imr_multiaddr;
	}

	state = WAITING;

	// TODO reset track and metatext to dummy

	t = std::thread(&SongcastOutput::ohz_thread, this);

	return true;

fail_ohm:
	close(ohm_fd);
fail_ohz:
	close(ohz_fd);

	return false;
}

inline void
SongcastOutput::Disable()
{
	pcm_export.Destruct();

	// TODO stop ohz_thread
	// TODO join ohz_thread
	close(ohz_fd);
	close(ohm_fd);
}

void add_fd(int efd, int fd, uint32_t events) {
	struct epoll_event event = {};
	event.data.fd = fd;
	event.events = events;

	epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}

void SongcastOutput::handle_ohz()
{
	struct sockaddr_storage src_addr;

	ohz1_header header;
	uint8_t buffer[256];

	struct iovec iov[2] = {};
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = buffer;
	iov[1].iov_len = sizeof(buffer);

	struct msghdr message = {};
	message.msg_name = &src_addr;
	message.msg_namelen = sizeof(src_addr);
	message.msg_iov = iov;
	message.msg_iovlen = 2;
	message.msg_control = 0;
	message.msg_controllen = 0;

	ssize_t n = recvmsg(ohz_fd, &message, 0);

	if (n < sizeof(ohz1_header))
		return;

	if (strncmp((const char*)header.signature, "Ohz ", 4) != 0)
		return;

	if (header.version != 1)
		return;

	if (header.type == OHZ1_PRESET_QUERY) {
		if (n < sizeof(ohz1_header) + sizeof(ohz1_preset_query))
			return;

		ohz1_preset_query *preset_query = (ohz1_preset_query*)buffer;

		if (htonl(preset_query->preset) != preset)
			return;

		const char *preset_info;

		std::string preset_info_string = std::string(
			"<?xml version=\"1.0\"?>"
			"<DIDL-Lite xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\" xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\">"
			"<item id=\"\" parentID=\"\" restricted=\"True\">"
    	"<res protocolInfo=\"ohz:*:*:m\">")
			+ ohz_uri
			+ std::string("</res>"
    	"<upnp:class>object.item.audioItem</upnp:class>"
			"</item>"
			"</DIDL-Lite>");

		preset_info = preset_info_string.c_str();

		ohz1_header response_hdr = {};
		ohz1_preset_info response = {};

		memcpy(&response_hdr.signature, "Ohz ", 4);
		response_hdr.version = 1;
		response_hdr.type = OHZ1_PRESET_INFO;

		response.preset = ntohl(preset);
		response.length = ntohl(strlen(preset_info));

		response_hdr.length = ntohs(sizeof(ohz1_header) + sizeof(ohz1_preset_info) + strlen(preset_info));

		struct iovec iov[3] = {};
		iov[0].iov_base = &response_hdr;
		iov[0].iov_len = sizeof(response_hdr);
		iov[1].iov_base = &response;
		iov[1].iov_len = sizeof(response);
		iov[2].iov_base = (void *)preset_info;
		iov[2].iov_len = strlen(preset_info);

		struct msghdr message = {};

		struct sockaddr_in dst = {
			dst.sin_family = AF_INET,
			dst.sin_port = htons(51972),
			dst.sin_addr.s_addr = inet_addr("239.255.255.250")
		};

		message.msg_name = &dst;
		message.msg_namelen = sizeof(dst);
		message.msg_iov = iov;
		message.msg_iovlen = 3;
		message.msg_control = 0;
		message.msg_controllen = 0;

		sendmsg(ohz_fd, &message, 0);
	}

	if (header.type == OHZ1_ZONE_QUERY) {
		if (n < sizeof(ohz1_header) + sizeof(ohz1_zone_query))
			return;

		ohz1_zone_query *query = (ohz1_zone_query*)buffer;
		size_t zone_length = ntohl(query->length);

		if (n < sizeof(ohz1_header) + sizeof(ohz1_zone_query) + zone_length)
			return;

		if (strlen(zone) != zone_length || strncmp(zone, query->zone, zone_length) != 0)
			return;

		struct sockaddr_in uri_addr = {
			uri_addr.sin_family = AF_INET
		};

		if (unicast) {
			socklen_t s = sizeof(uri_addr);
			if (getsockname(ohm_fd, (struct sockaddr *)&uri_addr, &s) == -1)
				return;

			// Figure out our own IP by connecting to the receiver
			int testfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (connect(testfd, (const sockaddr*)&src_addr, sizeof(src_addr)) != 0) {
				close(testfd);
				return;
			}

			struct sockaddr_in my_addr = {
				uri_addr.sin_family = AF_INET
			};

			if (getsockname(testfd, (struct sockaddr *)&my_addr, &s) == -1) {
				close(testfd);
				return;
			}

			uri_addr.sin_addr = my_addr.sin_addr;

			close(testfd);
		} else {
			uri_addr.sin_port = htons(51973);
			inet_aton((std::string("239.255.") + std::to_string(channel)).c_str(), &uri_addr.sin_addr);
		}

		char ip[INET_ADDRSTRLEN];
		std::string port = std::to_string(ntohs(uri_addr.sin_port));
		inet_ntop(AF_INET, &uri_addr.sin_addr, ip, INET_ADDRSTRLEN);

		std::string uri = std::string(unicast ? "ohu" : "ohm") + "://" + ip + ":" + port;

		ohz1_header response_hdr = {};
		ohz1_zone_uri response = {};

		memcpy(&response_hdr.signature, "Ohz ", 4);
		response_hdr.version = 1;
		response_hdr.type = OHZ1_ZONE_URI;

		response.zone_length = ntohl(strlen(zone));
		response.uri_length = ntohl(uri.length());

		response_hdr.length = ntohs(sizeof(ohz1_header) + sizeof(ohz1_preset_info) + strlen(zone) + uri.length());

		struct iovec iov[4] = {};
		iov[0].iov_base = &response_hdr;
		iov[0].iov_len = sizeof(response_hdr);
		iov[1].iov_base = &response;
		iov[1].iov_len = sizeof(response);
		iov[2].iov_base = (char *)zone;
		iov[2].iov_len = strlen(zone);
		iov[3].iov_base = (void *)uri.c_str();
		iov[3].iov_len = uri.length();

		struct msghdr message = {};

		struct sockaddr_in dst = {
			dst.sin_family = AF_INET,
			dst.sin_port = htons(51972),
			dst.sin_addr.s_addr = inet_addr("239.255.255.250")
		};

		message.msg_name = &dst;
		message.msg_namelen = sizeof(dst);
		message.msg_iov = iov;
		message.msg_iovlen = 4;
		message.msg_control = 0;
		message.msg_controllen = 0;

		sendmsg(ohz_fd, &message, 0);
	}
}

void SongcastOutput::handle_ohm()
{
	struct sockaddr_storage src_addr;

  // TODO we only ever expect the header... so just receive into that struct directly
  ohm1_header header;
	struct iovec iov[1] = {};
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);

	struct msghdr message = {
		message.msg_name = &src_addr,
		message.msg_namelen = sizeof(src_addr),
		message.msg_iov = iov,
		message.msg_iovlen = 1,
		message.msg_control = 0,
		message.msg_controllen = 0,
	};

	ssize_t n = recvmsg(ohm_fd, &message, 0);

	if (n >= 0 && (size_t)n < sizeof(header))
		return;

	if (strncmp((const char*)header.signature, "Ohm ", 4) != 0)
		return;

	if (header.version != 1)
		return;

	if (header.type == OHM1_JOIN) {
		printf("join\n");

		if (!unicast) {
			alive_timer.reset();
			if (state != ALIVE)
				state = ALIVE;
				//send_track_and_metatext();
		}
	}

	if (header.type == OHM1_LISTEN) {
		printf("listen\n");

		if (!unicast) {
			if (state == ALIVE)
				alive_timer.reset();
		}
	}

	if (header.type == OHM1_LEAVE) {
		// be aware of stray leave messages
		printf("leave\n");

		if (!unicast) {
			// ignore
		}
	}

  // share sendmsg for track and metatext with unicast and multicast

	// Alive timer: 10s
	// Blocked timer: 3s
	// implemented blocked as seperate state variable

	// TODO unicast
	//   join -> check if present, if not add receiver
	//           update timer for this receiver
	//           if first receiver: make it primary
	//           if not first: add to slave list (implicit as list being longer than 1?)
	//                         send slave message to primary
	//           send (cached) track and metatext to primary receiver
	//   listen -> check if present, else ignore
	//             refresh timer for this receiver (walk list...)
	//             check for expired receivers, update primary accordingly
	//               if anything changed: send slave message to primary
	//   leave -> remove from list if present, else ignore
	//            check for expired receivers, update primary and possibly send slavelist

	// multicast
	//   join -> set state to ALIVE, send (cached) track and metatext, reset alive timer
	//   listen -> if ALIVE, reset alive timer, else ignore
	//   leave -> not handled for multicast
}

void SongcastOutput::ohz_thread()
{
	int efd;
	int maxevents = 64;
	struct epoll_event *events;

	efd = epoll_create1(0);
	add_fd(efd, ohz_fd, EPOLLIN);
	add_fd(efd, ohm_fd, EPOLLIN);

	events = (epoll_event*)calloc(maxevents, sizeof(struct epoll_event));
	while (1) {
			int n;
			n = epoll_wait(efd, events, maxevents, 2000);

			if (n == 0) {
				// timeout
				// TODO receiver housekeeping here
				// TODO read flag
				continue;
			}

			for(int i = 0; i < n; i++) {
				if (ohz_fd == events[i].data.fd && events[i].events & EPOLLIN)
					handle_ohz();

				if (ohm_fd == events[i].data.fd && events[i].events & EPOLLIN)
					handle_ohm();
			}
		}

		free(events);

	// dazwischen mal irgendwann ein flag auslesen ob der thread sich beenden soll
	// das könnte eine pipe sein, oder?
	// was muss er dem haupt thread mitteilen? eigentlich nur, dass ein receiver da ist oder verschwindet.
	// also den state wechseln.
	// receiver selbst entfernen sollte dann wohl in der play methode stattfinden um raceconditions zu vermeiden
	// zum starten: erst receiver setzen, dann state auf ALIVE

	// kick receiver if inactive (no listen/join) for a few seconds
}

uint32_t latency_ms_to_media(int sample_rate, int latency)
{
	unsigned int multiplier = (sample_rate % 441) == 0 ? 44100 : 48000;
	return ((unsigned long long int)latency * multiplier * 256) / 1000;
}

bool
SongcastOutput::Open(AudioFormat &audio_format, Error &error)
{
	PcmExport::Params params;
	int bitdepth;

	switch (audio_format.format) {
		case SampleFormat::S16:
			params.reverse_endian = 2;
			bitdepth = 16;
			break;
		case SampleFormat::S24_P32:
		default:
			audio_format.format = SampleFormat::S24_P32;
			params.reverse_endian = 3;
			params.pack24 = true;
			bitdepth = 24;
			break;
	}

	switch (audio_format.sample_rate) {
		case 8000: case 16000: case 32000: case 48000: case 96000: case 192000:
		case 11025: case 22050: case 44100: case 88200: case 176400:
			break;
		default:
			audio_format.sample_rate = 96000;
			break;
	}

	frame = {};
	frame.audio_hdr_length = 50;
	frame.codec_length = 3;
	frame.channels = audio_format.channels;
	frame.sample_rate = htonl(audio_format.sample_rate);
	frame.bitdepth = bitdepth;
	frame.media_latency = htonl(latency_ms_to_media(audio_format.sample_rate, latency));

	pcm_export->Open(audio_format.format, audio_format.channels, params);
	framesize = pcm_export->GetFrameSize(audio_format);

	timer = new Timer(audio_format);

	return true;
}

void
SongcastOutput::Close()
{

	printf("Sending halt frame\n");
	frame.flags = OHM1_FLAG_HALT;
	frame.sample_count = htons(0);
	frame.frame = htonl(framecounter++);

	ohm1_header header;

	memcpy(&header.signature, "Ohm ", 4);
	header.version = 1;
	header.type = OHM1_AUDIO;
	header.length = htons(sizeof(header) + sizeof(frame) + strlen(codec));

	struct iovec iov[3] = {};
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = &frame;
	iov[1].iov_len = sizeof(frame);
	iov[2].iov_base = (void *)codec;
	iov[2].iov_len = strlen(codec);

	struct msghdr message = {};
	message.msg_name = &receiver;
	message.msg_namelen = sizeof(receiver);
	message.msg_iov = iov;
	message.msg_iovlen = 3;
	message.msg_control = 0;
	message.msg_controllen = 0;

	sendmsg(ohm_fd, &message, 0);
	// TODO send halt frame with no further audio data
	// reset track and metatext to dummy
	delete timer;

}

unsigned
SongcastOutput::Delay() const
{
	return timer->IsStarted()	? timer->GetDelay()	: 0;
}

size_t
SongcastOutput::Play(const void *chunk, size_t size, gcc_unused Error &error)
{
	if (!timer->IsStarted())
		timer->Start();

	timer->Add(size);

	// Discard when no receiver is listening
	if (state != ALIVE)
		return size;

	const auto e = pcm_export->Export({chunk, size});
	chunk = e.data;
	size = e.size;

	frame.flags = 0;
	frame.sample_count = htons(size / framesize);
	frame.frame = htonl(framecounter++);

	ohm1_header header;

	memcpy(&header.signature, "Ohm ", 4);
	header.version = 1;
	header.type = OHM1_AUDIO;
	header.length = htons(sizeof(header) + sizeof(frame) + strlen(codec) + size);

	struct iovec iov[4] = {};
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = &frame;
	iov[1].iov_len = sizeof(frame);
	iov[2].iov_base = (void *)codec;
	iov[2].iov_len = strlen(codec);
	iov[3].iov_base = (void *)chunk;
	iov[3].iov_len = size;

	struct msghdr message = {};
	message.msg_name = &receiver;
	message.msg_namelen = sizeof(receiver);
	message.msg_iov = iov;
	message.msg_iovlen = 4;
	message.msg_control = 0;
	message.msg_controllen = 0;

	sendmsg(ohm_fd, &message, 0);

	return pcm_export->CalcSourceSize(size);
}

inline void
SongcastOutput::Cancel()
{
	// calculate how many frames have been sent within latency
	// resent them with halt flag set and no data

	// This seems to confuse the DSM.
	return;

	int start = framecounter - 200;
	printf("start %i\n", start);
	framecounter++;

	for (int i = framecounter; i > start ; i--) {
		frame.flags = OHM1_FLAG_HALT | OHM1_FLAG_RESENT;
		frame.sample_count = htons(0);
		frame.frame = htonl(i);

		ohm1_header header;

		memcpy(&header.signature, "Ohm ", 4);
		header.version = 1;
		header.type = OHM1_AUDIO;
		header.length = htons(sizeof(header) + sizeof(frame) + strlen(codec));

		struct iovec iov[3] = {};
		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof(header);
		iov[1].iov_base = &frame;
		iov[1].iov_len = sizeof(frame);
		iov[2].iov_base = (void *)codec;
		iov[2].iov_len = strlen(codec);

		struct msghdr message = {};
		message.msg_name = &receiver;
		message.msg_namelen = sizeof(receiver);
		message.msg_iov = iov;
		message.msg_iovlen = 3;
		message.msg_control = 0;
		message.msg_controllen = 0;

		sendmsg(ohm_fd, &message, 0);
	}
}

// TODO remove/refactor/whatever
/* shout_tag_to_metadata(const Tag &tag, char *dest, size_t size)
{
	char artist[size];
	char title[size];

	artist[0] = 0;
	title[0] = 0;

	for (const auto &item : tag) {
		switch (item.type) {
		case TAG_ARTIST:
			strncpy(artist, item.value, size);
			break;
		case TAG_TITLE:
			strncpy(title, item.value, size);
			break;

		default:
			break;
		}
	}

	snprintf(dest, size, "%s - %s", artist, title);
}
*/

void
SongcastOutput::SendTag(const Tag &tag)
{
// TODO Send TRACK data
//	shout_tag_to_metadata(tag, song, sizeof(song));
// cache track and metatext somewhere
}

typedef AudioOutputWrapper<SongcastOutput> Wrapper;

const struct AudioOutputPlugin songcast_output_plugin = {
	"songcast",
	nullptr,
	&Wrapper::Init,
	&Wrapper::Finish,
	&Wrapper::Enable,
	&Wrapper::Disable,
	&Wrapper::Open,
	&Wrapper::Close,
	&Wrapper::Delay,
	&Wrapper::SendTag,
	&Wrapper::Play,
	nullptr,
	&Wrapper::Cancel,
	nullptr,
	nullptr,
};
