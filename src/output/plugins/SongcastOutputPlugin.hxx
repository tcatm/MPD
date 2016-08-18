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

#ifndef MPD_SONGCAST_OUTPUT_PLUGIN_HXX
#define MPD_SONGCAST_OUTPUT_PLUGIN_HXX

#include <string>
#include <stdint.h>

extern const struct AudioOutputPlugin songcast_output_plugin;

// OHZ

enum {
	OHZ1_ZONE_QUERY = 0,
	OHZ1_ZONE_URI,
	OHZ1_PRESET_QUERY,
	OHZ1_PRESET_INFO
};

typedef struct __attribute__((__packed__)) {
	uint8_t signature[4];
	uint8_t version;
	uint8_t type;
	uint16_t length;
} ohz1_header;

typedef struct __attribute__((__packed__))	{
	uint32_t length;
	char zone[];
} ohz1_zone_query;

typedef struct __attribute__((__packed__))	{
	uint32_t zone_length;
	uint32_t uri_length;
} ohz1_zone_uri;

typedef struct __attribute__((__packed__)) {
	uint32_t preset;
} ohz1_preset_query;

typedef struct __attribute__((__packed__)) {
	uint32_t preset;
	uint32_t length;
} ohz1_preset_info;

// OHM

enum {
	OHM1_JOIN = 0,
	OHM1_LISTEN,
	OHM1_LEAVE,
	OHM1_AUDIO,
	OHM1_TRACK,
	OHM1_METATEXT,
	OHM1_SLAVE,
	OHM1_RESEND_REQUEST,
};

#define OHM1_FLAG_HALT (1<<0)
#define OHM1_FLAG_LOSSLESS (1<<1)
#define OHM1_FLAG_TIMESTAMPED (1<<2)
#define OHM1_FLAG_RESENT (1<<3)

typedef struct __attribute__((__packed__)) {
	uint8_t signature[4];
	uint8_t version;
	uint8_t type;
	uint16_t length;
} ohm1_header;

typedef struct __attribute__((__packed__)) {
	uint8_t audio_hdr_length;
	uint8_t flags;
	uint16_t sample_count;
	uint32_t frame;
	uint32_t network_timestamp;
	uint32_t media_latency;
	uint32_t media_timestamp;
	uint64_t start_sample;
	uint64_t total_samples;
	uint32_t sample_rate;
	uint32_t bitrate;
	uint16_t volume_offset;
	uint8_t bitdepth;
	uint8_t channels;
	uint8_t reserved;
	uint8_t codec_length;
	uint8_t data[];
} ohm1_audio;

typedef struct __attribute__((__packed__)) {
	uint32_t sequence;
	uint32_t uri_length;
	uint32_t metadata_length;
	uint8_t data[];
} ohm1_track;

typedef struct __attribute__((__packed__)) {
	uint32_t sequence;
	uint32_t length;
	uint8_t data[];
} ohm1_metatext;

typedef struct __attribute__((__packed__)) {
	uint32_t addr;
	uint16_t port;
} ohm1_slave_entry;

typedef struct __attribute__((__packed__)) {
	uint32_t count;
	ohm1_slave_entry slaves[];
} ohm1_slave;

typedef struct __attribute__((__packed__)) {
	uint32_t count;
	uint32_t data[];
} ohm1_resend_request;

struct audio_frame_options {
	int channels;
	unsigned int sample_rate;
	int bitdepth;
	unsigned int media_latency;
	const char *codec;
};

struct cached_frame {
	int index;
	int flags;
	audio_frame_options options;
	size_t chunk_size;
	uint8_t chunk[];
};

#endif
