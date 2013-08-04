/*
 * Copyright (C) 2003-2013 The Music Player Daemon Project
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

/** \file
 *
 * This header declares the mixer_plugin class.  It should not be
 * included directly; use MixerInternal.hxx instead in mixer
 * implementations.
 */

#ifndef MPD_MIXER_PLUGIN_HXX
#define MPD_MIXER_PLUGIN_HXX

#include "gerror.h"

struct config_param;
class Mixer;

struct mixer_plugin {
	/**
         * Alocates and configures a mixer device.
	 *
	 * @param ao the pointer returned by audio_output_plugin.init
	 * @param param the configuration section
	 * @param error_r location to store the error occurring, or
	 * NULL to ignore errors
	 * @return a mixer object, or NULL on error
	 */
	Mixer *(*init)(void *ao, const config_param &param,
		       GError **error_r);

	/**
	 * Finish and free mixer data
         */
	void (*finish)(Mixer *data);

	/**
	 * Open mixer device
	 *
	 * @param error_r location to store the error occurring, or
	 * NULL to ignore errors
	 * @return true on success, false on error
	 */
	bool (*open)(Mixer *data, GError **error_r);

	/**
	 * Close mixer device
	 */
	void (*close)(Mixer *data);

	/**
	 * Reads the current volume.
	 *
	 * @param error_r location to store the error occurring, or
	 * NULL to ignore errors
	 * @return the current volume (0..100 including) or -1 if
	 * unavailable or on error (error_r set, mixer will be closed)
	 */
	int (*get_volume)(Mixer *mixer, GError **error_r);

	/**
	 * Sets the volume.
	 *
	 * @param error_r location to store the error occurring, or
	 * NULL to ignore errors
	 * @param volume the new volume (0..100 including)
	 * @return true on success, false on error
	 */
	bool (*set_volume)(Mixer *mixer, unsigned volume,
			   GError **error_r);

	/**
	 * If true, then the mixer is automatically opened, even if
	 * its audio output is not open.  If false, then the mixer is
	 * disabled as long as its audio output is closed.
	 */
	bool global;
};

#endif
