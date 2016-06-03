/* save.h
 *
 * Implementation of save functions.
 *
 *  Copyright (C) 2016 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef SAVE_H
#define SAVE_H

#include <stddef.h>
#include <stdint.h>

/* New tox format for load/save, more robust and forward compatible */

#define SAVE_STATE_COOKIE_GLOBAL 0x15ed1b1f

#define SAVE_STATE_COOKIE_TYPE      0x01ce
#define SAVE_STATE_TYPE_NOSPAMKEYS    1
#define SAVE_STATE_TYPE_DHT           2
#define SAVE_STATE_TYPE_OLDFRIENDS    3    /* Deprecated by *_FRIENDS */
#define SAVE_STATE_TYPE_NAME          4
#define SAVE_STATE_TYPE_STATUSMESSAGE 5
#define SAVE_STATE_TYPE_STATUS        6
#define SAVE_STATE_TYPE_TCP_RELAY     10
#define SAVE_STATE_TYPE_PATH_NODE     11
#define SAVE_STATE_TYPE_FRIENDS       12
#define SAVE_STATE_TYPE_END           255

#define NUM_SAVED_PATH_NODES 8

typedef struct Tox Tox;

/**
 * Calculates the number of bytes required to store the tox instance with
 * save_get_savedata. This function cannot fail. The result is always greater than 0.
 *
 * @see threading for concurrency implications.
 */
size_t save_get_savedata_size(const Tox *tox);

/**
 * Store all information associated with the tox instance to a byte array.
 *
 * @param data A memory region large enough to store the tox instance data.
 *   Call tox_get_savedata_size to find the number of bytes required. If this parameter
 *   is NULL, this function has no effect.
 */
void save_get_savedata(const Tox *tox, uint8_t *savedata);

/**
 * Writes the header for a save data section of length `len` and type `type` to `data`
 */
uint8_t *save_write_subheader(uint8_t *data, uint32_t len, uint16_t type, uint32_t cookie);

/**
 * Restores the state of `tox` and its optional components from the saved data
 * Will call the *_save_read_sections_callback for each Tox component
 */
int save_load_from_data(Tox *tox, const uint8_t *data, uint32_t length);

/* Runs a callback with the content of each section in the save data */
typedef int (*save_read_sections_callback_func)(void *outer, const uint8_t *data, uint32_t len, uint16_t type);
int save_read_sections(save_read_sections_callback_func save_read_sections_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

#endif // SAVE_H
