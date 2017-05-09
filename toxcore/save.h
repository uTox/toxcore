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

/* New tox format for load/save, more robust and forward compatible
 *
 * TODO rename save -> state. so funcs can be called state_save_ and state_load_,
 *                                                 vs save_save_ and save_load_
 *
 * Compiles on the same level as tox.h, but technically, is should be once layer below.
 * Meaning lower layers should be able to include save.h without gaining any additional knowledge
 * about what's goes on in other files. */

#define SAVE_STATE_COOKIE_GLOBAL 0x15ed1b1f

#define SAVE_STATE_COOKIE_TYPE      0x01ce
typedef enum {
    SAVE_STATE_TYPE_NOSPAMKEYS      = 1,
    SAVE_STATE_TYPE_DHT             = 2,
    SAVE_STATE_TYPE_OLDFRIENDS      = 3,    /* Deprecated by *_FRIENDS */
    SAVE_STATE_TYPE_NAME            = 4,
    SAVE_STATE_TYPE_STATUSMESSAGE   = 5,
    SAVE_STATE_TYPE_STATUS          = 6,
    SAVE_STATE_TYPE_TCP_RELAY       = 10,
    SAVE_STATE_TYPE_PATH_NODE       = 11,
    SAVE_STATE_TYPE_FRIENDS         = 12,
    SAVE_STATE_TYPE_MDEVICE         = 13,
    SAVE_STATE_TYPE_END             = 255,
} SAVE_STATE_TYPES;
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
uint8_t *save_write_subheader(uint8_t *data, size_t len, uint16_t type, uint32_t cookie);

/**
 * Size of a subheader written by `save_write_subheader`
 */
static inline size_t save_subheader_size(void) { return 2*sizeof(uint32_t); }

/**
 * Restores the state of `tox` and its optional components from the saved data
 * Will call the *_save_read_sections_callback for each non-NULL Tox component
 */
int save_load_from_data(Tox *tox, const uint8_t *data, uint32_t length);

/* Runs a callback with the content of each section in the save data */
typedef int (*save_read_sections_callback_func)(void *outer, const uint8_t *data, uint32_t len, uint16_t type);
int save_read_sections(save_read_sections_callback_func save_read_sections_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

#endif // SAVE_H
