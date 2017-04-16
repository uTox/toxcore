/*
 * util.c -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
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
 */

#define _XOPEN_SOURCE 600

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util.h"

#include "crypto_core.h" /* for CRYPTO_PUBLIC_KEY_SIZE */
#include "network.h" /* for current_time_monotonic */

#include <time.h>


/* don't call into system billions of times for no reason */
static uint64_t unix_time_value;
static uint64_t unix_base_time_value;

void unix_time_update(void)
{
    if (unix_base_time_value == 0) {
        unix_base_time_value = ((uint64_t)time(NULL) - (current_time_monotonic() / 1000ULL));
    }

    unix_time_value = (current_time_monotonic() / 1000ULL) + unix_base_time_value;
}

uint64_t unix_time(void)
{
    return unix_time_value;
}

int is_timeout(uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= unix_time();
}


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src)
{
    return public_key_cmp(dest, src) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, CRYPTO_PUBLIC_KEY_SIZE);
    return CRYPTO_PUBLIC_KEY_SIZE;
}

void host_to_net(uint8_t *num, uint16_t numbytes)
{
#ifndef WORDS_BIGENDIAN
    uint32_t i;
    uint8_t buff[numbytes];

    for (i = 0; i < numbytes; ++i) {
        buff[i] = num[numbytes - i - 1];
    }

    memcpy(num, buff, numbytes);
#endif
}

uint16_t lendian_to_host16(uint16_t lendian)
{
#ifdef WORDS_BIGENDIAN
    return (lendian << 8) | (lendian >> 8);
#else
    return lendian;
#endif
}

void host_to_lendian32(uint8_t *dest,  uint32_t num)
{
#ifdef WORDS_BIGENDIAN
    num = ((num << 8) & 0xFF00FF00) | ((num >> 8) & 0xFF00FF);
    num = (num << 16) | (num >> 16);
#endif
    memcpy(dest, &num, sizeof(uint32_t));
}

void lendian_to_host32(uint32_t *dest, const uint8_t *lendian)
{
    uint32_t d;
    memcpy(&d, lendian, sizeof(uint32_t));
#ifdef WORDS_BIGENDIAN
    d = ((d << 8) & 0xFF00FF00) | ((d >> 8) & 0xFF00FF);
    d = (d << 16) | (d >> 16);
#endif
    *dest = d;
}

int create_recursive_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    /* Create queue mutex */
    if (pthread_mutex_init(mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);

    return 0;
}
