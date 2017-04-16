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

#include "save.h"
#include "util.h"

#include "netcore.h"

#include "MDevice.h"
#include "Messenger.h"

/* Loads the non-otional state from the sections of the saved data */
static int save_read_sections_tox_callback(Netcore *n, const uint8_t *data, uint32_t length, uint16_t type)
{
    switch (type) {
        case SAVE_STATE_TYPE_NOSPAMKEYS:
            if (length == CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE + sizeof(uint32_t)) {
                set_nospam(n->net_crypto, *(uint32_t *)data);
                load_secret_key(n->net_crypto, (&data[sizeof(uint32_t)]) + CRYPTO_PUBLIC_KEY_SIZE);

                if (public_key_cmp((&data[sizeof(uint32_t)]), n->net_crypto->self_public_key) != 0) {
                    return -1;
                }
            } else {
                return -1;    /* critical */
            }

            break;

        case SAVE_STATE_TYPE_DHT:
            DHT_load(n->dht, data, length);
            break;

        case SAVE_STATE_TYPE_PATH_NODE: {
            Node_format nodes[NUM_SAVED_PATH_NODES];

            if (length == 0) {
                break;
            }

            int i, num = unpack_nodes(nodes, NUM_SAVED_PATH_NODES, 0, data, length, 0);

            for (i = 0; i < num; ++i) {
                onion_add_bs_path_node(n->onion_c, nodes[i].ip_port, nodes[i].public_key);
            }

            break;
        }
    }

    return 0;
}

static int save_read_sections_dispatch(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
{
    Netcore *n = outer;

    if (type == SAVE_STATE_TYPE_END) {
        if (length != 0) {
            return -1;
        } else {
            return -2;
        }
    }

    /* If anyone returns -1, we abort, so only do that if there's a critical error */
    if (n && messenger_save_read_sections_callback(n, data, length, type) < 0) {
        return -1;
    }

    // if (n && mdev_save_read_sections_callback(n, data, length, type) < 0) {
    //     return -1;
    // }

    return save_read_sections_tox_callback(n, data, length, type);
}

uint8_t *save_write_subheader(uint8_t *data, size_t len, uint16_t type, uint32_t cookie)
{
    if (len > UINT32_MAX) {
        printf("save_write_subheader: Unable to save section bigger than 4GiB!\n");
        cookie = len = type = 0;
    }

    host_to_lendian32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian32(data, (host_tolendian16(cookie) << 16) | host_tolendian16(type));
    data += sizeof(uint32_t);
    return data;
}

/* Returns the size of the Tox data to be saved */
static size_t save_tox_size(const Netcore *n)
{
    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    return     sizesubhead + sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE
             + sizesubhead + DHT_size(n->dht)                                 // DHT
             + sizesubhead + NUM_SAVED_PATH_NODES * packed_node_size(TCP_INET6) //saved path nodes
             ;
}

size_t save_get_savedata_size(const Netcore *n)
{
    const size_t header_size = sizeof(uint32_t)*2, footer_size = sizeof(uint32_t)*2;
    return header_size
         + save_tox_size(n)
         + messenger_size(n)
         // + mdev_size(n)
         + footer_size;
}

void save_get_savedata(const Netcore *n, uint8_t *data)
{
    if (!data)
        return;

    size_t data_size = save_get_savedata_size(n);
    if (data_size > UINT32_MAX) {
        printf("save_get_savedata: The save file would be bigger than 4GiB, unable to save!\n");
        return;
    }
    memset(data, 0, data_size);

    uint32_t len;
    uint16_t type;
    uint32_t size32 = sizeof(uint32_t);

    /* Write the header */
    memset(data, 0, size32);
    data += size32;
    host_to_lendian32(data, SAVE_STATE_COOKIE_GLOBAL);
    data += size32;

    /* Write mandatory data */
#ifdef DEBUG
    assert(sizeof(get_nospam(n->net_crypto)) == sizeof(uint32_t));
#endif
    len = size32 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE;
    type = SAVE_STATE_TYPE_NOSPAMKEYS;
    data = save_write_subheader(data, len, type, SAVE_STATE_COOKIE_TYPE);
    *(uint32_t *)data = get_nospam(n->net_crypto);
    save_keys(n->net_crypto, data + size32);
    data += len;

    len = DHT_size(n->dht);
    type = SAVE_STATE_TYPE_DHT;
    data = save_write_subheader(data, len, type, SAVE_STATE_COOKIE_TYPE);
    DHT_save(n->dht, data);
    data += len;

    Node_format nodes[NUM_SAVED_PATH_NODES];
    type = SAVE_STATE_TYPE_PATH_NODE;
    uint8_t *temp_data = data;
    data = save_write_subheader(data, 0, type, SAVE_STATE_COOKIE_TYPE);
    memset(nodes, 0, sizeof(nodes));
    // unsigned int num = onion_backup_nodes(n->onion_c, nodes, NUM_SAVED_PATH_NODES);
    // int l = pack_nodes(data, NUM_SAVED_PATH_NODES * packed_node_size(TCP_INET6), nodes, num);

    // if (l > 0) {
    //     len = l;
    //     data = save_write_subheader(temp_data, len, type, SAVE_STATE_COOKIE_TYPE);
    //     data += len;
    // }

    /* Add optional sections */
    if (n) {
        data = messenger_save(n, data);
    }

    // if (n) {
    //     data = mdev_save(n, data);
    // }

    /* Write final section */
    save_write_subheader(data, 0, SAVE_STATE_TYPE_END, SAVE_STATE_COOKIE_TYPE);
}

int save_load_from_data(Netcore *n, const uint8_t *data, uint32_t length)
{
    uint32_t data32[2];
    uint32_t cookie_len = sizeof(data32);

    if (length < cookie_len)
        return -1;

    memcpy(data32, data, sizeof(uint32_t));
    lendian_to_host32(data32 + 1, data + sizeof(uint32_t));

    if (data32[0]!=0 || data32[1] != SAVE_STATE_COOKIE_GLOBAL)
        return -1;

    return save_read_sections(save_read_sections_dispatch, n, data + cookie_len,
                                length - cookie_len, SAVE_STATE_COOKIE_TYPE);
}

int save_read_sections(save_read_sections_callback_func save_read_sections_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (!save_read_sections_callback || !data) {
        fprintf(stderr, "save_read_sections() called with invalid args.\n");
        return -1;
    }

    uint16_t type;
    uint32_t length_sub, cookie_type;
    uint32_t size_head = sizeof(uint32_t) * 2;

    while (length >= size_head) {
        lendian_to_host32(&length_sub, data);
        lendian_to_host32(&cookie_type, data + sizeof(length_sub));
        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
            fprintf(stderr, "state data too short: %u < %u\n", length, length_sub);
            return -1;
        }

        if (lendian_to_host16((cookie_type >> 16)) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
            fprintf(stderr, "state data garbeled: %04hx != %04hx\n", (cookie_type >> 16), cookie_inner);
            return -1;
        }

        type = lendian_to_host16(cookie_type & 0xFFFF);

        int ret = save_read_sections_callback(outer, data, length_sub, type);

        if (ret == -1) {
            return -1;
        }

        /* -2 means end of save. */
        if (ret == -2)
            return 0;

        data += length_sub;
        length -= length_sub;
    }

    return length == 0 ? 0 : -1;
};
