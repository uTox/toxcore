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
#include "tox.h"
#include "MDevice.h"
#include "Messenger.h"

uint8_t *save_write_subheader(uint8_t *data, uint32_t len, uint16_t type, uint32_t cookie)
{
    host_to_lendian32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian32(data, (host_tolendian16(cookie) << 16) | host_tolendian16(type));
    data += sizeof(uint32_t);
    return data;
}

/* Returns the size of the Tox data to be saved */
static size_t save_tox_size(const Tox* tox)
{
    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    return     sizesubhead + sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
             + sizesubhead + DHT_size(tox->dht)                                 // DHT
             + sizesubhead + NUM_SAVED_PATH_NODES * packed_node_size(TCP_INET6) //saved path nodes
             ;
}

size_t save_get_savedata_size(const Tox *tox)
{
    const size_t header_size = sizeof(uint32_t)*2, footer_size = sizeof(uint32_t)*2;
    return header_size + save_tox_size(tox) + messenger_size(tox) + mdev_size(tox) + footer_size;
}

void save_get_savedata(const Tox *tox, uint8_t *data)
{
    if (!data)
        return;

    size_t data_size = tox_get_savedata_size(tox);
    if (data_size > UINT32_MAX) {
        printf("The save file would be bigger than 4GiB, unable to save!");
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
    assert(sizeof(get_nospam(&(tox->m->fr))) == sizeof(uint32_t));
#endif
    len = size32 + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    type = SAVE_STATE_TYPE_NOSPAMKEYS;
    data = save_write_subheader(data, len, type, SAVE_STATE_COOKIE_TYPE);
    *(uint32_t *)data = get_nospam(tox->net_crypto);
    save_keys(tox->net_crypto, data + size32);
    data += len;

    len = DHT_size(tox->dht);
    type = SAVE_STATE_TYPE_DHT;
    data = save_write_subheader(data, len, type, SAVE_STATE_COOKIE_TYPE);
    DHT_save(tox->dht, data);
    data += len;

    Node_format nodes[NUM_SAVED_PATH_NODES];
    type = SAVE_STATE_TYPE_PATH_NODE;
    uint8_t *temp_data = data;
    data = save_write_subheader(data, 0, type, SAVE_STATE_COOKIE_TYPE);
    memset(nodes, 0, sizeof(nodes));
    unsigned int num = onion_backup_nodes(tox->onion_c, nodes, NUM_SAVED_PATH_NODES);
    int l = pack_nodes(data, NUM_SAVED_PATH_NODES * packed_node_size(TCP_INET6), nodes, num);

    if (l > 0) {
        len = l;
        data = save_write_subheader(temp_data, len, type, SAVE_STATE_COOKIE_TYPE);
        data += len;
    }

    /* Add optional sections */
    if (tox->m)
        data = messenger_save(tox, data);
    if (tox->mdev)
        data = mdev_save(tox, data);

    /* Write final section */
    save_write_subheader(data, 0, SAVE_STATE_TYPE_END, SAVE_STATE_COOKIE_TYPE);
}
