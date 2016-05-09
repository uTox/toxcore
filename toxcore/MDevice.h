/** MDevice.h
 *
 * Multidevice interface for Toxcore
 *
 */

#ifndef MDEV_H
#define MDEV_H

#include "Messenger.h"
#include "tox_connection.h"

/* TODO: These should only live in Messenger.h */
#define MAX_NAME_LENGTH 128
#define MAX_DEVICE_COUNT 16



typedef struct {
    uint8_t     status; //0 no device, 1-3 device confimed, 4-5 device is blocked
    uint8_t     real_pk[crypto_box_PUBLICKEYBYTES];

    int         toxconn_id;

    uint64_t    last_seen_time;

    uint8_t     localname[MAX_NAME_LENGTH];
    uint16_t    localname_length;

    uint8_t     remotename[MAX_NAME_LENGTH];
    uint16_t    remotename_length;
} Device;

typedef struct Messenger Messenger;

typedef struct {
    Messenger       *m;

    Networking_Core *net;
    Net_Crypto *net_crypto;

    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;

    Tox_Connections *dev_c;

    Device          device[MAX_DEVICE_COUNT];
    uint64_t        device_count;
    uint64_t        device_online_count;

    uint8_t status;

} MDevice;

#endif
