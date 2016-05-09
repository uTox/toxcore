/** MDevice.c
 *
 * Multidevice interface for Toxcore
 *
 */

#include "Messenger.h"

void do_multidevice(MDevice *dev)
{

    do_tox_connections(dev->dev_c);
}

int mdev_add_new_device(MDevice *dev, const uint8_t *real_pk)
{
    if (!public_key_valid(real_pk)) {
        return -1;
    }

    /* TODO
     *
     * check vs our primary key
     * check vs out DHT key
     * check vs already existing in list
     * check vs other? */

    int32_t friend_id = getfriend_id(dev->m, real_pk);

    if (friend_id != -1) {
        if (dev->device[friend_id].status >= FRIEND_CONFIRMED) {
            printf("ID Already exists in list...\n");
            return -1;
        }
    }

    // int32_t ret = init_new_device_(dev, friend_number, real_pk, DEVICE_CONFIRMED);
    int32_t ret = 0;

    return ret;
}
