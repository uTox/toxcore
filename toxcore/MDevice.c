/** MDevice.c
 *
 * Multidevice interface for Toxcore
 *
 */

#include "MDevice.h"
#include "util.h"
#include "save.h"
#include "assert.h"
#include <limits.h>

uint32_t toxmd_version_major(void)
{
    return TOX_VERSION_MAJOR;
}

uint32_t toxmd_version_minor(void)
{
    return TOX_VERSION_MINOR;
}

uint32_t toxmd_version_patch(void)
{
    return TOX_VERSION_PATCH;
}

bool toxmd_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
  return (TOX_VERSION_MAJOR == major && /* Force the major version */
            (TOX_VERSION_MINOR > minor || /* Current minor version must be newer than requested -- or -- */
                (TOX_VERSION_MINOR == minor && TOX_VERSION_PATCH >= patch) /* the patch must be the same or newer */
            )
         );
}


static int realloc_mdev_list(MDevice *dev, uint32_t num)
{
    if (num == 0) {
        free(dev->devices);
        dev->devices = NULL;
        return 0;
    }

    Device *new_dev_list = realloc(dev->devices, num * sizeof(Device));

    if (new_dev_list == NULL)
        return -1;

    dev->devices = new_dev_list;
    return 0;
}

static int realloc_mdev_removed_list(MDevice *dev, uint32_t num)
{
    if (num == 0) {
        free(dev->removed_devices);
        dev->removed_devices = NULL;
        return 0;
    }

    uint8_t (*removed_devices)[] = realloc(dev->removed_devices, num * crypto_box_PUBLICKEYBYTES);

    if (removed_devices == NULL)
        return -1;

    dev->removed_devices = removed_devices;
    return 0;
}

static uint8_t mdev_device_not_valid(const MDevice *dev, uint32_t dev_num)
{
    if (dev_num < dev->devices_count) {
        if (dev->devices[dev_num].status > MDEV_PENDING) {
            return 0;
        }
    }

    return 1;
}

static int send_mdev_packet(Tox *tox, int32_t dev_num, uint8_t *packet, size_t length)
{
    MDevice *mdev = tox->mdev;

    return write_cryptpacket(tox->net_crypto,
                             toxconn_crypt_connection_id(mdev->dev_conns, mdev->devices[dev_num].toxconn_id),
                             packet, length, 0) != -1;
}

static int send_online_packet(Tox *tox, int32_t dev_num, int32_t unused)
{
    if (mdev_device_not_valid(tox->mdev, dev_num)) {
        return 0;
    }

    uint8_t packet = PACKET_ID_ONLINE;
    return send_mdev_packet(tox, dev_num, &packet, sizeof(packet));
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status);
static int handle_packet(void *object, int dev_num, int device_id, uint8_t *temp, uint16_t len);
static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length);

static int32_t init_new_device_self(Tox *tox, const uint8_t *real_pk, uint8_t status)
{
    /* Resize the friend list if necessary. */
    if (realloc_mdev_list(tox->mdev, tox->mdev->devices_count + 1) != 0) {
        return FAERR_NOMEM;
    }

    memset(&(tox->mdev->devices[tox->mdev->devices_count]), 0, sizeof(Device));

    int devconn_id = new_tox_conn(tox->mdev->dev_conns, real_pk);

    if (devconn_id == -1) {
        return FAERR_NOMEM;
    }

    uint32_t i;

    for (i = 0; i <= tox->mdev->devices_count; ++i) {
        if (tox->mdev->devices[i].status == NO_MDEV) {
            tox->mdev->devices[i].status = status;
            tox->mdev->devices[i].toxconn_id = devconn_id;

            id_copy(tox->mdev->devices[i].real_pk, real_pk);

            toxconn_set_callbacks(tox->mdev->dev_conns,
                                  devconn_id,
                                  MDEV_CALLBACK_INDEX,
                                  &handle_status,
                                  &handle_packet,
                                  &handle_custom_lossy_packet,
                                  tox,
                                  i,  /* device number */
                                  0); /* sub_device number always 0 for mdevice, */

            if (tox->mdev->devices_count == i) {
                ++tox->mdev->devices_count;
            }

            if (toxconn_is_connected(tox->mdev->dev_conns, devconn_id) == TOXCONN_STATUS_CONNECTED) {
                tox->mdev->devices[i].status = MDEV_ONLINE;
                send_online_packet(tox, i, 0);
            }


            printf("init_device %u \n", i);
            return i;
        }
    }

    return FAERR_NOMEM;
}

static void set_mdevice_status(MDevice *mdev, uint32_t dev_num, MDEV_STATUS status)
{
    mdev->devices[dev_num].status = status;

    if (status == MDEV_CONFIRMED) {

    } else if (status == MDEV_ONLINE) {

    }
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status)
{
    Tox *tox = object;
    MDevice *mdev = tox->mdev;
    printf("handle_status MDEV dev_num %i || dev_id %i || status %u \n", dev_num, device_id, status);
    if (status) {
        set_mdevice_status(mdev, dev_num, MDEV_ONLINE);
    } else {
        set_mdevice_status(mdev, dev_num, MDEV_CONFIRMED);
    }
    return 0;
}


static int handle_packet(void *object, int dev_num, int device_id, uint8_t *pkt, uint16_t len)
{
    printf("handle_packet MDEV dev_num %i // dev_id %i // pkt %u // length %u \n", dev_num, device_id, pkt[0], len);

    if (len == 0) {
        return -1;
    }

    Tox      *tox = object;
    MDevice *mdev = tox->mdev;

    uint8_t packet_id = pkt[0];
    uint8_t *data = pkt + 1;
    uint32_t data_length = len - 1;

    if (mdev->devices[dev_num].status != MDEV_ONLINE) {
        if (packet_id == PACKET_ID_ONLINE && len == 1) {
            set_mdevice_status(mdev, dev_num, MDEV_ONLINE);
            send_online_packet(tox, dev_num, 0);
        } else {
            printf("error, this device is offline\n");
            return -1;
        }
    }

    switch (packet_id) {
        case PACKET_ID_OFFLINE: {
            if (data_length != 0)
                break;

            set_mdevice_status(mdev, dev_num, MDEV_CONFIRMED);
            break;
        }

        case PACKET_ID_MDEV_SEND: {
            if (data[0] == MDEV_SEND_NAME) {
                uint8_t *name        = data + 1;
                size_t   name_length = data_length - 1;

                if (data_length > MAX_NAME_LENGTH) {
                    break;
                }

                if (name_length > MAX_NAME_LENGTH) {
                    break;
                }

                if (tox->m->name_length == name_length && (name_length == 0 || memcmp(name, tox->m->name, name_length) == 0)) {
                    break;
                }

                if (name_length) {
                    memcpy(tox->m->name, name, name_length);
                }

                tox->m->name_length = name_length;

                if (mdev->self_name_change) {
                    mdev->self_name_change(tox, dev_num, name, name_length, mdev->self_name_change_userdata);

                }

            }
            break;
        }

        case PACKET_ID_STATUSMESSAGE: {
            if (data_length > MAX_STATUSMESSAGE_LENGTH)
                break;

            break;
        }

        case PACKET_ID_USERSTATUS: {
            if (data_length != 1)
                break;

            break;
        }

        case PACKET_ID_MESSAGE:
        case PACKET_ID_ACTION: {
            if (data_length == 0)
                break;

            break;
        }



        default: {
            break;
        }
    }

    return 0;
}


static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length)
{
    Tox *tox = object;
    printf("handle_custom_lossy_packet MDEV\n");
    return 0;
}


/******************************************************************************
 ******** Multi-device send data fxns                                  ********
 ******************************************************************************/
bool mdev_sync_name_change(Tox *tox, uint8_t *name, size_t length)
{
    uint8_t packet[length + 2];

    packet[0] = PACKET_ID_MDEV_SEND;
    packet[1] = MDEV_SEND_NAME;
    memcpy(&packet[2], name, length);

    if (tox->mdev->devices_count == 0) {
        return 0;
    }

    for (int i = 0; i <= tox->mdev->devices_count; ++i) {
        send_mdev_packet(tox, i, packet, length + 2);
    }

    return 1;
}


void mdev_send_message_generic(tox, friend_number, type, message, length)
{
    return;
}


/******************************************************************************
 ******** Multi-device set callbacks                                   ********
 ******************************************************************************/
void mdev_callback_self_name_change(Tox *tox,
                                   void (*function)(Tox *tox, uint32_t, const uint8_t *, size_t, void *),
                                   void *userdata)
{
    tox->mdev->self_name_change = function;
    tox->mdev->self_name_change_userdata = userdata;
}


/******************************************************************************
 ******** Multi-device init, exit fxns                                 ********
 ******************************************************************************/

/* TODO replace the options here with our own! */
MDevice *new_mdevice(Tox* tox, Messenger_Options *options, unsigned int *error)
{
    MDevice *dev = calloc(1, sizeof(MDevice));

    if (error) {
        *error = MESSENGER_ERROR_OTHER;
    }

    if (!dev) {
        return NULL;
    }

    dev->dev_conns = new_tox_conns(tox->onion_c);

    if (error) {
        *error = MESSENGER_ERROR_NONE;
    }

    return dev;
}

/* Run this before closing shop. */
void kill_multidevice(MDevice *dev)
{
    if (!dev) {
        return;
    }

    uint32_t i;

    free(dev->devices);
    free(dev);
}



void do_multidevice(MDevice *dev)
{
    if (!dev) {
        return;
    }

    do_tox_connections(dev->dev_conns);
}

static int get_device_id(MDevice *dev, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < dev->devices_count; ++i) {
        if (dev->devices[i].status > 0) {
            if (id_equal(real_pk, dev->devices[i].real_pk)) {
                return i;
            }
        }
    }

    return -1;
}

int mdev_add_new_device_self(Tox *tox, const uint8_t *real_pk)
{
    if (!public_key_valid(real_pk)) {
        return -1;
    }

    /* TODO
     *
     * check vs our primary key
     * check vs out DHT key
     * check vs already existing in list
     * check vs other?
     */

    int32_t dev_id = get_device_id(tox->mdev, real_pk);

    if (dev_id != -1) {
        if (tox->mdev->devices[dev_id].status >= FRIEND_CONFIRMED) {
            printf("Dev ID Already exists in list...\n");
            return -1;
        }
    }

    int32_t ret = init_new_device_self(tox, real_pk, MDEV_PENDING);

    return ret;
}

static size_t mdev_devices_size(MDevice* self)
{
    size_t size = 0, devi;
    for (devi = 0; devi < self->devices_count; ++devi) {
        Device* dev = &self->devices[devi];
        size +=   sizeof(uint8_t)
                + sizeof(dev->real_pk)
                + sizeof(dev->last_seen_time)
                + sizeof(uint16_t)
                + dev->localname_length
                + sizeof(uint16_t)
                + dev->remotename_length;
    }
    return size;
}

size_t mdev_size(const Tox *tox)
{
    if (!tox->mdev)
        return 0;

    return    save_subheader_size()                                         /* Section header */
            + sizeof(uint8_t)                                               /* Version field */
            + sizeof(tox->mdev->status)                                     /* Status */
            + sizeof(tox->mdev->devices_count)                              /* Device count */
            + mdev_devices_size(tox->mdev)                                  /* Device data */
            + sizeof(tox->mdev->removed_devices_count)                      /* Removed device count */
            + tox->mdev->removed_devices_count*crypto_box_PUBLICKEYBYTES    /* Removed device data */
            ;
}

uint8_t *mdev_save(const Tox *tox, uint8_t *data)
{
    size_t len = mdev_size(tox) - save_subheader_size();
    data = save_write_subheader(data, len, SAVE_STATE_TYPE_MDEVICE, SAVE_STATE_COOKIE_TYPE);

    *data++ = 1; /* Current version of the on-disk format */

    *data++ = tox->mdev->status;

    host_to_lendian32(data, tox->mdev->devices_count);
    data += sizeof(uint32_t);

    size_t devi;
    for (devi = 0; devi < tox->mdev->devices_count; ++devi) {
        Device* dev = &tox->mdev->devices[devi];

        *data++ = dev->status;

        memcpy(data, dev->real_pk, sizeof(dev->real_pk));
        data += sizeof(dev->real_pk);

        uint8_t last_seen_time[sizeof(uint64_t)];
        memcpy(last_seen_time, &dev->last_seen_time, sizeof(uint64_t));
        host_to_net(last_seen_time, sizeof(last_seen_time));
        memcpy(data, last_seen_time, sizeof(last_seen_time));
        data += sizeof(last_seen_time);

        uint16_t len = host_tolendian16(dev->localname_length);
        memcpy(data, &len, sizeof(uint16_t));
        data += sizeof(uint16_t);
        memcpy(data, dev->localname, dev->localname_length);
        data += dev->localname_length;

        len = host_tolendian16(dev->remotename_length);
        memcpy(data, &len, sizeof(uint16_t));
        data += sizeof(uint16_t);
        memcpy(data, dev->remotename, dev->remotename_length);
        data += dev->remotename_length;
    }

    host_to_lendian32(data, tox->mdev->removed_devices_count);
    data += sizeof(uint32_t);

    size_t size = tox->mdev->removed_devices_count * crypto_box_PUBLICKEYBYTES;
    memcpy(data, tox->mdev->removed_devices, size);
    data += size;

    return data;
}

int mdev_save_read_sections_callback(Tox *tox, const uint8_t *data, uint32_t length, uint16_t type)
{
    if (type != SAVE_STATE_TYPE_MDEVICE)
        return 0;

    if (length < sizeof(uint8_t))
        return -1;
    uint8_t version = data[0];
    data++;
    length--;

    MDevice* self = tox->mdev;

    if (version == 1) {
        if (length < sizeof(uint8_t)+sizeof(uint32_t))
            return 0;
        length -= sizeof(uint8_t)+sizeof(uint32_t);

        self->status = *data++;

        uint32_t devices_count;
        lendian_to_host32(&devices_count, data);
        self->devices_count = 0;
        data += sizeof(uint32_t);

        size_t devi;
        for (devi = 0; devi < devices_count; ++devi) {
            uint8_t status;
            uint8_t real_pk[crypto_box_PUBLICKEYBYTES];

            size_t required = sizeof(uint8_t)+sizeof(real_pk)+sizeof(uint64_t)+sizeof(uint16_t);
            if (length < required)
                goto fail_tooshort;
            length -= required;

            status = (MDEV_STATUS)*data++;

            memcpy(real_pk, data, sizeof(real_pk));
            data += sizeof(real_pk);

            if (mdev_add_new_device_self(tox, real_pk) < 0)
                goto fail_generic;

            Device* dev = &self->devices[devi];

            dev->status = status;

            uint8_t last_seen_time[sizeof(uint64_t)];
            memcpy(last_seen_time, data, sizeof(last_seen_time));
            net_to_host(last_seen_time, sizeof(last_seen_time));
            memcpy(&dev->last_seen_time, last_seen_time, sizeof(uint64_t));
            data += sizeof(last_seen_time);

            uint16_t len;
            memcpy(&len, data, sizeof(uint16_t));
            dev->localname_length = lendian_to_host16(len);
            data += sizeof(uint16_t);
            if (length < dev->localname_length + sizeof(uint16_t))
                goto fail_tooshort;
            length -= dev->localname_length + sizeof(uint16_t);
            memcpy(dev->localname, data, dev->localname_length);
            data += dev->localname_length;

            memcpy(&len, data, sizeof(uint16_t));
            dev->remotename_length = lendian_to_host16(len);
            data += sizeof(uint16_t);
            if (length < dev->remotename_length)
                goto fail_tooshort;
            length -= dev->remotename_length;
            memcpy(dev->remotename, data, dev->remotename_length);
            data += dev->remotename_length;
        }

        if (length < sizeof(uint32_t))
            goto fail_tooshort;
        length -= sizeof(uint32_t);

        lendian_to_host32(&self->removed_devices_count, data);
        data += sizeof(uint32_t);

        size_t removed_size = self->removed_devices_count * crypto_box_PUBLICKEYBYTES;
        if (length < removed_size)
            goto fail_tooshort;
        length -= removed_size;
        if (realloc_mdev_removed_list(self, self->removed_devices_count) < 0)
            goto fail_generic;
        memcpy(self->removed_devices, data, removed_size);
        data += removed_size;

        if (length)
            printf("mdev_save_read_sections_callback: Extra data ignored, save might be corrupted!\n");
    }

    return 0;

fail_tooshort:
    printf("Failed to read MDevice saved state, data is truncated!\n");
fail_generic:
    realloc_mdev_list(self, 0);
    self->devices_count = 0;
    self->status = NO_MDEV;
    return 0;
}

int mdev_remove_device(Tox *tox, uint32_t device_num)
{
    MDevice* self = tox->mdev;

    if (device_num >= self->devices_count)
        return -1;

    realloc_mdev_removed_list(self, self->removed_devices_count+1);
    memcpy(self->removed_devices[self->removed_devices_count], self->devices[device_num].real_pk,
            sizeof(self->devices[device_num].real_pk));
    self->removed_devices_count++;

    off_t pos = device_num*sizeof(Device), new_pos = pos-sizeof(Device);
    size_t size = (self->devices_count - device_num - 1)*sizeof(Device);
    memmove(self->devices+new_pos, self->devices+pos, size);
    realloc_mdev_list(self, self->devices_count-1); // Not a problem if it fails to shrink
    self->devices_count--;

    return 0;
}
