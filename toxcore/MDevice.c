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
        free(dev->device);
        dev->device = NULL;
        return 0;
    }

    Device *new_dev_list = realloc(dev->device, num * sizeof(Device));

    if (new_dev_list == NULL)
        return -1;

    dev->device = new_dev_list;
    return 0;
}

static uint8_t mdev_device_not_valid(const MDevice *dev, uint32_t dev_num)
{
    if (dev_num < dev->device_count) {
        if (dev->device[dev_num].status > MDEV_PENDING) {
            return 0;
        }
    }

    return 1;
}

static int send_online_packet(Tox *tox, int32_t dev_num, int32_t unused)
{
    if (mdev_device_not_valid(tox->mdev, dev_num)) {
        return 0;
    }

    uint8_t packet = PACKET_ID_ONLINE;
    return write_cryptpacket(tox->net_crypto,
                             toxconn_crypt_connection_id(tox->mdev->dev_conns, tox->mdev->device[dev_num].toxconn_id),
                             &packet, sizeof(packet), 0) != -1;
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status);
static int handle_packet(void *object, int dev_num, int device_id, uint8_t *temp, uint16_t len);
static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length);

static int32_t init_new_device_self(Tox *tox, const uint8_t *real_pk, uint8_t status)
{
    /* Resize the friend list if necessary. */
    if (realloc_mdev_list(tox->mdev, tox->mdev->device_count + 1) != 0) {
        return FAERR_NOMEM;
    }

    memset(&(tox->mdev->device[tox->mdev->device_count]), 0, sizeof(Device));

    int devconn_id = new_tox_conn(tox->mdev->dev_conns, real_pk);

    if (devconn_id == -1) {
        return FAERR_NOMEM;
    }

    uint32_t i;

    for (i = 0; i <= tox->mdev->device_count; ++i) {
        if (tox->mdev->device[i].status == NO_MDEV) {
            tox->mdev->device[i].status = status;
            tox->mdev->device[i].toxconn_id = devconn_id;

            id_copy(tox->mdev->device[i].real_pk, real_pk);

            toxconn_set_callbacks(tox->mdev->dev_conns,
                                  devconn_id,
                                  MDEV_CALLBACK_INDEX,
                                  &handle_status,
                                  &handle_packet,
                                  &handle_custom_lossy_packet,
                                  tox,
                                  i,  /* device number */
                                  0); /* sub_device number always 0 for mdevice, */

            if (tox->mdev->device_count == i) {
                ++tox->mdev->device_count;
            }

            if (toxconn_is_connected(tox->mdev->dev_conns, devconn_id) == TOXCONN_STATUS_CONNECTED) {
                tox->mdev->device[i].status = MDEV_ONLINE;
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
    mdev->device[dev_num].status = status;

    if (status == MDEV_CONFIRMED) {

    } else if (status == MDEV_ONLINE) {

    }
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status)
{
    Tox *tox = object;
    printf("handle_status MDEV dev_num %i || dev_id %i || status %u \n", dev_num, device_id, status);
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

    if (mdev->device[dev_num].status != MDEV_ONLINE) {
        if (packet_id == PACKET_ID_ONLINE && len == 1) {
            set_mdevice_status(mdev, dev_num, MDEV_ONLINE);
            send_online_packet(tox, dev_num, 0);
        } else {
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

        case PACKET_ID_NICKNAME: {
            if (data_length > MAX_NAME_LENGTH)
                break;

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

    free(dev->device);
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

    for (i = 0; i < dev->device_count; ++i) {
        if (dev->device[i].status > 0) {
            if (id_equal(real_pk, dev->device[i].real_pk)) {
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
        if (tox->mdev->device[dev_id].status >= FRIEND_CONFIRMED) {
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
    for (devi = 0; devi < self->device_count; ++devi) {
        Device* dev = &self->device[devi];
        size +=   sizeof(dev->status)
                + sizeof(dev->real_pk)
                + sizeof(uint32_t)
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

    return    save_subheader_size()                     /* Section header */
            + sizeof(uint8_t)                           /* Version field */
            + sizeof(tox->mdev->status)                 /* Status */
            + sizeof(tox->mdev->device_count)           /* Device count */
            + mdev_devices_size(tox->mdev)              /* Device data */
            ;
}

uint8_t *mdev_save(const Tox *tox, uint8_t *data)
{
    size_t len = mdev_size(tox) - save_subheader_size();
    data = save_write_subheader(data, len, SAVE_STATE_TYPE_MDEVICE, SAVE_STATE_COOKIE_TYPE);

    *data++ = 1; /* Current version of the on-disk format */

    *data++ = tox->mdev->status;

    host_to_lendian32(data, tox->mdev->device_count);
    data += sizeof(uint32_t);

    size_t devi;
    for (devi = 0; devi < tox->mdev->device_count; ++devi) {
        Device* dev = &tox->mdev->device[devi];

        *data++ = dev->status;

        memcpy(data, dev->real_pk, sizeof(dev->real_pk));
        data += sizeof(dev->real_pk);

        assert(dev->toxconn_id >= -1 /* Since toxconn_id can be -1, we do +1 to get a portable, saveable unsigned */
               && dev->toxconn_id < UINT32_MAX /* We'd wrap to 0 otherwise */
               && dev->toxconn_id < INT_MAX); /* Doing +1 would be UB otherwise */
        uint32_t toxconn_id_packed = (uint32_t)(dev->toxconn_id + 1);
        host_to_lendian32(data, toxconn_id_packed);
        data += sizeof(uint32_t);

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

        lendian_to_host32(&self->device_count, data);
        data += sizeof(uint32_t);

        realloc_mdev_list(self, self->device_count);

        /** TODO: Do we want to check MAX_DEVICE_COUNT here? */

        size_t devi;
        for (devi = 0; devi < self->device_count; ++devi) {
            Device* dev = &self->device[devi];

            size_t required = sizeof(uint8_t)+sizeof(dev->real_pk)+sizeof(uint32_t)+sizeof(uint64_t)+sizeof(uint16_t);
            if (length < required)
                goto fail_tooshort;
            length -= required;

            dev->status = (MDEV_STATUS)*data++;

            memcpy(dev->real_pk, data, sizeof(dev->real_pk));
            data += sizeof(dev->real_pk);

            uint32_t toxconn_id_packed;
            lendian_to_host32(&toxconn_id_packed, data);
            assert(toxconn_id_packed < INT_MAX);
            dev->toxconn_id = (int)toxconn_id_packed - 1;
            data += sizeof(uint32_t);

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
    }

    return 0;

fail_tooshort:
    printf("Failed to read MDevice saved state, data truncated\n");
    realloc_mdev_list(self, 0);
    self->device_count = 0;
    self->status = NO_MDEV;
    return 0;
}
