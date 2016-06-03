/** MDevice.c
 *
 * Multidevice interface for Toxcore
 *
 */

#include "MDevice.h"
#include "util.h"

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
        if (dev->device[dev_num].status > MDEV_OK) {
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

static int handle_status(void *object, int dev_num, int device_id, uint8_t status)
{
    Tox *tox = object;
    printf("handle_status MDEV\n");
    return 0;
}


static int handle_packet(void *object, int dev_num, int device_id, uint8_t *temp, uint16_t len)
{
    Tox *tox = object;
    printf("handle_packet MDEV\n");
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

