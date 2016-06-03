/** MDevice.h
 *
 * Multidevice interface for Toxcore
 *
 */

#ifndef MULTIDEV_H
#define MULTIDEV_H

#include "tox.h"
#include "Messenger.h"
#include "tox_connection.h"

/**
 * The major version number. Incremented when the API or ABI changes in an
 * incompatible way.
 */
#define TOXMD_VERSION_MAJOR               0u

/**
 * The minor version number. Incremented when functionality is added without
 * breaking the API or ABI. Set to 0 when the major version number is
 * incremented.
 */
#define TOXMD_VERSION_MINOR               0u

/**
 * The patch or revision number. Incremented when bugfixes are applied without
 * changing any functionality or API or ABI.
 */
#define TOXMD_VERSION_PATCH               0u

/**
 * A macro to check at preprocessing time whether the client code is compatible
 * with the installed version of Tox.
 */
#define TOXMD_VERSION_IS_API_COMPATIBLE(MAJOR, MINOR, PATCH)      \
  (TOXMD_VERSION_MAJOR == MAJOR &&                                \
   (TOXMD_VERSION_MINOR > MINOR ||                                \
    (TOXMD_VERSION_MINOR == MINOR &&                              \
     TOXMD_VERSION_PATCH >= PATCH)))

/**
 * A macro to make compilation fail if the client code is not compatible with
 * the installed version of Tox.
 */
#define TOXMD_VERSION_REQUIRE(MAJOR, MINOR, PATCH)                \
  typedef char tox_required_version[TOX_IS_COMPATIBLE(MAJOR, MINOR, PATCH) ? 1 : -1]

/**
 * Return the major version number of the library. Can be used to display the
 * Tox library version or to check whether the client is compatible with the
 * dynamically linked version of Tox.
 */
uint32_t toxmd_version_major(void);

/**
 * Return the minor version number of the library.
 */
uint32_t toxmd_version_minor(void);

/**
 * Return the patch number of the library.
 */
uint32_t toxmd_version_patch(void);

/**
 * Return whether the compiled library version is compatible with the passed
 * version numbers.
 */
bool toxmd_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch);

/**
 * A convenience macro to call toxmd_version_is_compatible with the currently
 * compiling API version.
 */
#define TOXMD_VERSION_IS_ABI_COMPATIBLE()                         \
  toxmd_version_is_compatible(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH)


/* TODO: These should only live in Messenger.h */
#define MAX_NAME_LENGTH 128
#define MAX_DEVICE_COUNT 16

#define MDEV_CALLBACK_INDEX 0

typedef enum {
    NO_MDEV,
    /* Device is blocked */
    MDEV_REMOVED,
    MDEV_REFUSED,
    MDEV_PENDING,
    /* Device is active */
    MDEV_OK,
    MDEV_CONFIRMED,
    MDEV_ONLINE,

} MDEV_STATUS;

typedef struct {
    MDEV_STATUS status; //0 no device, 1-3 device confimed, 4-5 device is blocked
    uint8_t     real_pk[crypto_box_PUBLICKEYBYTES];

    int         toxconn_id;

    uint64_t    last_seen_time;

    uint8_t     localname[MAX_NAME_LENGTH];
    uint16_t    localname_length;

    uint8_t     remotename[MAX_NAME_LENGTH];
    uint16_t    remotename_length;
} Device;

typedef struct Messenger Messenger;

typedef struct MDevice MDevice;

struct MDevice {
    Tox* tox;

    Tox_Connections *dev_conns;

    Device          *device;

    uint32_t        device_count;

    uint8_t status;
};

typedef struct Tox Tox;

/* TODO DOCUMENT THIS FXN */
void do_multidevice(MDevice *dev);

/* TODO DOCUMENT THIS FXN */
MDevice *new_mdevice(Tox* tox, Messenger_Options *options, unsigned int *error);

/* TODO DOCUMENT THIS FXN */
int mdev_add_new_device_self(Tox *tox, const uint8_t *real_pk);

#endif
