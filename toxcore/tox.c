/* tox.c
 *
 * The Tox public API.
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
 *
 */
#define _XOPEN_SOURCE 600

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tox.h"

#include "Messenger.h"
#include "MDevice.h"
#include "group.h"
#include "logger.h"
#include "save.h"
#include "util.h"

#include "../toxencryptsave/defines.h"

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#if TOX_HASH_LENGTH != CRYPTO_SHA256_SIZE
#error TOX_HASH_LENGTH is assumed to be equal to CRYPTO_SHA256_SIZE
#endif

#if FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE
#endif

#if TOX_FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error TOX_FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE
#endif

#if TOX_FILE_ID_LENGTH != TOX_HASH_LENGTH
#error TOX_FILE_ID_LENGTH is assumed to be equal to TOX_HASH_LENGTH
#endif

#if TOX_PUBLIC_KEY_SIZE != CRYPTO_PUBLIC_KEY_SIZE
#error TOX_PUBLIC_KEY_SIZE is assumed to be equal to CRYPTO_PUBLIC_KEY_SIZE
#endif

#if TOX_SECRET_KEY_SIZE != CRYPTO_SECRET_KEY_SIZE
#error TOX_SECRET_KEY_SIZE is assumed to be equal to CRYPTO_SECRET_KEY_SIZE
#endif

#if TOX_MAX_NAME_LENGTH != MAX_NAME_LENGTH
#error TOX_MAX_NAME_LENGTH is assumed to be equal to MAX_NAME_LENGTH
#endif

#if TOX_MAX_STATUS_MESSAGE_LENGTH != MAX_STATUSMESSAGE_LENGTH
#error TOX_MAX_STATUS_MESSAGE_LENGTH is assumed to be equal to MAX_STATUSMESSAGE_LENGTH
#endif


bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    return TOX_VERSION_IS_API_COMPATIBLE(major, minor, patch);
}


Tox *tox_new(const struct Tox_Options *options, TOX_ERR_NEW *error)
{
    Messenger_Options    m_options = {0};
    MDevice_Options   mdev_options = {0};

    bool load_savedata_sk = 0, load_savedata_tox = 0;

    if (options == NULL) {
        m_options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    } else {
        if (tox_options_get_savedata_type(options) != TOX_SAVEDATA_TYPE_NONE) {
            if (tox_options_get_savedata_data(options) == NULL || tox_options_get_savedata_length(options) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return NULL;
            }
        }

        if (tox_options_get_savedata_type(options) == TOX_SAVEDATA_TYPE_SECRET_KEY) {
            if (tox_options_get_savedata_length(options) != TOX_SECRET_KEY_SIZE) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return NULL;
            }

            load_savedata_sk = 1;
        } else if (tox_options_get_savedata_type(options) == TOX_SAVEDATA_TYPE_TOX_SAVE) {
            if (tox_options_get_savedata_length(options) < TOX_ENC_SAVE_MAGIC_LENGTH) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return NULL;
            }

            if (crypto_memcmp(tox_options_get_savedata_data(options), TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_ENCRYPTED);
                return NULL;
            }

            load_savedata_tox = 1;
        }

        m_options.ipv6enabled = tox_options_get_ipv6_enabled(options);
        m_options.udp_disabled = !tox_options_get_udp_enabled(options);
        m_options.port_range[0] = tox_options_get_start_port(options);
        m_options.port_range[1] = tox_options_get_end_port(options);
        m_options.tcp_server_port = tox_options_get_tcp_port(options);
        m_options.hole_punching_enabled = tox_options_get_hole_punching_enabled(options);
        m_options.local_discovery_enabled = tox_options_get_local_discovery_enabled(options);
        m_options.log_callback = (logger_cb *)tox_options_get_log_callback(options);
        m_options.log_user_data = tox_options_get_log_user_data(options);

        mdev_options.send_messages = tox_options_get_mdev_mirror_messages(options);

        switch (tox_options_get_proxy_type(options)) {
            case TOX_PROXY_TYPE_HTTP:
                m_options.proxy_info.proxy_type = TCP_PROXY_HTTP;
                break;

            case TOX_PROXY_TYPE_SOCKS5:
                m_options.proxy_info.proxy_type = TCP_PROXY_SOCKS5;
                break;

            case TOX_PROXY_TYPE_NONE:
                m_options.proxy_info.proxy_type = TCP_PROXY_NONE;
                break;

            default:
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_TYPE);
                return NULL;
        }

        if (m_options.proxy_info.proxy_type != TCP_PROXY_NONE) {
            if (tox_options_get_proxy_port(options) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_PORT);
                return NULL;
            }

            ip_init(&m_options.proxy_info.ip_port.ip, m_options.ipv6enabled);

            if (m_options.ipv6enabled) {
                m_options.proxy_info.ip_port.ip.family = AF_UNSPEC;
            }

            if (!addr_resolve_or_parse_ip(tox_options_get_proxy_host(options), &m_options.proxy_info.ip_port.ip, NULL)) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_HOST);
                // TODO(irungentoo): TOX_ERR_NEW_PROXY_NOT_FOUND if domain.
                return NULL;
            }

            m_options.proxy_info.ip_port.port = htons(tox_options_get_proxy_port(options));
        }
    }

    Tox *tox = calloc(1, sizeof(Tox));

    if (!tox) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return NULL;
    }

    tox->ncore = netcore_init(tox);
    if (!tox->ncore) {
        free(tox);
        return NULL;
    }

    Logger *log = NULL;
    if (options->log_callback) {
        log = logger_new();

        if (log != NULL) {
            logger_callback_log(log, options->log_callback, tox, options->log_user_data);
        }
    }
    tox->log = log;

    unsigned int net_err = 0;

    if (m_options.udp_disabled) {
        /* this is the easiest way to completely disable UDP without changing too much code. */
        tox->ncore->net = calloc(1, sizeof(Networking_Core));
    } else {
        IP ip;
        ip_init(&ip, m_options.ipv6enabled);
        tox->ncore->net = new_networking_ex(log, ip, m_options.port_range[0], m_options.port_range[1], &net_err);
    }

    if (tox->ncore->net == NULL) {
        netcore_raze(tox->ncore);
        free(tox);

        if (error && net_err == 1) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        }

        return NULL;
    }

    tox->ncore->dht = new_DHT(log, tox->ncore->net, tox_options_get_hole_punching_enabled(options));

    if (tox->ncore->dht == NULL) {
        kill_networking(tox->ncore->net);
        netcore_raze(tox->ncore);
        free(tox);
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return NULL;
    }

    tox->ncore->net_crypto = new_net_crypto(log, tox->ncore->dht, &m_options.proxy_info);

    if (tox->ncore->net_crypto == NULL) {
        kill_networking(tox->ncore->net);
        kill_DHT(tox->ncore->dht);
        netcore_raze(tox->ncore);
        free(tox);
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return NULL;
    }

    tox->ncore->onion    = new_onion(tox->ncore->dht);
    tox->ncore->onion_a  = new_onion_announce(tox->ncore->dht);
    tox->ncore->onion_c  = new_onion_client(tox->ncore->net_crypto);

    if (!(tox->ncore->onion && tox->ncore->onion_a && tox->ncore->onion_c)) {
        kill_onion(tox->ncore->onion);
        kill_onion_announce(tox->ncore->onion_a);
        kill_onion_client(tox->ncore->onion_c);
        kill_net_crypto(tox->ncore->net_crypto);
        kill_DHT(tox->ncore->dht);
        kill_networking(tox->ncore->net);
        netcore_raze(tox->ncore);
        free(tox);
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return NULL;
    }

    unsigned int m_error;

    tox->ncore->tox_conn = new_tox_conns(tox->ncore->onion_c);

    Messenger *m = messenger_new(log, tox->ncore, &m_options, &m_error);
    if (!m) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return NULL;
    }
    tox->m = m;

    MDevice *mdev = mdevice_new(tox, tox->ncore, &mdev_options, &m_error);
    if (!mdev) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return NULL;
    }
    mdev->tox = tox;
    mdev->m   = m;
    tox->mdev = mdev;

    tox->gc = new_groupchats(tox->m);
    if (!tox->gc) {
        kill_messenger(m); /* TODO messenger doesn't do everything anymore so we need to kill everything here instead */
                           /* OTHER TODO we need to make groupchats optional*/
        if (m_error == MESSENGER_ERROR_PORT) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else if (m_error == MESSENGER_ERROR_TCP_SERVER) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        }

        return NULL;
    }

    if (load_savedata_tox && save_load_from_data(tox, options->savedata_data, options->savedata_length) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
    } else if (load_savedata_sk) {
        load_secret_key(tox->ncore->net_crypto, options->savedata_data);
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    }

    unix_time_update();

    return tox;
}

void tox_kill(Tox *tox)
{
    if (tox == NULL) {
        return;
    }

    kill_groupchats(tox->gc);
    kill_messenger(tox->m);
}

size_t tox_get_savedata_size(const Tox *tox)
{
    return save_get_savedata_size(tox);
}

void tox_get_savedata(const Tox *tox, uint8_t *savedata)
{
    if (savedata) {
        save_get_savedata(tox, savedata);
    }
}

bool tox_bootstrap(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key, TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    struct addrinfo *root, *info;

    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    info = root;

    unsigned int count = 0;

    do {
        IP_Port ip_port;
        ip_port.port = htons(port);
        ip_port.ip.family = info->ai_family;

        if (info->ai_socktype && info->ai_socktype != SOCK_DGRAM) {
            continue;
        }

        if (info->ai_family == AF_INET) {
            ip_port.ip.ip4.in_addr = ((struct sockaddr_in *)info->ai_addr)->sin_addr;
        } else if (info->ai_family == AF_INET6) {
            ip_port.ip.ip6.in6_addr = ((struct sockaddr_in6 *)info->ai_addr)->sin6_addr;
        } else {
            continue;
        }

        onion_add_bs_path_node(tox->ncore->onion_c, ip_port, public_key);
        DHT_bootstrap(tox->ncore->dht, ip_port, public_key);
        ++count;
    } while ((info = info->ai_next));

    freeaddrinfo(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

bool tox_add_tcp_relay(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key,
                       TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    struct addrinfo *root, *info;

    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    info = root;

    unsigned int count = 0;

    do {
        IP_Port ip_port;
        ip_port.port = htons(port);
        ip_port.ip.family = info->ai_family;

        if (info->ai_socktype && info->ai_socktype != SOCK_STREAM) {
            continue;
        }

        if (info->ai_family == AF_INET) {
            ip_port.ip.ip4.in_addr = ((struct sockaddr_in *)info->ai_addr)->sin_addr;
        } else if (info->ai_family == AF_INET6) {
            ip_port.ip.ip6.in6_addr = ((struct sockaddr_in6 *)info->ai_addr)->sin6_addr;
        } else {
            continue;
        }

        add_tcp_relay(tox->ncore->net_crypto, ip_port, public_key);
        ++count;
    } while ((info = info->ai_next));

    freeaddrinfo(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

TOX_CONNECTION tox_self_get_connection_status(const Tox *tox)
{
    unsigned int ret = onion_connection_status(tox->ncore->onion_c);

    if (ret == 2) {
        return TOX_CONNECTION_UDP;
    }

    if (ret == 1) {
        return TOX_CONNECTION_TCP;
    }

    return TOX_CONNECTION_NONE;
}


void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback)
{
    m_callback_core_connection(tox->m, callback);
}

uint32_t tox_iteration_interval(const Tox *tox)
{
    return messenger_run_interval(tox->m);
}

void tox_iterate(Tox *tox, void *userdata)
{
    do_messenger(tox->m, userdata);
    do_groupchats(tox->gc, userdata);

    do_tox_connections(tox->ncore->tox_conn, userdata);
    do_multidevice(tox->mdev);

}

void tox_self_get_address(const Tox *tox, uint8_t *address)
{
    if (address)
        getaddress(tox->m, address);
}

bool tox_self_add_device(Tox *tox, const uint8_t* name, size_t length,
                         const uint8_t *address, TOX_ERR_DEVICE_ADD *error)
{
    if (!tox || !tox->mdev || length > MAX_NAME_LENGTH || !address) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_NULL);
        return 0;
    }

    if (!name && length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_NULL);
        return 0;
    }

    if (length > MAX_NAME_LENGTH ) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_TOO_LONG);
        return 0;
    }

    int ret;
    if ((ret = mdev_add_new_device_self(tox->mdev, name, length, address)) < 0) {
        if (ret == -2) {
            SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_BAD_KEY);
        } else if (ret == -3) {
            SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_OWN_KEY);
        } else if (ret == -4) {
            SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_BLACKLISTED);
        } else if (ret == -5) {
            SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_NULL);
        } else {
            SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_INTERNAL);
        }
        return 0;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_ADD_OK);
        return 1;
    }
}

uint32_t tox_self_get_device_count(const Tox *tox)
{
    if (!tox || !tox->mdev)
        return 0;

    return tox->mdev->devices_count;
}

bool tox_self_get_device(Tox *tox, uint32_t device_num, uint8_t *name, TOX_DEVICE_STATUS *status,
                         uint8_t *public_key, TOX_ERR_DEVICE_GET *error)
{
    if (!tox || !tox->mdev) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_GET_NULL);
        return 0;
    }

    if (device_num >= tox->mdev->devices_count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_GET_NODEV);
        return 0;
    }

    if (name) {
        memcpy(name, tox->mdev->devices[device_num].name, tox->mdev->devices[device_num].name_length);
        name[tox->mdev->devices[device_num].name_length] = '\0';
    }
    if (status) {
        *status = (TOX_DEVICE_STATUS)tox->mdev->devices[device_num].status;
    }
    memcpy(public_key, tox->mdev->devices[device_num].real_pk, sizeof(tox->mdev->devices[device_num].real_pk));
    SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_GET_OK);
    return 1;
}

uint32_t tox_self_get_blacklisted_device_count(const Tox *tox)
{
    if (!tox || !tox->mdev)
        return 0;

    return tox->mdev->removed_devices_count;
}

bool tox_self_get_blacklisted_device(Tox *tox, uint32_t device_num, uint8_t *public_key,
                                     TOX_ERR_BLACKLISTED_DEVICE_GET *error)
{
    if (!tox || !tox->mdev) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BLACKLISTED_DEVICE_GET_NULL);
        return 0;
    }

    if (device_num >= tox->mdev->removed_devices_count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BLACKLISTED_DEVICE_GET_NODEV);
        return 0;
    }

    memcpy(public_key, tox->mdev->removed_devices[device_num], sizeof(tox->mdev->removed_devices[device_num]));
    SET_ERROR_PARAMETER(error, TOX_ERR_BLACKLISTED_DEVICE_GET_OK);
    return 1;
}

bool tox_self_delete_device(Tox *tox, const uint8_t *address, TOX_ERR_DEVICE_DEL *error)
{
    if (!tox || !tox->mdev || !address) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_DEL_NULL);
        return 0;
    }

    if (mdev_remove_device(tox->mdev, address) < 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_DEL_NODEV);
        return 0;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_DEVICE_DEL_OK);
        return 1;
    }
}

void tox_callback_mdev_sent_message(Tox *tox,
                                    void (*callback)(Tox *tox, uint32_t sending_device, uint32_t target_friend,
                                                    uint8_t type, const uint8_t *msg, size_t msg_length,
                                                    void *userdata))
{
    mdev_callback_dev_sent_message(tox->mdev, callback);
}


void tox_self_set_nospam(Tox *tox, uint32_t nospam)
{
    set_nospam(tox->ncore->net_crypto, htonl(nospam));
}

uint32_t tox_self_get_nospam(const Tox *tox)
{
    return ntohl(get_nospam(tox->ncore->net_crypto));
}

void tox_self_get_public_key(const Tox *tox, uint8_t *public_key)
{
    if (public_key) {
        memcpy(public_key, tox->ncore->net_crypto->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    }
}

void tox_self_get_secret_key(const Tox *tox, uint8_t *secret_key)
{
    if (secret_key) {
        memcpy(secret_key, tox->ncore->net_crypto->self_secret_key, CRYPTO_SECRET_KEY_SIZE);
    }
}

bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, TOX_ERR_SET_INFO *error)
{
    if (!name && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox->m;

    if (setname(m, name, length) == 0) {
        // --: function to set different per group names?
        // Yes, in the new groupchats
        send_name_all_groups(tox->gc);

        /* TODO error checking here */
        mdev_send_name_change(tox->mdev, name, length);

        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
    return 0;
}

size_t tox_self_get_name_size(const Tox *tox)
{
    return m_get_self_name_size(tox->m);
}

void tox_self_get_name(const Tox *tox, uint8_t *name)
{
    if (name) {
        const Messenger *m = tox->m;
        getself_name(m, name);
    }
}

void tox_callback_mdev_self_name(Tox *tox, tox_mdev_self_name_cb *function)
{
    mdev_callback_self_name(tox->mdev, function);
}

bool tox_self_set_status_message(Tox *tox, const uint8_t *status, size_t length, TOX_ERR_SET_INFO *error)
{
    if (!status && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    if (m_set_statusmessage(tox->m, status, length) == 0) {

        /* TODO error checking here */
        mdev_send_status_message_change(tox->mdev, status, length);

        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
    return 0;
}

size_t tox_self_get_status_message_size(const Tox *tox)
{
    return m_get_self_statusmessage_size(tox->m);
}

void tox_self_get_status_message(const Tox *tox, uint8_t *status_message)
{
    if (status_message)
        m_copy_self_statusmessage(tox->m, status_message);
}

void tox_callback_mdev_self_status_message(Tox *tox, tox_mdev_self_status_message_cb *function)
{
    mdev_callback_self_status_message(tox->mdev, function);
}

void tox_self_set_status(Tox *tox, TOX_USER_STATUS status)
{
    m_set_userstatus(tox->m, status);

    /* TODO Error checking? */
    mdev_send_state_change(tox->mdev, status);
}

TOX_USER_STATUS tox_self_get_status(const Tox *tox)
{
    return m_get_self_userstatus(tox->m);
}

void tox_callback_mdev_self_state(Tox *tox, tox_mdev_self_state_cb *function)
{
    mdev_callback_self_state(tox->mdev, function);
}


static void set_friend_error(int32_t ret, TOX_ERR_FRIEND_ADD *error)
{
    switch (ret) {
        case FAERR_TOOLONG:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_TOO_LONG);
            break;

        case FAERR_NOMESSAGE:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE);
            break;

        case FAERR_OWNKEY:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OWN_KEY);
            break;

        case FAERR_ALREADYSENT:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT);
            break;

        case FAERR_BADCHECKSUM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
            break;

        case FAERR_SETNEWNOSPAM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM);
            break;

        case FAERR_NOMEM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_MALLOC);
            break;
    }
}

static void set_friend_dev_error(int32_t ret, TOX_ERR_FRIEND_ADD_DEVICE *error)
{
    switch (ret) {
        case FAERR_TOOLONG:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_TOO_LONG);
            break;

        case FAERR_NOMESSAGE:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_NO_MESSAGE);
            break;

        case FAERR_OWNKEY:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_OWN_KEY);
            break;

        case FAERR_ALREADYSENT:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_ALREADY_SENT);
            break;

        case FAERR_BADCHECKSUM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_BAD_CHECKSUM);
            break;

        case FAERR_SETNEWNOSPAM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_SET_NEW_NOSPAM);
            break;

        case FAERR_NOMEM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_MALLOC);
            break;

    }
}

uint32_t tox_friend_add(Tox *tox, const uint8_t *address, const uint8_t *message, size_t length,
                        TOX_ERR_FRIEND_ADD *error)
{
    if (!address || !message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    /* TODO return an error if mdevice has a sync in progress */

    int32_t ret = m_addfriend(tox->m, address, message, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

uint32_t tox_friend_add_device(Tox *tox, const uint8_t *address, uint32_t friend_number, TOX_ERR_FRIEND_ADD_DEVICE *error)
{
    if (!address) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_NULL);
        return UINT32_MAX;
    }

    /* TODO return an error if mdevice has a sync in progress */

    int32_t ret = m_add_device_to_friend(tox->m, address, friend_number);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_DEVICE_OK);
        return ret;
    }

    set_friend_dev_error(ret, error);
    return UINT32_MAX;
}

uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_ADD *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    /* TODO return an error if mdevice has a sync in progress */

    int32_t ret = m_addfriend_norequest(tox->m, public_key);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

bool tox_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error)
{
    /* TODO return an error if mdevice has a sync in progress */

    int ret = m_delfriend(tox->m, friend_number);

    // TODO(irungentoo): handle if realloc fails?
    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_OK);
    return 1;
}

uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_BY_PUBLIC_KEY *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL);
        return UINT32_MAX;
    }

    const Messenger *m = tox->m;
    int32_t ret = getfriend_id(m, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK);
    return ret;
}

bool tox_friend_get_public_key(const Tox *tox, uint32_t friend_number, uint8_t *public_key,
                               TOX_ERR_FRIEND_GET_PUBLIC_KEY *error)
{
    if (!public_key) {
        return 0;
    }

    if (get_real_pk(tox->m, friend_number, public_key) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);
    return 1;
}

bool tox_friend_exists(const Tox *tox, uint32_t friend_number)
{
    return m_friend_exists(tox->m, friend_number);
}

uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_GET_LAST_ONLINE *error)
{
    uint64_t timestamp = m_get_last_online(tox->m, friend_number);

    if (timestamp == UINT64_MAX) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND)
        return UINT64_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_OK);
    return timestamp;
}

size_t tox_self_get_friend_list_size(const Tox *tox)
{
    const Messenger *m = tox->m;
    return count_friendlist(m);
}

void tox_self_get_friend_list(const Tox *tox, uint32_t *friend_list)
{
    if (friend_list) {
        // TODO(irungentoo): size parameter?
        copy_friendlist(tox->m, friend_list, tox_self_get_friend_list_size(tox));
    }
}

void tox_callback_friend_list_change(Tox *tox, tox_friend_list_change_cb *function)
{
    mdev_callback_friend_list_change(tox->mdev, function);
}


size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    int ret = m_get_name_size(tox->m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, TOX_ERR_FRIEND_QUERY *error)
{
    if (!name) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox->m;
    int ret = getname(m, friend_number, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *callback)
{
    m_callback_namechange(tox->m, callback);
}

size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    int ret = m_get_statusmessage_size(tox->m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_status_message(const Tox *tox, uint32_t friend_number, uint8_t *status_message,
                                   TOX_ERR_FRIEND_QUERY *error)
{
    if (!status_message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    //TODO: size parameter?
    int ret = m_copy_statusmessage(tox->m, friend_number, status_message,
                                   m_get_statusmessage_size(tox->m, friend_number));

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *callback)
{
    m_callback_statusmessage(tox->m, callback);
}

TOX_USER_STATUS tox_friend_get_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    int ret = m_get_userstatus(tox->m, friend_number);

    if (ret == USERSTATUS_INVALID) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return (TOX_USER_STATUS)(TOX_USER_STATUS_BUSY + 1);
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (TOX_USER_STATUS)ret;
}

void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *callback)
{
    m_callback_userstatus(tox->m, (void (*)(Tox *, uint32_t, unsigned int, void *))callback);
}

TOX_CONNECTION tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    int ret = m_get_friend_connectionstatus(tox->m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_CONNECTION_NONE;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (TOX_CONNECTION)ret;
}

void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
    m_callback_connectionstatus(tox->m, (void (*)(Tox *, uint32_t, unsigned int, void *))callback);
}

bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    int ret = m_get_istyping(tox->m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return !!ret;
}

void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *callback)
{
    m_callback_typingchange(tox->m, callback);
}

bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool typing, TOX_ERR_SET_TYPING *error)
{

    if (m_set_usertyping(tox->m, friend_number, typing) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_OK);
    return 1;
}

static void set_message_error(int ret, TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ);
            break;

        case -5:
            /* can't happen */
            break;
    }
}

uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_NULL);
        return 0;
    }

    if (!length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY);
        return 0;
    }

    uint32_t message_id = 0;
    set_message_error(m_send_message_generic(tox->m, friend_number, type, message, length, &message_id), error);

    if (tox->mdev) {
        if (tox->mdev->options.send_messages) {
            mdev_send_message_generic(tox->mdev, friend_number, type, message, length);
        }
    }


    return message_id;
}

void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *callback)
{
    m_callback_read_receipt(tox->m, callback);
}

void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *callback)
{
    m_callback_friendrequest(tox->m, callback);
}

void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *callback)
{
    m_callback_friendmessage(tox->m, (void (*)(Tox *, uint32_t, unsigned int, const uint8_t *, size_t, void *))callback);
}

bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length)
{
    if (!hash || (length && !data)) {
        return 0;
    }

    crypto_sha256(hash, data, length);
    return 1;
}

bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                      TOX_ERR_FILE_CONTROL *error)
{
    int ret = file_control(tox->m, friend_number, file_number, control);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_FOUND);
            return 0;

        case -4:
            /* can't happen */
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_ALREADY_PAUSED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_DENIED);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_PAUSED);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_file_seek(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                   TOX_ERR_FILE_SEEK *error)
{
    int ret = file_seek(tox->m, friend_number, file_number, position);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_NOT_FOUND);
            return 0;

        case -4: // fall-through
        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_DENIED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_INVALID_POSITION);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback)
{
    callback_file_control(tox->m, (void (*)(Tox *, uint32_t, uint32_t, unsigned int, void *))callback);
}

bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          TOX_ERR_FILE_GET *error)
{
    if (!file_id) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NULL);
        return 0;
    }

    int ret = file_get_id(tox->m, friend_number, file_number, file_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_OK);
        return 1;
    }

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_FRIEND_NOT_FOUND);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NOT_FOUND);
    }

    return 0;
}

uint32_t tox_file_send(Tox *tox, uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t *file_id,
                       const uint8_t *filename, size_t filename_length, TOX_ERR_FILE_SEND *error)
{
    if (filename_length && !filename) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NULL);
        return UINT32_MAX;
    }

    uint8_t f_id[FILE_ID_LENGTH];

    if (!file_id) {
        /* Tox keys are 32 bytes like FILE_ID_LENGTH. */
        new_symmetric_key(f_id);
        file_id = f_id;
    }

    long int file_num = new_filesender(tox->m, friend_number, kind, file_size, file_id, filename, filename_length);

    if (file_num >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_OK);
        return file_num;
    }

    switch (file_num) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NAME_TOO_LONG);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_TOO_MANY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_file_send_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                         size_t length, TOX_ERR_FILE_SEND_CHUNK *error)
{
    int ret = file_data(tox->m, friend_number, file_number, position, data, length);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_SENDQ);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback)
{
    callback_file_reqchunk(tox->m, callback);
}

void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *callback)
{
    callback_file_sendrequest(tox->m, callback);
}

void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback)
{
    callback_file_data(tox->m, callback);
}

void tox_callback_conference_invite(Tox *tox, tox_conference_invite_cb *callback)
{
    g_callback_group_invite((Group_Chats *)tox->gc, (void (*)(Tox *m, uint32_t, int, const uint8_t *,
                            size_t,
                            void *))callback);
}

void tox_callback_conference_message(Tox *tox, tox_conference_message_cb *callback)
{
    g_callback_group_message((Group_Chats *)tox->gc, (void (*)(Tox * m, uint32_t, uint32_t, int,
                             const uint8_t *,
                             size_t, void *))callback);
}

void tox_callback_conference_title(Tox *tox, tox_conference_title_cb *callback)
{
    g_callback_group_title((Group_Chats *)tox->gc, callback);
}

void tox_callback_conference_namelist_change(Tox *tox, tox_conference_namelist_change_cb *callback)
{
    g_callback_group_namelistchange((Group_Chats *)tox->gc, (void (*)(Tox *, int, int, uint8_t,
                                    void *))callback);
}

uint32_t tox_conference_new(Tox *tox, TOX_ERR_CONFERENCE_NEW *error)
{
    int ret = add_groupchat((Group_Chats *)tox->gc, GROUPCHAT_TYPE_TEXT);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_INIT);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_OK);
    return ret;
}

bool tox_conference_delete(Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_DELETE *error)
{
    int ret = del_groupchat((Group_Chats *)tox->gc, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_DELETE_OK);
    return true;
}

uint32_t tox_conference_peer_count(const Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_PEER_QUERY *error)
{
    int ret = group_number_peers((Group_Chats *)tox->gc, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

size_t tox_conference_peer_get_name_size(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
        TOX_ERR_CONFERENCE_PEER_QUERY *error)
{
    int ret = group_peername_size((Group_Chats *)tox->gc, conference_number, peer_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

bool tox_conference_peer_get_name(const Tox *tox, uint32_t conference_number, uint32_t peer_number, uint8_t *name,
                                  TOX_ERR_CONFERENCE_PEER_QUERY *error)
{
    int ret = group_peername((Group_Chats *)tox->gc, conference_number, peer_number, name);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_peer_get_public_key(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        uint8_t *public_key, TOX_ERR_CONFERENCE_PEER_QUERY *error)
{
    int ret = group_peer_pubkey((Group_Chats *)tox->gc, conference_number, peer_number, public_key);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_peer_number_is_ours(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        TOX_ERR_CONFERENCE_PEER_QUERY *error)
{
    int ret = group_peernumber_is_ours((Group_Chats *)tox->gc, conference_number, peer_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

bool tox_conference_invite(Tox *tox, uint32_t friend_number, uint32_t conference_number,
                           TOX_ERR_CONFERENCE_INVITE *error)
{
    int ret = invite_friend((Group_Chats *)tox->gc, friend_number, conference_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_OK);
    return true;
}

uint32_t tox_conference_join(Tox *tox, uint32_t friend_number, const uint8_t *cookie, size_t length,
                             TOX_ERR_CONFERENCE_JOIN *error)
{
    int ret = join_groupchat((Group_Chats *)tox->gc, friend_number, GROUPCHAT_TYPE_TEXT, cookie, length);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_DUPLICATE);
            return UINT32_MAX;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_INIT_FAIL);
            return UINT32_MAX;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_FAIL_SEND);
            return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_OK);
    return ret;
}

bool tox_conference_send_message(Tox *tox, uint32_t conference_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_CONFERENCE_SEND_MESSAGE *error)
{
    int ret = 0;

    if (type == TOX_MESSAGE_TYPE_NORMAL) {
        ret = group_message_send((Group_Chats *)tox->gc, conference_number, message, length);
    } else {
        ret = group_action_send((Group_Chats *)tox->gc, conference_number, message, length);
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION);
            return false;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_OK);
    return true;
}

size_t tox_conference_get_title_size(const Tox *tox, uint32_t conference_number, TOX_ERR_CONFERENCE_TITLE *error)
{
    int ret = group_title_get_size((Group_Chats *)tox->gc, conference_number);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return ret;
}

bool tox_conference_get_title(const Tox *tox, uint32_t conference_number, uint8_t *title,
                              TOX_ERR_CONFERENCE_TITLE *error)
{
    int ret = group_title_get((Group_Chats *)tox->gc, conference_number, title);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return true;
}

bool tox_conference_set_title(Tox *tox, uint32_t conference_number, const uint8_t *title, size_t length,
                              TOX_ERR_CONFERENCE_TITLE *error)
{
    int ret = group_title_send((Group_Chats *)tox->gc, conference_number, title, length);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return true;
}

size_t tox_conference_get_chatlist_size(const Tox *tox)
{
    return count_chatlist((Group_Chats *)tox->gc);
}

void tox_conference_get_chatlist(const Tox *tox, uint32_t *chatlist)
{
    size_t list_size = tox_conference_get_chatlist_size(tox);
    copy_chatlist((Group_Chats *)tox->gc, chatlist, list_size);
}

TOX_CONFERENCE_TYPE tox_conference_get_type(const Tox *tox, uint32_t conference_number,
        TOX_ERR_CONFERENCE_GET_TYPE *error)
{
    int ret = group_get_type((Group_Chats *)tox->gc, conference_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND);
        return (TOX_CONFERENCE_TYPE)ret;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_OK);
    return (TOX_CONFERENCE_TYPE)ret;
}

static void set_custom_packet_error(int ret, TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED);
            break;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ);
            break;
    }
}

bool tox_friend_send_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                  TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    if (data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_LOSSY_AV_RESERVED)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
        return 0;
    }

    int ret = m_send_custom_lossy_packet(tox->m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    }

    return 0;
}

void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *callback)
{
    custom_lossy_packet_registerhandler(tox->m, callback);
}

bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                     TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    int ret = send_custom_lossless_packet(tox->m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    }

    return 0;
}

void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback)
{
    custom_lossless_packet_registerhandler(tox->m, callback);
}

void tox_self_get_dht_id(const Tox *tox, uint8_t *dht_id)
{
    if (dht_id) {
        memcpy(dht_id , tox->ncore->dht->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    }
}

uint16_t tox_self_get_udp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
{
    uint16_t port = htons(tox->ncore->net->port);

    if (port) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    }

    return port;
}

uint16_t tox_self_get_tcp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
{
    const Messenger *m = tox->m;

    if (m->tcp_server) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
        return m->options.tcp_server_port;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    return 0;
}
