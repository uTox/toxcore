// TODO header
//

#ifndef TOX_NETCORE
#define TOX_NETCORE

#include "network.h"
#include "DHT.h"
#include "net_crypto.h"
#include "tox_connection.h"
#include "onion.h"
#include "onion_announce.h"
#include "onion_client.h"

typedef struct Tox Tox;

typedef struct Netcore {
    Tox             *tox;

    Networking_Core *net;
    Net_Crypto      *net_crypto;
    DHT             *dht;
    Tox_Connections *tox_conn;

    Onion           *onion;
    Onion_Announce  *onion_a;
    Onion_Client    *onion_c;
} Netcore;

#endif // TOX_NETCORE
