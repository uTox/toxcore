// TODO header
//

#include "netcore.h"

Netcore *netcore_init(Tox *tox)
{
    Netcore *ncore = calloc(1, sizeof(Netcore));
    if (!ncore) {
        return NULL;
    }

    ncore->tox = tox;

    // ncore->net        = net;
    // ncore->dht        = dht;
    // ncore->net_crypto = net_crypto;
    // ncore->tox_conn   = tox_conn;

    // ncore->onion   = onion;
    // ncore->onion_a = onion_a;
    // ncore->onion_c = onion_c;

    return ncore;
}

void netcore_raze(Netcore *n)
{
    if (n) {
        free(n);
    }
}
