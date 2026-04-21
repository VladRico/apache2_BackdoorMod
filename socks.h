#ifndef SOCKS_H
#define SOCKS_H

#include "server.h"
#include "sblist.h"

enum socksstate {
    SS_1_CONNECTED,
    SS_2_NEED_AUTH,
    SS_3_AUTHED
};

enum authmethod {
    AM_NO_AUTH = 0,
    AM_GSSAPI = 1,
    AM_USERNAME = 2,
    AM_INVALID = 0xFF
};

enum errorcode {
    EC_SUCCESS = 0,
    EC_GENERAL_FAILURE = 1,
    EC_NOT_ALLOWED = 2,
    EC_NET_UNREACHABLE = 3,
    EC_HOST_UNREACHABLE = 4,
    EC_CONN_REFUSED = 5,
    EC_TTL_EXPIRED = 6,
    EC_COMMAND_NOT_SUPPORTED = 7,
    EC_ADDRESSTYPE_NOT_SUPPORTED = 8
};

struct socks_thread {
    pthread_t pt;
    struct client client;
    enum socksstate state;
    volatile int done;
};

int startProxy(const char *listenip, int port, const char *user, const char *password);

#endif
