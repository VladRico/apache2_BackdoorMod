# mod_backdoor
Apache Module Backdoor 

# Description
An Apache2 module backdoor inspired from Ringbuilder.
More info here: https://www.tarlogic.com/en/blog/backdoors-modulos-apache/
Original Author : Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))

# Notes
Socks5 code was adapted from https://github.com/fgssfgss/socks_proxy

# Build
apxs -i -a -c mod_backdoor.c -Wl,-lutil
-Wl,-lutil used to link mod_backdoor.so with libutiil.so to use forkpty() from <pty.h>

# Author
Vlad Rico ([@RicoVlad](https://twitter.com/RicoVlad))
