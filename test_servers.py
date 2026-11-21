import http.server
import socket
import socketserver
import struct
import threading


def tcp_echo(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(16)

    def h(c):
        try:
            while True:
                d = c.recv(4096)
                if not d: break
                c.sendall(d)
        except OSError:
            pass
        c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=h, args=(c,), daemon=True).start()


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', port))
    while True:
        d, a = s.recvfrom(4096)
        s.sendto(d, a)


def dns_reply(q):
    if len(q) < 12: return b''
    return q[:2] + struct.pack('!H', 0x8180) + q[4:]  # QR=1, RD, RA


def udp_dns(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    while True:
        d, a = s.recvfrom(4096)
        r = dns_reply(d)
        if r: s.sendto(r, a)


def tcp_dns(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(16)

    def h(c):
        try:
            d = c.recv(4096)
            if len(d) > 14:
                r = dns_reply(d[2:])
                c.sendall(struct.pack('!H', len(r)) + r)
        except OSError:
            pass
        c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=h, args=(c,), daemon=True).start()


def silent_tcp(port):  # открытый порт, который молчит (не опознаётся)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(16)
    cs = []
    while True: cs.append(s.accept()[0])


def http_srv(port):
    class Q(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a, **kwargs): pass

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer(('127.0.0.1', port), Q).serve_forever()


for f, p in [(tcp_echo, 7777), (udp_echo, 7778), (udp_dns, 5353), (tcp_dns, 5353),
             (silent_tcp, 9000), (http_srv, 8080)]:
    threading.Thread(target=f, args=(p,), daemon=True).start()
threading.Event().wait()
