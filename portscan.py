#!/usr/bin/env python3
"""portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...

TCP SYN (ручные пакеты) + UDP (+ICMP) на epoll, -v, -g (HTTP/DNS/ECHO).
"""
import argparse
import errno
import ipaddress
import random
import re
import select
import socket
import struct
import sys
import time
from collections import deque

MASK32 = 0xFFFFFFFF


def die(msg, code=2):
    print(msg, file=sys.stderr)
    sys.exit(code)


def parse_specs(specs):
    """['tcp/80,100-200', 'udp'] -> {'tcp': {...}, 'udp': {...}}"""
    ports = {'tcp': set(), 'udp': set()}
    for spec in specs:
        proto, slash, rest = spec.partition('/')
        proto = proto.lower()
        if proto not in ports:
            die(f'неизвестный протокол в "{spec}"')
        if not slash:  # голое tcp / udp -> все порты
            ports[proto].update(range(1, 65536))
            continue
        if not rest:
            die(f'пустой список портов в "{spec}"')
        for item in rest.split(','):
            m = re.fullmatch(r'(\d+)(?:-(\d+))?', item)
            if not m:
                die(f'неверный порт или диапазон "{item}" в "{spec}"')
            lo = int(m[1])
            hi = int(m[2]) if m[2] else lo
            if not 1 <= lo <= hi <= 65535:
                die(f'порт вне диапазона 1-65535: "{item}"')
            ports[proto].update(range(lo, hi + 1))
    return ports


def parse_args():
    p = argparse.ArgumentParser(
        prog='portscan',
        usage='portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...')
    p.add_argument('--timeout', type=float, default=2.0,
                   help='таймаут ожидания ответа, с (по умолчанию 2)')
    p.add_argument('-j', '--num-threads', type=int, default=100,
                   help='размер окна одновременных проб')
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('-g', '--guess', action='store_true')
    p.add_argument('ip')
    p.add_argument('specs', nargs='*')
    a = p.parse_args()
    try:
        a.ip = str(ipaddress.IPv4Address(a.ip))
    except ValueError:
        die(f'неверный IPv4-адрес "{a.ip}"')
    if a.timeout <= 0:
        die('--timeout должен быть > 0')
    if a.num_threads < 1:
        die('-j должен быть >= 1')
    if not a.specs:
        die('не указаны порты, например: tcp/80 udp/53')
    a.ports = parse_specs(a.specs)
    return a


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def tcp_segment(src, dst, sport, dport, seq, ack, flags, opts=b''):
    off_flags = ((5 + len(opts) // 4) << 12) | flags
    hdr = struct.pack('!HHIIHHHH', sport, dport, seq, ack, off_flags, 64240, 0, 0) + opts
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(hdr))
    return hdr[:16] + struct.pack('!H', checksum(pseudo + hdr)) + hdr[18:]


def local_ip_for(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 9))  # пакеты не уходят, только выбор маршрута
        return s.getsockname()[0]
    finally:
        s.close()


def scan_tcp(ip, ports, timeout, window):
    """Возвращает {порт: rtt_ms} для открытых портов."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    ep = select.epoll()
    try:
        raw.setblocking(False)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        ep.register(raw.fileno(), select.EPOLLIN)

        dst = socket.inet_aton(ip)
        src = socket.inet_aton(local_ip_for(ip))
        sport = random.randint(20000, 30000)
        secret = random.getrandbits(32)

        def cookie(port):  # наш seq зависит от порта
            return (secret ^ (port * 2654435761)) & MASK32

        pending = deque(sorted(ports))
        in_flight = {}  # порт -> время отправки
        deadlines = deque()  # (дедлайн, порт) по порядку отправки
        opened = {}
        mss = b'\x02\x04\x05\xb4'

        def handle(data, now):
            ihl = (data[0] & 15) * 4
            t = data[ihl:]
            if len(t) < 20:
                return
            sp, dp, _, ack = struct.unpack('!HHII', t[:12])
            flags = t[13]
            if dp != sport:
                return  # чужой трафик (и наши исходящие на loopback)
            if flags & 0x04:  # RST -> порт закрыт
                if flags & 0x10 and ack != (cookie(sp) + 1) & MASK32:
                    return
                in_flight.pop(sp, None)
            elif flags & 0x12 == 0x12 and ack == (cookie(sp) + 1) & MASK32:
                t0 = in_flight.pop(sp, None)
                if t0 is not None:  # дубликат/опоздавший ответ не пишем
                    opened[sp] = (now - t0) * 1000
                # в любом случае сбрасываем: полуоткрытых соединений не оставляем
                raw.sendto(tcp_segment(src, dst, sport, sp, ack, 0, 0x04), (ip, 0))

        while pending or in_flight:
            # 1. отправляем, пока есть место в окне
            while pending and len(in_flight) < window:
                port = pending.popleft()
                seg = tcp_segment(src, dst, sport, port, cookie(port), 0, 0x02, mss)
                try:
                    raw.sendto(seg, (ip, 0))
                except BlockingIOError:
                    pending.appendleft(port)
                    break
                now = time.monotonic()
                in_flight[port] = now
                deadlines.append((now + timeout, port))

            # 2. ждём до ближайшего дедлайна (устаревшие записи выкидываем)
            while deadlines and deadlines[0][1] not in in_flight:
                deadlines.popleft()
            wait = max(0.0, deadlines[0][0] - time.monotonic()) if deadlines else 0.0

            # 3. читаем всё, что пришло
            if ep.poll(wait):
                while True:
                    try:
                        data = raw.recv(65535)
                    except BlockingIOError:
                        break
                    handle(data, time.monotonic())

            # 4. списываем просроченные пробы
            now = time.monotonic()
            while deadlines and deadlines[0][0] <= now:
                in_flight.pop(deadlines.popleft()[1], None)
        return opened
    finally:
        ep.close()
        raw.close()


def dns_query(txid):
    q = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)  # RD=1, один вопрос
    return q + b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)  # A, IN


class Probes:
    def __init__(self, ip):
        self.dns_id = random.randint(0, 0xFFFF)
        self.dns = dns_query(self.dns_id)
        self.dns_tcp = struct.pack('!H', len(self.dns)) + self.dns  # TCP: префикс длины
        self.echo = b'portscan-%08x\n' % random.getrandbits(32)
        self.http = (f'GET / HTTP/1.1\r\nHost: {ip}\r\n'
                     'Connection: close\r\n\r\n').encode()


def classify(buf, probe, dns_id, tcp):
    """По форме ответа определяет протокол: HTTP / DNS / ECHO / None."""
    if buf.startswith(b'HTTP/'):
        return 'HTTP'
    msg = buf[2:] if tcp else buf  # в TCP-DNS первые 2 байта = длина
    if len(msg) >= 12:
        rid, flags = struct.unpack('!HH', msg[:4])
        if rid == dns_id and flags & 0x8000 and (flags >> 11) & 0xF == 0:  # QR=1, opcode=0
            return 'DNS'
    if len(buf) >= len(probe) and buf[:len(probe)] == probe:
        return 'ECHO'  # вернули ровно то, что мы отправили
    return None


def drain(sock, handler):
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except BlockingIOError:
            return
        except ConnectionRefusedError:
            continue
        handler(data, addr)


def scan_udp(ip, ports, timeout, window):
    """Возвращает {порт: протокол|None} для портов, с которых пришёл UDP-ответ."""
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ep = select.epoll()
    try:
        usock.bind(('0.0.0.0', 0))
        local_port = usock.getsockname()[1]
        usock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        for s in (usock, icmp):
            s.setblocking(False)
            ep.register(s.fileno(), select.EPOLLIN)

        pr = Probes(ip)
        is_local = ip.startswith('127.') or local_ip_for(ip) == ip
        # при скане своего хоста наш же сокет "ответил" бы сам себе
        pending = deque(p for p in sorted(ports) if not (is_local and p == local_port))
        in_flight = {}
        deadlines = deque()
        found = {}

        def on_udp(data, addr):
            port = addr[1]
            if addr[0] != ip or (port not in in_flight and port not in found):
                return
            in_flight.pop(port, None)
            g = classify(data, pr.dns, pr.dns_id, False) or classify(data, pr.echo, pr.dns_id, False)
            if found.get(port) is None:  # более точный ответ может прийти позже
                found[port] = g

        def on_icmp(data, addr):
            if addr[0] != ip or len(data) < 20:
                return
            ihl = (data[0] & 15) * 4
            if len(data) < ihl + 8 + 20 or data[ihl] != 3:  # type 3 = unreachable
                return  # (code 3 = порт закрыт)
            inner = data[ihl + 8:]  # копия нашего IP+UDP заголовков
            iihl = (inner[0] & 15) * 4
            if inner[9] != 17 or socket.inet_ntoa(inner[16:20]) != ip or len(inner) < iihl + 4:
                return
            sp, dp = struct.unpack('!HH', inner[iihl:iihl + 4])
            if sp == local_port:
                in_flight.pop(dp, None)

        while pending or in_flight:
            while pending and len(in_flight) < window:
                port = pending.popleft()
                try:
                    usock.sendto(pr.dns, (ip, port))
                    usock.sendto(pr.echo, (ip, port))
                except BlockingIOError:
                    pending.appendleft(port)
                    break
                except ConnectionRefusedError:
                    continue
                now = time.monotonic()
                in_flight[port] = now
                deadlines.append((now + timeout, port))

            while deadlines and deadlines[0][1] not in in_flight:
                deadlines.popleft()
            wait = max(0.0, deadlines[0][0] - time.monotonic()) if deadlines else 0.0

            for fd, _ in ep.poll(wait):
                if fd == usock.fileno():
                    drain(usock, on_udp)
                else:
                    drain(icmp, on_icmp)

            now = time.monotonic()
            while deadlines and deadlines[0][0] <= now:
                in_flight.pop(deadlines.popleft()[1], None)
        return found
    finally:
        ep.close()
        usock.close()
        icmp.close()


class Job:
    __slots__ = ('port', 'probe', 'sock', 'state', 'buf', 'done')

    def __init__(self, port, probe, sock):
        self.port, self.probe, self.sock = port, probe, sock
        self.state, self.buf, self.done = 0, b'', False  # 0=connect, 1=ждём ответ


def guess_tcp(ip, ports, timeout, window):
    """Для открытых TCP-портов: по отдельному соединению на каждую пробу."""
    pr = Probes(ip)
    pending = deque((p, pb) for p in sorted(ports) for pb in (pr.http, pr.dns_tcp, pr.echo))
    jobs, deadlines, result = {}, deque(), {}
    ep = select.epoll()

    def finish(job):
        if job.done:
            return
        job.done = True
        fd = job.sock.fileno()
        jobs.pop(fd, None)
        try:
            ep.unregister(fd)
        except OSError:
            pass
        job.sock.close()
        g = classify(job.buf, job.probe, pr.dns_id, True)
        if g and result.get(job.port) is None:
            result[job.port] = g

    def start(port, probe):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        if s.connect_ex((ip, port)) not in (0, errno.EINPROGRESS):
            s.close()
            return
        job = Job(port, probe, s)
        jobs[s.fileno()] = job
        ep.register(s.fileno(), select.EPOLLOUT)
        deadlines.append((time.monotonic() + timeout, job))

    def on_event(job):
        if job.state == 0:  # connect завершился (успешно или нет)
            if job.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                return finish(job)
            try:
                job.sock.send(job.probe)
            except OSError:
                return finish(job)
            job.state = 1
            ep.modify(job.sock.fileno(), select.EPOLLIN)
            return None
        try:
            data = job.sock.recv(65535)
        except BlockingIOError:
            return None
        except OSError:
            return finish(job)
        if not data:  # сервер закрыл соединение
            return finish(job)
        job.buf += data
        if classify(job.buf, job.probe, pr.dns_id, True):
            finish(job)
        return None

    try:
        while pending or jobs:
            while pending and len(jobs) < window:
                start(*pending.popleft())
            while deadlines and deadlines[0][1].done:
                deadlines.popleft()
            wait = max(0.0, deadlines[0][0] - time.monotonic()) if deadlines else 0.0
            for fd, _ in ep.poll(wait):
                job = jobs.get(fd)
                if job:
                    on_event(job)
            now = time.monotonic()
            while deadlines and deadlines[0][0] <= now:
                finish(deadlines.popleft()[1])
        return result
    finally:
        for job in list(jobs.values()):
            job.sock.close()
        ep.close()


def main():
    a = parse_args()
    results = []  # (proto, port, rtt_ms | None, guess | None)
    try:
        if a.ports['tcp']:
            opened = scan_tcp(a.ip, a.ports['tcp'], a.timeout, a.num_threads)
            guesses = {}
            if a.guess and opened:
                guesses = guess_tcp(a.ip, opened, a.timeout, a.num_threads)
            for port, rtt in opened.items():
                results.append(('tcp', port, rtt, guesses.get(port)))
        if a.ports['udp']:
            for port, g in scan_udp(a.ip, a.ports['udp'], a.timeout, a.num_threads).items():
                results.append(('udp', port, None, g))
    except PermissionError:
        die('нужны права root (raw-сокеты): запустите через sudo', 1)
    except KeyboardInterrupt:
        sys.exit(130)
    except OSError as e:
        die(f'ошибка: {e}', 1)

    for proto, port, rtt, guess in sorted(results, key=lambda r: (r[0] != 'tcp', r[1])):
        line = f'{proto.upper()} {port}'
        if a.verbose:
            line += f' {rtt:.0f}' if rtt is not None else ' -'
        if a.guess:
            line += f' {guess or "-"}'
        print(line)


if __name__ == '__main__':
    main()
