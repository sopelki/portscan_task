#!/usr/bin/env python3
"""portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...

Часть 1: разбор аргументов, TCP SYN-скан (ручные пакеты, epoll), -v, вывод.
"""
import argparse
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


def main():
    a = parse_args()
    results = []  # (proto, port, rtt_ms | None, guess | None)
    try:
        if a.ports['tcp']:
            for port, rtt in scan_tcp(a.ip, a.ports['tcp'], a.timeout, a.num_threads).items():
                results.append(('tcp', port, rtt, None))
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
