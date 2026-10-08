"""Exact-target ARP validation only. Never run this helper without deployment approval."""
import argparse
import ctypes
import concurrent.futures
import ipaddress
import json
import os
import posixpath
import re
import select
import signal
import socket
import stat
import struct
import threading
import time
from datetime import datetime, timezone, timedelta

MAX_REQUEST = 1024
MAX_FRAME = 1518


def utc():
    return datetime.now(timezone.utc).isoformat()


def target(address, interface, local, prefix, allowed):
    if interface not in allowed or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', interface):
        raise ValueError('Interface not permitted')
    value = ipaddress.IPv4Address(address)
    source = ipaddress.IPv4Address(local)
    network = ipaddress.IPv4Network((source, prefix), strict=False)
    if str(value) != address or value not in network or value in (source, network.network_address, network.broadcast_address) or value.is_loopback or value.is_multicast or value.is_unspecified or value.is_link_local:
        raise ValueError('Target must be one permitted on-link unicast IPv4')
    return value


def request_frame(local_ip, local_mac, candidate):
    return bytes.fromhex('ffffffffffff') + local_mac + struct.pack('!H', 0x0806) + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + local_mac + socket.inet_aton(local_ip) + bytes(6) + socket.inet_aton(candidate)


def reply_mac(frame, candidate, local_ip, local_mac):
    if not 42 <= len(frame) <= MAX_FRAME:
        return None
    if frame[12:14] != b'\x08\x06' or struct.unpack('!HHBBH', frame[14:22]) != (1, 0x0800, 6, 4, 2):
        return None
    sender = frame[22:28]
    if sender[0] & 1 or sender == bytes(6) or sender == local_mac or frame[6:12] != sender:
        return None
    if frame[0:6] != local_mac or frame[28:32] != socket.inet_aton(candidate) or frame[32:38] != local_mac or frame[38:42] != socket.inet_aton(local_ip):
        return None
    return ':'.join(f'{b:02X}' for b in sender)


def interface_state(name):
    import fcntl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        arg = struct.pack('256s', name.encode('ascii'))
        address = socket.inet_ntoa(fcntl.ioctl(control, 0x8915, arg)[20:24])
        mask = socket.inet_ntoa(fcntl.ioctl(control, 0x891b, arg)[20:24])
        flags = struct.unpack('H', fcntl.ioctl(control, 0x8913, arg)[16:18])[0]
        if not flags & 1 or flags & 8:
            raise ValueError('Interface unavailable')
        mac = fcntl.ioctl(control, 0x8927, arg)[18:24]
        if mac == bytes(6) or mac[0] & 1:
            raise ValueError('Interface has no unicast Ethernet identity')
        prefix = ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen
        return address, prefix, mac, socket.if_nametoindex(name)


class ArpTransport:
    def validate(self, address, interface, state, stop):
        local, prefix, mac, index = state
        answers = set()
        relevant = 0
        observed = None
        deadline = time.monotonic() + 2
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as raw:
            raw.bind((interface, 0)); raw.setblocking(False)
            frame = request_frame(local, mac, address)
            sent = 0
            while time.monotonic() < deadline and not stop.is_set():
                if sent == 0 or sent == 1 and deadline - time.monotonic() <= 1:
                    raw.send(frame); sent += 1
                ready, _, _ = select.select([raw], [], [], min(.05, max(0, deadline-time.monotonic())))
                if ready:
                    packet, peer = raw.recvfrom(MAX_FRAME+1)
                    relevant += 1
                    if relevant > 32:
                        return 'Conflict', [], 'Response budget exceeded'
                    if peer[0] != interface:
                        continue
                    value = reply_mac(packet, address, local, mac)
                    if value:
                        answers.add(value); observed = utc()
            if interface_state(interface) != state:
                return 'Conflict', [], 'Interface changed during validation'
        if stop.is_set():
            return 'Unavailable', [], 'Cancelled'
        if len(answers) > 1:
            return 'Conflict', sorted(answers), 'Conflicting MAC claims'
        return ('Confirmed', list(answers), 'Targeted ARP reply; unauthenticated network claim', observed) if answers else ('Timeout', [], 'No valid reply; absence not established')


# Passive evidence is a bounded observation, not authenticated physical identity.
PASSIVE_TTL = 10
PASSIVE_LIMIT = 64


def checksum(data):
    if len(data) % 2: data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while total >> 16: total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def passive_dns_claim(frame, peer, interface, state):
    # AF_PACKET exposes incoming Ethernet headers without promiscuous mode.
    # Never accept outbound/other-host frames, fragments, VLAN guesses or proxies.
    if len(peer) < 4 or peer[0] != interface or peer[2] != 0 or peer[3] != 1 or not 54 <= len(frame) <= MAX_FRAME:
        return None
    local, prefix, local_mac, _ = state
    source_mac = frame[6:12]
    if frame[:6] != local_mac or frame[12:14] != b'\x08\x00' or source_mac == local_mac or source_mac == bytes(6) or source_mac[0] & 1:
        return None
    ip = frame[14:]
    if ip[0] != 0x45 or checksum(ip[:20]) != 0 or struct.unpack('!H', ip[6:8])[0] & 0xbfff:
        return None
    size = struct.unpack('!H', ip[2:4])[0]
    if size < 40 or size > len(ip) or ip[16:20] != socket.inet_aton(local): return None
    source = socket.inet_ntoa(ip[12:16])
    try: target(source, interface, local, prefix, {interface})
    except ValueError: return None
    segment = ip[20:size]
    pseudo = ip[12:20] + bytes([0, ip[9]]) + struct.pack('!H', len(segment))
    if ip[9] == 17:
        if len(segment) < 20 or struct.unpack('!H', segment[2:4])[0] != 53 or struct.unpack('!H', segment[4:6])[0] != len(segment): return None
        if segment[6:8] != bytes(2) and checksum(pseudo + segment) != 0: return None
        dns = segment[8:]
    elif ip[9] == 6:
        if len(segment) < 34 or struct.unpack('!H', segment[2:4])[0] != 53 or checksum(pseudo + segment) != 0: return None
        header = (segment[12] >> 4) * 4
        if header < 20 or header + 14 > len(segment) or segment[13] & 7: return None
        payload = segment[header:]
        length = struct.unpack('!H', payload[:2])[0]
        if length < 12 or length + 2 > len(payload): return None
        dns = payload[2:2+length]
    else: return None
    if len(dns) < 12 or dns[2] & 0x80 or dns[4:6] != b'\x00\x01': return None
    return source, ':'.join(f'{b:02X}' for b in source_mac)


class PassiveDnsEvidence:
    def __init__(self, allowed, state=interface_state, clock=time.monotonic, wall=lambda: datetime.now(timezone.utc)):
        self.allowed = frozenset(allowed); self.state = state; self.clock = clock; self.wall = wall
        self.lock = threading.Lock(); self.rows = {}; self.states = {}; self.ready = False
        self.blocked_until = 0; self.last_clock = None; self.reason = 'Passive receiver not ready'
        self.stop = threading.Event(); self.thread = None

    def invalidate(self, reason):
        with self.lock:
            self.rows.clear(); self.ready = False; self.reason = reason
            self.blocked_until = self.clock() + PASSIVE_TTL

    def observe(self, frame, peer, interface, state):
        claim = passive_dns_claim(frame, peer, interface, state)
        if claim is None: return
        now = self.clock(); observed = self.wall()
        with self.lock:
            if not self.ready or now < self.blocked_until: return
            if self.last_clock is not None and now < self.last_clock:
                self.rows.clear(); self.ready = False; self.reason = 'Monotonic clock regression'; return
            self.last_clock = now
            self.rows = {k:v for k,v in self.rows.items() if 0 <= now-v[0] < PASSIVE_TTL}
            key = (interface, claim[0], claim[1])
            if key not in self.rows and len(self.rows) >= PASSIVE_LIMIT:
                self.rows.clear(); self.ready = False; self.blocked_until = now + PASSIVE_TTL; self.reason = 'Passive evidence capacity exceeded'; return
            self.rows[key] = (now, observed)

    def snapshot(self, request_id):
        now = self.clock(); wall = self.wall()
        # Readback cannot refresh packet timestamps. Interface changes invalidate all evidence.
        try: states = {name:self.state(name) for name in self.allowed}
        except (OSError, ValueError): self.invalidate('Interface unavailable'); states = {}
        with self.lock:
            complete = self.ready and states == self.states and now >= self.blocked_until and (self.last_clock is None or now >= self.last_clock)
            if states != self.states:
                self.ready = False; self.reason = 'Interface unavailable or changed'
            if not complete: self.rows.clear()
            self.rows = {k:v for k,v in self.rows.items() if 0 <= now-v[0] < PASSIVE_TTL and v[1] <= wall < v[1]+timedelta(seconds=PASSIVE_TTL)}
            rows = [dict(interface=k[0], address=k[1], mac=k[2], observedAtUtc=v[1].isoformat(), expiresAtUtc=(v[1]+timedelta(seconds=PASSIVE_TTL)).isoformat()) for k,v in sorted(self.rows.items())] if complete else []
            return dict(requestId=request_id, method='PassiveDnsL2', complete=complete, readAtUtc=wall.isoformat(), reason='Incoming Ethernet DNS; unauthenticated network claim' if complete else self.reason, evidence=rows)

    def start(self):
        if not 1 <= len(self.allowed) <= 2: raise ValueError('Passive capture requires one or two approved interfaces')
        self.thread = threading.Thread(target=self._receive, name='passive-dns', daemon=True); self.thread.start()

    def _receive(self):
        sockets = {}
        try:
            states = {name:self.state(name) for name in self.allowed}
            for name in sorted(self.allowed):
                raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)); sockets[raw] = name
                raw.bind((name, 0)); raw.setblocking(False)
                # No send(), PACKET_ADD_MEMBERSHIP or promiscuous mode.
            with self.lock: self.states = states; self.ready = True; self.reason = 'Passive receiver ready'
            next_check = self.clock() + 1; count = 0
            while not self.stop.is_set():
                now = self.clock()
                if now >= next_check:
                    if {name:self.state(name) for name in self.allowed} != states: raise ValueError('Interface changed')
                    for raw in sockets:
                        _, drops = struct.unpack('II', raw.getsockopt(263, 6, 8))  # PACKET_STATISTICS, resets counters
                        if drops: self.invalidate('Passive packet loss')
                    with self.lock:
                        if now >= self.blocked_until: self.ready = True
                    count = 0; next_check = now + 1
                readable, _, _ = select.select(list(sockets), [], [], .05)
                for raw in readable:
                    frame, peer = raw.recvfrom(MAX_FRAME+1); count += 1
                    if count > 1024: self.invalidate('Passive receive budget exceeded')
                    else: self.observe(frame, peer, sockets[raw], states[sockets[raw]])
        except (OSError, ValueError, AttributeError): self.invalidate('Passive receiver unavailable or interface changed')
        finally:
            for raw in sockets: raw.close()
            self.invalidate('Passive receiver stopped')


class Validator:
    def __init__(self, allowed, transport=None, state=interface_state, clock=time.monotonic):
        self.allowed = frozenset(allowed)
        self.transport = transport or ArpTransport()
        self.state = state; self.clock = clock
        self.lock = threading.Lock(); self.active = set(); self.last = {}; self.global_times = []
        self.stop = threading.Event()
        self.passive = None

    def validate(self, request):
        requested = utc()
        if isinstance(request, dict) and request.get('operation') == 'passiveDnsRead':
            if set(request) != {'requestId', 'operation'} or not isinstance(request['requestId'], str) or not re.fullmatch('[a-f0-9]{32}', request['requestId']):
                raise ValueError('Invalid passive read request')
            if self.passive is None:
                return dict(requestId=request['requestId'], method='PassiveDnsL2', complete=False, readAtUtc=utc(), reason='Passive capture disabled', evidence=[])
            return self.passive.snapshot(request['requestId'])
        if not isinstance(request, dict) or set(request) != {'requestId', 'address', 'interface'} or not all(isinstance(v, str) for v in request.values()) or not re.fullmatch('[a-f0-9]{32}', request['requestId']):
            raise ValueError('Invalid bounded request')
        address, interface = request['address'], request['interface']
        # Validate allowlist before any interface operation or raw socket construction.
        if interface not in self.allowed:
            raise ValueError('Interface not permitted')
        current = self.state(interface)
        target(address, interface, current[0], current[1], self.allowed)
        key = (interface, address); now = self.clock()
        with self.lock:
            self.last = {k:v for k,v in self.last.items() if now-v < 30}
            self.global_times = [t for t in self.global_times if now-t < 1]
            if key in self.active or now-self.last.get(key, -1000) < 30 or len(self.active) >= 2 or len(self.last) >= 64 or len(self.global_times) >= 4:
                outcome, macs, reason = 'Unavailable', [], 'Deduplicated or rate limited'
                return self.result(request, requested, outcome, macs, reason)
            self.active.add(key); self.last[key] = now; self.global_times.append(now)
        try:
            try:
                reply = self.transport.validate(address, interface, current, self.stop)
                outcome, macs, reason = reply[:3]
                observed = reply[3] if len(reply)>3 else utc()
            except (OSError, ValueError):
                outcome, macs, reason = 'Unavailable', [], 'Validation transport unavailable'
                observed = utc()
            return self.result(request, requested, outcome, macs, reason, observed)
        finally:
            with self.lock:
                self.active.discard(key)

    @staticmethod
    def result(request, requested, outcome, macs, reason, observed=None):
        observed = observed or utc()
        return dict(requestId=request['requestId'], address=request['address'], interface=request['interface'], requestedAtUtc=requested, observedAtUtc=observed,
                    confirmedAtUtc=observed if outcome == 'Confirmed' else None, validatedAtUtc=utc() if outcome == 'Confirmed' else None,
                    expiresAtUtc=(datetime.fromisoformat(observed)+timedelta(seconds=45)).isoformat(), method='TargetedARP', outcome=outcome, macs=macs, reason=reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


GREETING = b'HG-NETWORKVALIDATOR/2 AUTHORIZED\n'
SO_PEERPIDFD = 77  # Linux >= 6.5. No PID-only fallback.


class EngineManager:
    """Fixed root system-bus authority, never caller-controlled environment or PID files."""
    def __init__(self):
        library = '/usr/lib/x86_64-linux-gnu/libsystemd.so.0'
        if not protected_executable(library):
            raise ValueError('Untrusted systemd library')
        trusted_path('/run/dbus/system_bus_socket', socket_file=True, mode=None)
        self.lib = ctypes.CDLL(library)
        signatures = {
            'sd_bus_new': [ctypes.POINTER(ctypes.c_void_p)],
            'sd_bus_set_address': [ctypes.c_void_p, ctypes.c_char_p],
            'sd_bus_set_bus_client': [ctypes.c_void_p, ctypes.c_int],
            'sd_bus_set_method_call_timeout': [ctypes.c_void_p, ctypes.c_uint64],
            'sd_bus_start': [ctypes.c_void_p],
            'sd_bus_get_property_trivial': [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char, ctypes.c_void_p],
        }
        for name, arguments in signatures.items():
            function = getattr(self.lib, name); function.argtypes = arguments; function.restype = ctypes.c_int
        self.lib.sd_bus_unref.argtypes = [ctypes.c_void_p]; self.lib.sd_bus_unref.restype = ctypes.c_void_p

    def main_pid(self):
        bus = ctypes.c_void_p(); value = ctypes.c_uint32()
        try:
            def check(result):
                if result < 0: raise OSError(-result, 'Engine manager unavailable')
            check(self.lib.sd_bus_new(ctypes.byref(bus)))
            check(self.lib.sd_bus_set_address(bus, b'unix:path=/run/dbus/system_bus_socket'))
            check(self.lib.sd_bus_set_bus_client(bus, 1))
            check(self.lib.sd_bus_set_method_call_timeout(bus, 300000))
            check(self.lib.sd_bus_start(bus))
            check(self.lib.sd_bus_get_property_trivial(bus, b'org.freedesktop.systemd1',
                b'/org/freedesktop/systemd1/unit/hostsguardian_2dengine_2eservice',
                b'org.freedesktop.systemd1.Service', b'MainPID', None, b'u', ctypes.byref(value)))
            return value.value
        finally:
            if bus: self.lib.sd_bus_unref(bus)


class AuthorizedPeer:
    def __init__(self, peer, uid, manager):
        self.fd = -1; self.manager = manager
        pid, peer_uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_PEERCRED', 17), 12))
        if peer_uid != uid or pid <= 1: raise ValueError('Unauthorized caller')
        self.pid = pid
        self.fd = struct.unpack('i', peer.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]
        try: self.check()
        except BaseException: self.close(); raise

    def check(self):
        # Kernel socket-associated pidfd, not pidfd_open(numeric_pid): guards peer exit/PID reuse.
        if self.fd < 0 or select.select([self.fd], [], [], 0)[0]: raise ValueError('Caller exited')
        if self.manager.main_pid() != self.pid: raise ValueError('Caller is not the live Engine MainPID')
        if select.select([self.fd], [], [], 0)[0]: raise ValueError('Caller exited during authorization')

    def close(self):
        if self.fd >= 0: os.close(self.fd); self.fd = -1


def trusted_path(path, socket_file=False, mode=0o660, group=None):
    if not posixpath.isabs(path) or posixpath.normpath(path) != path or path.startswith('//'): raise ValueError('Noncanonical path')
    current = path
    while True:
        info = os.lstat(current)
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode): raise ValueError('Untrusted path owner/type')
        if current == path and socket_file:
            if not stat.S_ISSOCK(info.st_mode) or mode is not None and stat.S_IMODE(info.st_mode) != mode or group is not None and info.st_gid != group:
                raise ValueError('Untrusted socket permissions/type')
        elif not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('Writable or invalid socket ancestor')
        parent = posixpath.dirname(current)
        if parent == current: return os.lstat(path)
        current = parent


def activated_listener(path):
    if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
        raise ValueError('Exactly one systemd socket required')
    info = trusted_path(path, socket_file=True, group=os.getegid())
    server = socket.socket(fileno=os.dup(3))
    try:
        if server.family != socket.AF_UNIX or server.type != socket.SOCK_STREAM or not server.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) or server.getsockname() != path:
            raise ValueError('Unexpected inherited listener')
        again = trusted_path(path, socket_file=True, group=os.getegid())
        if (info.st_dev, info.st_ino) != (again.st_dev, again.st_ino): raise ValueError('Socket replaced')
        return server
    except BaseException: server.close(); raise


def protected_executable(executable):
    # Root ownership of the file alone is insufficient in a user-writable parent.
    current = os.path.realpath(executable)
    while True:
        info = os.stat(current)
        if info.st_uid != 0 or info.st_mode & 0o022:
            return False
        parent = os.path.dirname(current)
        if parent == current: return True
        current = parent


def handle_peer(peer, validator, uid, manager):
    identity = None
    try:
        with peer:
            peer.settimeout(3)
            identity = AuthorizedPeer(peer, uid, manager)
            peer.sendall(GREETING)
            data = bytearray()
            read_deadline = time.monotonic()+3
            while b'\n' not in data and len(data) <= MAX_REQUEST:
                peer.settimeout(max(.001,read_deadline-time.monotonic()))
                if time.monotonic()>=read_deadline:return
                chunk = peer.recv(min(256, MAX_REQUEST+1-len(data)))
                if not chunk: return
                data.extend(chunk)
            if len(data) > MAX_REQUEST or data.count(b'\n') != 1 or not data.endswith(b'\n'):
                return
            identity.check()
            result = validator.validate(json.loads(data, object_pairs_hook=unique_object))
            identity.check()
            peer.sendall(json.dumps(result, separators=(',', ':')).encode()+b'\n')
    except (OSError, ValueError, KeyError, TypeError):
        pass
    finally:
        if identity is not None: identity.close()


def serve(path, validator, uid, executable):
    if not protected_executable(executable):
        raise ValueError('Engine executable and all parent directories must be root-owned and protected')
    manager = EngineManager()
    with activated_listener(path) as server, concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        server.settimeout(.5)
        slots = threading.BoundedSemaphore(2)
        def handle(peer):
            try: handle_peer(peer, validator, uid, manager)
            finally: slots.release()
        try:
            while not validator.stop.is_set():
                try: peer, _ = server.accept()
                except socket.timeout: continue
                if slots.acquire(False): pool.submit(handle, peer)
                else: peer.close()
        finally:
            validator.stop.set()  # PID1 owns the path; helper never creates/removes it.


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket', required=True)
    parser.add_argument('--interface', action='append', required=True)
    parser.add_argument('--engine-uid', type=int, required=True)
    parser.add_argument('--engine-executable', required=True)
    parser.add_argument('--passive-dns', action='store_true', help='Receive-only bounded L2 DNS evidence; does not enable ARP probing')
    args = parser.parse_args()
    if not os.path.isabs(args.socket) or not os.path.isabs(args.engine_executable) or args.engine_uid != os.geteuid():
        parser.error('Absolute paths and same restricted service UID required')
    validator = Validator(args.interface)
    signal.signal(signal.SIGTERM, lambda *_: validator.stop.set())
    signal.signal(signal.SIGINT, lambda *_: validator.stop.set())
    # Validate the protected executable before starting any packet observer.
    if not protected_executable(os.path.realpath(args.engine_executable)): raise ValueError('Unprotected Engine executable')
    if args.passive_dns:
        validator.passive = PassiveDnsEvidence(args.interface); validator.passive.start()
    try: serve(args.socket, validator, args.engine_uid, os.path.realpath(args.engine_executable))
    finally:
        if validator.passive is not None:
            validator.passive.stop.set(); validator.passive.thread.join(timeout=2)
