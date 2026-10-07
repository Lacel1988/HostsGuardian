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


class Validator:
    def __init__(self, allowed, transport=None, state=interface_state, clock=time.monotonic):
        self.allowed = frozenset(allowed)
        self.transport = transport or ArpTransport()
        self.state = state; self.clock = clock
        self.lock = threading.Lock(); self.active = set(); self.last = {}; self.global_times = []
        self.stop = threading.Event()

    def validate(self, request):
        requested = utc()
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
    args = parser.parse_args()
    if not os.path.isabs(args.socket) or not os.path.isabs(args.engine_executable) or args.engine_uid != os.geteuid():
        parser.error('Absolute paths and same restricted service UID required')
    validator = Validator(args.interface)
    signal.signal(signal.SIGTERM, lambda *_: validator.stop.set())
    signal.signal(signal.SIGINT, lambda *_: validator.stop.set())
    serve(args.socket, validator, args.engine_uid, os.path.realpath(args.engine_executable))
