import concurrent.futures
import inspect
import socket
import struct
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
from validator import PassiveDnsEvidence, Validator, checksum, passive_dns_claim

LOCAL = '192.0.2.10'
SOURCE = '192.0.2.20'
LOCAL_MAC = bytes.fromhex('020000000001')
MAC = bytes.fromhex('020000000002')
STATE = (LOCAL, 24, LOCAL_MAC, 1)
PEER = ('fixture0', 0x0800, 0, 1, MAC)


def frame(source=SOURCE, mac=MAC, tcp=False):
    dns = bytes.fromhex('123401000001000000000000') + b'\x01a\x00\x00\x01\x00\x01'
    proto = 6 if tcp else 17
    payload = struct.pack('!H', len(dns)) + dns if tcp else dns
    header = struct.pack('!HHIIHHHH', 12000, 53, 1, 1, 0x5018, 1024, 0, 0) if tcp else struct.pack('!HHHH', 12000, 53, len(payload)+8, 0)
    segment = header + payload
    addresses = socket.inet_aton(source) + socket.inet_aton(LOCAL)
    value = checksum(addresses + bytes([0, proto]) + struct.pack('!H', len(segment)) + segment)
    offset = 16 if tcp else 6
    segment = segment[:offset] + struct.pack('!H', value or 65535) + segment[offset+2:]
    ip = bytes.fromhex('4500') + struct.pack('!H', 20+len(segment)) + bytes.fromhex('0000400040') + bytes([proto]) + bytes(2) + addresses
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return LOCAL_MAC + mac + b'\x08\x00' + ip + segment


class PassiveTests(unittest.TestCase):
    def fixture(self):
        self.now = 100.0
        self.wall = datetime(2026, 1, 1, tzinfo=timezone.utc)
        observer = PassiveDnsEvidence(['fixture0'], lambda _: STATE, lambda: self.now, lambda: self.wall)
        observer.states = {'fixture0': STATE}; observer.ready = True
        return observer

    def test_udp_and_tcp_exact_incoming_dns_headers(self):
        for tcp in (False, True):
            self.assertEqual(passive_dns_claim(frame(tcp=tcp), PEER, 'fixture0', STATE), (SOURCE, '02:00:00:00:00:02'))

    def test_wrong_interface_direction_mac_ip_checksums_fragments_and_non_dns_rejected(self):
        good = frame()
        for packet_type in (1, 2, 3, 4):
            self.assertIsNone(passive_dns_claim(good, ('fixture0', 0x0800, packet_type), 'fixture0', STATE))
        self.assertIsNone(passive_dns_claim(good, PEER, 'other', STATE))
        for offset in (0, 12, 14, 16, 20, 24, 26, 30, 36, 38, 42, 44):
            bad = bytearray(good); bad[offset] ^= 1
            self.assertIsNone(passive_dns_claim(bytes(bad), PEER, 'fixture0', STATE), offset)
        for size in range(54): self.assertIsNone(passive_dns_claim(good[:size], PEER, 'fixture0', STATE))
        for mac in (bytes(6), LOCAL_MAC, bytes.fromhex('010000000002')):
            self.assertIsNone(passive_dns_claim(frame(mac=mac), PEER, 'fixture0', STATE))
        self.assertIsNone(passive_dns_claim(frame(source='192.0.3.20'), PEER, 'fixture0', STATE))
        self.assertIsNone(passive_dns_claim(frame()+bytes(1518), PEER, 'fixture0', STATE))

    def test_packet_freshness_not_renewed_by_readback_and_exact_expiry(self):
        observer = self.fixture(); observer.observe(frame(), PEER, 'fixture0', STATE)
        original = observer.snapshot('a'*32)['evidence'][0]['observedAtUtc']
        for seconds in (1, 5, 9):
            self.now = 100+seconds; self.wall = datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=seconds)
            self.assertEqual(observer.snapshot('a'*32)['evidence'][0]['observedAtUtc'], original)
        self.now += 1; self.wall += timedelta(seconds=1)
        self.assertEqual(observer.snapshot('a'*32)['evidence'], [])

    def test_continuous_dns_retains_evidence_without_neighbour_confirmation(self):
        observer = self.fixture()
        for seconds in range(0, 120, 2):
            self.now = 100+seconds; self.wall = datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=seconds)
            observer.observe(frame(tcp=seconds % 4 == 0), PEER, 'fixture0', STATE)
            self.assertEqual(len(observer.snapshot('a'*32)['evidence']), 1)

    def test_conflicting_ip_mac_claims_are_retained_not_overwritten(self):
        observer = self.fixture()
        observer.observe(frame(), PEER, 'fixture0', STATE)
        observer.observe(frame(mac=bytes.fromhex('020000000003')), PEER, 'fixture0', STATE)
        observer.observe(frame(source='192.0.2.21'), PEER, 'fixture0', STATE)
        self.assertEqual(len(observer.snapshot('a'*32)['evidence']), 3)

    def test_parallel_queries_bounded_and_capacity_overflow_fail_closed(self):
        observer = self.fixture()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: observer.observe(frame(), PEER, 'fixture0', STATE), range(200)))
        self.assertEqual(len(observer.snapshot('a'*32)['evidence']), 1)
        for index in range(21, 85):
            observer.observe(frame(source=f'192.0.2.{index}'), PEER, 'fixture0', STATE)
        self.assertFalse(observer.snapshot('a'*32)['complete'])
        self.assertEqual(observer.snapshot('a'*32)['evidence'], [])

    def test_unavailable_interface_clock_errors_and_receiver_loss_fail_closed(self):
        for scenario in ('interface', 'monotonic', 'wall', 'loss'):
            observer = self.fixture(); observer.observe(frame(), PEER, 'fixture0', STATE)
            if scenario == 'interface': observer.state = lambda _: (LOCAL, 24, LOCAL_MAC, 2)
            if scenario == 'monotonic': self.now = 99
            if scenario == 'wall': self.wall -= timedelta(seconds=1)
            if scenario == 'loss': observer.invalidate('Passive packet loss')
            self.assertEqual(observer.snapshot('a'*32)['evidence'], [], scenario)

    def test_authenticated_operation_is_read_only_and_capture_disabled_by_default(self):
        validator = Validator(['fixture0'], transport=Mock(), state=lambda _: STATE)
        request = dict(requestId='a'*32, operation='passiveDnsRead')
        self.assertFalse(validator.validate(request)['complete'])
        validator.passive = self.fixture(); validator.passive.observe(frame(), PEER, 'fixture0', STATE)
        self.assertTrue(validator.validate(request)['complete']); validator.transport.validate.assert_not_called()
        for bad in (dict(request, address=SOURCE), dict(request, requestId='invalid')):
            with self.assertRaises(ValueError): validator.validate(bad)
        receiver = inspect.getsource(PassiveDnsEvidence._receive)
        self.assertNotIn('raw.send', receiver); self.assertNotIn('setsockopt', receiver)

    def test_full_ip_mac_impersonation_is_not_cryptographically_detectable(self):
        # Explicit limitation: L2 evidence proves a received claim, not physical ownership.
        self.assertIsNotNone(passive_dns_claim(frame(), PEER, 'fixture0', STATE))
        self.assertIn('unauthenticated', self.fixture().snapshot('a'*32)['reason'])

    def test_receiver_failure_closes_socket_and_invalidates_without_transmitting(self):
        observer = self.fixture(); raw = Mock(); raw.bind.side_effect = OSError('fixture failure')
        with patch('validator.socket.AF_PACKET', 17, create=True), patch('validator.socket.socket', return_value=raw):
            observer._receive_generation()
        raw.close.assert_called_once(); raw.send.assert_not_called()
        self.assertFalse(observer.snapshot('a'*32)['complete'])

    def test_socket_receive_loop_no_transmit_and_kernel_drop_invalidates(self):
        observer = self.fixture(); raw = Mock()
        raw.recvfrom.return_value = (frame(), PEER)
        def receive(*_):
            if raw.recvfrom.called:
                self.now = 102
                return [], [], []
            return [raw], [], []
        def statistics(*_):
            self.assertEqual(len(observer.snapshot('a'*32)['evidence']), 1)
            observer.stop.set()
            return struct.pack('II', 2, 1)
        raw.getsockopt.side_effect = statistics
        with patch('validator.socket.AF_PACKET', 17, create=True), patch('validator.socket.socket', return_value=raw), patch('validator.select.select', side_effect=receive):
            observer._receive_generation()
        raw.send.assert_not_called(); raw.setsockopt.assert_not_called(); raw.close.assert_called_once()
        self.assertFalse(observer.snapshot('a'*32)['complete'])

    def test_retry_is_bounded_and_cancellable_after_capture_failure(self):
        observer = self.fixture()
        delays = []
        def wait(delay):
            delays.append(delay)
            if len(delays) == 8: observer.stop.set()
            return observer.stop.is_set()
        with patch.object(observer, '_receive_generation', return_value=False) as receive, patch.object(observer.stop, 'wait', side_effect=wait):
            observer._receive()
        self.assertEqual(receive.call_count, 8)
        self.assertEqual(delays, [.25, .5, 1, 2, 4, 5, 5, 5])

    def test_socket_failure_and_wifi_down_up_reopen_with_new_generation(self):
        for failure in ('socket', 'wifi', 'interface'):
            with self.subTest(failure=failure):
                observer=self.fixture(); raws=[Mock(),Mock()]; attempt=[0]; checked=[]
                current=[STATE]
                observer.state=lambda _:current[0]
                for raw in raws:raw.recvfrom.return_value=(frame(),PEER)
                def receive(*_):
                    if attempt[0]==0:
                        self.now=102
                        if failure=='socket':raise OSError('Capture failed')
                        if failure=='wifi':observer.state=lambda _:(_ for _ in ()).throw(OSError('Link down'))
                        else:current[0]=(LOCAL,24,LOCAL_MAC,2)
                        return [],[],[]
                    if not raws[1].recvfrom.called:return [raws[1]],[],[]
                    read=observer.snapshot('a'*32)
                    checked.append(read);observer.stop.set();return [],[],[]
                def retry(_):
                    attempt[0]=1;self.now+=11;self.wall+=timedelta(seconds=11)
                    current[0]=STATE;observer.state=lambda _:current[0]
                    return False
                with patch('validator.socket.AF_PACKET',17,create=True),patch('validator.socket.socket',side_effect=raws),patch('validator.select.select',side_effect=receive),patch.object(observer.stop,'wait',side_effect=retry):
                    observer._receive()
                self.assertEqual(len(checked),1)
                self.assertTrue(checked[0]['complete']);self.assertEqual(checked[0]['interfaceGeneration'],2)
                self.assertEqual(len(checked[0]['evidence']),1)
                for raw in raws:raw.close.assert_called_once();raw.send.assert_not_called()

    def test_old_generation_and_changed_interface_cannot_publish_late_evidence(self):
        observer = self.fixture(); observer.generation = 2
        observer.observe(frame(), PEER, 'fixture0', STATE, 1)
        self.assertEqual(observer.snapshot('a'*32)['evidence'], [])
        observer.observe(frame(), PEER, 'fixture0', STATE, 2)
        self.assertEqual(len(observer.snapshot('a'*32)['evidence']), 1)
        observer.invalidate('Interface down')
        observer.states = {'fixture0': (LOCAL, 24, LOCAL_MAC, 2)}
        observer.generation = 3; observer.ready = True; self.now += 11; self.wall += timedelta(seconds=11)
        observer.observe(frame(), PEER, 'fixture0', STATE, 2)
        self.assertEqual(observer.snapshot('a'*32)['evidence'], [])

    def test_helper_restart_changes_capture_instance_and_never_restores_claims(self):
        old = self.fixture(); old.observe(frame(), PEER, 'fixture0', STATE)
        fresh = self.fixture()
        self.assertNotEqual(old.instance, fresh.instance)
        self.assertEqual(fresh.snapshot('a'*32)['evidence'], [])

    def test_parallel_snapshot_reads_cannot_make_unavailable_capture_ready(self):
        observer = self.fixture(); observer.invalidate('Capture socket unavailable')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            reads = list(pool.map(lambda _: observer.snapshot('a'*32), range(100)))
        self.assertTrue(all(not r['complete'] and r['captureState'] == 'UNAVAILABLE' and not r['evidence'] for r in reads))

    def test_passive_operation_uses_existing_peer_authorization(self):
        from unittest.mock import MagicMock
        from validator import handle_peer, GREETING
        request = b'{"requestId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"passiveDnsRead"}\n'
        for authorized in (True, False):
            peer = MagicMock(); peer.recv.side_effect = [request, b'']; validator = Mock()
            validator.validate.return_value = {'complete': False, 'evidence': []}
            with patch('validator.AuthorizedPeer') as identity:
                if not authorized: identity.side_effect = ValueError('Wrong live MainPID')
                handle_peer(peer, validator, 1000, Mock())
                self.assertEqual(validator.validate.called, authorized)
                if authorized:
                    self.assertEqual(identity.return_value.check.call_count, 2)
                    peer.sendall.assert_any_call(GREETING)


if __name__ == '__main__': unittest.main()
