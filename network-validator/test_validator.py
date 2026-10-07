import unittest
import struct
import socket
from unittest.mock import Mock, patch
from validator import Validator, target, reply_mac, request_frame, AuthorizedPeer

LOCAL='192.0.2.10'; CANDIDATE='192.0.2.20'; MAC=bytes.fromhex('020000000001'); PEER=bytes.fromhex('020000000002')


def frame(sender=PEER):
    return MAC+sender+bytes.fromhex('0806')+struct.pack('!HHBBH',1,0x0800,6,4,2)+sender+socket.inet_aton(CANDIDATE)+MAC+socket.inet_aton(LOCAL)


class Tests(unittest.TestCase):
    def test_exact_reply_and_outgoing_request(self):
        self.assertEqual(reply_mac(frame(),CANDIDATE,LOCAL,MAC),'02:00:00:00:00:02')
        outgoing=request_frame(LOCAL,MAC,CANDIDATE)
        self.assertEqual(len(outgoing),42);self.assertEqual(outgoing[-4:],socket.inet_aton(CANDIDATE))

    def test_malformed_spoof_wrong_target_and_oversized_frames_reject(self):
        good=frame()
        for size in range(42):self.assertIsNone(reply_mac(good[:size],CANDIDATE,LOCAL,MAC))
        for offset in (0,6,12,14,16,18,19,20,22,28,32,38):
            corrupt=bytearray(good);corrupt[offset]^=1
            self.assertIsNone(reply_mac(bytes(corrupt),CANDIDATE,LOCAL,MAC))
        self.assertIsNone(reply_mac(good+bytes(1518),CANDIDATE,LOCAL,MAC))
        self.assertIsNone(reply_mac(frame(bytes.fromhex('010000000002')),CANDIDATE,LOCAL,MAC))

    def test_scope_excludes_offlink_broadcast_local_multicast_and_unapproved_interface(self):
        self.assertEqual(str(target(CANDIDATE,'fixture0',LOCAL,24,{'fixture0'})),CANDIDATE)
        for address in ('192.0.3.20','192.0.2.0','192.0.2.255',LOCAL,'127.0.0.1','224.0.0.1','0.0.0.0','::1'):
            with self.assertRaises(ValueError):target(address,'fixture0',LOCAL,24,{'fixture0'})
        with self.assertRaises(ValueError):target(CANDIDATE,'other',LOCAL,24,{'fixture0'})

    def validator(self,outcome='Confirmed'):
        transport=Mock();transport.validate.return_value=(outcome,['02:00:00:00:00:02'] if outcome=='Confirmed' else [],'Fixture only')
        return Validator(['fixture0'],transport,lambda _: (LOCAL,24,MAC,1),lambda:100),transport

    def test_bounded_contract_and_rate_limit_no_second_packet_operation(self):
        validator,transport=self.validator();request=dict(requestId='a'*32,address=CANDIDATE,interface='fixture0')
        result=validator.validate(request);self.assertEqual(result['outcome'],'Confirmed');self.assertIsNotNone(result['confirmedAtUtc'])
        self.assertEqual(validator.validate(request)['outcome'],'Unavailable');self.assertEqual(transport.validate.call_count,1)
        with self.assertRaises(ValueError):validator.validate(dict(request,arbitraryFrame='bad'))
        with self.assertRaises(ValueError):validator.validate(dict(request,interface='unapproved'))

    def test_timeout_conflict_unavailable_never_confirm(self):
        for outcome in ('Timeout','Conflict','Unavailable'):
            validator,transport=self.validator(outcome);result=validator.validate(dict(requestId='a'*32,address=CANDIDATE,interface='fixture0'))
            self.assertIsNone(result['confirmedAtUtc']);self.assertIsNone(result['validatedAtUtc'])

    def test_deduplication_concurrency_and_rate_bounds(self):
        validator,transport=self.validator();validator.active.update({('fixture0','192.0.2.21'),('fixture0','192.0.2.22')})
        self.assertEqual(validator.validate(dict(requestId='a'*32,address=CANDIDATE,interface='fixture0'))['outcome'],'Unavailable')
        transport.validate.assert_not_called()
        validator.active.clear();validator.global_times=[100]*4
        self.assertEqual(validator.validate(dict(requestId='a'*32,address=CANDIDATE,interface='fixture0'))['outcome'],'Unavailable')

    def test_kernel_peer_and_manager_accept_engine_reject_same_uid_impostor(self):
        peer=Mock();peer.getsockopt.side_effect=lambda _,option,size:struct.pack('3i',123,1000,1000) if size==12 else struct.pack('i',42)
        manager=Mock();manager.main_pid.return_value=123
        with patch('validator.select.select',return_value=([],[],[])),patch('validator.os.close') as close:
            identity=AuthorizedPeer(peer,1000,manager);identity.check();identity.close();close.assert_called_once_with(42)
            with self.assertRaises(ValueError):AuthorizedPeer(peer,1001,manager)
            manager.main_pid.return_value=124
            with self.assertRaises(ValueError):AuthorizedPeer(peer,1000,manager)

    def test_exited_peer_pid_reuse_and_restart_fail_closed(self):
        peer=Mock();peer.getsockopt.side_effect=[struct.pack('3i',123,1000,1000),struct.pack('i',42)]
        manager=Mock();manager.main_pid.return_value=123
        with patch('validator.select.select',return_value=([42],[],[])),patch('validator.os.close'):
            with self.assertRaises(ValueError):AuthorizedPeer(peer,1000,manager)
            manager.main_pid.assert_not_called()

    def test_kernel_without_peerpidfd_has_no_numeric_pid_fallback(self):
        peer=Mock();peer.getsockopt.side_effect=[struct.pack('3i',123,1000,1000),OSError('unsupported')]
        with self.assertRaises(OSError):AuthorizedPeer(peer,1000,Mock())


class JsonSecurityTests(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self):
        import json
        from validator import unique_object
        with self.assertRaises(ValueError):json.loads('{"address":"192.0.2.1","address":"192.0.2.2"}',object_pairs_hook=unique_object)

    def test_executable_rejects_writable_parent_even_when_file_is_root_owned(self):
        from validator import protected_executable
        from types import SimpleNamespace
        with patch('validator.os.path.realpath',return_value='/opt/engine'),patch('validator.os.stat',side_effect=[SimpleNamespace(st_uid=0,st_mode=0o755),SimpleNamespace(st_uid=1000,st_mode=0o755)]):
            self.assertFalse(protected_executable('/opt/engine'))

    def test_packet_mutations_are_bounded_and_safe(self):
        import random
        rng=random.Random(42)
        for length in range(1600):
            packet=bytes(rng.randrange(256) for _ in range(length))
            self.assertIsNone(reply_mac(packet,CANDIDATE,LOCAL,MAC))

class TransportTests(unittest.TestCase):
    def run_packets(self,packets):
        from validator import ArpTransport
        import threading
        state=(LOCAL,24,MAC,1)
        raw=Mock();raw.__enter__=Mock(return_value=raw);raw.__exit__=Mock(return_value=False)
        queue=list(packets);ticks=[0]
        def clock():ticks[0]+=.01;return ticks[0]
        def receive(_):return queue.pop(0),('fixture0',0)
        raw.recvfrom.side_effect=receive
        with patch('validator.socket.AF_PACKET',17,create=True),patch('validator.socket.socket',return_value=raw),patch('validator.select.select',side_effect=lambda *_:([raw] if queue else [],[],[])),patch('validator.time.monotonic',side_effect=clock),patch('validator.interface_state',return_value=state):
            return ArpTransport().validate(CANDIDATE,'fixture0',state,threading.Event())

    def test_conflicting_replies_fail_closed(self):
        def reply(sender):
            return MAC+sender+struct.pack('!H',0x0806)+struct.pack('!HHBBH',1,0x0800,6,4,2)+sender+socket.inet_aton(CANDIDATE)+MAC+socket.inet_aton(LOCAL)
        result=self.run_packets([reply(bytes.fromhex('020000000011')),reply(bytes.fromhex('020000000012'))])
        self.assertEqual(result[0],'Conflict');self.assertEqual(len(result[1]),2)

    def test_response_budget_rejects_noise_without_unbounded_capture(self):
        result=self.run_packets([bytes(42)]*33)
        self.assertEqual(result[0],'Conflict');self.assertIn('budget',result[2])

if __name__=='__main__':unittest.main()
