"""No raw sockets, root actions or production requests in these tests."""
import os
import socket
import stat
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from validator import trusted_path, activated_listener, EngineManager, AuthorizedPeer, handle_peer, GREETING


class IpcTests(unittest.TestCase):
    def test_inherited_listener_substitution_and_nonlistening_fd_reject(self):
        from unittest.mock import MagicMock
        before=SimpleNamespace(st_dev=1,st_ino=2);after=SimpleNamespace(st_dev=1,st_ino=3)
        family=getattr(socket,'AF_UNIX',1)
        server=MagicMock();server.family=family;server.type=socket.SOCK_STREAM;server.getsockopt.return_value=1;server.getsockname.return_value='/run/fixture/socket'
        with patch('validator.socket.AF_UNIX',family,create=True),patch.dict(os.environ,dict(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1')),patch('validator.os.getegid',return_value=1000,create=True),patch('validator.os.dup',return_value=9),patch('validator.socket.socket',return_value=server),patch('validator.trusted_path',side_effect=[before,after]):
            with self.assertRaises(ValueError):activated_listener('/run/fixture/socket')
            server.close.assert_called_once()
        server.getsockopt.return_value=0
        with patch('validator.socket.AF_UNIX',family,create=True),patch.dict(os.environ,dict(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1')),patch('validator.os.getegid',return_value=1000,create=True),patch('validator.os.dup',return_value=9),patch('validator.socket.socket',return_value=server),patch('validator.trusted_path',return_value=before):
            with self.assertRaises(ValueError):activated_listener('/run/fixture/socket')

    def test_framing_health_only_malformed_oversized_and_valid_request(self):
        import json
        from unittest.mock import MagicMock
        valid=json.dumps(dict(requestId='a'*32,address='192.0.2.20',interface='fixture0')).encode()+b'\n'
        for data,expected in ((b'',False),(b'x'*1025,False),(b'{}\nextra',False),(b'not-json\n',False),(valid,True)):
            peer=MagicMock();peer.recv.side_effect=[data,b''];validator=Mock();validator.validate.return_value={'fixture':'no network'}
            with patch('validator.AuthorizedPeer') as identity:
                handle_peer(peer,validator,1000,Mock())
                self.assertEqual(validator.validate.called,expected)
                peer.sendall.assert_any_call(GREETING)
                identity.return_value.close.assert_called_once()

    def test_root_socket_and_ancestors_reject_owner_mode_type_symlink(self):
        def info(mode=stat.S_IFSOCK|0o660,uid=0,gid=1000):return SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=mode,st_dev=1,st_ino=2)
        parents=info(stat.S_IFDIR|0o755)
        for bad in (info(uid=1000),info(mode=stat.S_IFSOCK|0o666),info(mode=stat.S_IFLNK|0o777),info(mode=stat.S_IFREG|0o660),info(gid=1001)):
            with patch('validator.os.lstat',return_value=bad):
                with self.assertRaises(ValueError):trusted_path('/run/fixture/socket',True,group=1000)
        with patch('validator.os.lstat',side_effect=lambda p:info() if p.endswith('socket') else parents):
            self.assertEqual(trusted_path('/run/fixture/socket',True,group=1000).st_ino,2)
        for parent in (info(stat.S_IFDIR|0o777),info(stat.S_IFDIR|0o755,uid=1000),info(stat.S_IFLNK|0o755)):
            with patch('validator.os.lstat',side_effect=[info(),parent]):
                with self.assertRaises(ValueError):trusted_path('/run/fixture/socket',True,group=1000)

    def test_activation_required_no_self_bind_or_stale_socket_recovery(self):
        with patch.dict(os.environ,{},clear=True),patch('validator.socket.socket') as create:
            with self.assertRaises(ValueError):activated_listener('/run/fixture/socket')
            create.assert_not_called()

    def test_manager_failure_and_peer_restart_reject_before_raw(self):
        peer=Mock();peer.getsockopt.side_effect=lambda _,opt,size:struct.pack('3i',123,1000,1000) if size==12 else struct.pack('i',42)
        manager=Mock();manager.main_pid.return_value=123
        with patch('validator.select.select',return_value=([],[],[])),patch('validator.os.close'):
            identity=AuthorizedPeer(peer,1000,manager)
            manager.main_pid.return_value=124
            with self.assertRaises(ValueError):identity.check()
            manager.main_pid.side_effect=OSError('bus unavailable')
            with self.assertRaises(OSError):identity.check()
            identity.close()

    @unittest.skipUnless(os.name=='posix','Linux kernel credential fixture')
    def test_live_kernel_credentials_and_peer_pidfd_without_raw(self):
        # Connected socketpair is sufficient to exercise real getsockopt semantics.
        left,right=socket.socketpair()
        try:
            manager=Mock();manager.main_pid.return_value=os.getpid()
            identity=AuthorizedPeer(left,os.getuid(),manager)
            identity.check();identity.close()
        finally:left.close();right.close()
