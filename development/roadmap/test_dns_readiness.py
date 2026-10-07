import importlib.util
from pathlib import Path
import socket,struct,threading,unittest
spec=importlib.util.spec_from_file_location('dns_readiness',Path(__file__).with_name('dns_readiness.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class ReadinessTests(unittest.TestCase):
    def test_real_family_and_transport_responses(self):
        for family,address in ((socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')):
            for transport,kind in (('udp',socket.SOCK_DGRAM),('tcp',socket.SOCK_STREAM)):
                with self.subTest(address=address,transport=transport),socket.socket(family,kind) as server:
                    server.bind((address,0));port=server.getsockname()[1]
                    if transport=='tcp':server.listen(1)
                    server.settimeout(3)
                    def answer():
                        if transport=='udp':packet,peer=server.recvfrom(1024)
                        else:
                            client,_=server.accept();client.settimeout(3);length=struct.unpack('!H',client.recv(2))[0];packet=client.recv(length)
                        response=bytearray(packet);response[2]|=0x80;response[7]=1
                        response+=b'\xc0\x0c\0\1\0\1\0\0\0\1\0\4\0\0\0\0'
                        if transport=='udp':server.sendto(response,peer)
                        else:client.sendall(struct.pack('!H',len(response))+response);client.close()
                    worker=threading.Thread(target=answer);worker.start()
                    self.assertTrue(module.probe(address,transport,'blocked.invalid',port)['ready']);worker.join(3);self.assertFalse(worker.is_alive())
    def test_missing_listener_is_failure_not_ready(self):
        with socket.socket() as server:server.bind(('127.0.0.1',0));port=server.getsockname()[1]
        with self.assertRaises((ConnectionError,OSError,TimeoutError)):module.probe('127.0.0.1','tcp','blocked.invalid',port,.1)
    def test_invalid_domain_is_rejected(self):
        with self.assertRaises(ValueError):module.query('a'*64+'.invalid',1)
    def test_real_dual_mode_ipv6_sockets_serve_both_families(self):
        # Unprivileged ephemeral loopback sockets only; no production port53.
        for transport,kind in (('udp',socket.SOCK_DGRAM),('tcp',socket.SOCK_STREAM)):
            with self.subTest(transport=transport),socket.socket(socket.AF_INET6,kind) as server:
                server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
                server.bind(('::',0));port=server.getsockname()[1];server.settimeout(3)
                if transport=='tcp':server.listen(2)
                errors=[]
                def answer_both():
                    try:
                        for _ in range(2):
                            if transport=='udp':packet,peer=server.recvfrom(1024)
                            else:
                                client,_=server.accept();client.settimeout(3)
                                def read_exact(count):
                                    data=b''
                                    while len(data)<count:
                                        chunk=client.recv(count-len(data))
                                        if not chunk:raise ConnectionError('fixture truncated')
                                        data+=chunk
                                    return data
                                length=struct.unpack('!H',read_exact(2))[0];packet=read_exact(length)
                            response=bytearray(packet);response[2]|=0x80;response[7]=1
                            response+=b'\xc0\x0c\0\1\0\1\0\0\0\1\0\4\0\0\0\0'
                            if transport=='udp':server.sendto(response,peer)
                            else:client.sendall(struct.pack('!H',len(response))+response);client.close()
                    except Exception as error:errors.append(error)
                worker=threading.Thread(target=answer_both);worker.start()
                for address in ('127.0.0.1','::1'):
                    self.assertTrue(module.probe(address,transport,'fixture.invalid',port)['ready'])
                worker.join(4);self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
if __name__=='__main__':unittest.main()
