"""Bounded protocol readiness for human-gated deployments; never changes configuration."""
import ipaddress
import secrets
import socket
import struct
import time


def query(domain,identifier):
    labels=domain.rstrip('.').encode('ascii').split(b'.')
    if not labels or any(not 1<=len(label)<=63 for label in labels) or sum(map(len,labels))+len(labels)>254:
        raise ValueError('Invalid readiness domain')
    return struct.pack('!6H',identifier,0x100,1,0,0,0)+b''.join(bytes([len(label)])+label for label in labels)+b'\0\0\1\0\1'


def probe(address,transport,domain,port=53,timeout=2):
    deadline=time.monotonic()+timeout
    family=socket.AF_INET6 if ipaddress.ip_address(address).version==6 else socket.AF_INET
    identifier=secrets.randbelow(65536);packet=query(domain,identifier)
    def remaining():
        value=deadline-time.monotonic()
        if value<=0:raise TimeoutError('DNS readiness deadline exhausted')
        return value
    with socket.socket(family,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as client:
        client.settimeout(remaining());client.connect((address,port))
        if transport=='udp':
            client.send(packet);client.settimeout(remaining());response=client.recv(4096)
        elif transport=='tcp':
            client.settimeout(remaining());client.sendall(struct.pack('!H',len(packet))+packet)
            def read(count):
                result=b''
                while len(result)<count:
                    client.settimeout(remaining());chunk=client.recv(count-len(result))
                    if not chunk:raise ConnectionError('Truncated DNS response')
                    result+=chunk
                return result
            length=struct.unpack('!H',read(2))[0]
            if not 12<=length<=4096:raise ValueError('Invalid DNS response length')
            response=read(length)
        else:raise ValueError('Invalid transport')
    if len(response)<12:raise ValueError('Short DNS response')
    transaction,flags,questions,answers,_,_=struct.unpack('!6H',response[:12])
    if transaction!=identifier or not flags&0x8000 or flags&15 or questions!=1 or answers<1 or response[12:len(packet)]!=packet[12:]:
        raise ValueError('DNS response is not a successful matching readiness answer')
    return {'ready':True,'family':ipaddress.ip_address(address).version,'transport':transport,'responseBytes':len(response)}
