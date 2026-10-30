import ctypes
from ctypes import wintypes
import os
import pytest

from hostsguardian_ai.dpapi import Blob, unprotect_token
from hostsguardian_ai.engine import read_secret, EngineHTTPS
from test_gate4 import config, tls_files, https_fixture, block_non_loopback
import hashlib
import ssl

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows CurrentUser DPAPI")


def protect(value):
    crypt=ctypes.WinDLL("crypt32",use_last_error=True)
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    crypt.CryptProtectData.argtypes=[ctypes.POINTER(Blob),wintypes.LPCWSTR,ctypes.c_void_p,
        ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    crypt.CryptProtectData.restype=wintypes.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    incoming=(ctypes.c_ubyte*len(value)).from_buffer_copy(value)
    source=Blob(len(value),incoming);output=Blob()
    assert crypt.CryptProtectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(output))
    try: return ctypes.string_at(output.data,output.size)
    finally: kernel.LocalFree(output.data)


def test_current_user_bridge_never_persists_plaintext(tmp_path,capsys,caplog):
    path=tmp_path/"credential.bin"
    encrypted=protect(b"a"*64);path.write_bytes(encrypted)
    secret=read_secret(path,"dpapi-current-user")
    assert secret.get_secret_value()=="a"*64 and "a"*64 not in repr(secret)
    assert path.read_bytes()==encrypted and list(tmp_path.iterdir())==[path]
    assert "a"*64 not in capsys.readouterr().out+caplog.text


@pytest.mark.parametrize("value",[b"",b"broken",b"x"*16385])
def test_invalid_protected_input_fails_closed(value):
    with pytest.raises(ValueError): unprotect_token(value)


@pytest.mark.parametrize("value",[b"not-a-token",b"x"*64,b"a"*65])
def test_invalid_decrypted_format_fails_closed(value):
    with pytest.raises(ValueError,match="Invalid protected credential"): unprotect_token(protect(value))


async def test_dpapi_tls_reader_uses_existing_encrypted_file(tmp_path,tls_files,https_fixture):
    port,captured,server=https_fixture
    conf=config(tmp_path,f"https://127.0.0.1:{port}")
    encrypted=protect(b"a"*64);conf.token_file.write_bytes(encrypted)
    der=ssl.PEM_cert_to_DER_cert((tls_files/"cert.pem").read_text())
    conf=conf.model_copy(update={"token_format":"dpapi-current-user","certificate_file":tls_files/"cert.pem",
        "certificate_sha256":hashlib.sha256(der).hexdigest()})
    result,_=await EngineHTTPS(conf).get("/health")
    assert result["ok"] and captured[0][2]=="Bearer "+"a"*64
    assert conf.token_file.read_bytes()==encrypted
