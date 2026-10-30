"""Current Windows-user DPAPI read; plaintext never crosses a process/file boundary."""
import ctypes
from ctypes import wintypes
import os
from pydantic import SecretStr


class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def unprotect_token(encrypted: bytes) -> SecretStr:
    if os.name != "nt":
        raise ValueError("DPAPI requires the authorized Windows user")
    if not encrypted or len(encrypted) > 16384:
        raise ValueError("Invalid protected credential")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    incoming = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
    source = Blob(len(encrypted), incoming)
    output = Blob()
    if not crypt.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise ValueError("Protected credential unavailable for current Windows user") from None
    try:
        if output.size != 64 or any(output.data[i] not in b"0123456789abcdefABCDEF" for i in range(output.size)):
            raise ValueError("Invalid protected credential")
        return SecretStr(ctypes.string_at(output.data, output.size).decode("ascii"))
    finally:
        if output.data:
            ctypes.memset(output.data, 0, output.size)
            kernel.LocalFree(output.data)
