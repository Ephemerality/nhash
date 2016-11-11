import struct
import ctypes

from nhash import hash32

_nhash = ctypes.cdll.LoadLibrary("nhash32.dll")
_nhash.compute_hash.argtypes = (ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32)
_nhash.compute_hash.restype = ctypes.c_uint64

HASH_SEED = 0x46e945f8
    
def hash32DLL(buf, seed):
    buf = struct.pack(">I", seed) + buf
    hash64 = calcHashDLL(buf)
    signedhash64 = ctypes.c_int64(hash64)
    return ctypes.c_uint(signedhash64.value).value ^ ctypes.c_uint(signedhash64.value >> 32).value

def calcHashDLL(buf):
    global _nhash
    buf = list(bytearray(buf))
    num_bytes = len(buf)
    array_type = ctypes.c_ubyte * num_bytes
    data = _nhash.compute_hash(array_type(*buf), ctypes.c_uint32(num_bytes));
    return ctypes.c_uint64(data).value

print "Native: " + str(hash32(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", HASH_SEED))
print "DLL: " + str(hash32DLL(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", HASH_SEED))