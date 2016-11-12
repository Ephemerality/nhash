import binascii
import struct
import ctypes
import os
import timeit

from nhash import hash32, hash64salt32

_nhash = ctypes.cdll.LoadLibrary("nhash32.dll")
_nhash.compute_hash.argtypes = (ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32)
_nhash.compute_hash.restype = ctypes.c_uint64

HASH_SEED = 0x46e945f8

def hash64salt32DLL(buf, seed):
    buf = struct.pack(">I", seed) + buf
    return calcHashDLL(buf)
    
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

def native():
    for i in range(1, 2048):
        testarray = bytearray(i)
        tmp = hash64salt32(testarray, HASH_SEED)
        
def dll():
    for i in range(1, 2048):
        testarray = bytearray(i)
        tmp = hash64salt32DLL(testarray, HASH_SEED)
        
# for i in range(1, 1024):
    # testarray = bytearray(i)
    # native = hash64salt32(testarray, HASH_SEED)
    # dll = hash64salt32DLL(testarray, HASH_SEED)
    # print "Native: " + str(native)
    # print "DLL: " + str(dll)
    # if native != dll:
        # print "FAILED AT " + str(i)
        # break
print "Native:"
print timeit.timeit(stmt=native, number=100)
print "DLL:"
print timeit.timeit(stmt=dll, number=100)