import struct
import ctypes

def HI(n):
	return LO(n >> 32)
	
def LO(n):
	return n & 0xffffffff

def TO64(n):
	return n & 0xFFFFFFFFFFFFFFFF
	
HASH_SEED = 0x46e945f8

magic_table = [
  0x2dd7caaefcf073eb, 0xa9209937349cfe9c,
  0xb84bfc934b0e60ef, 0xff709c157b26e477,
  0x3936fd8735455112, 0xca141bf22338d331,
  0xdd40e749cb64fd02, 0x5e268f564b0deb26,
  0x658239596bdea9ec, 0x31cedf33ac38c624,
  0x12f56816481b0cfd, 0x94e9de155f40f095,
  0x5089c907844c6325, 0xdf887e97d73c50e3,
  0xae8870787ce3c11d, 0xa6767d18c58d2117,
]

ROUND_MAGIC = 0xe3f0d44988bcdfab081570afdd535ec3
FINAL_MAGIC0 = 0xce7c4801d683e824
FINAL_MAGIC1 = 0x6823775b1daad522

def read_int64(p, start):
	return struct.unpack("<q", p[start:start+8])[0]

def compute_hash(buf, len):
	num_chunks = len / 128

	# copy tail, pad with zeroes
	tail_size = len % 128
	tail = buf[len - tail_size:len] + bytearray(128 - tail_size)

	hash = b''
	if num_chunks:
		# Hash the first 128 bytes
		hash = hash_chunk(buf, 128)
	else:
		# Hash the tail
		hash = hash_chunk(tail, tail_size)
	
	hash = hash + ROUND_MAGIC

	if num_chunks:
		while num_chunks > 0:
			buf = buf + 128
			hash = hash_muladd(hash, ROUND_MAGIC, hash_chunk(buf, 128))
			num_chunks = num_chunks - 1

		if tail_size:
			hash = hash_muladd(hash, ROUND_MAGIC, hash_chunk(tail, tail_size))

	# Finalize the hash
	hash = hash + ((tail_size * 8) << 64)
	if hash >= 0x7fffffffffffffffffffffffffffffff:
		hash = hash + 1
	hash = hash & 0x7fffffffffffffffffffffffffffffff

	hash_high = TO64(hash >> 64)
	hash_low = TO64(hash)
	X = hash_high + HI(hash_low)
	X = TO64(HI(X + HI(X) + 1) + hash_high)
	Y = TO64((X << 32) + hash_low)

	A = TO64(X + FINAL_MAGIC0)
	if A < X:
		A = A + 0x101
	B = TO64(Y + FINAL_MAGIC1)
	if B < Y:
		B = B + 0x101
	H = A * B
	H = (0x101 * TO64(H >> 64)) + TO64(H)
	H = (0x101 * TO64(H >> 64)) + TO64(H)
	if H >> 64:
		H = H + 0x101
	if H > 0xFFFFFFFFFFFFFEFE:
		H = H + 0x101
	return H

def hash_chunk(chunk, size):
	hash = 0
	for i in range(0, 8):
		offset = i * 16
		if offset >= size:
			break
		a = read_int64(chunk, offset)
		b = read_int64(chunk, offset + 8)
		hash = hash + (a + magic_table[i * 2]) * (b + magic_table[i * 2 + 1])
	return hash & 0x3fffffffffffffffffffffffffffffff

def hash_muladd(hash, mul, add):
	a0 = LO(add)
	a1 = HI(add)
	a23 = add >> 64
	m0 = LO(mul)
	m1 = HI(mul)
	m2 = LO(mul >> 64)
	m3 = HI(mul >> 64)
	h0 = LO(hash)
	h1 = HI(hash)
	h2 = LO(hash >> 64)
	h3 = HI(hash >> 64)

	# Column sums, before carry
	c0 = (h0 * m0)
	c1 = (h0 * m1) + (h1 * m0)
	c2 = (h0 * m2) + (h1 * m1) + (h2 * m0)
	c3 = (h0 * m3) + (h1 * m2) + (h2 * m1) + (h3 * m0)
	c4 = (h1 * m3) + (h2 * m2) + (h3 * m1)
	c5 = (h2 * m3) + (h3 * m2)
	c6 = (h3 * m3)

	# Combine, add, and carry (bugs included)
	r2 = c2 + (c6 << 1) + a23
	r3 = c3                   + HI(r2)
	r0 = c0 + (c4 << 1) + a0  + (r3 >> 31)
	r1 = c1 + (c5 << 1) + a1  + HI(r0)

	# Return as uint128_t
	result = ((r3 << 33 >> 1) | LO(r2)) + HI(r1)
	return (result << 64) | (r1 << 32) | LO(r0)
	
def hash64salt32(buf, seed):
    buf = struct.pack(">I", seed) + buf
    return calcHash(buf)
    
def hash64salt64(buf, seed):
    buf = struct.pack(">Q", seed) + buf
    return calcHash(buf)
    
def hash32(buf, seed):
    buf = struct.pack(">I", seed) + buf
    hash64 = calcHash(buf)
    signedhash64 = ctypes.c_int64(hash64)
    return ctypes.c_uint(signedhash64.value).value ^ ctypes.c_uint(signedhash64.value >> 32).value

def calcHash(buf):
	return compute_hash(buf, len(buf))