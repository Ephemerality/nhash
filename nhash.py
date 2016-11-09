import struct
import ctypes

def HI(n):
	return LO(n >> 32)
	
def LO(n):
	return n & 0xffffffff

def TO64(n):
	return n & 0xFFFFFFFFFFFFFFFF
	
HASH_SEED = 0x61247FBF

magic_table = [
	0x95C05F4D1512959E, 0xE4F3C46EEF0DCF07,
	0x6238DC228F980AD2, 0x53F3E3BC49607092,
	0x4E7BE7069078D625, 0x1016D709D1AD25FC,
	0x044E89B8AC76E045, 0xE0B684DDA364BFA1,
	0x90C533B835E89E5F, 0x3DAF462A74FA874F,
	0xFEA54965DD3EF5A0, 0x287A5D7CCB31B970,
	0xAE681046800752F8, 0x121C2D6EAF66EC6E,
	0xEE8F8CA7E090FB20, 0xCE1AE25F48FE0A52,
]

ROUND_MAGIC = 0x78F32468CD48D6DE14C983660183C0AE
FINAL_MAGIC0 = 0xBDB31B10864F3F87
FINAL_MAGIC1 = 0x5B7E9E828A9B8ABD

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