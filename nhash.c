#include "nhash.h"

#define HI(n) ((uint64_t)(n)>>32)
#define LO(n) ((uint64_t)(n)&0xffffffff)
#define U128(hi,lo) ((my_uint128_t){ .high = hi, .low = lo})

typedef struct {
	uint64_t high;
	uint64_t low;
} my_uint128_t;
#define __uint128_t my_uint128_t

my_uint128_t add128(my_uint128_t left, my_uint128_t right) {
	my_uint128_t sum = U128(left.high + right.high, left.low + right.low);
	if (sum.low < right.low) {
		++sum.high;
	}
	return sum;
}

int cmp128(my_uint128_t left, my_uint128_t right) {
	if (left.high == right.high) {
		if (left.low == right.low) {
			return 0;
		}
		return left.low < right.low ? -1 : 1;
	}
	return left.high < right.high ? -1 : 1;
}

my_uint128_t and128(my_uint128_t left, my_uint128_t right) {
	return U128(
		left.high & right.high,
		left.low & left.low
	);
}

my_uint128_t mul64(uint64_t left, uint64_t right) {
	uint64_t u1 = LO(left);
	uint64_t v1 = LO(right);
	uint64_t t = u1 * v1;
	uint64_t w3 = LO(t);
	uint64_t k = HI(t);

	left = HI(left);
	t = (left * v1) + k;
	k = LO(t);
	uint64_t w1 = HI(t);

	right = HI(right);
	t = (u1 * right) + k;
	k = HI(t);

	__uint128_t tmp = U128((left * right) + w1 + k, (t << 32) + w3);
	return tmp;
}

#if 1
/* IOS 1.13.3 */
static uint64_t magic_table[16] = {
	0x95C05F4D1512959E, 0xE4F3C46EEF0DCF07,
	0x6238DC228F980AD2, 0x53F3E3BC49607092,
	0x4E7BE7069078D625, 0x1016D709D1AD25FC,
	0x044E89B8AC76E045, 0xE0B684DDA364BFA1,
	0x90C533B835E89E5F, 0x3DAF462A74FA874F,
	0xFEA54965DD3EF5A0, 0x287A5D7CCB31B970,
	0xAE681046800752F8, 0x121C2D6EAF66EC6E,
	0xEE8F8CA7E090FB20, 0xCE1AE25F48FE0A52,
};
#define ROUND_MAGIC U128(0x78F32468CD48D6DE,0x14C983660183C0AE)
#define FINAL_MAGIC0 0xBDB31B10864F3F87
#define FINAL_MAGIC1 0x5B7E9E828A9B8ABD
#endif

uint64_t compute_hash(const uint8_t *in, uint32_t len);

static __uint128_t hash_muladd(__uint128_t hash, __uint128_t mul, __uint128_t add);
static __uint128_t hash_chunk(const uint8_t *chunk, int64_t size);
static uint64_t read_int64(const uint8_t *p);

uint64_t read_int64(const uint8_t *p)
{
	// endian-safe read 64-bit integer
	uint64_t n = 0;
	for (int i = 7; i >= 0; i--) {
		n = (n << 8) | p[i];
	}
	return n;
}

uint64_t compute_hash(const uint8_t *in, uint32_t len)
{
	uint32_t num_chunks = len / 128;

	// copy tail, pad with zeroes
	uint8_t tail[128] = {0};
	int tail_size = len % 128;
	memcpy(tail, in + len - tail_size, tail_size);

	__uint128_t hash;
	if (num_chunks) {
		// Hash the first 128 bytes
		hash = hash_chunk(in, 128);

	} else {
		// Hash the tail
		hash = hash_chunk(tail, tail_size);
	}
	
	hash = add128(hash, ROUND_MAGIC);

	if (num_chunks) {
		while (--num_chunks) {
			in += 128;
			hash = hash_muladd(hash, ROUND_MAGIC, hash_chunk(in, 128));
		}

		if (tail_size) {
			hash = hash_muladd(hash, ROUND_MAGIC, hash_chunk(tail, tail_size));
		}
	}

	// Finalize the hash
	hash = add128(hash, U128(tail_size * 8, 0));
	if (cmp128(hash, U128(0x7fffffffffffffff,0xffffffffffffffff)) >= 0) {
		hash = add128(hash, U128(0, 1));
	}
	hash = and128(hash, U128(0x7fffffffffffffff,0xffffffffffffffff));

	uint64_t hash_high = hash.high;
	uint64_t hash_low = hash.low;
	uint64_t X = hash_high + HI(hash_low);
	X = HI(X + HI(X) + 1) + hash_high;
	uint64_t Y = (X << 32) + hash_low;
	
	uint64_t A = X + FINAL_MAGIC0;
	if (A < X) {
		A += 0x101;
	}

	uint64_t B = Y + FINAL_MAGIC1;
	if (B < Y) {
		B += 0x101;
	}

	__uint128_t H = mul64(A, B);
	H = add128(mul64(0x101, H.high), U128(0, H.low));
	H = add128(mul64(0x101, H.high), U128(0, H.low));
	if (H.high) {
		H = add128(H, U128(0, 0x101));
	}
	if (H.low > 0xFFFFFFFFFFFFFEFE) {
		H = add128(H, U128(0, 0x101));
	}
	return H.low;
}

__uint128_t hash_chunk(const uint8_t *chunk, int64_t size)
{
	__uint128_t hash = U128(0, 0);
	for (int i = 0; i < 8; i++) {
		int offset = i * 16;
		if (offset >= size) {
			break;
		}
		uint64_t a = read_int64(chunk + offset);
		uint64_t b = read_int64(chunk + offset + 8);
		hash = add128(hash, mul64(a + magic_table[i * 2], b + magic_table[i * 2 + 1]));
	}	
	return and128(hash, U128(0x3fffffffffffffff, 0xffffffffffffffff));
}

__uint128_t hash_muladd(__uint128_t hash, __uint128_t mul, __uint128_t add)
{
	uint64_t a0 = LO(add.low), a1 = HI(add.low), a23 = add.high;
	uint64_t m0 = LO(mul.low),   m1 = HI(mul.low);
	uint64_t m2 = LO(mul.high),  m3 = HI(mul.high);
	uint64_t h0 = LO(hash.low),  h1 = HI(hash.low);
	uint64_t h2 = LO(hash.high), h3 = HI(hash.high);

	/* Column sums, before carry */
	uint64_t c0 = (h0 * m0);
	uint64_t c1 = (h0 * m1) + (h1 * m0);
	uint64_t c2 = (h0 * m2) + (h1 * m1) + (h2 * m0);
	uint64_t c3 = (h0 * m3) + (h1 * m2) + (h2 * m1) + (h3 * m0);
	uint64_t c4 = (h1 * m3) + (h2 * m2) + (h3 * m1);
	uint64_t c5 = (h2 * m3) + (h3 * m2);
	uint64_t c6 = (h3 * m3);

	/* Combine, add, and carry (bugs included) */
	uint64_t r2 = c2 + (c6 << 1) + a23;
	uint64_t r3 = c3                   + HI(r2);
	uint64_t r0 = c0 + (c4 << 1) + a0  + (r3 >> 31);
	uint64_t r1 = c1 + (c5 << 1) + a1  + HI(r0);

	/* Return as uint128_t */
	return U128(((r3 << 33 >> 1) | LO(r2)) + HI(r1), (r1 << 32) | LO(r0));
}