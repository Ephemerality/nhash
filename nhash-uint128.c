#include "nhash.h"

#define HI(n) ((uint64_t)(n)>>32)
#define LO(n) ((uint64_t)(n)&0xffffffff)
#define U128(high,low) ((__uint128_t)(uint64_t)high<<64 | (uint64_t)low)
#define HASH_SEED 0x61247FBF

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
#if 0
/* Android 0.43.4 */
static uint64_t magic_table[16] = {
	0x48CD0D725609F95F, 0x25D4A39B5ACB4330,
	0x1C0C27978A3649A3, 0x5C7068B9C51C5E4B,
	0x69A054CBE1369106, 0x4C318ED6A12B9645,
	0xC751EECD2715C836, 0xAAEDCC7A92014B7A,
	0xE91DB51D36F47460, 0x78EA4A974D9157B8,
	0xE4E65C1A929E8AB1, 0x6BC61BB9C5988769,
	0x78C7794B899D8819, 0xB338727B9C7600F7,
	0x26BA60FCB9EDC151, 0xE7D74B3CD6293E6B,
};
#define ROUND_MAGIC U128(0x1A32C90D816A2F1F,0x76327D13FD037D57)
#define FINAL_MAGIC0 0x106245053E723AD8
#define FINAL_MAGIC1 0x1CDA65FFA125C8F6
#endif
#if 0
/* Android 0.41.4 */
static uint64_t magic_table[16] = {
	0x475BD60F17CE7238, 0xC11B0E0066794E31,
	0x75F5BD04F566D70C, 0x09F4F46E7CEC785C,
	0x6A52B40820F5EBFF, 0x27F300DB7195A066,
	0xBDFDE4DAC75939BF, 0xF7F239CFD77A36AB,
	0x7013DEFA151CD579, 0x8864183CFD4C24F9,
	0x21C426C79EA1445A, 0xB188FEAE415747BA,
	0x127421C8D0BD9352, 0x8C7E6FC0526AD558,
	0x7E33F449C404A71A, 0xE955B7D15DE757DC,
};
#define ROUND_MAGIC U128(0x232B242A99C10878,0x667EFDF872801CD8)
#define FINAL_MAGIC0 0xF6AC14F2D12AB0C1
#define FINAL_MAGIC1 0x101FF0340EC93F87
#endif

uint64_t compute_hash(const uint8_t *in, uint32_t len);

static __uint128_t hash_muladd(
		__uint128_t hash, __uint128_t mul, __uint128_t add);
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

	hash += ROUND_MAGIC;

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
	hash += U128(tail_size * 8, 0);
	if (hash >= U128(0x7fffffffffffffff,0xffffffffffffffff)) {
		hash++;
	}
	hash = hash << 1 >> 1;

	uint64_t hash_high = hash >> 64;
	uint64_t hash_low = hash;
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

	__uint128_t H = (__uint128_t) A * B;
	H = 0x101 * (H >> 64) + (uint64_t) H;
	H = 0x101 * (H >> 64) + (uint64_t) H;
	if (H >> 64) {
		H += 0x101;
	}
	if ((uint64_t) H > 0xFFFFFFFFFFFFFEFE) {
		H += 0x101;
	}
	return (uint64_t) H;
}

__uint128_t hash_chunk(const uint8_t *chunk, int64_t size)
{
	__uint128_t hash = 0;
	for (int i = 0; i < 8; i++) {
		int offset = i * 16;
		if (offset >= size) {
			break;
		}
		uint64_t a = read_int64(chunk + offset);
		uint64_t b = read_int64(chunk + offset + 8);
		hash += (__uint128_t) (a + magic_table[i * 2]) *
			(__uint128_t) (b + magic_table[i * 2 + 1]);
	}
	return hash << 2 >> 2;
}

__uint128_t hash_muladd(__uint128_t hash, __uint128_t mul, __uint128_t add)
{
	uint64_t a0 = LO(add), a1 = HI(add), a23 = add >> 64;
	uint64_t m0 = LO(mul),        m1 = HI(mul);
	uint64_t m2 = LO(mul >> 64),  m3 = HI(mul >> 64);
	uint64_t h0 = LO(hash),       h1 = HI(hash);
	uint64_t h2 = LO(hash >> 64), h3 = HI(hash >> 64);

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
	__uint128_t result = ((r3 << 33 >> 1) | LO(r2)) + HI(r1);
	return (result << 64) | (r1 << 32) | LO(r0);
}

uint32_t hash32(uint8_t* buffer, uint32_t len)
{
    return hash32salt(buffer, len, HASH_SEED);
}

uint32_t hash32salt(uint8_t* buffer, uint32_t len, uint32_t salt)
{
    uint64_t result = hash64salt(buffer, len, salt);
    return (uint32_t)result ^ (uint32_t)(result >> 32);
}

uint64_t hash64salt(uint8_t* buffer, uint32_t len, uint32_t salt)
{
    uint8_t* newBuffer = (uint8_t*)malloc(len + 4);
    memcpy(newBuffer, &salt, 4);
    memcpy(newBuffer + 4, buffer, len);
    return compute_hash(newBuffer, len + 4);
}

uint64_t hash64salt64(uint8_t* buffer, uint32_t len, uint64_t salt)
{
    uint8_t* newBuffer = (uint8_t*)malloc(len + 8);
    memcpy(newBuffer, &salt, 8);
    memcpy(newBuffer + 8, buffer, len);
    return compute_hash(newBuffer, len + 8);
}