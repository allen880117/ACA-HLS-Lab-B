#if 0
#include "sha256.h"
#include <iostream>

#define USE_HLS_PRAGMA 0
#define II3 0
#define II2 (II3)
#define M16 0
#define DBUF 0

#if 0
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))
#else
u32_t ROTLEFT(u32_t a, u32_t b)
{
#pragma HLS INLINE
	return (((a) << (b)) | ((a) >> (32 - (b))));
}
u32_t ROTRIGHT(u32_t a, u32_t b)
{
#pragma HLS INLINE
	return (((a) >> (b)) | ((a) << (32 - (b))));
}
u32_t CH(u32_t x, u32_t y, u32_t z)
{
#pragma HLS INLINE
	return ((x) & (y)) ^ (~(x) & (z));
}
u32_t MAJ(u32_t x, u32_t y, u32_t z)
{
#pragma HLS INLINE
	return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
}
u32_t EP0(u32_t x)
{
#pragma HLS INLINE
	return (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22));
}
u32_t EP1(u32_t x)
{
#pragma HLS INLINE
	return (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25));
}
u32_t SIG0(u32_t x)
{
#pragma HLS INLINE
	return (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3));
}
u32_t SIG1(u32_t x)
{
#pragma HLS INLINE
	return (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10));
}
#endif

static const u32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_update(u512_t data, u32_t hash[8]);
void sha256_read(char ctx_mem[CTX_MEM_SIZE], u512_t &data, u64_t offset, u32_t byte_len);

#if !DBUF
u256_t sha256(char ctx_mem[CTX_MEM_SIZE], u64_t ctx_len)
{

	/* Initialize Hash Value */
	u32_t hash[8];
	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	/* Some Variables*/
	u512_t data;  // Data of One Chunk
	u64_t offset; // Memory Read Offset

	/* Update Hash Value */
UPDATE:
	for (offset = 0; offset < (CTX_MEM_SIZE); offset += 64)
	{
#pragma HLS LOOP_TRIPCOUNT min = 0 max = 8 avg = 8

#if USE_HLS_PRAGMA
#pragma HLS LOOP_FLATTEN off
#endif

		/* Preserve Tail Context */
		if (offset + 64 > ctx_len)
			break;

		/* Proceed 512-bits (64-bytes) chunk and Update Hash Values*/
		sha256_read(ctx_mem, data, offset, 64);
		sha256_update(data, hash);
	}

	/* Get Length (Bytes) of Tail Context */
	u64_t tail_len = ctx_len - offset;

	/* Read Tail Context */
	data = 0;									  // Clear
	sha256_read(ctx_mem, data, offset, tail_len); // Read

	/* Since we have to
	 *   1. Append 1 at the tail of message (Need 1 Byte)
	 *   2. Fill the length of context at the end of chunk (Need 8 Byte).
	 *   There are two situations we have to consider.
	 * */
	if (tail_len <= 64 - 1 - 8)
	{
		/* No need of one more update*/
		/* 1. Append 1 at the tail of message*/
		data.set((int)(511 - tail_len * 8));
		/* 2. Fill the length of context at the end of chunk*/
		data(63, 0) = ctx_len * 8; // bit length
	}
	else
	{
		/* Need one more update*/
		/* 1. Append 1 at the tail of message*/
		data.set((int)(511 - tail_len * 8));
		/* 1.1 Extra Update */
		sha256_update(data, hash);
		/* 2. Fill the length of context at the end of chunk*/
		data = 0;				   // Clear
		data(63, 0) = ctx_len * 8; // bit length
	}

	/* Final Update */
	sha256_update(data, hash);

	return (hash[0], hash[1], hash[2], hash[3],
			hash[4], hash[5], hash[6], hash[7]);
}
#else
u256_t sha256(char ctx_mem[CTX_MEM_SIZE], u64_t ctx_len)
{

	/* Initialize Hash Value */
	u32_t hash[8];
	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	/* Some Variables*/
	u512_t data_0; // Data of One Chunk
	u512_t data_1; // Data of One Chunk
	bool use_0 = true;

	u64_t first_read_size = 0;
	u64_t offset; // Memory Read Offset

	if (ctx_len >= 64)
	{
		first_read_size = 64;
		sha256_read(ctx_mem, data_0, 0, 64);
	}
	else
	{
		first_read_size = 0;
	}

	/* Update Hash Value */
UPDATE:
	for (offset = first_read_size; offset < (CTX_MEM_SIZE / 64); offset += 64)
	{
#pragma HLS LOOP_TRIPCOUNT min = 0 max = 8 avg = 8

#if USE_HLS_PRAGMA
#pragma HLS LOOP_FLATTEN off
#endif

		/* Preserve Tail Context */
		if (offset + 64 > ctx_len)
			break;

		/* Proceed 512-bits (64-bytes) chunk and Update Hash Values*/
		if (use_0)
		{
			sha256_read(ctx_mem, data_1, offset, 64);
			sha256_update(data_0, hash);
		}
		else
		{
			sha256_read(ctx_mem, data_0, offset, 64);
			sha256_update(data_1, hash);
		}

		use_0 = (!use_0);
	}

	/* Buffer 0/1 still has unprocessed data */
	if (first_read_size != 0)
	{
		if (use_0)
			sha256_update(data_0, hash);
		else
			sha256_update(data_1, hash);
	}

	/* Get Length (Bytes) of Tail Context */
	u64_t tail_len = ctx_len - offset;

	if (use_0)
	{
		/* Read Tail Context */
		data_1 = 0;										// Clear
		sha256_read(ctx_mem, data_1, offset, tail_len); // Read

		/* Since we have to
		 *   1. Append 1 at the tail of message (Need 1 Byte)
		 *   2. Fill the length of context at the end of chunk (Need 8 Byte).
		 *   There are two situations we have to consider.
		 * */
		if (tail_len <= 64 - 1 - 8)
		{
			/* No need of one more update*/
			/* 1. Append 1 at the tail of message*/
			data_1.set((int)(511 - tail_len * 8));
			/* 2. Fill the length of context at the end of chunk*/
			data_1(63, 0) = ctx_len * 8; // bit length

			/* Final Update */
			sha256_update(data_1, hash);
		}
		else
		{
			/* Need one more update*/
			/* 1. Append 1 at the tail of message*/
			data_1.set((int)(511 - tail_len * 8));
			/* 1.1 Extra Update */
			sha256_update(data_1, hash);

			/* 2. Use "Another Buffer" to
			 * 	  Fill the length of context at the end of chunk */
			data_0 = 0;					 // Clear
			data_0(63, 0) = ctx_len * 8; // bit length

			/* Final Update */
			sha256_update(data_0, hash);
		}
	}
	else
	{
		/* Read Tail Context */
		data_0 = 0;										// Clear
		sha256_read(ctx_mem, data_0, offset, tail_len); // Read

		/* Since we have to
		 *   1. Append 1 at the tail of message (Need 1 Byte)
		 *   2. Fill the length of context at the end of chunk (Need 8 Byte).
		 *   There are two situations we have to consider.
		 * */
		if (tail_len <= 64 - 1 - 8)
		{
			/* No need of one more update*/
			/* 1. Append 1 at the tail of message*/
			data_0.set((int)(511 - tail_len * 8));
			/* 2. Fill the length of context at the end of chunk*/
			data_0(63, 0) = ctx_len * 8; // bit length

			/* Final Update */
			sha256_update(data_0, hash);
		}
		else
		{
			/* Need one more update*/
			/* 1. Append 1 at the tail of message*/
			data_0.set((int)(511 - tail_len * 8));
			/* 1.1 Extra Update */
			sha256_update(data_0, hash);

			/* 2. Use "Another Buffer" to
			 * 	  Fill the length of context at the end of chunk */
			data_1 = 0;					 // Clear
			data_1(63, 0) = ctx_len * 8; // bit length

			/* Final Update */
			sha256_update(data_1, hash);
		}
	}

	return (hash[0], hash[1], hash[2], hash[3],
			hash[4], hash[5], hash[6], hash[7]);
}
#endif

void sha256_update(u512_t data, u32_t hash[8])
{
#if !M16
	/* Temporary Variables*/
	u32_t a, b, c, d, e, f, g, h;

	/* W-series Temporary Variables */
	u32_t w[64];
	u32_t wsig0[64];
	u32_t wsig1[64];

#if USE_HLS_PRAGMA
#pragma HLS ARRAY_PARTITION variable = w complete dim = 1
#pragma HLS ARRAY_PARTITION variable = wsig0 complete dim = 1
#pragma HLS ARRAY_PARTITION variable = wsig1 complete dim = 1
#endif

	/* Copy Current Hash Value to Temporary Variables */
	a = hash[0], b = hash[1], c = hash[2], d = hash[3];
	e = hash[4], f = hash[5], g = hash[6], h = hash[7];

	/* Assign First 16 W */
ASSIGN_M_0_16:
	for (u32_t i = 0; i < 16; i++)
	{
#if USE_HLS_PRAGMA
#pragma HLS UNROLL
#endif
		u32_t tmp_wi = data(511 - i * 32, 480 - i * 32);
		w[i] = tmp_wi;
		wsig0[i] = SIG0(tmp_wi);
		wsig1[i] = SIG1(tmp_wi);
	}

#if II2
	u32_t tmp_e_0 = d + h + k[0] + w[0];
	u32_t tmp_e_1;
	u32_t tmp_a_0 = h + k[0] + w[0];
	u32_t tmp_a_1;
	bool use_0 = true;
#endif

	/* Iterate 64 times */
ITERATE_64:
	for (u32_t i = 0; i < 64; i++)
	{
#if USE_HLS_PRAGMA
#pragma HLS PIPELINE
#endif
		/* Temporary Wi */
		u32_t tmp_wi = w[i];

#if II3
#if II2
		/* Get this value uncoditionally (Reduce Criti. Path.)*/
		u32_t tmp_wi_back_1 = w[i - 1];

		u32_t tmp_e, tmp_a;
		u32_t k_i_1 = k[i + 1];
		u32_t w_i_1 = w[i + 1];
		if (use_0)
		{
			tmp_e = tmp_e_0 + EP1(e) + CH(e, f, g);
			tmp_a = tmp_a_0 + EP1(e) + CH(e, f, g) + EP0(a) + MAJ(a, b, c);
			tmp_e_1 = c + g + k_i_1 + w_i_1;
			tmp_a_1 = g + k_i_1 + w_i_1;
		}
		else
		{
			tmp_e = tmp_e_1 + EP1(e) + CH(e, f, g);
			tmp_a = tmp_a_1 + EP1(e) + CH(e, f, g) + EP0(a) + MAJ(a, b, c);
			tmp_e_0 = c + g + k_i_1 + w_i_1;
			tmp_a_0 = g + k_i_1 + w_i_1;
		}
		use_0 = (!use_0);
#else
		/* Temporal Summation */
		u32_t tmp_e = d + h + EP1(e) + CH(e, f, g) + k[i] + tmp_wi;
		u32_t tmp_a = h + EP1(e) + CH(e, f, g) + k[i] + tmp_wi + EP0(a) + MAJ(a, b, c);
#endif
		/* Swap Values*/
		h = g;
		g = f;
		f = e;
		e = tmp_e;

		d = c;
		c = b;
		b = a;
		a = tmp_a;

		/* Forward Calculation
		 *   1. For Reducing the Critical Path
		 * */
		if (i < 64 - 16)
		{
			u32_t tmp_wi_16 = wsig1[i + 14] + w[i + 9] + wsig0[i + 1] + tmp_wi;
			w[i + 16] = tmp_wi_16;
#if !II2
			wsig0[i + 16] = SIG0(tmp_wi_16);
			wsig1[i + 16] = SIG1(tmp_wi_16);
#endif
		}

#if II2
		if (i != 0 && i < 64 - 16)
		{
			/* Delay 1 Cycle (Reduce Criti. Path.) */
			wsig0[i + 15] = SIG0(tmp_wi_back_1);
			wsig1[i + 15] = SIG1(tmp_wi_back_1);
		}
#endif

#else
		/* Temporal Summation */
		u32_t t1 = h + EP1(e) + CH(e, f, g) + k[i] + tmp_wi;
		u32_t t2 = EP0(a) + MAJ(a, b, c);

		/* Swap Values*/
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;

		/* Forward Calculation
		 *   1. For Reducing the Critical Path
		 * */
		if (i < 64 - 16)
		{
			u32_t tmp_wi_16 = wsig1[i + 14] + w[i + 9] + wsig0[i + 1] + tmp_wi;
			w[i + 16] = tmp_wi_16;
			wsig0[i + 16] = SIG0(tmp_wi_16);
			wsig1[i + 16] = SIG1(tmp_wi_16);
		}
#endif
	}

	/* Update Hash Value with Temporary Variables */
	hash[0] += a, hash[1] += b, hash[2] += c, hash[3] += d;
	hash[4] += e, hash[5] += f, hash[6] += g, hash[7] += h;
#else
	/* Temporary Variables*/
	u32_t a, b, c, d, e, f, g, h;

	/* W-series Temporary Variables */
	u32_t w[16];
	u32_t wsig0[16];
	u32_t wsig1[16];

#if USE_HLS_PRAGMA
#pragma HLS ARRAY_PARTITION variable = w complete dim = 1
#pragma HLS ARRAY_PARTITION variable = wsig0 complete dim = 1
#pragma HLS ARRAY_PARTITION variable = wsig1 complete dim = 1
#endif

	/* Copy Current Hash Value to Temporary Variables */
	a = hash[0], b = hash[1], c = hash[2], d = hash[3];
	e = hash[4], f = hash[5], g = hash[6], h = hash[7];

	/* Assign First 16 W */
ASSIGN_M_0_16:
	for (u32_t i = 0; i < 16; i++)
	{
#if USE_HLS_PRAGMA
#pragma HLS UNROLL
#endif
		u32_t tmp_wi = data(511 - i * 32, 480 - i * 32);
		w[i] = tmp_wi;
		wsig0[i] = SIG0(tmp_wi);
		wsig1[i] = SIG1(tmp_wi);
	}

#if II2
	u32_t tmp_e_0 = d + h + k[0] + w[0];
	u32_t tmp_e_1;
	u32_t tmp_a_0 = h + k[0] + w[0];
	u32_t tmp_a_1;
	bool use_0 = true;
#endif

	/* Iterate 64 times */
ITERATE_64:
	for (u32_t i = 0; i < 64; i++)
	{
#if USE_HLS_PRAGMA
#pragma HLS PIPELINE
#endif
		/* Temporary Wi */
		ap_uint<4> cur = i;
		u32_t tmp_wi = w[cur];

		/* Temporal Summation */
#if II2
		/* Get this value uncoditionally (Reduce Criti. Path.)*/
		u32_t tmp_wi_back_1 = w[ap_uint<4>(cur - 1)];

		u32_t tmp_e, tmp_a;
		u32_t k_i_1 = k[i + 1];
		u32_t w_i_1 = w[ap_uint<4>(cur + 1)];
		if (use_0)
		{
			tmp_e = tmp_e_0 + EP1(e) + CH(e, f, g);
			tmp_a = tmp_a_0 + EP1(e) + CH(e, f, g) + EP0(a) + MAJ(a, b, c);
			tmp_e_1 = c + g + k_i_1 + w_i_1;
			tmp_a_1 = g + k_i_1 + w_i_1;
		}
		else
		{
			tmp_e = tmp_e_1 + EP1(e) + CH(e, f, g);
			tmp_a = tmp_a_1 + EP1(e) + CH(e, f, g) + EP0(a) + MAJ(a, b, c);
			tmp_e_0 = c + g + k_i_1 + w_i_1;
			tmp_a_0 = g + k_i_1 + w_i_1;
		}
		use_0 = (!use_0);
#else
		u32_t tmp_e = d + h + EP1(e) + CH(e, f, g) + k[i] + tmp_wi;
		u32_t tmp_a = h + EP1(e) + CH(e, f, g) + k[i] + tmp_wi + EP0(a) + MAJ(a, b, c);
#endif

		/* Swap Values*/
		h = g;
		g = f;
		f = e;
		e = tmp_e;

		d = c;
		c = b;
		b = a;
		a = tmp_a;

		/* Forward Calculation
		 *   1. For Reducing the Critical Path
		 * */
		if (i < 64 - 16)
		{
			u32_t tmp_wi_16 = wsig1[(ap_uint<4>)(cur + 14)] + w[(ap_uint<4>)(cur + 9)] + wsig0[(ap_uint<4>)(cur + 1)] + tmp_wi;
			w[cur] = tmp_wi_16;
#if !II2
			wsig0[cur] = SIG0(tmp_wi_16);
			wsig1[cur] = SIG1(tmp_wi_16);
#endif
		}

#if II2
		if (i != 0 && i < 64 - 16)
		{
			/* Delay 1 Cycle (Reduce Criti. Path.) */
			wsig0[(ap_uint<4>)(cur - 1)] = SIG0(tmp_wi_back_1);
			wsig1[(ap_uint<4>)(cur - 1)] = SIG1(tmp_wi_back_1);
		}
#endif
	}

	/* Update Hash Value with Temporary Variables */
	hash[0] += a, hash[1] += b, hash[2] += c, hash[3] += d;
	hash[4] += e, hash[5] += f, hash[6] += g, hash[7] += h;
#endif
}

void sha256_read(char ctx_mem[CTX_MEM_SIZE], u512_t &data, u64_t offset, u32_t byte_len)
{
READ:
	for (u32_t i = 0; i < byte_len; i++)
	{
#pragma HLS LOOP_TRIPCOUNT min = 0 max = 64 avg = 64

#if USE_HLS_PRAGMA
#pragma HLS PIPELINE
#endif
		data(511 - i * 8, 504 - i * 8) = (u8_t)ctx_mem[offset + i];
	}
}
#endif
