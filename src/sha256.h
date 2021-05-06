#ifndef _SHA256_H_
#define _SHA256_H_

#include "ap_int.h"

/* Data Type */
typedef ap_uint<8>   u8_t;
typedef ap_uint<32>  u32_t;
typedef ap_uint<64>  u64_t;
typedef ap_uint<256> u256_t;
typedef ap_uint<512> u512_t;

/* Common Function */
#if 1
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))
#else
u32_t ROTLEFT(u32_t a, u32_t b) {
#pragma HLS INLINE
    return (((a) << (b)) | ((a) >> (32 - (b))));
}
u32_t ROTRIGHT(u32_t a, u32_t b) {
#pragma HLS INLINE
    return (((a) >> (b)) | ((a) << (32 - (b))));
}
u32_t CH(u32_t x, u32_t y, u32_t z) {
#pragma HLS INLINE
    return ((x) & (y)) ^ (~(x) & (z));
}
u32_t MAJ(u32_t x, u32_t y, u32_t z) {
#pragma HLS INLINE
    return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
}
u32_t EP0(u32_t x) {
#pragma HLS INLINE
    return (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22));
}
u32_t EP1(u32_t x) {
#pragma HLS INLINE
    return (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25));
}
u32_t SIG0(u32_t x) {
#pragma HLS INLINE
    return (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3));
}
u32_t SIG1(u32_t x) {
#pragma HLS INLINE
    return (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10));
}
#endif

/* Memory Size */
#define CTX_MEM_SIZE (512)

/* Functions */
u256_t sha256(volatile char* ctx_mem, u64_t ctx_len);
u256_t sha256_main_basic(volatile char* ctx_mem, u64_t ctx_len);
u256_t sha256_main_DBUF(volatile char* ctx_mem, u64_t ctx_len);

void sha256_update(u512_t data, u32_t hash[8]);
void sha256_update_basic(u512_t data, u32_t hash[8]);
void sha256_update_II2(u512_t data, u32_t hash[8]);
void sha256_update_II2_W16(u512_t data, u32_t hash[8]);

void sha256_read(volatile char* ctx_mem, u512_t &data, u64_t offset,
                 u32_t byte_len);

/* Switch */
#define BASIC_OPT 1
#define II2_UPDATE 1
#define W_16 1
#define DOUBLE_BUFFER 1
#endif
