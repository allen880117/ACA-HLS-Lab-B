#ifndef _SHA256_H_
#define _SHA256_H_

#define CTX_MEM_SIZE (512)

#include "ap_int.h"

typedef ap_uint<8> 	 u8_t;
typedef ap_uint<32>  u32_t;
typedef ap_uint<64>  u64_t;
typedef ap_uint<256> u256_t;
typedef ap_uint<512> u512_t;

u256_t sha256(char ctx_mem[CTX_MEM_SIZE], u64_t ctx_len);

#endif
