#include "sha256.h"

void sha256_read(volatile char* ctx_mem, u512_t &data, u64_t offset,
                 u32_t byte_len) {
READ:
    for (u32_t i = 0; i < byte_len; i++) {
#pragma HLS LOOP_TRIPCOUNT min=0 max=64

#if BASIC_OPT
#pragma HLS PIPELINE
#endif
        data(511 - i * 8, 504 - i * 8) = (u8_t)ctx_mem[offset + i];
    }
}
