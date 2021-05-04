#include "sha256.h"

u256_t sha256(volatile char* ctx_mem, u64_t ctx_len){

#pragma HLS INTERFACE m_axi depth=512 port=ctx_mem offset=slave
#pragma HLS INTERFACE s_axilite port=ctx_len
#pragma HLS INTERFACE s_axilite port=return

#if !DOUBLE_BUFFER
  return sha256_main_basic(ctx_mem, ctx_len);
#else
  return sha256_main_DBUF(ctx_mem, ctx_len);
#endif
}
