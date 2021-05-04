#include "sha256.h"

u256_t sha256_main_basic(volatile char* ctx_mem, u64_t ctx_len) {
#pragma HLS INLINE
    /* Initialize Hash Value */
    u32_t hash[8];
    hash[0] = 0x6a09e667, hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372, hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f, hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab, hash[7] = 0x5be0cd19;

    /* Some Variables*/
    u512_t data;    // Data of One Chunk
    u64_t  offset;  // Memory Read Offset

    /* Update Hash Value */
UPDATE:
    for (offset = 0; offset < (CTX_MEM_SIZE); offset += 64) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=8
#pragma HLS LOOP_FLATTEN off

        /* Preserve Tail Context */
        if (offset + 64 > ctx_len) break;

        /* Proceed 512-bits (64-bytes) chunk and Update Hash Values*/
        sha256_read(ctx_mem, data, offset, 64);
        sha256_update(data, hash);
    }

    /* Get Length (Bytes) of Tail Context */
    u64_t tail_len = ctx_len - offset;

    /* Read Tail Context */
    data = 0;                                      // Clear
    sha256_read(ctx_mem, data, offset, tail_len);  // Read

    /* Since we have to
     *   1. Append 1 at the tail of message (Need 1 Byte)
     *   2. Fill the length of context at the end of chunk (Need 8 Byte).
     *   There are two situations we have to consider.
     * */
    if (tail_len <= 64 - 1 - 8) {
        /* No need of one more update*/
        /* 1. Append 1 at the tail of message*/
        data.set((int)(511 - tail_len * 8));
        /* 2. Fill the length of context at the end of chunk*/
        data(63, 0) = ctx_len * 8;  // bit length
    } else {
        /* Need one more update*/
        /* 1. Append 1 at the tail of message*/
        data.set((int)(511 - tail_len * 8));
        /* 1.1 Extra Update */
        sha256_update(data, hash);
        /* 2. Fill the length of context at the end of chunk*/
        data        = 0;            // Clear
        data(63, 0) = ctx_len * 8;  // bit length
    }

    /* Final Update */
    sha256_update(data, hash);

    return (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6],
            hash[7]);
}
