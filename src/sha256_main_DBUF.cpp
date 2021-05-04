#include "sha256.h"

u256_t sha256_main_DBUF(volatile char* ctx_mem, u64_t ctx_len) {
#pragma HLS INLINE
    /* Initialize Hash Value */
    u32_t hash[8];
    hash[0] = 0x6a09e667, hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372, hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f, hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab, hash[7] = 0x5be0cd19;

    /* Buffers */
    u512_t data_0;  // Data of One Chunk
    u512_t data_1;  // Data of One Chunk
    bool   use_0 = true;

    /* Length-Related Variables */
    u64_t first_read_size = 0;
    u64_t offset;  // Memory Read Offset

    /* Initialize First Buffer*/
    if (ctx_len >= 64) {
        first_read_size = 64;
        sha256_read(ctx_mem, data_0, 0, 64);
    } else {
        first_read_size = 0;
    }

    /* Update Hash Value */
UPDATE:
    for (offset = first_read_size; offset < (CTX_MEM_SIZE); offset += 64) {
#pragma HLS LOOP_TRIPCOUNT min=0 max=7
#pragma HLS LOOP_FLATTEN off

        /* Preserve Tail Context */
        if (offset + 64 > ctx_len) break;

        /* Proceed 512-bits (64-bytes) chunk and Update Hash Values*/
        if (use_0) {
            sha256_read(ctx_mem, data_1, offset, 64);
            sha256_update(data_0, hash);
        } else {
            sha256_read(ctx_mem, data_0, offset, 64);
            sha256_update(data_1, hash);
        }

        /* Ping-Pong */
        use_0 = (!use_0);
    }

    /* Buffer 0/1 still has unprocessed data */
    if (first_read_size != 0) {
        if (use_0)
            sha256_update(data_0, hash);
        else
            sha256_update(data_1, hash);
    }

    /* Get Length (Bytes) of Tail Context */
    u64_t tail_len = ctx_len - offset;

    if (use_0) {
        /* Read Tail Context */
        data_1 = 0;                                      // Clear
        sha256_read(ctx_mem, data_1, offset, tail_len);  // Read

        /* Since we have to
         *   1. Append 1 at the tail of message (Need 1 Byte)
         *   2. Fill the length of context at the end of chunk (Need 8 Byte).
         *   There are two situations we have to consider.
         * */
        if (tail_len <= 64 - 1 - 8) {
            /* No need of one more update*/
            /* 1. Append 1 at the tail of message*/
            data_1.set((int)(511 - tail_len * 8));
            /* 2. Fill the length of context at the end of chunk*/
            data_1(63, 0) = ctx_len * 8;  // bit length

            /* Final Update */
            sha256_update(data_1, hash);
        } else {
            /* Need one more update*/
            /* 1. Append 1 at the tail of message*/
            data_1.set((int)(511 - tail_len * 8));
            /* 1.1 Extra Update */
            sha256_update(data_1, hash);

            /* 2. Use "Another Buffer" to
             * 	  Fill the length of context at the end of chunk */
            data_0        = 0;            // Clear
            data_0(63, 0) = ctx_len * 8;  // bit length

            /* Final Update */
            sha256_update(data_0, hash);
        }
    } else {
        /* Read Tail Context */
        data_0 = 0;                                      // Clear
        sha256_read(ctx_mem, data_0, offset, tail_len);  // Read

        /* Since we have to
         *   1. Append 1 at the tail of message (Need 1 Byte)
         *   2. Fill the length of context at the end of chunk (Need 8 Byte).
         *   There are two situations we have to consider.
         * */
        if (tail_len <= 64 - 1 - 8) {
            /* No need of one more update*/
            /* 1. Append 1 at the tail of message*/
            data_0.set((int)(511 - tail_len * 8));
            /* 2. Fill the length of context at the end of chunk*/
            data_0(63, 0) = ctx_len * 8;  // bit length

            /* Final Update */
            sha256_update(data_0, hash);
        } else {
            /* Need one more update*/
            /* 1. Append 1 at the tail of message*/
            data_0.set((int)(511 - tail_len * 8));
            /* 1.1 Extra Update */
            sha256_update(data_0, hash);

            /* 2. Use "Another Buffer" to
             * 	  Fill the length of context at the end of chunk */
            data_1        = 0;            // Clear
            data_1(63, 0) = ctx_len * 8;  // bit length

            /* Final Update */
            sha256_update(data_1, hash);
        }
    }

    return (hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6],
            hash[7]);
}
