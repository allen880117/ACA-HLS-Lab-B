#include "sha256.h"

static const u32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_update_II2_W16(u512_t data, u32_t hash[8]) {
#pragma HLS INLINE
    /* Temporary Variables*/
    u32_t a, b, c, d, e, f, g, h;

    /* W-series Temporary Variables */
    u32_t w[16];
    u32_t wsig0[16];
    u32_t wsig1[16];

#if BASIC_OPT
#pragma HLS ARRAY_PARTITION variable = w complete dim = 1
#pragma HLS ARRAY_PARTITION variable = wsig0 complete dim = 1
#pragma HLS ARRAY_PARTITION variable = wsig1 complete dim = 1
#endif

    /* Copy Current Hash Value to Temporary Variables */
    a = hash[0], b = hash[1], c = hash[2], d = hash[3];
    e = hash[4], f = hash[5], g = hash[6], h = hash[7];

    /* Assign First 16 W */
ASSIGN_M_0_16:
    for (u32_t i = 0; i < 16; i++) {
#if BASIC_OPT
#pragma HLS UNROLL
#endif
        u32_t tmp_wi = data(511 - i * 32, 480 - i * 32);
        w[i]         = tmp_wi;
        wsig0[i]     = SIG0(tmp_wi);
        wsig1[i]     = SIG1(tmp_wi);
    }

    /* Variables for forwarding*/
    u32_t tmp_e_0 = d + h + k[0] + w[0];
    u32_t tmp_e_1;
    u32_t tmp_a_0 = h + k[0] + w[0];
    u32_t tmp_a_1;
    bool  use_0 = true;

    /* Iterate 64 times */
ITERATE_64:
    for (u32_t i = 0; i < 64; i++) {
#if BASIC_OPT
#pragma HLS PIPELINE
#endif
        /* Temporary Wi */
        ap_uint<4> cur    = i;
        u32_t      tmp_wi = w[cur];

        /* Get these values uncoditionally (Reduce Critical Path.)*/
        u32_t tmp_wi_back_1 = w[ap_uint<4>(cur - 1)];
        u32_t k_i_1         = k[i + 1];
        u32_t w_i_1         = w[ap_uint<4>(cur + 1)];

        /* Ping-Pong Calculation (Critical Path. will change to SIG0 and SIG1)*/
        u32_t tmp_e, tmp_a;
        if (use_0) {
            tmp_e   = tmp_e_0 + EP1(e) + CH(e, f, g);
            tmp_a   = tmp_a_0 + EP1(e) + CH(e, f, g) + EP0(a) + MAJ(a, b, c);
            tmp_e_1 = c + g + k_i_1 + w_i_1;
            tmp_a_1 = g + k_i_1 + w_i_1;
        } else {
            tmp_e   = tmp_e_1 + EP1(e) + CH(e, f, g);
            tmp_a   = tmp_a_1 + EP1(e) + CH(e, f, g) + EP0(a) + MAJ(a, b, c);
            tmp_e_0 = c + g + k_i_1 + w_i_1;
            tmp_a_0 = g + k_i_1 + w_i_1;
        }

        /* Ping-Pong */
        use_0 = (!use_0);

        /* Swap Values*/
        h = g;
        g = f;
        f = e;
        e = tmp_e;

        d = c;
        c = b;
        b = a;
        a = tmp_a;

        /* Forward Calculation(For Reducing the Critical Path) */
        if (i < 64 - 16)
            w[cur] = wsig1[(ap_uint<4>)(cur + 14)] + w[(ap_uint<4>)(cur + 9)] +
                     wsig0[(ap_uint<4>)(cur + 1)] + tmp_wi;

        /* SIG0 and SIG1 : Delay 1 Cycle (Reduce Criti. Path.) */
        if (i != 0 && i < 64 - 15) {
            wsig0[(ap_uint<4>)(cur - 1)] = SIG0(tmp_wi_back_1);
            wsig1[(ap_uint<4>)(cur - 1)] = SIG1(tmp_wi_back_1);
        }
    }

    /* Update Hash Value with Temporary Variables */
    hash[0] += a, hash[1] += b, hash[2] += c, hash[3] += d;
    hash[4] += e, hash[5] += f, hash[6] += g, hash[7] += h;
}
