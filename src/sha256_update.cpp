#include "sha256.h"

void sha256_update(u512_t data, u32_t hash[8]) {
#if (II2_UPDATE && W_16)
    sha256_update_II2_W16(data, hash);
#elif (II2_UPDATE)
    sha256_update_II2(data, hash);
#else
    sha256_update_basic(data, hash);
#endif
}