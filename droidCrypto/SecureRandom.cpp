#include <droidCrypto/SecureRandom.h>

namespace droidCrypto {
    uint64_t SecureRandom::rand() {
        return p.get<uint64_t>();
    }

    block SecureRandom::randBlock() {
        block tmp;
        p.get((uint8_t*)&tmp, sizeof(block));
        return tmp;
    }

    std::vector<block> SecureRandom::randBlocks(size_t count) {
        std::vector<block> tmp(count);
        p.get((uint8_t *)tmp.data(), sizeof(block)*count);
        return tmp;
    }

    void SecureRandom::randBytes(uint8_t* buffer, size_t len) {
        p.get(buffer, len);
    }
}