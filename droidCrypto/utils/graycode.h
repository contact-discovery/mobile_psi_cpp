#pragma once

#include <cstdint>
#include <vector>

namespace {
static const uint32_t
    Mod37BitPosition[] =  // map a bit value mod 37 to its position
    {32, 0,  1,  26, 2,  23, 27, 0,  3, 16, 24, 30, 28, 11, 0,  13, 4,  7, 17,
     0,  25, 22, 31, 15, 29, 10, 12, 6, 0,  21, 14, 9,  5,  20, 8,  19, 18};
}
// precomputed graycode
namespace droidCrypto {
struct GrayCode {
  std::vector<uint32_t> ord;
  std::vector<uint32_t> inc;

  GrayCode(uint32_t N) : ord(1ULL << N), inc(1ULL << N) {
    for (uint32_t j = 1; j < (1ULL << N); j++) {
      ord[j] = (j) ^ (j >> 1);
      uint32_t change = ord[j] ^ ord[j - 1];
      inc[j - 1] = Mod37BitPosition[(-change & change) % 37];
    }
  }
};
}  // namespace droidCrypto
