#pragma once
// This file and the associated implementation has been placed in the public
// domain, waiving all copyright. No restrictions are placed on its use.
#include <droidCrypto/Defines.h>
#include <array>
#include <cstring>
#include <type_traits>

extern "C" {
#include <droidCrypto/keccak/KeccakHash.h>
}

namespace droidCrypto {

// An implementation of SHA1 based on ARM NEON instructions
class SHAKE128 {
 public:
  // Default constructor of the class. Sets the internal state to zero.
  SHAKE128(uint64_t outputLength = 32) { Reset(outputLength); }

  // Resets the interal state.
  void Reset() { Reset(outputLength); }

  // Resets the interal state and sets the desired output length in bytes.
  void Reset(uint64_t digestByteLength) {
    Keccak_HashInitialize_SHAKE128(&ctx);
    outputLength = digestByteLength;
  }

  // Add length bytes pointed to by dataIn to the internal SHA1 state.
  template <typename T>
  typename std::enable_if<std::is_pod<T>::value>::type Update(const T *dd,
                                                              uint64_t ll) {
    auto length = ll * sizeof(T);
    uint8_t *dataIn = (uint8_t *)dd;

    Keccak_HashUpdate(&ctx, dataIn, length * 8);
  }
  template <typename T>
  typename std::enable_if<std::is_pod<T>::value>::type Update(const T &blk) {
    Update((uint8_t *)&blk, sizeof(T));
  }

  // Finalize the SHAKE128 digest and output the result to DataOut.
  // Required: DataOut must be at least SHAKE128::outputLength in length.
  void Final(uint8_t *DataOut) {
    Keccak_HashFinal(&ctx, NULL);
    Keccak_HashSqueeze(&ctx, DataOut, outputLength * 8);
  }

  // Copy the interal state of a SHA1 computation.
  SHAKE128 &operator=(const SHAKE128 &src);

  uint64_t getOutputLength() const { return outputLength; }

 private:
  Keccak_HashInstance ctx;
  uint32_t outputLength;
};
}  // namespace droidCrypto
