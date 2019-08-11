#pragma once
// This file and the associated implementation has been placed in the public
// domain, waiving all copyright. No restrictions are placed on its use.
#include <droidCrypto/AES.h>
#include <droidCrypto/Defines.h>

#include <cstring>
#include <vector>

namespace droidCrypto {

// A Peudorandom number generator implemented using AES-NI.
class PRNG {
 public:
  // default construct leaves the PRNG in an invalid state.
  // SetSeed(...) must be called before get(...)
  PRNG() = default;

  // explicit constructor to initialize the PRNG with the
  // given seed and to buffer bufferSize number of AES block
  PRNG(const block &seed, uint64_t bufferSize = 256);

  // standard move constructor. The moved from PRNG is invalide
  // unless SetSeed(...) is called.
  PRNG(PRNG &&s);

  // Copy is not allowed.
  PRNG(const PRNG &) = delete;

  // Set seed from a block and set the desired buffer size.
  void SetSeed(const block &b, uint64_t bufferSize = 256);

  // Return the seed for this PRNG.
  const block getSeed() const;

  // Templated function that returns the a random element
  // of the given type T.
  // Required: T must be a POD type.
  template <typename T>
  typename std::enable_if<std::is_pod<T>::value, T>::type get() {
    T ret;
    get((uint8_t *)&ret, sizeof(T));
    return ret;
  }

  // Templated function that fills the provided buffer
  // with random elements of the given type T.
  // Required: T must be a POD type.
  template <typename T>
  typename std::enable_if<std::is_pod<T>::value, void>::type get(
      T *dest, uint64_t length) {
    uint64_t lengthuint8_t = length * sizeof(T);
    uint8_t *destuint8_t = (uint8_t *)dest;
    while (lengthuint8_t) {
      uint64_t step = std::min(lengthuint8_t, mBufferByteCapacity - mBytesIdx);

      memcpy(destuint8_t, ((uint8_t *)mBuffer.data()) + mBytesIdx, step);

      destuint8_t += step;
      lengthuint8_t -= step;
      mBytesIdx += step;

      if (mBytesIdx == mBufferByteCapacity) refillBuffer();
    }
  }

  // Templated function that fills the provided buffer
  // with random elements of the given type T.
  // Required: T must be a POD type.
  template <typename T>
  typename std::enable_if<std::is_pod<T>::value, void>::type get(span<T> dest) {
    get(dest.data(), dest.size());
  }

  // Returns a random element from {0,1}
  uint8_t getBit();

  // STL random number interface
  typedef uint32_t result_type;
  constexpr static result_type min() { return 0; }
  constexpr static result_type max() { return (result_type)-1; }
  result_type operator()() { return get<result_type>(); }
  result_type operator()(int mod) { return get<result_type>() % mod; }

  // internal buffer to store future random values.
  std::vector<block> mBuffer;

  // AES that generates the randomness by computing AES_seed({0,1,2,...})
  AES mAes;

  // Indicators denoting the current state of the buffer.
  uint64_t mBytesIdx = 0, mBlockIdx = 0, mBufferByteCapacity = 0;

  // refills the internal buffer with fresh randomness
  void refillBuffer();

  static inline PRNG getTestPRNG() {
    PRNG t(TestBlock);
    return t;
  }
};

// specialization to make bool work correctly.
template <>
inline void PRNG::get<bool>(bool *dest, uint64_t length) {
  get((uint8_t *)dest, length);
  for (uint64_t i = 0; i < length; ++i) dest[i] = ((uint8_t *)dest)[i] & 1;
}

// specialization to make bool work correctly.
template <>
inline bool PRNG::get<bool>() {
  uint8_t ret;
  get((uint8_t *)&ret, 1);
  return ret & 1;
}

template <typename T>
typename std::enable_if<std::is_pod<T>::value, PRNG &>::type operator<<(
    T &rhs, PRNG &lhs) {
  lhs.get(&rhs, 1);
}

}  // namespace droidCrypto
