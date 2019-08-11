#pragma once
// This file and the associated implementation has been placed in the public
// domain, waiving all copyright. No restrictions are placed on its use.
#include <droidCrypto/BitIterator.h>
#include <droidCrypto/Defines.h>
#include <droidCrypto/PRNG.h>

#include <string>

namespace droidCrypto {

// A class to access a vector of packed bits. Similar to std::vector<bool>.
// In the underlying representation, bit 0 is the LSB of byte 0, bit 7 is the
// MSB of byte 0, bit 8 is the LSB of byte 1 etc
class BitVector {
 public:
  typedef uint8_t value_type;
  typedef value_type *pointer;
  typedef uint64_t size_type;

  // Default constructor.
  BitVector() = default;

  // Inititialize the BitVector with length bits pointed to by data.
  BitVector(uint8_t *data, uint64_t length);

  // Inititialize the BitVector from a string of '0' and '1' characters.
  BitVector(std::string data);

  // Construct a zero initialized BitVector of size n.
  explicit BitVector(uint64_t n) { reset(n); }

  // Copy an existing BitVector.
  BitVector(const BitVector &K) { assign(K); }

  // Move an existing BitVector. Moved from is set to size zero.
  BitVector(BitVector &&rref);

  ~BitVector() { delete[] mData; }

  // Reset the BitVector to have value b.
  void assign(const block &b);

  // Copy an existing BitVector
  void assign(const BitVector &K);

  // Append length bits pointed to by data starting a the bit index by offset.
  void append(uint8_t *data, uint64_t length, uint64_t offset = 0);

  // Append length bits pointed to by data starting a the bit index by offset,
  // in reverse byte order
  void appendREV(uint8_t *data, uint64_t length, uint64_t offset = 0);

  // Append an existing BitVector to this BitVector.
  void append(const BitVector &k) { append(k.data(), k.size()); }

  // erases original contents and set the new size, default 0.
  void reset(uint64_t new_nbits = 0);

  // Resize the BitVector to have the desired number of bits,
  void resize(uint64_t newSize);

  // Reserve enough space for the specified number of bits.
  void reserve(uint64_t bits);

  // Copy length bits from src starting at offset idx.
  void copy(const BitVector &src, uint64_t idx, uint64_t length);

  // Returns the number of bits this BitVector can contain using the current
  // allocation.
  uint64_t capacity() const { return mAllocBytes * 8; }

  // Returns the number of bits this BitVector current has.
  uint64_t size() const { return mNumBits; }

  // Return the number of bytes the BitVector currently utilize.
  uint64_t sizeBytes() const { return (mNumBits + 7) / 8; }

  // Returns a byte pointer to the underlying storage.
  uint8_t *data() const { return mData; }

  // Copy and existing BitVector.
  BitVector &operator=(const BitVector &K);

  // Returns a byte consisting of 8 bits starting at the specified index, only
  // works if aligned on byte border
  uint8_t get8BitsAligned(const uint64_t idx) const;

  // Get a reference to a specific bit.
  BitReference operator[](const uint64_t idx) const;

  // Xor two BitVectors together and return the result. Must have the same size.
  BitVector operator^(const BitVector &B) const;

  // AND two BitVectors together and return the result. Must have the same size.
  BitVector operator&(const BitVector &B) const;

  // OR two BitVectors together and return the result. Must have the same size.
  BitVector operator|(const BitVector &B) const;

  // Invert the bits of the BitVector and return the result.
  BitVector operator~() const;

  // Xor the rhs into this BitVector
  void operator^=(const BitVector &A);

  // And the rhs into this BitVector
  void operator&=(const BitVector &A);

  // Or the rhs into this BitVector
  void operator|=(const BitVector &A);

  // Check for equality between two BitVectors
  bool operator==(const BitVector &k) { return equals(k); }

  // Check for inequality between two BitVectors
  bool operator!=(const BitVector &k) const { return !equals(k); }

  // Check for equality between two BitVectors
  bool equals(const BitVector &K) const;

  // Initialize this BitVector from a string of '0' and '1' characters.
  void fromString(std::string data);

  // Returns an Iterator for the first bit.
  BitIterator begin() const;

  // Returns an Iterator for the position past the last bit.
  BitIterator end() const;

  // Initialize this bit vector to size n with a random set of k bits set to 1.
  void nChoosek(uint64_t n, uint64_t k, PRNG &prng);

  // Return the hamming weight of the BitVector.
  uint64_t hammingWeight() const;

  // Append the bit to the end of the BitVector.
  void pushBack(uint8_t bit);

  // Returns a refernce to the last bit.
  inline BitReference back() { return (*this)[size() - 1]; }

  // Set all the bits to random values.
  void randomize(PRNG &G);

  // Return the parity of the vector.
  uint8_t parity();

  // Return the hex representation of the vector.
  std::string hex() const;

  // Return the hex representation of the vector, in reverse Byte order
  std::string hexREV() const;

  // Reinterpret the vector of bits as a vector of type T.
  template <class T>
  span<T> getArrayView() const;

  // Reinterpret the vector of bits as a vector of type T.
  template <class T>
  span<T> getSpan() const;

 private:
  uint8_t *mData = nullptr;
  uint64_t mNumBits = 0, mAllocBytes = 0;
};

template <class T>
inline span<T> BitVector::getArrayView() const {
  return span<T>((T *)mData, (T *)mData + (sizeBytes() / sizeof(T)));
}

template <class T>
inline gsl::span<T> BitVector::getSpan() const {
  return gsl::span<T>((T *)mData, (T *)mData + (sizeBytes() / sizeof(T)));
}

std::ostream &operator<<(std::ostream &in, const BitVector &val);

//    template<>
//    inline uint8_t* channelBuffData<BitVector>(const BitVector& container)
//    {
//        return (uint8_t*)container.data();
//    }
//
//    template<>
//    inline BitVector::size_type channelBuffSize<BitVector>(const BitVector&
//    container)
//    {
//        return container.sizeBytes();
//    }
//
//    template<>
//    inline bool channelBuffResize<BitVector>(BitVector& container, uint64_t
//    size)
//    {
//        return size == container.sizeBytes();
//    }

}