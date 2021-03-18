/* Copyright (C) 2013, Carnegie Mellon University and Intel Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Modified by Daniel Kales, 2019
 *  * added Variants of TwoIndependantMultiplyShift for 128 and 256 bit inputs
 *  * added Setter/Getter for TwowIndependantMultiplyShift parameters
 */
#ifndef CUCKOO_FILTER_HASHUTIL_H_
#define CUCKOO_FILTER_HASHUTIL_H_

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <string>

//#include <openssl/evp.h>
#include <climits>
#include <random>

namespace cuckoofilter {

class HashUtil {
 public:
  // Bob Jenkins Hash
  static uint32_t BobHash(const void *buf, size_t length, uint32_t seed = 0);
  static uint32_t BobHash(const std::string &s, uint32_t seed = 0);

  // Bob Jenkins Hash that returns two indices in one call
  // Useful for Cuckoo hashing, power of two choices, etc.
  // Use idx1 before idx2, when possible. idx1 and idx2 should be initialized to
  // seeds.
  static void BobHash(const void *buf, size_t length, uint32_t *idx1,
                      uint32_t *idx2);
  static void BobHash(const std::string &s, uint32_t *idx1, uint32_t *idx2);

  // MurmurHash2
  static uint32_t MurmurHash(const void *buf, size_t length, uint32_t seed = 0);
  static uint32_t MurmurHash(const std::string &s, uint32_t seed = 0);

  // Null hash (shift and mask)
  static uint32_t NullHash(const void *buf, size_t length, uint32_t shiftbytes);

  // Wrappers for MD5 and SHA1 hashing using EVP
  //  static std::string MD5Hash(const char *inbuf, size_t in_length);
  //  static std::string SHA1Hash(const char *inbuf, size_t in_length);

 private:
  HashUtil();
};

// See Martin Dietzfelbinger, "Universal hashing and k-wise independent random
// variables via integer arithmetic without primes".
class TwoIndependentMultiplyShift {
  unsigned __int128 multiply_, add_;

 public:
  TwoIndependentMultiplyShift() {
    ::std::random_device random;
    for (auto v : {&multiply_, &add_}) {
      *v = random();
      for (int i = 1; i <= 4; ++i) {
        *v = *v << 32;
        *v |= random();
      }
    }
  }

  uint64_t operator()(uint64_t key) const {
    return (add_ + multiply_ * static_cast<decltype(multiply_)>(key)) >> 64;
  }

  std::vector<__uint128_t> getParams() const {
    std::vector<__uint128_t> res;
    res.push_back(multiply_);
    res.push_back(add_);
    return res;
  }

  void setParams(std::vector<__uint128_t> params) {
    multiply_ = params[0];
    add_ = params[1];
  }
};

// See Martin Dietzfelbinger, "Universal hashing and k-wise independent random
// variables via integer arithmetic without primes". Extended for 128 bit inputs
class TwoIndependentMultiplyShift128 {
  unsigned __int128 multiply0_, multiply1_, add_;

 public:
  TwoIndependentMultiplyShift128() {
    ::std::random_device random;
    for (auto v : {&multiply0_, &multiply1_, &add_}) {
      *v = random();
      for (int i = 1; i <= 4; ++i) {
        *v = *v << 32;
        *v |= random();
      }
    }
  }

  uint64_t operator()(uint64_t *key) const {
    return (add_ + multiply0_ * static_cast<decltype(multiply0_)>(key[0]) +
            multiply1_ * static_cast<decltype(multiply1_)>(key[1])) >>
           64;
  }

  std::vector<__uint128_t> getParams() const {
    std::vector<__uint128_t> res;
    res.push_back(multiply0_);
    res.push_back(multiply1_);
    res.push_back(add_);
    return res;
  }

  void setParams(std::vector<__uint128_t> params) {
    multiply0_ = params[0];
    multiply1_ = params[1];
    add_ = params[2];
  }
};

// See Martin Dietzfelbinger, "Universal hashing and k-wise independent random
// variables via integer arithmetic without primes". Extended for 256 bit inputs
class TwoIndependentMultiplyShift256 {
  unsigned __int128 multiply0_, multiply1_, multiply2_, multiply3_, add_;

 public:
  TwoIndependentMultiplyShift256() {
    ::std::random_device random;
    for (auto v : {&multiply0_, &multiply1_, &multiply2_, &multiply3_, &add_}) {
      *v = random();
      for (int i = 1; i <= 4; ++i) {
        *v = *v << 32;
        *v |= random();
      }
    }
  }

  uint64_t operator()(uint64_t *key) const {
    return (add_ + multiply0_ * static_cast<decltype(multiply0_)>(key[0]) +
            multiply1_ * static_cast<decltype(multiply1_)>(key[1]) +
            multiply2_ * static_cast<decltype(multiply2_)>(key[2]) +
            multiply3_ * static_cast<decltype(multiply3_)>(key[3])) >>
           64;
  }
  std::vector<__uint128_t> getParams() const {
    std::vector<__uint128_t> res;
    res.push_back(multiply0_);
    res.push_back(multiply1_);
    res.push_back(multiply2_);
    res.push_back(multiply3_);
    res.push_back(add_);
    return res;
  }

  void setParams(std::vector<__uint128_t> params) {
    multiply0_ = params[0];
    multiply1_ = params[1];
    multiply2_ = params[2];
    multiply3_ = params[3];
    add_ = params[4];
  }
};

// See Patrascu and Thorup's "The Power of Simple Tabulation Hashing"
class SimpleTabulation {
  uint64_t tables_[sizeof(uint64_t)][1 << CHAR_BIT];

 public:
  SimpleTabulation() {
    ::std::random_device random;
    for (unsigned i = 0; i < sizeof(uint64_t); ++i) {
      for (int j = 0; j < (1 << CHAR_BIT); ++j) {
        tables_[i][j] = random() | ((static_cast<uint64_t>(random())) << 32);
      }
    }
  }

  uint64_t operator()(uint64_t key) const {
    uint64_t result = 0;
    for (unsigned i = 0; i < sizeof(key); ++i) {
      result ^= tables_[i][reinterpret_cast<uint8_t *>(&key)[i]];
    }
    return result;
  }
};
}  // namespace cuckoofilter

#endif  // CUCKOO_FILTER_HASHUTIL_H_
