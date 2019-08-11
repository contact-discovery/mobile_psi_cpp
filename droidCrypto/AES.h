#pragma once

#include <cstdint>

#include <jni.h>

#include <droidCrypto/Defines.h>

#if defined(HAVE_NEON)
#include <arm_acle.h>
#include <arm_neon.h>
#else
#include <wmmintrin.h>
#include <xmmintrin.h>
#endif

namespace droidCrypto {
class AES {
  template <int N>
  friend class MultiKeyAES;

 public:
  AES();
  AES(const block &key);
  AES(const uint8_t *key);

  void setKey(const block &key);
  void setKey(const uint8_t *key);

  void encryptECB(const block &plaintext, block &ciphertext) const;
  block encryptECB(const block &plaintext) const {
    block tmp;
    encryptECB(plaintext, tmp);
    return tmp;
  }

  void decryptECB(const block &ciphertext, block &plaintext) const;
  block decryptECB(const block &ciphertext) const {
    block tmp;
    decryptECB(ciphertext, tmp);
    return tmp;
  }
  void encryptECBBlocks(const block *plaintexts, uint64_t blockLength,
                        block *ciphertexts) const;

  void encryptCTR(uint64_t baseIdx, uint64_t blockLength,
                  block *ciphertext) const;
  block key;

 private:
  block mRoundKeysEnc[11];
  block mRoundKeysDec[11];
#if defined(HAVE_NEON)
  void keyschedule(const uint8_t *key);
#endif
};

// Specialization of the AES class to support encryption of N values under N
// different keys
template <int N>
class MultiKeyAES {
 public:
  std::array<AES, N> mAESs;

  // Default constructor leave the class in an invalid state
  // until setKey(...) is called.
  MultiKeyAES() = default;

  // Constructor to initialize the class with the given key
  MultiKeyAES(span<block> keys) { setKeys(keys); }

  // Set the N keys to be used for encryption.
  void setKeys(span<block> keys) {
    for (int i = 0; i < N; ++i) {
      mAESs[i].setKey(keys[i]);
    }
  }

  // Computes the encrpytion of N blocks pointed to by plaintext
  // and stores the result at ciphertext.
  void ecbEncNBlocks(const block *plaintext, block *ciphertext) const {
#ifdef HAVE_NEON
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(plaintext[i], mAESs[i].mRoundKeysEnc[0]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[1]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[2]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[3]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[4]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[5]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[6]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[7]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[8]);
    for (int i = 0; i < N; ++i) ciphertext[i] = vaesmcq_u8(ciphertext[i]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = vaeseq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[9]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] = veorq_u8(ciphertext[i], mAESs[i].mRoundKeysEnc[10]);
#else
    for (int i = 0; i < N; ++i)
      ciphertext[i] = _mm_xor_si128(plaintext[i], mAESs[i].mRoundKeysEnc[0]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[1]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[2]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[3]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[4]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[5]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[6]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[7]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[8]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenc_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[9]);
    for (int i = 0; i < N; ++i)
      ciphertext[i] =
          _mm_aesenclast_si128(ciphertext[i], mAESs[i].mRoundKeysEnc[10]);
#endif
  }

  const MultiKeyAES<N> &operator=(const MultiKeyAES<N> &rhs) {
    for (int i = 0; i < N; ++i)
      for (int j = 0; j < 11; ++j) {
        mAESs[i].key = rhs.mAESs[i].key;
        mAESs[i].mRoundKeysEnc[j] = rhs.mAESs[i].mRoundKeysEnc[j];
        mAESs[i].mRoundKeysDec[j] = rhs.mAESs[i].mRoundKeysDec[j];
      }

    return rhs;
  }
};
// An AES instance with a fixed and public key
extern const AES mAesFixedKey;
}  // namespace droidCrypto

extern "C" JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_Crypto_AES_fixedKeyEnc(JNIEnv *, jclass,
                                                           jobject, jobject);
