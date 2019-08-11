#include <assert.h>
#include <droidCrypto/AES.h>

namespace droidCrypto {
const uint8_t fixed_key[16] = {36,  156, 50,  234, 92, 230, 49, 9,
                               174, 170, 205, 160, 98, 236, 29, 243};
const AES mAesFixedKey(fixed_key);

#if defined(HAVE_NEON)

static const uint8_t sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C
    // D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

uint32_t SubWord(uint32_t word) {
  uint32_t result;

  result = (uint32_t)sbox[word & 0x000000FF];
  result += (uint32_t)sbox[(word >> 8) & 0x000000FF] << 8;
  result += (uint32_t)sbox[(word >> 16) & 0x000000FF] << 16;
  result += (uint32_t)sbox[(word >> 24) & 0x000000FF] << 24;
  return result;
}

#define KE_ROTWORD(x) (((x) << 8) | ((x) >> 24))

void KeyExpansion(const uint8_t *key, uint8_t *out) {
  uint32_t *w = (uint32_t *)out;
  // only for 128 bit
  size_t Nb = 4, Nr = 10, Nk = 4, idx;
  uint32_t temp,
      Rcon[] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
                0x6c000000, 0xd8000000, 0xab000000, 0x4d000000, 0x9a000000};

  for (idx = 0; idx < Nk; ++idx) {
    w[idx] = ((key[4 * idx]) << 24) | ((key[4 * idx + 1]) << 16) |
             ((key[4 * idx + 2]) << 8) | ((key[4 * idx + 3]));
  }

  for (idx = Nk; idx < Nb * (Nr + 1); ++idx) {
    temp = w[idx - 1];
    if ((idx % Nk) == 0)
      temp = SubWord(KE_ROTWORD(temp)) ^ Rcon[(idx - 1) / Nk];
    else if (Nk > 6 && (idx % Nk) == 4)
      temp = SubWord(temp);
    w[idx] = w[idx - Nk] ^ temp;
  }

  // for aes_neon compat
  for (idx = 0; idx < Nb * (Nr + 1); ++idx) {
    uint8_t tmp;
    tmp = out[0 + idx * 4];
    out[0 + idx * 4] = out[3 + idx * 4];
    out[3 + idx * 4] = tmp;
    tmp = out[1 + idx * 4];
    out[1 + idx * 4] = out[2 + idx * 4];
    out[2 + idx * 4] = tmp;
  }
}
#else
block keyGenHelper(block key, block keyRcon) {
  keyRcon = _mm_shuffle_epi32(keyRcon, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keyRcon);
}
#endif

AES::AES() {
  uint8_t zerokey[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
#if defined(HAVE_NEON)
  keyschedule(zerokey);
#else
  setKey(toBlock(zerokey));
#endif
}

AES::AES(const block &key) { setKey(key); }
AES::AES(const uint8_t *key) { setKey(key); }

void AES::setKey(const block &key) {
#if defined(HAVE_NEON)
  uint8_t tmp[16];
  vst1q_u8(tmp, key);
  keyschedule(tmp);
#else

  mRoundKeysEnc[0] = key;
  mRoundKeysEnc[1] = keyGenHelper(
      mRoundKeysEnc[0], _mm_aeskeygenassist_si128(mRoundKeysEnc[0], 0x01));
  mRoundKeysEnc[2] = keyGenHelper(
      mRoundKeysEnc[1], _mm_aeskeygenassist_si128(mRoundKeysEnc[1], 0x02));
  mRoundKeysEnc[3] = keyGenHelper(
      mRoundKeysEnc[2], _mm_aeskeygenassist_si128(mRoundKeysEnc[2], 0x04));
  mRoundKeysEnc[4] = keyGenHelper(
      mRoundKeysEnc[3], _mm_aeskeygenassist_si128(mRoundKeysEnc[3], 0x08));
  mRoundKeysEnc[5] = keyGenHelper(
      mRoundKeysEnc[4], _mm_aeskeygenassist_si128(mRoundKeysEnc[4], 0x10));
  mRoundKeysEnc[6] = keyGenHelper(
      mRoundKeysEnc[5], _mm_aeskeygenassist_si128(mRoundKeysEnc[5], 0x20));
  mRoundKeysEnc[7] = keyGenHelper(
      mRoundKeysEnc[6], _mm_aeskeygenassist_si128(mRoundKeysEnc[6], 0x40));
  mRoundKeysEnc[8] = keyGenHelper(
      mRoundKeysEnc[7], _mm_aeskeygenassist_si128(mRoundKeysEnc[7], 0x80));
  mRoundKeysEnc[9] = keyGenHelper(
      mRoundKeysEnc[8], _mm_aeskeygenassist_si128(mRoundKeysEnc[8], 0x1B));
  mRoundKeysEnc[10] = keyGenHelper(
      mRoundKeysEnc[9], _mm_aeskeygenassist_si128(mRoundKeysEnc[9], 0x36));
#endif
}

void AES::setKey(const uint8_t *key) {
#if defined(HAVE_NEON)
  keyschedule(key);
#else
  setKey(toBlock(key));
#endif
}

#if defined(HAVE_NEON)
void AES::keyschedule(const uint8_t *key) {
  uint8_t expandedKey[16 * 11];
  KeyExpansion(key, expandedKey);

  mRoundKeysEnc[0] = vld1q_u8(expandedKey);
  mRoundKeysEnc[1] = vld1q_u8(expandedKey + 16 * 1);
  mRoundKeysEnc[2] = vld1q_u8(expandedKey + 16 * 2);
  mRoundKeysEnc[3] = vld1q_u8(expandedKey + 16 * 3);
  mRoundKeysEnc[4] = vld1q_u8(expandedKey + 16 * 4);
  mRoundKeysEnc[5] = vld1q_u8(expandedKey + 16 * 5);
  mRoundKeysEnc[6] = vld1q_u8(expandedKey + 16 * 6);
  mRoundKeysEnc[7] = vld1q_u8(expandedKey + 16 * 7);
  mRoundKeysEnc[8] = vld1q_u8(expandedKey + 16 * 8);
  mRoundKeysEnc[9] = vld1q_u8(expandedKey + 16 * 9);
  mRoundKeysEnc[10] = vld1q_u8(expandedKey + 16 * 10);

  mRoundKeysDec[0] = mRoundKeysEnc[10];
  mRoundKeysDec[1] = vaesimcq_u8(mRoundKeysEnc[9]);
  mRoundKeysDec[2] = vaesimcq_u8(mRoundKeysEnc[8]);
  mRoundKeysDec[3] = vaesimcq_u8(mRoundKeysEnc[7]);
  mRoundKeysDec[4] = vaesimcq_u8(mRoundKeysEnc[6]);
  mRoundKeysDec[5] = vaesimcq_u8(mRoundKeysEnc[5]);
  mRoundKeysDec[6] = vaesimcq_u8(mRoundKeysEnc[4]);
  mRoundKeysDec[7] = vaesimcq_u8(mRoundKeysEnc[3]);
  mRoundKeysDec[8] = vaesimcq_u8(mRoundKeysEnc[2]);
  mRoundKeysDec[9] = vaesimcq_u8(mRoundKeysEnc[1]);
  mRoundKeysDec[10] = mRoundKeysEnc[0];

  this->key = mRoundKeysEnc[0];
}

void AES::encryptECB(const block &plaintext, block &ciphertext) const {
  ciphertext = vaeseq_u8(plaintext, mRoundKeysEnc[0]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[1]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[2]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[3]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[4]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[5]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[6]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[7]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[8]);
  ciphertext = vaesmcq_u8(ciphertext);
  ciphertext = vaeseq_u8(ciphertext, mRoundKeysEnc[9]);
  ciphertext = veorq_u8(ciphertext, mRoundKeysEnc[10]);
}

void AES::decryptECB(const block &ciphertext, block &plaintext) const {
  plaintext = vaesdq_u8(ciphertext, mRoundKeysDec[0]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[1]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[2]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[3]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[4]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[5]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[6]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[7]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[8]);
  plaintext = vaesimcq_u8(plaintext);
  plaintext = vaesdq_u8(plaintext, mRoundKeysDec[9]);
  plaintext = veorq_u8(plaintext, mRoundKeysDec[10]);
}

void AES::encryptECBBlocks(const block *plaintexts, uint64_t blockLength,
                           block *ciphertexts) const {
  const uint64_t step = 8;
  uint64_t idx = 0;
  uint64_t length = blockLength - blockLength % step;

  // std::array<block, step> temp;
  block temp[step];

  for (; idx < length; idx += step) {
    temp[0] = vaeseq_u8(plaintexts[idx + 0], mRoundKeysEnc[0]);
    temp[1] = vaeseq_u8(plaintexts[idx + 1], mRoundKeysEnc[0]);
    temp[2] = vaeseq_u8(plaintexts[idx + 2], mRoundKeysEnc[0]);
    temp[3] = vaeseq_u8(plaintexts[idx + 3], mRoundKeysEnc[0]);
    temp[4] = vaeseq_u8(plaintexts[idx + 4], mRoundKeysEnc[0]);
    temp[5] = vaeseq_u8(plaintexts[idx + 5], mRoundKeysEnc[0]);
    temp[6] = vaeseq_u8(plaintexts[idx + 6], mRoundKeysEnc[0]);
    temp[7] = vaeseq_u8(plaintexts[idx + 7], mRoundKeysEnc[0]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[1]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[1]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[1]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[1]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[1]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[1]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[1]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[1]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[2]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[2]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[2]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[2]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[2]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[2]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[2]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[2]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[3]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[3]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[3]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[3]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[3]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[3]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[3]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[3]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[4]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[4]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[4]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[4]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[4]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[4]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[4]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[4]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[5]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[5]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[5]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[5]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[5]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[5]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[5]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[5]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[6]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[6]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[6]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[6]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[6]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[6]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[6]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[6]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[7]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[7]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[7]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[7]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[7]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[7]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[7]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[7]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[8]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[8]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[8]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[8]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[8]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[8]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[8]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[8]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[9]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[9]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[9]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[9]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[9]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[9]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[9]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[9]);

    ciphertexts[idx + 0] = veorq_u8(temp[0], mRoundKeysEnc[10]);
    ciphertexts[idx + 1] = veorq_u8(temp[1], mRoundKeysEnc[10]);
    ciphertexts[idx + 2] = veorq_u8(temp[2], mRoundKeysEnc[10]);
    ciphertexts[idx + 3] = veorq_u8(temp[3], mRoundKeysEnc[10]);
    ciphertexts[idx + 4] = veorq_u8(temp[4], mRoundKeysEnc[10]);
    ciphertexts[idx + 5] = veorq_u8(temp[5], mRoundKeysEnc[10]);
    ciphertexts[idx + 6] = veorq_u8(temp[6], mRoundKeysEnc[10]);
    ciphertexts[idx + 7] = veorq_u8(temp[7], mRoundKeysEnc[10]);
  }

  for (; idx < blockLength; ++idx) {
    ciphertexts[idx] = vaeseq_u8(plaintexts[idx], mRoundKeysEnc[0]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[1]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[2]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[3]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[4]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[5]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[6]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[7]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[8]);
    ciphertexts[idx] = vaesmcq_u8(ciphertexts[idx]);
    ciphertexts[idx] = vaeseq_u8(ciphertexts[idx], mRoundKeysEnc[9]);
    ciphertexts[idx] = veorq_u8(ciphertexts[idx], mRoundKeysEnc[10]);
  }
}

void AES::encryptCTR(uint64_t baseIdx, uint64_t blockLength,
                     block *ciphertext) const {
  const uint64_t step = 8;
  uint64_t idx = 0;
  uint64_t length = blockLength - blockLength % step;

  // std::array<block, step> temp;
  block temp[step];

  for (; idx < length; idx += step, baseIdx += step) {
    temp[0] = vaeseq_u8(dupUint64(baseIdx + 0), mRoundKeysEnc[0]);
    temp[1] = vaeseq_u8(dupUint64(baseIdx + 1), mRoundKeysEnc[0]);
    temp[2] = vaeseq_u8(dupUint64(baseIdx + 2), mRoundKeysEnc[0]);
    temp[3] = vaeseq_u8(dupUint64(baseIdx + 3), mRoundKeysEnc[0]);
    temp[4] = vaeseq_u8(dupUint64(baseIdx + 4), mRoundKeysEnc[0]);
    temp[5] = vaeseq_u8(dupUint64(baseIdx + 5), mRoundKeysEnc[0]);
    temp[6] = vaeseq_u8(dupUint64(baseIdx + 6), mRoundKeysEnc[0]);
    temp[7] = vaeseq_u8(dupUint64(baseIdx + 7), mRoundKeysEnc[0]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[1]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[1]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[1]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[1]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[1]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[1]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[1]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[1]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[2]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[2]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[2]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[2]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[2]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[2]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[2]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[2]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[3]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[3]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[3]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[3]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[3]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[3]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[3]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[3]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[4]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[4]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[4]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[4]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[4]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[4]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[4]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[4]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[5]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[5]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[5]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[5]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[5]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[5]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[5]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[5]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[6]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[6]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[6]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[6]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[6]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[6]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[6]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[6]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[7]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[7]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[7]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[7]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[7]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[7]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[7]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[7]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[8]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[8]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[8]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[8]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[8]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[8]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[8]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[8]);
    temp[0] = vaesmcq_u8(temp[0]);
    temp[1] = vaesmcq_u8(temp[1]);
    temp[2] = vaesmcq_u8(temp[2]);
    temp[3] = vaesmcq_u8(temp[3]);
    temp[4] = vaesmcq_u8(temp[4]);
    temp[5] = vaesmcq_u8(temp[5]);
    temp[6] = vaesmcq_u8(temp[6]);
    temp[7] = vaesmcq_u8(temp[7]);

    temp[0] = vaeseq_u8(temp[0], mRoundKeysEnc[9]);
    temp[1] = vaeseq_u8(temp[1], mRoundKeysEnc[9]);
    temp[2] = vaeseq_u8(temp[2], mRoundKeysEnc[9]);
    temp[3] = vaeseq_u8(temp[3], mRoundKeysEnc[9]);
    temp[4] = vaeseq_u8(temp[4], mRoundKeysEnc[9]);
    temp[5] = vaeseq_u8(temp[5], mRoundKeysEnc[9]);
    temp[6] = vaeseq_u8(temp[6], mRoundKeysEnc[9]);
    temp[7] = vaeseq_u8(temp[7], mRoundKeysEnc[9]);

    ciphertext[idx + 0] = veorq_u8(temp[0], mRoundKeysEnc[10]);
    ciphertext[idx + 1] = veorq_u8(temp[1], mRoundKeysEnc[10]);
    ciphertext[idx + 2] = veorq_u8(temp[2], mRoundKeysEnc[10]);
    ciphertext[idx + 3] = veorq_u8(temp[3], mRoundKeysEnc[10]);
    ciphertext[idx + 4] = veorq_u8(temp[4], mRoundKeysEnc[10]);
    ciphertext[idx + 5] = veorq_u8(temp[5], mRoundKeysEnc[10]);
    ciphertext[idx + 6] = veorq_u8(temp[6], mRoundKeysEnc[10]);
    ciphertext[idx + 7] = veorq_u8(temp[7], mRoundKeysEnc[10]);
  }

  for (; idx < blockLength; ++idx, ++baseIdx) {
    ciphertext[idx] = vaeseq_u8(dupUint64(baseIdx), mRoundKeysEnc[0]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[1]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[2]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[3]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[4]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[5]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[6]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[7]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[8]);
    ciphertext[idx] = vaesmcq_u8(ciphertext[idx]);
    ciphertext[idx] = vaeseq_u8(ciphertext[idx], mRoundKeysEnc[9]);
    ciphertext[idx] = veorq_u8(ciphertext[idx], mRoundKeysEnc[10]);
  }
}
#else

void AES::encryptECB(const block &plaintext, block &ciphertext) const {
  ciphertext = _mm_xor_si128(plaintext, mRoundKeysEnc[0]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[1]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[2]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[3]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[4]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[5]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[6]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[7]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[8]);
  ciphertext = _mm_aesenc_si128(ciphertext, mRoundKeysEnc[9]);
  ciphertext = _mm_aesenclast_si128(ciphertext, mRoundKeysEnc[10]);
}
// TODO
// void decryptECB(const block& ciphertext, block& plaintext) const;
void AES::encryptECBBlocks(const block *plaintexts, uint64_t blockLength,
                           block *ciphertexts) const {
  const uint64_t step = 8;
  uint64_t idx = 0;
  uint64_t length = blockLength - blockLength % step;

  // std::array<block, step> temp;
  block temp[step];

  for (; idx < length; idx += step) {
    temp[0] = _mm_xor_si128(plaintexts[idx + 0], mRoundKeysEnc[0]);
    temp[1] = _mm_xor_si128(plaintexts[idx + 1], mRoundKeysEnc[0]);
    temp[2] = _mm_xor_si128(plaintexts[idx + 2], mRoundKeysEnc[0]);
    temp[3] = _mm_xor_si128(plaintexts[idx + 3], mRoundKeysEnc[0]);
    temp[4] = _mm_xor_si128(plaintexts[idx + 4], mRoundKeysEnc[0]);
    temp[5] = _mm_xor_si128(plaintexts[idx + 5], mRoundKeysEnc[0]);
    temp[6] = _mm_xor_si128(plaintexts[idx + 6], mRoundKeysEnc[0]);
    temp[7] = _mm_xor_si128(plaintexts[idx + 7], mRoundKeysEnc[0]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[1]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[1]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[1]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[1]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[1]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[1]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[1]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[1]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[2]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[2]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[2]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[2]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[2]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[2]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[2]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[2]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[3]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[3]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[3]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[3]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[3]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[3]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[3]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[3]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[4]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[4]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[4]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[4]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[4]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[4]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[4]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[4]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[5]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[5]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[5]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[5]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[5]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[5]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[5]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[5]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[6]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[6]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[6]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[6]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[6]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[6]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[6]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[6]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[7]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[7]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[7]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[7]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[7]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[7]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[7]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[7]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[8]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[8]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[8]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[8]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[8]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[8]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[8]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[8]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[9]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[9]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[9]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[9]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[9]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[9]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[9]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[9]);

    ciphertexts[idx + 0] = _mm_aesenclast_si128(temp[0], mRoundKeysEnc[10]);
    ciphertexts[idx + 1] = _mm_aesenclast_si128(temp[1], mRoundKeysEnc[10]);
    ciphertexts[idx + 2] = _mm_aesenclast_si128(temp[2], mRoundKeysEnc[10]);
    ciphertexts[idx + 3] = _mm_aesenclast_si128(temp[3], mRoundKeysEnc[10]);
    ciphertexts[idx + 4] = _mm_aesenclast_si128(temp[4], mRoundKeysEnc[10]);
    ciphertexts[idx + 5] = _mm_aesenclast_si128(temp[5], mRoundKeysEnc[10]);
    ciphertexts[idx + 6] = _mm_aesenclast_si128(temp[6], mRoundKeysEnc[10]);
    ciphertexts[idx + 7] = _mm_aesenclast_si128(temp[7], mRoundKeysEnc[10]);
  }

  for (; idx < blockLength; ++idx) {
    ciphertexts[idx] = _mm_xor_si128(plaintexts[idx], mRoundKeysEnc[0]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[1]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[2]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[3]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[4]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[5]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[6]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[7]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[8]);
    ciphertexts[idx] = _mm_aesenc_si128(ciphertexts[idx], mRoundKeysEnc[9]);
    ciphertexts[idx] =
        _mm_aesenclast_si128(ciphertexts[idx], mRoundKeysEnc[10]);
  }
}

void AES::encryptCTR(uint64_t baseIdx, uint64_t blockLength,
                     block *ciphertext) const {
  const uint64_t step = 8;
  uint64_t idx = 0;
  uint64_t length = blockLength - blockLength % step;

  // std::array<block, step> temp;
  block temp[step];

  for (; idx < length; idx += step, baseIdx += step) {
    temp[0] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 0), mRoundKeysEnc[0]);
    temp[1] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 1), mRoundKeysEnc[0]);
    temp[2] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 2), mRoundKeysEnc[0]);
    temp[3] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 3), mRoundKeysEnc[0]);
    temp[4] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 4), mRoundKeysEnc[0]);
    temp[5] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 5), mRoundKeysEnc[0]);
    temp[6] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 6), mRoundKeysEnc[0]);
    temp[7] = _mm_xor_si128(_mm_set1_epi64x(baseIdx + 7), mRoundKeysEnc[0]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[1]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[1]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[1]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[1]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[1]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[1]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[1]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[1]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[2]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[2]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[2]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[2]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[2]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[2]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[2]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[2]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[3]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[3]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[3]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[3]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[3]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[3]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[3]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[3]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[4]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[4]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[4]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[4]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[4]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[4]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[4]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[4]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[5]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[5]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[5]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[5]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[5]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[5]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[5]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[5]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[6]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[6]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[6]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[6]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[6]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[6]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[6]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[6]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[7]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[7]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[7]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[7]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[7]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[7]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[7]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[7]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[8]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[8]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[8]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[8]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[8]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[8]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[8]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[8]);

    temp[0] = _mm_aesenc_si128(temp[0], mRoundKeysEnc[9]);
    temp[1] = _mm_aesenc_si128(temp[1], mRoundKeysEnc[9]);
    temp[2] = _mm_aesenc_si128(temp[2], mRoundKeysEnc[9]);
    temp[3] = _mm_aesenc_si128(temp[3], mRoundKeysEnc[9]);
    temp[4] = _mm_aesenc_si128(temp[4], mRoundKeysEnc[9]);
    temp[5] = _mm_aesenc_si128(temp[5], mRoundKeysEnc[9]);
    temp[6] = _mm_aesenc_si128(temp[6], mRoundKeysEnc[9]);
    temp[7] = _mm_aesenc_si128(temp[7], mRoundKeysEnc[9]);

    ciphertext[idx + 0] = _mm_aesenclast_si128(temp[0], mRoundKeysEnc[10]);
    ciphertext[idx + 1] = _mm_aesenclast_si128(temp[1], mRoundKeysEnc[10]);
    ciphertext[idx + 2] = _mm_aesenclast_si128(temp[2], mRoundKeysEnc[10]);
    ciphertext[idx + 3] = _mm_aesenclast_si128(temp[3], mRoundKeysEnc[10]);
    ciphertext[idx + 4] = _mm_aesenclast_si128(temp[4], mRoundKeysEnc[10]);
    ciphertext[idx + 5] = _mm_aesenclast_si128(temp[5], mRoundKeysEnc[10]);
    ciphertext[idx + 6] = _mm_aesenclast_si128(temp[6], mRoundKeysEnc[10]);
    ciphertext[idx + 7] = _mm_aesenclast_si128(temp[7], mRoundKeysEnc[10]);
  }

  for (; idx < blockLength; ++idx, ++baseIdx) {
    ciphertext[idx] = _mm_xor_si128(_mm_set1_epi64x(baseIdx), mRoundKeysEnc[0]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[1]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[2]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[3]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[4]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[5]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[6]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[7]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[8]);
    ciphertext[idx] = _mm_aesenc_si128(ciphertext[idx], mRoundKeysEnc[9]);
    ciphertext[idx] = _mm_aesenclast_si128(ciphertext[idx], mRoundKeysEnc[10]);
  }
}
#endif

}  // namespace droidCrypto

JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_Crypto_AES_fixedKeyEnc(JNIEnv *env,
                                                           jclass /*this*/,
                                                           jobject pt,
                                                           jobject ct) {
  droidCrypto::block *plaintexts =
      (droidCrypto::block *)env->GetDirectBufferAddress(pt);
  jlong len = env->GetDirectBufferCapacity(pt);
  droidCrypto::block *ciphertexts =
      (droidCrypto::block *)env->GetDirectBufferAddress(ct);
  jlong len2 = env->GetDirectBufferCapacity(ct);
  assert(len == len2);
  droidCrypto::mAesFixedKey.encryptECBBlocks(plaintexts, len / 16, ciphertexts);
}