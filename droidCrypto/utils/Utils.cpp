#include <droidCrypto/BitVector.h>
#include <droidCrypto/Defines.h>
#include <droidCrypto/utils/Utils.h>

using std::array;

namespace droidCrypto {
namespace Utils {
//  load          column  w,w+1          (byte index)
//                   __________________
//                  |                  |
//                  |                  |
//                  |                  |
//                  |                  |
//  row  16*h,      |     #.#          |
//       ...,       |     ...          |
//  row  16*(h+1)   |     #.#          |     into  uint16_tOutView  column wise
//                  |                  |
//                  |                  |
//                   ------------------
//
// note: uint16_tOutView is a 16x16 bit matrix = 16 rows of 2 bytes each.
//       uint16_tOutView[0] stores the first column of 16 bytes,
//       uint16_tOutView[1] stores the second column of 16 bytes.
#if defined(HAVE_NEON)
inline void neon_loadSubSquare(array<block, 128> &in, array<block, 2> &out,
                               uint64_t x, uint64_t y) {
  static_assert(sizeof(array<array<uint8_t, 16>, 2>) == sizeof(array<block, 2>),
                "");
  static_assert(
      sizeof(array<array<uint8_t, 16>, 128>) == sizeof(array<block, 128>), "");

  array<array<uint8_t, 16>, 2> &outByteView =
      *(array<array<uint8_t, 16>, 2> *)&out;
  array<array<uint8_t, 16>, 128> &inByteView =
      *(array<array<uint8_t, 16>, 128> *)&in;

  for (int l = 0; l < 16; l++) {
    outByteView[0][l] = inByteView[16 * x + l][2 * y];
    outByteView[1][l] = inByteView[16 * x + l][2 * y + 1];
  }
}

inline uint16_t neon_mm_movemask_epi8_single(uint8x16_t input) {
  const int8_t __attribute__((aligned(16)))
  xr[8] = {-7, -6, -5, -4, -3, -2, -1, 0};
  uint8x8_t mask_and = vdup_n_u8(0x80);
  int8x8_t mask_shift = vld1_s8(xr);

  uint8x8_t lo = vget_low_u8(input);
  uint8x8_t hi = vget_high_u8(input);

  lo = vand_u8(lo, mask_and);
  lo = vshl_u8(lo, mask_shift);

  hi = vand_u8(hi, mask_and);
  hi = vshl_u8(hi, mask_shift);

  lo = vpadd_u8(lo, lo);
  lo = vpadd_u8(lo, lo);
  lo = vpadd_u8(lo, lo);

  hi = vpadd_u8(hi, hi);
  hi = vpadd_u8(hi, hi);
  hi = vpadd_u8(hi, hi);

  return ((hi[0] << 8) | (lo[0] & 0xFF));
}
// taken and modified from
// https://stackoverflow.com/questions/11870910/sse-mm-movemask-epi8-equivalent-method-for-arm-neon
inline uint16_t neon_mm_movemask_epi8(uint8x16_t input) {
  const int8_t __attribute__((aligned(16)))
  xr[16] = {-7, -6, -5, -4, -3, -2, -1, 0, -7, -6, -5, -4, -3, -2, -1, 0};

  int8x16_t mask_shift = vld1q_s8(xr);
  uint8x16_t mask_and = vdupq_n_u8(0x80);

  // Compute the mask from the input
  uint64x2_t mask = vpaddlq_u32(
      vpaddlq_u16(vpaddlq_u8(vshlq_u8(vandq_u8(input, mask_and), mask_shift))));

  // Get the resulting bytes
  return (mask[1] << 8) | mask[0];
}

// given a 16x16 sub square, place its transpose into uint16_tOutView at
// rows  16*h, ..., 16 *(h+1)  a byte  columns w, w+1.
inline void neon_transposeSubSquare(array<block, 128> &out, array<block, 2> &in,
                                    uint64_t x, uint64_t y) {
  static_assert(
      sizeof(array<array<uint16_t, 8>, 128>) == sizeof(array<block, 128>), "");

  array<array<uint16_t, 8>, 128> &outU16View =
      *(array<array<uint16_t, 8>, 128> *)&out;

  for (int j = 0; j < 8; j++) {
    outU16View[16 * x + 7 - j][y] = neon_mm_movemask_epi8(in[0]);
    outU16View[16 * x + 15 - j][y] = neon_mm_movemask_epi8(in[1]);

    in[0] = vshlq_n_u64(in[0], 1);
    in[1] = vshlq_n_u64(in[1], 1);
  }
}
void neon_transpose128(array<block, 128> &inOut) {
  array<block, 2> a, b;

  for (int j = 0; j < 8; j++) {
    neon_loadSubSquare(inOut, a, j, j);
    neon_transposeSubSquare(inOut, a, j, j);

    for (int k = 0; k < j; k++) {
      neon_loadSubSquare(inOut, a, k, j);
      neon_loadSubSquare(inOut, b, j, k);
      neon_transposeSubSquare(inOut, a, j, k);
      neon_transposeSubSquare(inOut, b, k, j);
    }
  }
}

inline void neon_loadSubSquarex(array<array<block, 8>, 128> &in,
                                array<block, 2> &out, uint64_t x, uint64_t y,
                                uint64_t i) {
  typedef array<array<uint8_t, 16>, 2> OUT_t;
  typedef array<array<uint8_t, 128>, 128> IN_t;

  static_assert(sizeof(OUT_t) == sizeof(array<block, 2>), "");
  static_assert(sizeof(IN_t) == sizeof(array<array<block, 8>, 128>), "");

  OUT_t &outByteView = *(OUT_t *)&out;
  IN_t &inByteView = *(IN_t *)&in;

  auto x16 = (x * 16);

  auto i16y2 = (i * 16) + 2 * y;
  auto i16y21 = (i * 16) + 2 * y + 1;

  outByteView[0][0] = inByteView[x16 + 0][i16y2];
  outByteView[1][0] = inByteView[x16 + 0][i16y21];
  outByteView[0][1] = inByteView[x16 + 1][i16y2];
  outByteView[1][1] = inByteView[x16 + 1][i16y21];
  outByteView[0][2] = inByteView[x16 + 2][i16y2];
  outByteView[1][2] = inByteView[x16 + 2][i16y21];
  outByteView[0][3] = inByteView[x16 + 3][i16y2];
  outByteView[1][3] = inByteView[x16 + 3][i16y21];
  outByteView[0][4] = inByteView[x16 + 4][i16y2];
  outByteView[1][4] = inByteView[x16 + 4][i16y21];
  outByteView[0][5] = inByteView[x16 + 5][i16y2];
  outByteView[1][5] = inByteView[x16 + 5][i16y21];
  outByteView[0][6] = inByteView[x16 + 6][i16y2];
  outByteView[1][6] = inByteView[x16 + 6][i16y21];
  outByteView[0][7] = inByteView[x16 + 7][i16y2];
  outByteView[1][7] = inByteView[x16 + 7][i16y21];
  outByteView[0][8] = inByteView[x16 + 8][i16y2];
  outByteView[1][8] = inByteView[x16 + 8][i16y21];
  outByteView[0][9] = inByteView[x16 + 9][i16y2];
  outByteView[1][9] = inByteView[x16 + 9][i16y21];
  outByteView[0][10] = inByteView[x16 + 10][i16y2];
  outByteView[1][10] = inByteView[x16 + 10][i16y21];
  outByteView[0][11] = inByteView[x16 + 11][i16y2];
  outByteView[1][11] = inByteView[x16 + 11][i16y21];
  outByteView[0][12] = inByteView[x16 + 12][i16y2];
  outByteView[1][12] = inByteView[x16 + 12][i16y21];
  outByteView[0][13] = inByteView[x16 + 13][i16y2];
  outByteView[1][13] = inByteView[x16 + 13][i16y21];
  outByteView[0][14] = inByteView[x16 + 14][i16y2];
  outByteView[1][14] = inByteView[x16 + 14][i16y21];
  outByteView[0][15] = inByteView[x16 + 15][i16y2];
  outByteView[1][15] = inByteView[x16 + 15][i16y21];
}

inline void neon_transposeSubSquarex(array<array<block, 8>, 128> &out,
                                     array<block, 2> &in, uint64_t x,
                                     uint64_t y, uint64_t i) {
  static_assert(sizeof(array<array<uint16_t, 64>, 128>) ==
                    sizeof(array<array<block, 8>, 128>),
                "");

  array<array<uint16_t, 64>, 128> &outU16View =
      *(array<array<uint16_t, 64>, 128> *)&out;

  auto i8y = i * 8 + y;
  auto x16_7 = x * 16 + 7;
  auto x16_15 = x * 16 + 15;

  block b0 = vshlq_n_u64(in[0], 0);
  block b1 = vshlq_n_u64(in[0], 1);
  block b2 = vshlq_n_u64(in[0], 2);
  block b3 = vshlq_n_u64(in[0], 3);
  block b4 = vshlq_n_u64(in[0], 4);
  block b5 = vshlq_n_u64(in[0], 5);
  block b6 = vshlq_n_u64(in[0], 6);
  block b7 = vshlq_n_u64(in[0], 7);

  outU16View[x16_7 - 0][i8y] = neon_mm_movemask_epi8(b0);
  outU16View[x16_7 - 1][i8y] = neon_mm_movemask_epi8(b1);
  outU16View[x16_7 - 2][i8y] = neon_mm_movemask_epi8(b2);
  outU16View[x16_7 - 3][i8y] = neon_mm_movemask_epi8(b3);
  outU16View[x16_7 - 4][i8y] = neon_mm_movemask_epi8(b4);
  outU16View[x16_7 - 5][i8y] = neon_mm_movemask_epi8(b5);
  outU16View[x16_7 - 6][i8y] = neon_mm_movemask_epi8(b6);
  outU16View[x16_7 - 7][i8y] = neon_mm_movemask_epi8(b7);

  b0 = vshlq_n_u64(in[1], 0);
  b1 = vshlq_n_u64(in[1], 1);
  b2 = vshlq_n_u64(in[1], 2);
  b3 = vshlq_n_u64(in[1], 3);
  b4 = vshlq_n_u64(in[1], 4);
  b5 = vshlq_n_u64(in[1], 5);
  b6 = vshlq_n_u64(in[1], 6);
  b7 = vshlq_n_u64(in[1], 7);

  outU16View[x16_15 - 0][i8y] = neon_mm_movemask_epi8(b0);
  outU16View[x16_15 - 1][i8y] = neon_mm_movemask_epi8(b1);
  outU16View[x16_15 - 2][i8y] = neon_mm_movemask_epi8(b2);
  outU16View[x16_15 - 3][i8y] = neon_mm_movemask_epi8(b3);
  outU16View[x16_15 - 4][i8y] = neon_mm_movemask_epi8(b4);
  outU16View[x16_15 - 5][i8y] = neon_mm_movemask_epi8(b5);
  outU16View[x16_15 - 6][i8y] = neon_mm_movemask_epi8(b6);
  outU16View[x16_15 - 7][i8y] = neon_mm_movemask_epi8(b7);
}

// we have long rows of contiguous data data, 128 columns
void neon_transpose128x1024(array<array<block, 8>, 128> &inOut) {
  array<block, 2> a, b;

  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 8; j++) {
      neon_loadSubSquarex(inOut, a, j, j, i);
      neon_transposeSubSquarex(inOut, a, j, j, i);

      for (int k = 0; k < j; k++) {
        neon_loadSubSquarex(inOut, a, k, j, i);
        neon_loadSubSquarex(inOut, b, j, k, i);
        neon_transposeSubSquarex(inOut, a, j, k, i);
        neon_transposeSubSquarex(inOut, b, k, j, i);
      }
    }
  }
}
#else

void sse_loadSubSquare(array<block, 128> &in, array<block, 2> &out, uint64_t x,
                       uint64_t y) {
  static_assert(sizeof(array<array<uint8_t, 16>, 2>) == sizeof(array<block, 2>),
                "");
  static_assert(
      sizeof(array<array<uint8_t, 16>, 128>) == sizeof(array<block, 128>), "");

  array<array<uint8_t, 16>, 2> &outByteView =
      *(array<array<uint8_t, 16>, 2> *)&out;
  array<array<uint8_t, 16>, 128> &inByteView =
      *(array<array<uint8_t, 16>, 128> *)&in;

  for (int l = 0; l < 16; l++) {
    outByteView[0][l] = inByteView[16 * x + l][2 * y];
    outByteView[1][l] = inByteView[16 * x + l][2 * y + 1];
  }
}

// given a 16x16 sub square, place its transpose into uint16_tOutView at
// rows  16*h, ..., 16 *(h+1)  a byte  columns w, w+1.
void sse_transposeSubSquare(array<block, 128> &out, array<block, 2> &in,
                            uint64_t x, uint64_t y) {
  static_assert(
      sizeof(array<array<uint16_t, 8>, 128>) == sizeof(array<block, 128>), "");

  array<array<uint16_t, 8>, 128> &outU16View =
      *(array<array<uint16_t, 8>, 128> *)&out;

  for (int j = 0; j < 8; j++) {
    outU16View[16 * x + 7 - j][y] = _mm_movemask_epi8(in[0]);
    outU16View[16 * x + 15 - j][y] = _mm_movemask_epi8(in[1]);

    in[0] = _mm_slli_epi64(in[0], 1);
    in[1] = _mm_slli_epi64(in[1], 1);
  }
}

void sse_transpose128(array<block, 128> &inOut) {
  array<block, 2> a, b;

  for (int j = 0; j < 8; j++) {
    sse_loadSubSquare(inOut, a, j, j);
    sse_transposeSubSquare(inOut, a, j, j);

    for (int k = 0; k < j; k++) {
      sse_loadSubSquare(inOut, a, k, j);
      sse_loadSubSquare(inOut, b, j, k);
      sse_transposeSubSquare(inOut, a, j, k);
      sse_transposeSubSquare(inOut, b, k, j);
    }
  }
}

inline void sse_loadSubSquarex(array<array<block, 8>, 128> &in,
                               array<block, 2> &out, uint64_t x, uint64_t y,
                               uint64_t i) {
  typedef array<array<uint8_t, 16>, 2> OUT_t;
  typedef array<array<uint8_t, 128>, 128> IN_t;

  static_assert(sizeof(OUT_t) == sizeof(array<block, 2>), "");
  static_assert(sizeof(IN_t) == sizeof(array<array<block, 8>, 128>), "");

  OUT_t &outByteView = *(OUT_t *)&out;
  IN_t &inByteView = *(IN_t *)&in;

  auto x16 = (x * 16);

  auto i16y2 = (i * 16) + 2 * y;
  auto i16y21 = (i * 16) + 2 * y + 1;

  outByteView[0][0] = inByteView[x16 + 0][i16y2];
  outByteView[1][0] = inByteView[x16 + 0][i16y21];
  outByteView[0][1] = inByteView[x16 + 1][i16y2];
  outByteView[1][1] = inByteView[x16 + 1][i16y21];
  outByteView[0][2] = inByteView[x16 + 2][i16y2];
  outByteView[1][2] = inByteView[x16 + 2][i16y21];
  outByteView[0][3] = inByteView[x16 + 3][i16y2];
  outByteView[1][3] = inByteView[x16 + 3][i16y21];
  outByteView[0][4] = inByteView[x16 + 4][i16y2];
  outByteView[1][4] = inByteView[x16 + 4][i16y21];
  outByteView[0][5] = inByteView[x16 + 5][i16y2];
  outByteView[1][5] = inByteView[x16 + 5][i16y21];
  outByteView[0][6] = inByteView[x16 + 6][i16y2];
  outByteView[1][6] = inByteView[x16 + 6][i16y21];
  outByteView[0][7] = inByteView[x16 + 7][i16y2];
  outByteView[1][7] = inByteView[x16 + 7][i16y21];
  outByteView[0][8] = inByteView[x16 + 8][i16y2];
  outByteView[1][8] = inByteView[x16 + 8][i16y21];
  outByteView[0][9] = inByteView[x16 + 9][i16y2];
  outByteView[1][9] = inByteView[x16 + 9][i16y21];
  outByteView[0][10] = inByteView[x16 + 10][i16y2];
  outByteView[1][10] = inByteView[x16 + 10][i16y21];
  outByteView[0][11] = inByteView[x16 + 11][i16y2];
  outByteView[1][11] = inByteView[x16 + 11][i16y21];
  outByteView[0][12] = inByteView[x16 + 12][i16y2];
  outByteView[1][12] = inByteView[x16 + 12][i16y21];
  outByteView[0][13] = inByteView[x16 + 13][i16y2];
  outByteView[1][13] = inByteView[x16 + 13][i16y21];
  outByteView[0][14] = inByteView[x16 + 14][i16y2];
  outByteView[1][14] = inByteView[x16 + 14][i16y21];
  outByteView[0][15] = inByteView[x16 + 15][i16y2];
  outByteView[1][15] = inByteView[x16 + 15][i16y21];
}

inline void sse_transposeSubSquarex(array<array<block, 8>, 128> &out,
                                    array<block, 2> &in, uint64_t x, uint64_t y,
                                    uint64_t i) {
  static_assert(sizeof(array<array<uint16_t, 64>, 128>) ==
                    sizeof(array<array<block, 8>, 128>),
                "");

  array<array<uint16_t, 64>, 128> &outU16View =
      *(array<array<uint16_t, 64>, 128> *)&out;

  auto i8y = i * 8 + y;
  auto x16_7 = x * 16 + 7;
  auto x16_15 = x * 16 + 15;

  block b0 = _mm_slli_epi64(in[0], 0);
  block b1 = _mm_slli_epi64(in[0], 1);
  block b2 = _mm_slli_epi64(in[0], 2);
  block b3 = _mm_slli_epi64(in[0], 3);
  block b4 = _mm_slli_epi64(in[0], 4);
  block b5 = _mm_slli_epi64(in[0], 5);
  block b6 = _mm_slli_epi64(in[0], 6);
  block b7 = _mm_slli_epi64(in[0], 7);

  outU16View[x16_7 - 0][i8y] = _mm_movemask_epi8(b0);
  outU16View[x16_7 - 1][i8y] = _mm_movemask_epi8(b1);
  outU16View[x16_7 - 2][i8y] = _mm_movemask_epi8(b2);
  outU16View[x16_7 - 3][i8y] = _mm_movemask_epi8(b3);
  outU16View[x16_7 - 4][i8y] = _mm_movemask_epi8(b4);
  outU16View[x16_7 - 5][i8y] = _mm_movemask_epi8(b5);
  outU16View[x16_7 - 6][i8y] = _mm_movemask_epi8(b6);
  outU16View[x16_7 - 7][i8y] = _mm_movemask_epi8(b7);

  b0 = _mm_slli_epi64(in[1], 0);
  b1 = _mm_slli_epi64(in[1], 1);
  b2 = _mm_slli_epi64(in[1], 2);
  b3 = _mm_slli_epi64(in[1], 3);
  b4 = _mm_slli_epi64(in[1], 4);
  b5 = _mm_slli_epi64(in[1], 5);
  b6 = _mm_slli_epi64(in[1], 6);
  b7 = _mm_slli_epi64(in[1], 7);

  outU16View[x16_15 - 0][i8y] = _mm_movemask_epi8(b0);
  outU16View[x16_15 - 1][i8y] = _mm_movemask_epi8(b1);
  outU16View[x16_15 - 2][i8y] = _mm_movemask_epi8(b2);
  outU16View[x16_15 - 3][i8y] = _mm_movemask_epi8(b3);
  outU16View[x16_15 - 4][i8y] = _mm_movemask_epi8(b4);
  outU16View[x16_15 - 5][i8y] = _mm_movemask_epi8(b5);
  outU16View[x16_15 - 6][i8y] = _mm_movemask_epi8(b6);
  outU16View[x16_15 - 7][i8y] = _mm_movemask_epi8(b7);
}

// we have long rows of contiguous data data, 128 columns
void sse_transpose128x1024(array<array<block, 8>, 128> &inOut) {
  array<block, 2> a, b;

  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 8; j++) {
      sse_loadSubSquarex(inOut, a, j, j, i);
      sse_transposeSubSquarex(inOut, a, j, j, i);

      for (int k = 0; k < j; k++) {
        sse_loadSubSquarex(inOut, a, k, j, i);
        sse_loadSubSquarex(inOut, b, j, k, i);
        sse_transposeSubSquarex(inOut, a, j, k, i);
        sse_transposeSubSquarex(inOut, b, k, j, i);
      }
    }
  }
}
#endif
void print(array<block, 128> &inOut) {
  BitVector temp(128);

  for (size_t i = 0; i < 128; ++i) {
    temp.assign(inOut[i]);
    //            std::cout << temp << std::endl;
  }
  //        std::cout << std::endl;
}

uint8_t getBit(array<block, 128> &inOut, uint64_t i, uint64_t j) {
  BitVector temp(128);
  temp.assign(inOut[i]);

  return temp[j];
}

void eklundh_transpose128(array<block, 128> &inOut) {
  const static uint64_t TRANSPOSE_MASKS128[7][2] = {
      {0x0000000000000000, 0xFFFFFFFFFFFFFFFF},
      {0x00000000FFFFFFFF, 0x00000000FFFFFFFF},
      {0x0000FFFF0000FFFF, 0x0000FFFF0000FFFF},
      {0x00FF00FF00FF00FF, 0x00FF00FF00FF00FF},
      {0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F},
      {0x3333333333333333, 0x3333333333333333},
      {0x5555555555555555, 0x5555555555555555}};

  uint32_t width = 64;
  uint32_t logn = 7, nswaps = 1;

#ifdef TRANSPOSE_DEBUG
  stringstream input_ss[128];
  stringstream output_ss[128];
#endif

  // now transpose output a-place
  for (uint32_t i = 0; i < logn; i++) {
    uint64_t mask1 = TRANSPOSE_MASKS128[i][1], mask2 = TRANSPOSE_MASKS128[i][0];
    uint64_t inv_mask1 = ~mask1, inv_mask2 = ~mask2;

    // for width >= 64, shift is undefined so treat as h special case
    // (and avoid branching a inner loop)
    if (width < 64) {
      for (uint32_t j = 0; j < nswaps; j++) {
        for (uint32_t k = 0; k < width; k++) {
          uint32_t i1 = k + 2 * width * j;
          uint32_t i2 = k + width + 2 * width * j;

          // t1 is lower 64 bits, t2 is upper 64 bits
          // (remember we're transposing a little-endian format)
          uint64_t &d1 = ((uint64_t *)&inOut[i1])[0];
          uint64_t &d2 = ((uint64_t *)&inOut[i1])[1];

          uint64_t &dd1 = ((uint64_t *)&inOut[i2])[0];
          uint64_t &dd2 = ((uint64_t *)&inOut[i2])[1];

          uint64_t t1 = d1;
          uint64_t t2 = d2;

          uint64_t tt1 = dd1;
          uint64_t tt2 = dd2;

          // swap operations due to little endian-ness
          d1 = (t1 & mask1) ^ ((tt1 & mask1) << width);

          d2 = (t2 & mask2) ^ ((tt2 & mask2) << width) ^
               ((tt1 & mask1) >> (64 - width));

          dd1 = (tt1 & inv_mask1) ^ ((t1 & inv_mask1) >> width) ^
                ((t2 & inv_mask2)) << (64 - width);

          dd2 = (tt2 & inv_mask2) ^ ((t2 & inv_mask2) >> width);
        }
      }
    } else {
      for (uint32_t j = 0; j < nswaps; j++) {
        for (uint32_t k = 0; k < width; k++) {
          uint32_t i1 = k + 2 * width * j;
          uint32_t i2 = k + width + 2 * width * j;

          // t1 is lower 64 bits, t2 is upper 64 bits
          // (remember we're transposing a little-endian format)
          uint64_t &d1 = ((uint64_t *)&inOut[i1])[0];
          uint64_t &d2 = ((uint64_t *)&inOut[i1])[1];

          uint64_t &dd1 = ((uint64_t *)&inOut[i2])[0];
          uint64_t &dd2 = ((uint64_t *)&inOut[i2])[1];

          // uint64_t t1 = d1;
          uint64_t t2 = d2;

          // uint64_t tt1 = dd1;
          // uint64_t tt2 = dd2;

          d1 &= mask1;
          d2 = (t2 & mask2) ^ ((dd1 & mask1) >> (64 - width));

          dd1 = (dd1 & inv_mask1) ^ ((t2 & inv_mask2)) << (64 - width);

          dd2 &= inv_mask2;
        }
      }
    }
    nswaps *= 2;
    width /= 2;
  }
#ifdef TRANSPOSE_DEBUG
  for (uint32_t k = 0; k < 128; k++) {
    for (uint32_t blkIdx = 0; blkIdx < 128; blkIdx++) {
      output_ss[blkIdx] << inOut[offset + blkIdx].get_bit(k);
    }
  }
  for (uint32_t k = 0; k < 128; k++) {
    if (output_ss[k].str().compare(input_ss[k].str()) != 0) {
      cerr << "String " << k << " failed. offset = " << offset << endl;
      exit(1);
    }
  }
  std::cout << "\ttranspose with offset " << offset << " ok\n";
#endif
}

void transpose128(std::array<block, 128> &inOut) {
#if defined(HAVE_NEON)
  neon_transpose128(inOut);
//        eklundh_transpose128(inOut);
#else

  eklundh_transpose128(inOut);
//        sse_transpose128(inOut);
#endif
}
void transpose128x1024(std::array<std::array<block, 8>, 128> &inOut) {
#if defined(HAVE_NEON)
  neon_transpose128x1024(inOut);
#else
  sse_transpose128x1024(inOut);
#endif
}

void transpose(const MatrixView<block> &in, const MatrixView<block> &out) {
  MatrixView<uint8_t> inn((uint8_t *)in.data(), in.bounds()[0],
                          in.stride() * sizeof(block));
  MatrixView<uint8_t> outt((uint8_t *)out.data(), out.bounds()[0],
                           out.stride() * sizeof(block));

  transpose(inn, outt);
}

#if defined(HAVE_NEON)
void neon_transpose(const MatrixView<uint8_t> &in,
                    const MatrixView<uint8_t> &out) {
  // the amount of work that we use to vectorize (hard code do not change)
  static const uint64_t chunkSize = 8;

  // the number of input columns
  uint64_t bitWidth = in.bounds()[0];

  // In the main loop, we tranpose things in subBlocks. This is how many we
  // have. a subblock is 16 (bits) columns wide and 64 bits tall
  uint64_t subBlockWidth = bitWidth / 16;
  uint64_t subBlockHight = out.bounds()[0] / (8 * chunkSize);

  // since we allows arbitrary sized inputs, we have to deal with the left overs
  uint64_t leftOverHeight = out.bounds()[0] % (chunkSize * 8);
  uint64_t leftOverWidth = in.bounds()[0] % 16;

  // make sure that the output can hold the input.
  if (out.stride() < (bitWidth + 7) / 8) throw std::runtime_error(LOCATION);

  // we can handle the case that the output should be truncated, but
  // not the case that the input is too small. (simple call this function
  // with a smaller out.bounds()[0], since thats "free" to do.)
  if (out.bounds()[0] > in.stride() * 8) throw std::runtime_error(LOCATION);

  union TempObj {
    // array<block, chunkSize> blks;
    block blks[chunkSize];
    // array < array<uint8_t, 16>, chunkSize> bytes;
    uint8_t bytes[chunkSize][16];
  };

  TempObj t;

  // some useful constants that we will use
  auto wStep = 16 * in.stride();
  auto eightOutSize1 = 8 * out.stride();
  auto outStart = out.data() + (7) * out.stride();
  auto step = in.stride();
  auto step01 = step * 1, step02 = step * 2, step03 = step * 3,
       step04 = step * 4, step05 = step * 5, step06 = step * 6,
       step07 = step * 7, step08 = step * 8, step09 = step * 9,
       step10 = step * 10, step11 = step * 11, step12 = step * 12,
       step13 = step * 13, step14 = step * 14, step15 = step * 15;

  // this is the main loop that gets the best performance (highly vectorized).
  for (uint64_t h = 0; h < subBlockHight; ++h) {
    // we are concerned with the output rows a range [16 * h, 16 * h + 15]

    for (uint64_t w = 0; w < subBlockWidth; ++w) {
      // we are concerned with the w'th section of 16 bits for the 16 output
      // rows above.

      auto start = in.data() + h * chunkSize + w * wStep;

      auto src00 = start;
      auto src01 = start + step01;
      auto src02 = start + step02;
      auto src03 = start + step03;
      auto src04 = start + step04;
      auto src05 = start + step05;
      auto src06 = start + step06;
      auto src07 = start + step07;
      auto src08 = start + step08;
      auto src09 = start + step09;
      auto src10 = start + step10;
      auto src11 = start + step11;
      auto src12 = start + step12;
      auto src13 = start + step13;
      auto src14 = start + step14;
      auto src15 = start + step15;

      // perform the transpose on the byte level. We will then use
      // sse instrucitions to get it on the bit level. t.bytes is the
      // same as a but in a 2D byte view.
      t.bytes[0][0] = src00[0];
      t.bytes[1][0] = src00[1];
      t.bytes[2][0] = src00[2];
      t.bytes[3][0] = src00[3];
      t.bytes[4][0] = src00[4];
      t.bytes[5][0] = src00[5];
      t.bytes[6][0] = src00[6];
      t.bytes[7][0] = src00[7];
      t.bytes[0][1] = src01[0];
      t.bytes[1][1] = src01[1];
      t.bytes[2][1] = src01[2];
      t.bytes[3][1] = src01[3];
      t.bytes[4][1] = src01[4];
      t.bytes[5][1] = src01[5];
      t.bytes[6][1] = src01[6];
      t.bytes[7][1] = src01[7];
      t.bytes[0][2] = src02[0];
      t.bytes[1][2] = src02[1];
      t.bytes[2][2] = src02[2];
      t.bytes[3][2] = src02[3];
      t.bytes[4][2] = src02[4];
      t.bytes[5][2] = src02[5];
      t.bytes[6][2] = src02[6];
      t.bytes[7][2] = src02[7];
      t.bytes[0][3] = src03[0];
      t.bytes[1][3] = src03[1];
      t.bytes[2][3] = src03[2];
      t.bytes[3][3] = src03[3];
      t.bytes[4][3] = src03[4];
      t.bytes[5][3] = src03[5];
      t.bytes[6][3] = src03[6];
      t.bytes[7][3] = src03[7];
      t.bytes[0][4] = src04[0];
      t.bytes[1][4] = src04[1];
      t.bytes[2][4] = src04[2];
      t.bytes[3][4] = src04[3];
      t.bytes[4][4] = src04[4];
      t.bytes[5][4] = src04[5];
      t.bytes[6][4] = src04[6];
      t.bytes[7][4] = src04[7];
      t.bytes[0][5] = src05[0];
      t.bytes[1][5] = src05[1];
      t.bytes[2][5] = src05[2];
      t.bytes[3][5] = src05[3];
      t.bytes[4][5] = src05[4];
      t.bytes[5][5] = src05[5];
      t.bytes[6][5] = src05[6];
      t.bytes[7][5] = src05[7];
      t.bytes[0][6] = src06[0];
      t.bytes[1][6] = src06[1];
      t.bytes[2][6] = src06[2];
      t.bytes[3][6] = src06[3];
      t.bytes[4][6] = src06[4];
      t.bytes[5][6] = src06[5];
      t.bytes[6][6] = src06[6];
      t.bytes[7][6] = src06[7];
      t.bytes[0][7] = src07[0];
      t.bytes[1][7] = src07[1];
      t.bytes[2][7] = src07[2];
      t.bytes[3][7] = src07[3];
      t.bytes[4][7] = src07[4];
      t.bytes[5][7] = src07[5];
      t.bytes[6][7] = src07[6];
      t.bytes[7][7] = src07[7];
      t.bytes[0][8] = src08[0];
      t.bytes[1][8] = src08[1];
      t.bytes[2][8] = src08[2];
      t.bytes[3][8] = src08[3];
      t.bytes[4][8] = src08[4];
      t.bytes[5][8] = src08[5];
      t.bytes[6][8] = src08[6];
      t.bytes[7][8] = src08[7];
      t.bytes[0][9] = src09[0];
      t.bytes[1][9] = src09[1];
      t.bytes[2][9] = src09[2];
      t.bytes[3][9] = src09[3];
      t.bytes[4][9] = src09[4];
      t.bytes[5][9] = src09[5];
      t.bytes[6][9] = src09[6];
      t.bytes[7][9] = src09[7];
      t.bytes[0][10] = src10[0];
      t.bytes[1][10] = src10[1];
      t.bytes[2][10] = src10[2];
      t.bytes[3][10] = src10[3];
      t.bytes[4][10] = src10[4];
      t.bytes[5][10] = src10[5];
      t.bytes[6][10] = src10[6];
      t.bytes[7][10] = src10[7];
      t.bytes[0][11] = src11[0];
      t.bytes[1][11] = src11[1];
      t.bytes[2][11] = src11[2];
      t.bytes[3][11] = src11[3];
      t.bytes[4][11] = src11[4];
      t.bytes[5][11] = src11[5];
      t.bytes[6][11] = src11[6];
      t.bytes[7][11] = src11[7];
      t.bytes[0][12] = src12[0];
      t.bytes[1][12] = src12[1];
      t.bytes[2][12] = src12[2];
      t.bytes[3][12] = src12[3];
      t.bytes[4][12] = src12[4];
      t.bytes[5][12] = src12[5];
      t.bytes[6][12] = src12[6];
      t.bytes[7][12] = src12[7];
      t.bytes[0][13] = src13[0];
      t.bytes[1][13] = src13[1];
      t.bytes[2][13] = src13[2];
      t.bytes[3][13] = src13[3];
      t.bytes[4][13] = src13[4];
      t.bytes[5][13] = src13[5];
      t.bytes[6][13] = src13[6];
      t.bytes[7][13] = src13[7];
      t.bytes[0][14] = src14[0];
      t.bytes[1][14] = src14[1];
      t.bytes[2][14] = src14[2];
      t.bytes[3][14] = src14[3];
      t.bytes[4][14] = src14[4];
      t.bytes[5][14] = src14[5];
      t.bytes[6][14] = src14[6];
      t.bytes[7][14] = src14[7];
      t.bytes[0][15] = src15[0];
      t.bytes[1][15] = src15[1];
      t.bytes[2][15] = src15[2];
      t.bytes[3][15] = src15[3];
      t.bytes[4][15] = src15[4];
      t.bytes[5][15] = src15[5];
      t.bytes[6][15] = src15[6];
      t.bytes[7][15] = src15[7];

      // get pointers to the output.
      auto out0 = outStart + (chunkSize * h + 0) * eightOutSize1 + w * 2;
      auto out1 = outStart + (chunkSize * h + 1) * eightOutSize1 + w * 2;
      auto out2 = outStart + (chunkSize * h + 2) * eightOutSize1 + w * 2;
      auto out3 = outStart + (chunkSize * h + 3) * eightOutSize1 + w * 2;
      auto out4 = outStart + (chunkSize * h + 4) * eightOutSize1 + w * 2;
      auto out5 = outStart + (chunkSize * h + 5) * eightOutSize1 + w * 2;
      auto out6 = outStart + (chunkSize * h + 6) * eightOutSize1 + w * 2;
      auto out7 = outStart + (chunkSize * h + 7) * eightOutSize1 + w * 2;

      for (uint64_t j = 0; j < 8; j++) {
        // use the special _mm_movemask_epi8 to perform the final step of that
        // bit-wise tranpose. this instruction takes ever 8'th bit (start at idx
        // 7) and moves them into a single 16 bit output. Its like shaving off
        // the top bit of each of the 16 bytes.
        *(uint16_t *)out0 = neon_mm_movemask_epi8(t.blks[0]);
        *(uint16_t *)out1 = neon_mm_movemask_epi8(t.blks[1]);
        *(uint16_t *)out2 = neon_mm_movemask_epi8(t.blks[2]);
        *(uint16_t *)out3 = neon_mm_movemask_epi8(t.blks[3]);
        *(uint16_t *)out4 = neon_mm_movemask_epi8(t.blks[4]);
        *(uint16_t *)out5 = neon_mm_movemask_epi8(t.blks[5]);
        *(uint16_t *)out6 = neon_mm_movemask_epi8(t.blks[6]);
        *(uint16_t *)out7 = neon_mm_movemask_epi8(t.blks[7]);

        // step each of out 8 pointer over to the next output row.
        out0 -= out.stride();
        out1 -= out.stride();
        out2 -= out.stride();
        out3 -= out.stride();
        out4 -= out.stride();
        out5 -= out.stride();
        out6 -= out.stride();
        out7 -= out.stride();

        // shift the 128 values so that the top bit is not the next one.
        t.blks[0] = vshlq_n_u64(t.blks[0], 1);
        t.blks[1] = vshlq_n_u64(t.blks[1], 1);
        t.blks[2] = vshlq_n_u64(t.blks[2], 1);
        t.blks[3] = vshlq_n_u64(t.blks[3], 1);
        t.blks[4] = vshlq_n_u64(t.blks[4], 1);
        t.blks[5] = vshlq_n_u64(t.blks[5], 1);
        t.blks[6] = vshlq_n_u64(t.blks[6], 1);
        t.blks[7] = vshlq_n_u64(t.blks[7], 1);
      }
    }
  }

  // this is a special case there we dont have chunkSize bytes of input column
  // left. because of this, the vectorized code above does not work and we
  // instead so thing one byte as a time.

  // hhEnd denotes how many bytes are left [0,8).
  auto hhEnd = (leftOverHeight + 7) / 8;

  // the last byte might be only part of a byte, so we also account for this
  auto lastSkip = (8 - leftOverHeight % 8) % 8;

  for (uint64_t hh = 0; hh < hhEnd; ++hh) {
    // compute those parameters that determine if this is the last byte
    // and that its a partial byte meaning that the last so mant output
    // rows  should not be written to.
    auto skip = hh == (hhEnd - 1) ? lastSkip : 0;
    auto rem = 8 - skip;

    for (uint64_t w = 0; w < subBlockWidth; ++w) {
      auto start = in.data() + subBlockHight * chunkSize + hh + w * wStep;

      t.bytes[0][0] = *(start);
      t.bytes[0][1] = *(start + step01);
      t.bytes[0][2] = *(start + step02);
      t.bytes[0][3] = *(start + step03);
      t.bytes[0][4] = *(start + step04);
      t.bytes[0][5] = *(start + step05);
      t.bytes[0][6] = *(start + step06);
      t.bytes[0][7] = *(start + step07);
      t.bytes[0][8] = *(start + step08);
      t.bytes[0][9] = *(start + step09);
      t.bytes[0][10] = *(start + step10);
      t.bytes[0][11] = *(start + step11);
      t.bytes[0][12] = *(start + step12);
      t.bytes[0][13] = *(start + step13);
      t.bytes[0][14] = *(start + step14);
      t.bytes[0][15] = *(start + step15);

      auto out0 = outStart +
                  (chunkSize * subBlockHight + hh) * 8 * out.stride() + w * 2;

      out0 -= out.stride() * skip;
#ifdef HAVE_NEON
      int64x2_t b = vmovq_n_s64(skip);
      t.blks[0] = vreinterpretq_u8_u64(vshlq_u64(t.blks[0], b));
#else
      t.blks[0] = _mm_slli_epi64(t.blks[0], int(skip));
#endif

      for (uint64_t j = 0; j < rem; j++) {
        *(uint16_t *)out0 = neon_mm_movemask_epi8(t.blks[0]);

        out0 -= out.stride();

        t.blks[0] = vshlq_n_u64(t.blks[0], 1);
      }
    }
  }

  // this is a special case where the input column count was not a multiple
  // of 16. For this case, we use
  if (leftOverWidth) {
    for (uint64_t h = 0; h < subBlockHight; ++h) {
      // we are concerned with the output rows a range [16 * h, 16 * h + 15]

      auto start = in.data() + h * chunkSize + subBlockWidth * wStep;

      std::array<uint8_t *, 16> src{
          start,          start + step01, start + step02, start + step03,
          start + step04, start + step05, start + step06, start + step07,
          start + step08, start + step09, start + step10, start + step11,
          start + step12, start + step13, start + step14, start + step15};

      memset(t.blks, 0, sizeof(t));
      for (uint64_t i = 0; i < leftOverWidth; ++i) {
        t.bytes[0][i] = src[i][0];
        t.bytes[1][i] = src[i][1];
        t.bytes[2][i] = src[i][2];
        t.bytes[3][i] = src[i][3];
        t.bytes[4][i] = src[i][4];
        t.bytes[5][i] = src[i][5];
        t.bytes[6][i] = src[i][6];
        t.bytes[7][i] = src[i][7];
      }

      auto out0 =
          outStart + (chunkSize * h + 0) * eightOutSize1 + subBlockWidth * 2;
      auto out1 =
          outStart + (chunkSize * h + 1) * eightOutSize1 + subBlockWidth * 2;
      auto out2 =
          outStart + (chunkSize * h + 2) * eightOutSize1 + subBlockWidth * 2;
      auto out3 =
          outStart + (chunkSize * h + 3) * eightOutSize1 + subBlockWidth * 2;
      auto out4 =
          outStart + (chunkSize * h + 4) * eightOutSize1 + subBlockWidth * 2;
      auto out5 =
          outStart + (chunkSize * h + 5) * eightOutSize1 + subBlockWidth * 2;
      auto out6 =
          outStart + (chunkSize * h + 6) * eightOutSize1 + subBlockWidth * 2;
      auto out7 =
          outStart + (chunkSize * h + 7) * eightOutSize1 + subBlockWidth * 2;

      if (leftOverWidth <= 8) {
        for (uint64_t j = 0; j < 8; j++) {
          *out0 = neon_mm_movemask_epi8(t.blks[0]);
          *out1 = neon_mm_movemask_epi8(t.blks[1]);
          *out2 = neon_mm_movemask_epi8(t.blks[2]);
          *out3 = neon_mm_movemask_epi8(t.blks[3]);
          *out4 = neon_mm_movemask_epi8(t.blks[4]);
          *out5 = neon_mm_movemask_epi8(t.blks[5]);
          *out6 = neon_mm_movemask_epi8(t.blks[6]);
          *out7 = neon_mm_movemask_epi8(t.blks[7]);

          out0 -= out.stride();
          out1 -= out.stride();
          out2 -= out.stride();
          out3 -= out.stride();
          out4 -= out.stride();
          out5 -= out.stride();
          out6 -= out.stride();
          out7 -= out.stride();

          t.blks[0] = vshlq_n_u64(t.blks[0], 1);
          t.blks[1] = vshlq_n_u64(t.blks[1], 1);
          t.blks[2] = vshlq_n_u64(t.blks[2], 1);
          t.blks[3] = vshlq_n_u64(t.blks[3], 1);
          t.blks[4] = vshlq_n_u64(t.blks[4], 1);
          t.blks[5] = vshlq_n_u64(t.blks[5], 1);
          t.blks[6] = vshlq_n_u64(t.blks[6], 1);
          t.blks[7] = vshlq_n_u64(t.blks[7], 1);
        }
      } else {
        for (uint64_t j = 0; j < 8; j++) {
          *(uint16_t *)out0 = neon_mm_movemask_epi8(t.blks[0]);
          *(uint16_t *)out1 = neon_mm_movemask_epi8(t.blks[1]);
          *(uint16_t *)out2 = neon_mm_movemask_epi8(t.blks[2]);
          *(uint16_t *)out3 = neon_mm_movemask_epi8(t.blks[3]);
          *(uint16_t *)out4 = neon_mm_movemask_epi8(t.blks[4]);
          *(uint16_t *)out5 = neon_mm_movemask_epi8(t.blks[5]);
          *(uint16_t *)out6 = neon_mm_movemask_epi8(t.blks[6]);
          *(uint16_t *)out7 = neon_mm_movemask_epi8(t.blks[7]);

          out0 -= out.stride();
          out1 -= out.stride();
          out2 -= out.stride();
          out3 -= out.stride();
          out4 -= out.stride();
          out5 -= out.stride();
          out6 -= out.stride();
          out7 -= out.stride();

          t.blks[0] = vshlq_n_u64(t.blks[0], 1);
          t.blks[1] = vshlq_n_u64(t.blks[1], 1);
          t.blks[2] = vshlq_n_u64(t.blks[2], 1);
          t.blks[3] = vshlq_n_u64(t.blks[3], 1);
          t.blks[4] = vshlq_n_u64(t.blks[4], 1);
          t.blks[5] = vshlq_n_u64(t.blks[5], 1);
          t.blks[6] = vshlq_n_u64(t.blks[6], 1);
          t.blks[7] = vshlq_n_u64(t.blks[7], 1);
        }
      }
    }

    // auto hhEnd = (leftOverHeight + 7) / 8;
    // auto lastSkip = (8 - leftOverHeight % 8) % 8;
    for (uint64_t hh = 0; hh < hhEnd; ++hh) {
      auto skip = hh == (hhEnd - 1) ? lastSkip : 0;
      auto rem = 8 - skip;

      // we are concerned with the output rows a range [16 * h, 16 * h + 15]
      auto w = subBlockWidth;

      auto start = in.data() + subBlockHight * chunkSize + hh + w * wStep;

      std::array<uint8_t *, 16> src{
          start,          start + step01, start + step02, start + step03,
          start + step04, start + step05, start + step06, start + step07,
          start + step08, start + step09, start + step10, start + step11,
          start + step12, start + step13, start + step14, start + step15};

      t.blks[0] = ZeroBlock;
      for (uint64_t i = 0; i < leftOverWidth; ++i) {
        t.bytes[0][i] = src[i][0];
      }

      auto out0 = outStart +
                  (chunkSize * subBlockHight + hh) * 8 * out.stride() + w * 2;

      out0 -= out.stride() * skip;
#ifdef HAVE_NEON
      int64x2_t b = vmovq_n_s64(skip);
      t.blks[0] = vreinterpretq_u8_u64(vshlq_u64(t.blks[0], b));
#else
      t.blks[0] = _mm_slli_epi64(t.blks[0], int(skip));
#endif

      for (uint64_t j = 0; j < rem; j++) {
        if (leftOverWidth > 8) {
          *(uint16_t *)out0 = neon_mm_movemask_epi8(t.blks[0]);
        } else {
          *out0 = neon_mm_movemask_epi8(t.blks[0]);
        }

        out0 -= out.stride();

        t.blks[0] = vshlq_n_u64(t.blks[0], 1);
      }
    }
  }
}
#else
void sse_transpose(const MatrixView<uint8_t> &in,
                   const MatrixView<uint8_t> &out) {
  // the amount of work that we use to vectorize (hard code do not change)
  static const uint64_t chunkSize = 8;

  // the number of input columns
  uint64_t bitWidth = in.bounds()[0];

  // In the main loop, we tranpose things in subBlocks. This is how many we
  // have. a subblock is 16 (bits) columns wide and 64 bits tall
  uint64_t subBlockWidth = bitWidth / 16;
  uint64_t subBlockHight = out.bounds()[0] / (8 * chunkSize);

  // since we allows arbitrary sized inputs, we have to deal with the left overs
  uint64_t leftOverHeight = out.bounds()[0] % (chunkSize * 8);
  uint64_t leftOverWidth = in.bounds()[0] % 16;

  // make sure that the output can hold the input.
  if (out.stride() < (bitWidth + 7) / 8) throw std::runtime_error(LOCATION);

  // we can handle the case that the output should be truncated, but
  // not the case that the input is too small. (simple call this function
  // with a smaller out.bounds()[0], since thats "free" to do.)
  if (out.bounds()[0] > in.stride() * 8) throw std::runtime_error(LOCATION);

  union TempObj {
    // array<block, chunkSize> blks;
    block blks[chunkSize];
    // array < array<uint8_t, 16>, chunkSize> bytes;
    uint8_t bytes[chunkSize][16];
  };

  TempObj t;

  // some useful constants that we will use
  auto wStep = 16 * in.stride();
  auto eightOutSize1 = 8 * out.stride();
  auto outStart = out.data() + (7) * out.stride();
  auto step = in.stride();
  auto step01 = step * 1, step02 = step * 2, step03 = step * 3,
       step04 = step * 4, step05 = step * 5, step06 = step * 6,
       step07 = step * 7, step08 = step * 8, step09 = step * 9,
       step10 = step * 10, step11 = step * 11, step12 = step * 12,
       step13 = step * 13, step14 = step * 14, step15 = step * 15;

  // this is the main loop that gets the best performance (highly vectorized).
  for (uint64_t h = 0; h < subBlockHight; ++h) {
    // we are concerned with the output rows a range [16 * h, 16 * h + 15]

    for (uint64_t w = 0; w < subBlockWidth; ++w) {
      // we are concerned with the w'th section of 16 bits for the 16 output
      // rows above.

      auto start = in.data() + h * chunkSize + w * wStep;

      auto src00 = start;
      auto src01 = start + step01;
      auto src02 = start + step02;
      auto src03 = start + step03;
      auto src04 = start + step04;
      auto src05 = start + step05;
      auto src06 = start + step06;
      auto src07 = start + step07;
      auto src08 = start + step08;
      auto src09 = start + step09;
      auto src10 = start + step10;
      auto src11 = start + step11;
      auto src12 = start + step12;
      auto src13 = start + step13;
      auto src14 = start + step14;
      auto src15 = start + step15;

      // perform the transpose on the byte level. We will then use
      // sse instrucitions to get it on the bit level. t.bytes is the
      // same as a but in a 2D byte view.
      t.bytes[0][0] = src00[0];
      t.bytes[1][0] = src00[1];
      t.bytes[2][0] = src00[2];
      t.bytes[3][0] = src00[3];
      t.bytes[4][0] = src00[4];
      t.bytes[5][0] = src00[5];
      t.bytes[6][0] = src00[6];
      t.bytes[7][0] = src00[7];
      t.bytes[0][1] = src01[0];
      t.bytes[1][1] = src01[1];
      t.bytes[2][1] = src01[2];
      t.bytes[3][1] = src01[3];
      t.bytes[4][1] = src01[4];
      t.bytes[5][1] = src01[5];
      t.bytes[6][1] = src01[6];
      t.bytes[7][1] = src01[7];
      t.bytes[0][2] = src02[0];
      t.bytes[1][2] = src02[1];
      t.bytes[2][2] = src02[2];
      t.bytes[3][2] = src02[3];
      t.bytes[4][2] = src02[4];
      t.bytes[5][2] = src02[5];
      t.bytes[6][2] = src02[6];
      t.bytes[7][2] = src02[7];
      t.bytes[0][3] = src03[0];
      t.bytes[1][3] = src03[1];
      t.bytes[2][3] = src03[2];
      t.bytes[3][3] = src03[3];
      t.bytes[4][3] = src03[4];
      t.bytes[5][3] = src03[5];
      t.bytes[6][3] = src03[6];
      t.bytes[7][3] = src03[7];
      t.bytes[0][4] = src04[0];
      t.bytes[1][4] = src04[1];
      t.bytes[2][4] = src04[2];
      t.bytes[3][4] = src04[3];
      t.bytes[4][4] = src04[4];
      t.bytes[5][4] = src04[5];
      t.bytes[6][4] = src04[6];
      t.bytes[7][4] = src04[7];
      t.bytes[0][5] = src05[0];
      t.bytes[1][5] = src05[1];
      t.bytes[2][5] = src05[2];
      t.bytes[3][5] = src05[3];
      t.bytes[4][5] = src05[4];
      t.bytes[5][5] = src05[5];
      t.bytes[6][5] = src05[6];
      t.bytes[7][5] = src05[7];
      t.bytes[0][6] = src06[0];
      t.bytes[1][6] = src06[1];
      t.bytes[2][6] = src06[2];
      t.bytes[3][6] = src06[3];
      t.bytes[4][6] = src06[4];
      t.bytes[5][6] = src06[5];
      t.bytes[6][6] = src06[6];
      t.bytes[7][6] = src06[7];
      t.bytes[0][7] = src07[0];
      t.bytes[1][7] = src07[1];
      t.bytes[2][7] = src07[2];
      t.bytes[3][7] = src07[3];
      t.bytes[4][7] = src07[4];
      t.bytes[5][7] = src07[5];
      t.bytes[6][7] = src07[6];
      t.bytes[7][7] = src07[7];
      t.bytes[0][8] = src08[0];
      t.bytes[1][8] = src08[1];
      t.bytes[2][8] = src08[2];
      t.bytes[3][8] = src08[3];
      t.bytes[4][8] = src08[4];
      t.bytes[5][8] = src08[5];
      t.bytes[6][8] = src08[6];
      t.bytes[7][8] = src08[7];
      t.bytes[0][9] = src09[0];
      t.bytes[1][9] = src09[1];
      t.bytes[2][9] = src09[2];
      t.bytes[3][9] = src09[3];
      t.bytes[4][9] = src09[4];
      t.bytes[5][9] = src09[5];
      t.bytes[6][9] = src09[6];
      t.bytes[7][9] = src09[7];
      t.bytes[0][10] = src10[0];
      t.bytes[1][10] = src10[1];
      t.bytes[2][10] = src10[2];
      t.bytes[3][10] = src10[3];
      t.bytes[4][10] = src10[4];
      t.bytes[5][10] = src10[5];
      t.bytes[6][10] = src10[6];
      t.bytes[7][10] = src10[7];
      t.bytes[0][11] = src11[0];
      t.bytes[1][11] = src11[1];
      t.bytes[2][11] = src11[2];
      t.bytes[3][11] = src11[3];
      t.bytes[4][11] = src11[4];
      t.bytes[5][11] = src11[5];
      t.bytes[6][11] = src11[6];
      t.bytes[7][11] = src11[7];
      t.bytes[0][12] = src12[0];
      t.bytes[1][12] = src12[1];
      t.bytes[2][12] = src12[2];
      t.bytes[3][12] = src12[3];
      t.bytes[4][12] = src12[4];
      t.bytes[5][12] = src12[5];
      t.bytes[6][12] = src12[6];
      t.bytes[7][12] = src12[7];
      t.bytes[0][13] = src13[0];
      t.bytes[1][13] = src13[1];
      t.bytes[2][13] = src13[2];
      t.bytes[3][13] = src13[3];
      t.bytes[4][13] = src13[4];
      t.bytes[5][13] = src13[5];
      t.bytes[6][13] = src13[6];
      t.bytes[7][13] = src13[7];
      t.bytes[0][14] = src14[0];
      t.bytes[1][14] = src14[1];
      t.bytes[2][14] = src14[2];
      t.bytes[3][14] = src14[3];
      t.bytes[4][14] = src14[4];
      t.bytes[5][14] = src14[5];
      t.bytes[6][14] = src14[6];
      t.bytes[7][14] = src14[7];
      t.bytes[0][15] = src15[0];
      t.bytes[1][15] = src15[1];
      t.bytes[2][15] = src15[2];
      t.bytes[3][15] = src15[3];
      t.bytes[4][15] = src15[4];
      t.bytes[5][15] = src15[5];
      t.bytes[6][15] = src15[6];
      t.bytes[7][15] = src15[7];

      // get pointers to the output.
      auto out0 = outStart + (chunkSize * h + 0) * eightOutSize1 + w * 2;
      auto out1 = outStart + (chunkSize * h + 1) * eightOutSize1 + w * 2;
      auto out2 = outStart + (chunkSize * h + 2) * eightOutSize1 + w * 2;
      auto out3 = outStart + (chunkSize * h + 3) * eightOutSize1 + w * 2;
      auto out4 = outStart + (chunkSize * h + 4) * eightOutSize1 + w * 2;
      auto out5 = outStart + (chunkSize * h + 5) * eightOutSize1 + w * 2;
      auto out6 = outStart + (chunkSize * h + 6) * eightOutSize1 + w * 2;
      auto out7 = outStart + (chunkSize * h + 7) * eightOutSize1 + w * 2;

      for (uint64_t j = 0; j < 8; j++) {
        // use the special _mm_movemask_epi8 to perform the final step of that
        // bit-wise tranpose. this instruction takes ever 8'th bit (start at idx
        // 7) and moves them into a single 16 bit output. Its like shaving off
        // the top bit of each of the 16 bytes.
        *(uint16_t *)out0 = _mm_movemask_epi8(t.blks[0]);
        *(uint16_t *)out1 = _mm_movemask_epi8(t.blks[1]);
        *(uint16_t *)out2 = _mm_movemask_epi8(t.blks[2]);
        *(uint16_t *)out3 = _mm_movemask_epi8(t.blks[3]);
        *(uint16_t *)out4 = _mm_movemask_epi8(t.blks[4]);
        *(uint16_t *)out5 = _mm_movemask_epi8(t.blks[5]);
        *(uint16_t *)out6 = _mm_movemask_epi8(t.blks[6]);
        *(uint16_t *)out7 = _mm_movemask_epi8(t.blks[7]);

        // step each of out 8 pointer over to the next output row.
        out0 -= out.stride();
        out1 -= out.stride();
        out2 -= out.stride();
        out3 -= out.stride();
        out4 -= out.stride();
        out5 -= out.stride();
        out6 -= out.stride();
        out7 -= out.stride();

        // shift the 128 values so that the top bit is not the next one.
        t.blks[0] = _mm_slli_epi64(t.blks[0], 1);
        t.blks[1] = _mm_slli_epi64(t.blks[1], 1);
        t.blks[2] = _mm_slli_epi64(t.blks[2], 1);
        t.blks[3] = _mm_slli_epi64(t.blks[3], 1);
        t.blks[4] = _mm_slli_epi64(t.blks[4], 1);
        t.blks[5] = _mm_slli_epi64(t.blks[5], 1);
        t.blks[6] = _mm_slli_epi64(t.blks[6], 1);
        t.blks[7] = _mm_slli_epi64(t.blks[7], 1);
      }
    }
  }

  // this is a special case there we dont have chunkSize bytes of input column
  // left. because of this, the vectorized code above does not work and we
  // instead so thing one byte as a time.

  // hhEnd denotes how many bytes are left [0,8).
  auto hhEnd = (leftOverHeight + 7) / 8;

  // the last byte might be only part of a byte, so we also account for this
  auto lastSkip = (8 - leftOverHeight % 8) % 8;

  for (uint64_t hh = 0; hh < hhEnd; ++hh) {
    // compute those parameters that determine if this is the last byte
    // and that its a partial byte meaning that the last so mant output
    // rows  should not be written to.
    auto skip = hh == (hhEnd - 1) ? lastSkip : 0;
    auto rem = 8 - skip;

    for (uint64_t w = 0; w < subBlockWidth; ++w) {
      auto start = in.data() + subBlockHight * chunkSize + hh + w * wStep;

      t.bytes[0][0] = *(start);
      t.bytes[0][1] = *(start + step01);
      t.bytes[0][2] = *(start + step02);
      t.bytes[0][3] = *(start + step03);
      t.bytes[0][4] = *(start + step04);
      t.bytes[0][5] = *(start + step05);
      t.bytes[0][6] = *(start + step06);
      t.bytes[0][7] = *(start + step07);
      t.bytes[0][8] = *(start + step08);
      t.bytes[0][9] = *(start + step09);
      t.bytes[0][10] = *(start + step10);
      t.bytes[0][11] = *(start + step11);
      t.bytes[0][12] = *(start + step12);
      t.bytes[0][13] = *(start + step13);
      t.bytes[0][14] = *(start + step14);
      t.bytes[0][15] = *(start + step15);

      auto out0 = outStart +
                  (chunkSize * subBlockHight + hh) * 8 * out.stride() + w * 2;

      out0 -= out.stride() * skip;
      t.blks[0] = _mm_slli_epi64(t.blks[0], int(skip));

      for (uint64_t j = 0; j < rem; j++) {
        *(uint16_t *)out0 = _mm_movemask_epi8(t.blks[0]);

        out0 -= out.stride();

        t.blks[0] = _mm_slli_epi64(t.blks[0], 1);
      }
    }
  }

  // this is a special case where the input column count was not a multiple
  // of 16. For this case, we use
  if (leftOverWidth) {
    for (uint64_t h = 0; h < subBlockHight; ++h) {
      // we are concerned with the output rows a range [16 * h, 16 * h + 15]

      auto start = in.data() + h * chunkSize + subBlockWidth * wStep;

      std::array<uint8_t *, 16> src{
          start,          start + step01, start + step02, start + step03,
          start + step04, start + step05, start + step06, start + step07,
          start + step08, start + step09, start + step10, start + step11,
          start + step12, start + step13, start + step14, start + step15};

      memset(t.blks, 0, sizeof(t));
      for (uint64_t i = 0; i < leftOverWidth; ++i) {
        t.bytes[0][i] = src[i][0];
        t.bytes[1][i] = src[i][1];
        t.bytes[2][i] = src[i][2];
        t.bytes[3][i] = src[i][3];
        t.bytes[4][i] = src[i][4];
        t.bytes[5][i] = src[i][5];
        t.bytes[6][i] = src[i][6];
        t.bytes[7][i] = src[i][7];
      }

      auto out0 =
          outStart + (chunkSize * h + 0) * eightOutSize1 + subBlockWidth * 2;
      auto out1 =
          outStart + (chunkSize * h + 1) * eightOutSize1 + subBlockWidth * 2;
      auto out2 =
          outStart + (chunkSize * h + 2) * eightOutSize1 + subBlockWidth * 2;
      auto out3 =
          outStart + (chunkSize * h + 3) * eightOutSize1 + subBlockWidth * 2;
      auto out4 =
          outStart + (chunkSize * h + 4) * eightOutSize1 + subBlockWidth * 2;
      auto out5 =
          outStart + (chunkSize * h + 5) * eightOutSize1 + subBlockWidth * 2;
      auto out6 =
          outStart + (chunkSize * h + 6) * eightOutSize1 + subBlockWidth * 2;
      auto out7 =
          outStart + (chunkSize * h + 7) * eightOutSize1 + subBlockWidth * 2;

      if (leftOverWidth <= 8) {
        for (uint64_t j = 0; j < 8; j++) {
          *out0 = _mm_movemask_epi8(t.blks[0]);
          *out1 = _mm_movemask_epi8(t.blks[1]);
          *out2 = _mm_movemask_epi8(t.blks[2]);
          *out3 = _mm_movemask_epi8(t.blks[3]);
          *out4 = _mm_movemask_epi8(t.blks[4]);
          *out5 = _mm_movemask_epi8(t.blks[5]);
          *out6 = _mm_movemask_epi8(t.blks[6]);
          *out7 = _mm_movemask_epi8(t.blks[7]);

          out0 -= out.stride();
          out1 -= out.stride();
          out2 -= out.stride();
          out3 -= out.stride();
          out4 -= out.stride();
          out5 -= out.stride();
          out6 -= out.stride();
          out7 -= out.stride();

          t.blks[0] = _mm_slli_epi64(t.blks[0], 1);
          t.blks[1] = _mm_slli_epi64(t.blks[1], 1);
          t.blks[2] = _mm_slli_epi64(t.blks[2], 1);
          t.blks[3] = _mm_slli_epi64(t.blks[3], 1);
          t.blks[4] = _mm_slli_epi64(t.blks[4], 1);
          t.blks[5] = _mm_slli_epi64(t.blks[5], 1);
          t.blks[6] = _mm_slli_epi64(t.blks[6], 1);
          t.blks[7] = _mm_slli_epi64(t.blks[7], 1);
        }
      } else {
        for (uint64_t j = 0; j < 8; j++) {
          *(uint16_t *)out0 = _mm_movemask_epi8(t.blks[0]);
          *(uint16_t *)out1 = _mm_movemask_epi8(t.blks[1]);
          *(uint16_t *)out2 = _mm_movemask_epi8(t.blks[2]);
          *(uint16_t *)out3 = _mm_movemask_epi8(t.blks[3]);
          *(uint16_t *)out4 = _mm_movemask_epi8(t.blks[4]);
          *(uint16_t *)out5 = _mm_movemask_epi8(t.blks[5]);
          *(uint16_t *)out6 = _mm_movemask_epi8(t.blks[6]);
          *(uint16_t *)out7 = _mm_movemask_epi8(t.blks[7]);

          out0 -= out.stride();
          out1 -= out.stride();
          out2 -= out.stride();
          out3 -= out.stride();
          out4 -= out.stride();
          out5 -= out.stride();
          out6 -= out.stride();
          out7 -= out.stride();

          t.blks[0] = _mm_slli_epi64(t.blks[0], 1);
          t.blks[1] = _mm_slli_epi64(t.blks[1], 1);
          t.blks[2] = _mm_slli_epi64(t.blks[2], 1);
          t.blks[3] = _mm_slli_epi64(t.blks[3], 1);
          t.blks[4] = _mm_slli_epi64(t.blks[4], 1);
          t.blks[5] = _mm_slli_epi64(t.blks[5], 1);
          t.blks[6] = _mm_slli_epi64(t.blks[6], 1);
          t.blks[7] = _mm_slli_epi64(t.blks[7], 1);
        }
      }
    }

    // auto hhEnd = (leftOverHeight + 7) / 8;
    // auto lastSkip = (8 - leftOverHeight % 8) % 8;
    for (uint64_t hh = 0; hh < hhEnd; ++hh) {
      auto skip = hh == (hhEnd - 1) ? lastSkip : 0;
      auto rem = 8 - skip;

      // we are concerned with the output rows a range [16 * h, 16 * h + 15]
      auto w = subBlockWidth;

      auto start = in.data() + subBlockHight * chunkSize + hh + w * wStep;

      std::array<uint8_t *, 16> src{
          start,          start + step01, start + step02, start + step03,
          start + step04, start + step05, start + step06, start + step07,
          start + step08, start + step09, start + step10, start + step11,
          start + step12, start + step13, start + step14, start + step15};

      t.blks[0] = ZeroBlock;
      for (uint64_t i = 0; i < leftOverWidth; ++i) {
        t.bytes[0][i] = src[i][0];
      }

      auto out0 = outStart +
                  (chunkSize * subBlockHight + hh) * 8 * out.stride() + w * 2;

      out0 -= out.stride() * skip;
      t.blks[0] = _mm_slli_epi64(t.blks[0], int(skip));

      for (uint64_t j = 0; j < rem; j++) {
        if (leftOverWidth > 8) {
          *(uint16_t *)out0 = _mm_movemask_epi8(t.blks[0]);
        } else {
          *out0 = _mm_movemask_epi8(t.blks[0]);
        }

        out0 -= out.stride();

        t.blks[0] = _mm_slli_epi64(t.blks[0], 1);
      }
    }
  }
}
#endif

void transpose(const MatrixView<uint8_t> &in, const MatrixView<uint8_t> &out) {
#if defined(HAVE_NEON)
  neon_transpose(in, out);
#else
  sse_transpose(in, out);
#endif
}
}  // namespace Utils
}  // namespace droidCrypto
