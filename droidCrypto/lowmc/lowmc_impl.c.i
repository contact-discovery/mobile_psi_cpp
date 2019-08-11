/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#if defined(LOWMC_INSTANCE)
#define lowmc LOWMC_INSTANCE
#else
#define lowmc lowmc_instance
#endif

static mzd_local_t* N_LOWMC(lowmc_t const* lowmc_instance, const expanded_key exp_key,
                            mzd_local_t const* p) {
#if defined(LOWMC_INSTANCE)
  (void)lowmc_instance;
#endif
#if defined(REDUCED_LINEAR_LAYER)
  mzd_local_t* x       = mzd_local_init_ex(1, LOWMC_N, false);
  mzd_local_t* y       = mzd_local_init_ex(1, LOWMC_N, false);
  mzd_local_t* tmp     = mzd_local_init_ex(1, LOWMC_N, false);

  XOR(x, p, exp_key.key_0);
#if defined(REDUCED_LINEAR_LAYER_NEXT)

  lowmc_round_t const* round = lowmc->rounds;
  for (unsigned i = 0; i < LOWMC_R-1; ++i, ++round) {
    SBOX(x, &lowmc->mask);

#if defined(M_FIXED_10)
    const word nl = CONST_FIRST_ROW(exp_key.nl_part)[i >> 1];
    FIRST_ROW(x)
    [(LOWMC_N) / (sizeof(word) * 8) - 1] ^= (nl << (1-(i&1))*32) & WORD_C(0xFFFFFFFF00000000);
#elif defined(M_FIXED_1)
    const word nl = CONST_FIRST_ROW(exp_key.nl_part)[i / 21];
    FIRST_ROW(x)[(LOWMC_N) / (sizeof(word) * 8) - 1] ^= (nl << ((20-(i%21))*3)) & WORD_C(0xE000000000000000);
#else
#error "RLL only works with 1 or 10 Sboxes atm"
#endif

    MUL_Z(y, x, CONCAT(round->z, matrix_postfix));
    //shuffle x correctly (in-place), slow and probably stupid version
    for(unsigned j = round->num_fixes; j; j--) {
        for(unsigned k = round->r_cols[j-1]; k < LOWMC_N - 1 - (3*LOWMC_M-j); k++) {
            //swap bits
            word a = (FIRST_ROW(x)[k / (sizeof(word) * 8)] >> (k % (sizeof(word) * 8))) & WORD_C(0x1);
            word b = (FIRST_ROW(x)[(k+1) / (sizeof(word) * 8)] >> ((k+1) % (sizeof(word) * 8))) & WORD_C(0x1);
            word xx = a ^ b;
            FIRST_ROW(x)[k / (sizeof(word) * 8)] ^=  xx << (k % (sizeof(word) * 8));
            FIRST_ROW(x)[(k+1) / (sizeof(word) * 8)] ^=  xx << ((k+1) % (sizeof(word) * 8));
        }
    }
    MUL_R(y, x, CONCAT(round->r, matrix_postfix));

#if defined(M_FIXED_10)
    FIRST_ROW(x)[(LOWMC_N) / (sizeof(word) * 8) - 1] &= WORD_C(0x00000003FFFFFFFF); //clear nl part
#elif defined(M_FIXED_1)
    FIRST_ROW(x)[(LOWMC_N) / (sizeof(word) * 8) - 1] &= WORD_C(0x1FFFFFFFFFFFFFFF); //clear nl part
#else
#error "RLL only works with 1 or 10 Sboxes atm"
#endif
    XOR(x, y, x);
//    mzd_local_t* t = x;
//    x              = y;
//    y              = t;

  }
  SBOX(x, &lowmc->mask);

  unsigned i = (LOWMC_R-1);
#if defined(M_FIXED_10)
  const word nl = CONST_FIRST_ROW(exp_key.nl_part)[i >> 1];
  FIRST_ROW(x)
  [(LOWMC_N) / (sizeof(word) * 8) - 1] ^= (nl << (1-(i&1))*32) & WORD_C(0xFFFFFFFF00000000);
#elif defined(M_FIXED_1)
  const word nl = CONST_FIRST_ROW(exp_key.nl_part)[i / 21];
  FIRST_ROW(x)[(LOWMC_N) / (sizeof(word) * 8) - 1] ^= (nl << ((20-(i%21))*3)) & WORD_C(0xE000000000000000);
#else
#error "RLL only works with 1 or 10 Sboxes atm"
#endif
  MUL(y,x,CONCAT(lowmc->zr, matrix_postfix));
  mzd_local_t* t = x;
  x              = y;
  y              = t;
#else

  lowmc_round_t const* round = lowmc->rounds;
  for (unsigned i = 0; i < LOWMC_R; ++i, ++round) {
    SBOX(x, &lowmc->mask);

#if defined(M_FIXED_10)
    const word nl = CONST_FIRST_ROW(exp_key.nl_part)[i >> 1];
    FIRST_ROW(x)
    [(LOWMC_N) / (sizeof(word) * 8) - 1] ^=
        (i & 1) ? (nl & WORD_C(0xFFFFFFFF00000000)) : (nl << 32);
#elif defined(M_FIXED_1)
    const word nl = CONST_FIRST_ROW(exp_key.nl_part)[i / 21];
    FIRST_ROW(x)[(LOWMC_N) / (sizeof(word) * 8) - 1] ^= (nl << ((20-(i%21))*3)) & WORD_C(0xE000000000000000);
#else
#error "RLL only works with 1 or 10 Sboxes atm"
#endif
    MUL(y, x, CONCAT(round->l, matrix_postfix));
    // swap x and y
    mzd_local_t* t = x;
    x              = y;
    y              = t;
  }
#endif
  mzd_local_free(y);
  mzd_local_free(tmp);
  return x;
#else
  mzd_local_t* x = mzd_local_init_ex(1, LOWMC_N, false);
  mzd_local_t* y = mzd_local_init_ex(1, LOWMC_N, false);

  mzd_local_copy(x, p);
  ADDMUL(x, exp_key.lowmc_key, CONCAT(lowmc->k0, matrix_postfix));

  lowmc_round_t const* round = lowmc->rounds;
  for (unsigned int i = LOWMC_R; i; --i, ++round) {
    SBOX(x, &lowmc->mask);

    MUL(y, x, CONCAT(round->l, matrix_postfix));
    XOR(x, y, round->constant);
    ADDMUL(x, exp_key.lowmc_key, CONCAT(round->k, matrix_postfix));
  }

  mzd_local_free(y);
  return x;
#endif
}

#undef lowmc

// vim: ft=c
