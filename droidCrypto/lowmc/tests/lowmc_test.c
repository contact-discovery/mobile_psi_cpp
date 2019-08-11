#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../io.h"
#include "../lowmc.h"
#include "../lowmc_128_128_192.h"

#include <stdint.h>

static int lowmc_enc(const lowmc_t* lowmc, const uint8_t* key, const uint8_t* plaintext,
                     const uint8_t* expected) {
  uint8_t a[lowmc->n / 8];

  mzd_local_t* sk = mzd_local_init(1, lowmc->k);
  mzd_local_t* pt = mzd_local_init(1, lowmc->n);
  mzd_local_t* ct = mzd_local_init(1, lowmc->n);

  mzd_from_char_array(sk, key, lowmc->n / 8);
  mzd_from_char_array(pt, plaintext, lowmc->n / 8);
  mzd_from_char_array(ct, expected, lowmc->n / 8);

  int ret              = 0;
  expanded_key exp_key = lowmc_expand_key(lowmc, sk);
  mzd_local_t* ctr     = lowmc_call(lowmc, exp_key, pt);
  if (!ctr) {
    ret = 1;
    goto end;
  }
  mzd_to_char_array(a, ctr, lowmc->n / 8);
  for (unsigned int i = 0; i < lowmc->n / 8; i++) {
    printf("0x%02X, ", a[i]);
  }
  printf("\n");

  if (!mzd_local_equal(ctr, ct)) {
    ret = 2;
  }

end:
  mzd_local_free(ctr);
  mzd_local_free(ct);
  mzd_local_free(pt);
  mzd_local_free(sk);

  return ret;
}

static int LowMC_test_vector_128_128_192(void) {
  const uint8_t key[16]                 = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const uint8_t plaintext[16]           = {0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const uint8_t ciphertext_expected[16] = {
      0x00, 0x4D, 0x0A, 0xE0, 0xEC, 0x4A, 0xE0, 0xB6,
      0xEC, 0x17, 0xC8, 0xA4, 0xBE, 0x18, 0x3C, 0xA2,
  };

  return lowmc_enc(&lowmc_128_128_192, key, plaintext, ciphertext_expected);
}

typedef int (*test_fn_t)(void);

static const test_fn_t tests[] = {
    LowMC_test_vector_128_128_192,
};
//    LowMC_test_vectorL1_1_new, LowMC_test_vectorL3_1_new, LowMC_test_vectorL5_1_new,
//    LowMC_test_vectorL1_1_1_new, LowMC_test_vectorL3_1_1_new, LowMC_test_vectorL5_1_1_new};

static const size_t num_tests = sizeof(tests) / sizeof(tests[0]);

int main() {
  int ret = 0;
  for (size_t s = 0; s < num_tests; ++s) {
    const int t = tests[s]();
    if (t) {
      printf("ERR: lowmc_enc %zu FAILED (%d)\n", s, t);
      ret = -1;
    }
  }

  return ret;
}
