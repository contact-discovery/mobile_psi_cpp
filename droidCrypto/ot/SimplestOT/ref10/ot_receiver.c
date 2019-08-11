#include "ot_receiver.h"

#include <stdlib.h>
#include <string.h>

#include "crypto_hash.h"
#include "ge.h"

void receiver_procS(RECEIVER *r) {
  int i;

  ge_p3 S;

  if (ge_frombytes_vartime(&S, r->S_pack) != 0) {
    fprintf(stderr, "Error: point decompression failed\n");
    exit(-1);
  }

  for (i = 0; i < 3; i++) ge_p3_dbl_p3(&S, &S);  // 8S

  ge_p3_tobytes(r->S_pack, &S);  // E_1(S)
  r->S = S;
}

void receiver_procSandVerify(RECEIVER *r) {
  int i;
  unsigned char c[32];
  unsigned char tmp[32];

  ge_p3 S, A, Z1, Z2;
  ge_cached A_cached;
  ge_p1p1 Z2_p1p1;

  if (ge_frombytes_vartime(&S, r->S_pack) != 0) {
    fprintf(stderr, "Error: point decompression failed\n");
    exit(-1);
  }

  if (ge_frombytes_vartime(&A, r->A_pack) != 0) {
    fprintf(stderr, "Error: point decompression failed\n");
    exit(-1);
  }

  crypto_hash(c, r->A_pack, 32);
  c[0] &= 248;
  c[31] &= 127;

  ge_scalarmult_base(&Z1, r->z);
  ge_scalarmult_vartime(&Z2, c, &S);
  ge_p3_to_cached(&A_cached, &A);
  ge_add(&Z2_p1p1, &Z2, &A_cached);
  ge_p1p1_to_p3(&Z2, &Z2_p1p1);
  ge_p3_tobytes(c, &Z1);
  ge_p3_tobytes(tmp, &Z2);
  if (memcmp(c, tmp, 32) != 0) {
    fprintf(stderr, "Error: dlog proof failed\n");
    exit(-1);
  }

  for (i = 0; i < 3; i++) ge_p3_dbl_p3(&S, &S);  // 8S

  ge_p3_tobytes(r->S_pack, &S);  // E_1(S)
  r->S = S;
}

void receiver_rsgen(RECEIVER *r, unsigned char *Rs_pack, unsigned char c,
                    rand_source rand) {
  ge_p1p1 P;
  ge_p3 P_tmp;
  ge_cached xB;

  sc_random(r->x, 1, rand);
  ge_scalarmult_base(&r->xB, r->x);  // 8x^iB

  ge_p3_to_cached(&xB, &r->xB);

  ge_sub(&P, &r->S, &xB);  // 8S - 8x^iB
  ge_p1p1_to_p3(&P_tmp, &P);
  ge_p3_cmov(&r->xB, &P_tmp, c);

  ge_p3_tobytes(Rs_pack, &r->xB);  // E^1(R^i)
}

void receiver_keygen(RECEIVER *r, unsigned char keys[SIMPLEST_OT_HASHBYTES]) {
  int i;

  unsigned char Rs_pack[SIMPLEST_OT_PACKBYTES];
  ge_p3 P;

  //

  for (i = 0; i < 3; i++) ge_p3_dbl_p3(&r->xB, &r->xB);
  ge_p3_tobytes(Rs_pack, &r->xB);  // E_2(R^i)

  ge_scalarmult_vartime(&P, r->x, &r->S);  // 64x^iS

  ge_hash(keys, r->S_pack, Rs_pack, &P);  // E_2(x^iS)
}
