#include "ot_sender.h"

#include <stdlib.h>

#include "ge.h"
#include "crypto_hash.h"


void sender_genS(SENDER * s, unsigned char * S_pack, rand_source rand)
{
	int i;

	ge_p3 S, yS;

	//

	sc_random(s->y, 0, rand);

	ge_scalarmult_base(&S, s->y); // S

	ge_p3_tobytes(S_pack, &S); // E^0(S)

	for (i = 0; i < 3; i++) ge_p3_dbl_p3(&S, &S); // 8S

	ge_p3_tobytes(s->S_pack, &S); // E_1(S)

	ge_scalarmult_vartime(&yS, s->y, &S);
	for (i = 0; i < 3; i++) ge_p3_dbl_p3(&yS, &yS); // 64T
	s->yS = yS;
}

void sender_genSandProof(SENDER * s, unsigned char * S_pack, rand_source rand)
{
    unsigned char a [32];
    unsigned char c [32];
    unsigned char tmp [32];
    ge_p3 A;

    sender_genS(s, S_pack, rand);
    //

    sc_random(a, 1, rand);
    ge_scalarmult_base(&A, a); // A = g^a
    ge_p3_tobytes(s->A_pack, &A);

    ge_p3_tobytes(tmp, &A);
    crypto_hash(c, tmp, 32);
    c[0] &= 248;
    c[31] &= 127;

    sc_muladd(s->z, c, s->y, a);
}

void sender_keygen(SENDER * s, 
                   unsigned char * Rs_pack, 
                   unsigned char (*keys)[SIMPLEST_OT_HASHBYTES])
{
	int i;

	ge_p3 P0;
	ge_p3 P1;
	ge_p3 Rs;
	ge_cached tmp;
	ge_p1p1 tmp2;

	//

	if (ge_frombytes_vartime(&Rs, Rs_pack) != 0)
	{ 
		fprintf(stderr, "Error: point decompression failed\n"); exit(-1);
	}

	for (i = 0; i < 3; i++) ge_p3_dbl_p3(&Rs, &Rs); // 64R^i

	ge_p3_tobytes(Rs_pack, &Rs); // E_2(R^i)

	ge_scalarmult_vartime(&P0, s->y, &Rs); // 64yR^i
	ge_hash(keys[0], s->S_pack, Rs_pack, &P0); // E_2(yR^i)

	ge_p3_to_cached(&tmp, &P0);
	ge_sub(&tmp2, &s->yS, &tmp); // 64(T-yR^i)
	ge_p1p1_to_p3(&P1, &tmp2);
	ge_hash(keys[1], s->S_pack, Rs_pack, &P1); // E_2(T - yR^i)
}

