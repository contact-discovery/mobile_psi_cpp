#ifndef SIMPLEST_OT_SENDER_H
#define SIMPLEST_OT_SENDER_H

#include <stdio.h>

#include "ge.h"
#include "sc.h"
#include "ot_config.h"
#include "randombytes.h"

struct ot_sender
{
	unsigned char S_pack[ SIMPLEST_OT_PACKBYTES ];
	unsigned char y [32];
	ge_p3 yS;
	// dlog proof elements
    unsigned char A_pack[ SIMPLEST_OT_PACKBYTES ];
    unsigned char z [32];
};

typedef struct ot_sender SENDER;

void sender_genS(SENDER *, unsigned char *, rand_source);
void sender_genSandProof(SENDER *, unsigned char *, rand_source);
void sender_keygen(SENDER *, unsigned char *, unsigned char (*)[SIMPLEST_OT_HASHBYTES]);

#endif //ifndef OT_SENDER_H

