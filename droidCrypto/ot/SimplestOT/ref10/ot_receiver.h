#ifndef SIMPLEST_OT_RECEIVER_H
#define SIMPLEST_OT_RECEIVER_H

#include <stdio.h>

#include "sc.h"
#include "ge.h"
#include "ot_config.h"

struct ot_receiver
{
	unsigned char S_pack[ SIMPLEST_OT_PACKBYTES ];
	ge_p3 S;

	// temporary

	ge_p3 xB;
	unsigned char x[32];

    // dlog proof elements
    unsigned char A_pack[ SIMPLEST_OT_PACKBYTES ];
    unsigned char z [32];
};

typedef struct ot_receiver RECEIVER;

void receiver_procS(RECEIVER *);
void receiver_procSandVerify(RECEIVER *);
void receiver_rsgen(RECEIVER *, unsigned char *, unsigned char, rand_source);
void receiver_keygen(RECEIVER *, unsigned char [SIMPLEST_OT_HASHBYTES]);

#endif //ifndef SIMPLEST_OT_RECEIVER_H

