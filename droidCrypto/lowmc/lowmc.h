/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef LOWMC_H
#define LOWMC_H

#include "lowmc_pars.h"

typedef struct {
    mzd_local_t* lowmc_key;
    mzd_local_t* key_0;
    mzd_local_t* nl_part;
} expanded_key;

typedef mzd_local_t* (*lowmc_implementation_f)(lowmc_t const*, const expanded_key, mzd_local_t const*);

lowmc_implementation_f lowmc_get_implementation(const lowmc_t* lowmc);


expanded_key lowmc_expand_key(lowmc_t const* lowmc, lowmc_key_t const* key);
/**
 * Implements LowMC encryption
 *
 * \param  lowmc                the lowmc parameters
 * \param  lowmc_expanded_key   the already expanded key
 * \param  p                    the plaintext
 * \return                      the ciphertext
 */
mzd_local_t* lowmc_call(lowmc_t const* lowmc, const expanded_key lowmc_expanded_key, mzd_local_t const* p);

#endif
