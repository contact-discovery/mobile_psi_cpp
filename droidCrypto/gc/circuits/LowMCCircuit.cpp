/**
 \file 		Some parts of this file are taken from
 ABY/src/examples/lowmc/common/lowmccircuit.cpp \author
 michael.zohner@ec-spride.de \copyright	ABY - A Framework for Efficient
 Mixed-protocol Secure Two-party Computation Copyright (C) 2019 Engineering
 Cryptographic Protocols Group, TU Darmstadt This program is free software: you
 can redistribute it and/or modify it under the terms of the GNU Lesser General
 Public License as published by the Free Software Foundation, either version 3
 of the License, or (at your option) any later version. ABY is distributed in
 the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
 implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
 the GNU Lesser General Public License for more details. You should have
 received a copy of the GNU Lesser General Public License along with this
 program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of AESCiruit

 *  Modified by Daniel Kales, 2019
 *  * used LowMC circuit from ABY as a starting point for circuit implementation
 *  * added correct LowMC constants, is compatible with reference lowmc
 implementation
 *  * implemented optimizations from the paper
 *    "Linear Equivalence of Block Ciphers with Partial Non-Linear Layers:
 Application to LowMC",
 *    Itai Dinur, Daniel Kales, Angela Promitzer, Sebastian Ramacher, Christian
 Rechberger, Eurocrypt 2019
 */
#include <assert.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/HalfGate.h>
#include <droidCrypto/gc/WireLabel.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include <droidCrypto/utils/Log.h>
#include <iostream>

#define ceil_divide(x, y) ((((x) + (y)-1) / (y)))

namespace droidCrypto {

//    LowMCCircuit::LowMCCircuit(ChannelWrapper& chan) : Circuit(chan,
//    params.blocksize/*(params.nrounds+1)*/, params.blocksize,
//    params.blocksize), mGrayCode(FOUR_RUSSIAN_WINDOW_SIZE){
//
//        m_linlayer.appendREV(lowmc_linlayer, sizeof(lowmc_linlayer)*8);
//        m_roundconst.appendREV(lowmc_consts, sizeof(lowmc_consts)*8);
//
//    }
//
//    std::vector<WireLabel> LowMCCircuit::computeFunction(const
//    std::vector<WireLabel>& key, const std::vector<WireLabel>& pt, GCEnv& env)
//    {
//
//        uint32_t round, i;
//        uint32_t nsboxes = params.nsboxes;
//        uint32_t statesize = params.blocksize;
//        uint32_t nrounds = params.nrounds;
//
//        std::vector<WireLabel> state(statesize);
//        m_linCtr = 0;
//        m_constCtr = 0;
//
//        //Build the GrayCode for the optimal window-size
//
//        //copy the input to the current state
//        for (i = 0; i < statesize; i++)
//            state[i] = pt[i];
//
//        LowMCAddRoundKey(state, key, statesize, 0, env); //ARK
//        for (round = 1; round <= nrounds; round++) {
//
//            //substitution via 3-bit SBoxes
//            LowMCPutSBoxLayer(state, nsboxes, statesize, env);
//
//            //multiply state with GF2Matrix
//            FourRussiansMatrixMult(state, statesize, env);//4 Russians version
//            of the state multiplication
//
//            //XOR constants
//            LowMCXORConstants(state, statesize, env);
//
//            //XOR with multiplied key
//            LowMCAddRoundKey(state, key, statesize, round, env);
//        }
//
//        return state;
//    }
//
//    void LowMCCircuit::LowMCAddRoundKey(std::vector<WireLabel>& val, const
//    std::vector<WireLabel>& key, uint32_t lowmcstatesize, uint32_t round,
//    GCEnv& env) {
//        for (uint32_t i = 0; i < lowmcstatesize; i++) {
//            val[i] = env.XOR(val[i], key[i+(round) * lowmcstatesize]);
//        }
//    }
//
//    void LowMCCircuit::LowMCXORConstants(std::vector<WireLabel>& state,
//    uint32_t lowmcstatesize, GCEnv& env) {
//        for (uint32_t i = 0; i < lowmcstatesize; i++, m_constCtr++) {
//            if (m_roundconst[m_constCtr]) {
//                state[i] = env.NOT(state[i]);
//            }
//        }
//    }
//
//    void LowMCCircuit::LowMCPutSBoxLayer(std::vector<WireLabel>& input,
//    uint32_t numsboxes, uint32_t statesize, GCEnv& env) {
//        for (uint32_t i = 0; i < numsboxes * 3; i += 3) {
//            LowMCPutSBox(input[statesize-1-(i+2)], input[statesize-1-(i+1)],
//            input[statesize-1-(i+0)], env);
//        }
//    }
//
//    void LowMCCircuit::LowMCPutSBox(WireLabel& o1, WireLabel& o2, WireLabel&
//    o3, GCEnv& env) {
//        WireLabel i1 = o1;
//        WireLabel i2 = o2;
//        WireLabel i3 = o3;
//
//        WireLabel ni1 = env.NOT(i1);
//        WireLabel ni2 = env.NOT(i2);
//        WireLabel ni3 = env.NOT(i3);
//
//        //C = B * C + A
//        o1 = env.XOR(env.AND(i2, i3), i1);
//
//        //E = A * (NOT C) + B
//        o2 = env.XOR(env.AND(i1, ni3), i2);
//
//        //F = (NOT ((NOT B) * (NOT A))) + C
//        o3 = env.XOR(env.NOT(env.AND(ni2, ni1)), i3);
//    }
//
//    void LowMCCircuit::FourRussiansMatrixMult(std::vector<WireLabel>& state,
//    uint32_t lowmcstatesize, GCEnv& env) {
//        //round to nearest square for optimal window size
//        uint32_t wsize = 8;//floor_log2(lowmcstatesize);
//
//        //will only work if the statesize is a multiple of the window size
//        assert(lowmcstatesize % wsize == 0);
//        WireLabel* lut = new WireLabel[(1 << wsize)];
//        uint32_t i, j;
//        uint8_t tmp = 0;
//
//        lut[0] = WireLabel::getZEROLabel(); //TODO:Think about this more
//        //circ->PutConstantGate(0, 1);
//
//        std::vector<WireLabel> tmpstate(ceil_divide(lowmcstatesize, wsize) *
//        wsize, lut[0]);
//        //pad the state to a multiple of the window size and fill with zeros
//        std::vector<WireLabel> state_pad(ceil_divide(lowmcstatesize, wsize) *
//        wsize, lut[0]); for (i = 0; i < lowmcstatesize; i++)
//            state_pad[i] = state[i];
//
//        for (i = 0; i < ceil_divide(lowmcstatesize, wsize); i++) { //for each
//        column-window
//            for (j = 1; j < (1U << wsize); j++) {
//                lut[mGrayCode.ord[j]] = env.XOR(lut[mGrayCode.ord[j -
//                1]], state_pad[i * wsize + mGrayCode.inc[j - 1]]);
//            }
//
//            for (j = 0; j < lowmcstatesize; j++) {
//                tmp =
//                m_linlayer.get8BitsAligned(m_linCtr+i*wsize+j*lowmcstatesize);
//                tmpstate[j] = env.XOR(tmpstate[j], lut[tmp]);
//            }
//        }
//        m_linCtr += lowmcstatesize*lowmcstatesize;
//
//        for (i = 0; i < lowmcstatesize; i++)
//            state[i] = tmpstate[i];
//
//        delete[] lut;
//    }

//----------------------------------------------------------------------------------------------
// SIMD
SIMDLowMCCircuit::SIMDLowMCCircuit(ChannelWrapper &chan)
    : SIMDCircuit(chan, params->n, params->n, params->n),
      mGrayCode(FOUR_RUSSIAN_WINDOW_SIZE) {}

std::vector<SIMDWireLabel> SIMDLowMCCircuit::computeFunction(
    const std::vector<WireLabel> &keyRev, const std::vector<SIMDWireLabel> &pt,
    SIMDGCEnv &env) {
  uint32_t round, i;
  const uint32_t statesize = params->n;
  const uint32_t nrounds = params->r;

  std::vector<SIMDWireLabel> state(statesize);
  std::vector<SIMDWireLabel> result(statesize);

  // copy the input to the current state, fixing memory representation
  for (i = 0; i < statesize; i++)
    state[(i / 8) * 8 + 7 - i % 8] = pt[statesize - 1 - i];
  // fix key memory representation
  std::vector<WireLabel> key(keyRev.size());
  for (i = 0; i < keyRev.size(); i++)
    key[(i / 8) * 8 + 7 - i % 8] = keyRev[keyRev.size() - 1 - i];

#if defined(REDUCED_LINEAR_LAYER) && defined(REDUCED_LINEAR_LAYER_NEXT)
  LowMCXORConstant(state, params->precomputed_constant_linear, env);
  LowMCAddRoundKeyMult(state, key, params->k0_matrix, env);
  std::vector<WireLabel> nl_part = LowMCPrecomputeNLPart(key, env);
  for (round = 0; round < nrounds - 1; round++) {
    LowMCPutSBoxLayer(state, env);
    LowMCAddRRK(state, nl_part, round, env);
    LowMCRLLMult(state, round, env);
  }
  LowMCPutSBoxLayer(state, env);
  LowMCAddRRK(state, nl_part, round, env);
  FourRussiansMatrixMult(state, params->zr_matrix, env);
//        LowMCMult(state, params->zr_matrix, env);
#else
  LowMCAddRoundKeyMult(state, key, params->k0_matrix, env);  // ARK
  for (round = 1; round <= nrounds; round++) {
    // substitution via 3-bit SBoxes
    LowMCPutSBoxLayer(state, env);

    // multiply state with GF2Matrix
    FourRussiansMatrixMult(
        state, params->rounds[round - 1].l_matrix,
        env);  // 4 Russians version of the state multiplication
    //            LowMCMult(state, params->rounds[round-1].l_matrix, env);//4
    //            Russians version of the state multiplication

    // XOR constants
    LowMCXORConstant(state, params->rounds[round - 1].constant, env);

    // XOR with multiplied key
    LowMCAddRoundKeyMult(state, key, params->rounds[round - 1].k_matrix, env);
  }

#endif
  for (i = 0; i < statesize; i++)
    result[(i / 8) * 8 + 7 - i % 8] = state[statesize - 1 - i];
  return result;
}

void SIMDLowMCCircuit::LowMCAddRoundKeyMult(std::vector<SIMDWireLabel> &val,
                                            const std::vector<WireLabel> &key,
                                            const mzd_local_t *keymat,
                                            SIMDGCEnv &env) {
  std::vector<WireLabel> tmp(val.size(), WireLabel::getZEROLabel());
  for (uint32_t i = 0; i < params->n; i++) {
    const word *k = CONST_ROW(keymat, i);
    for (uint32_t j = 0; j < params->n; j++) {
      if (READ_BIT(k, j)) {
        tmp[j] = env.XOR(tmp[j], key[i]);
      }
    }
  }
  for (uint32_t i = 0; i < params->n; i++) {
    val[i] = env.XOR(val[i], tmp[i]);
  }
}

void SIMDLowMCCircuit::LowMCAddRoundKey(std::vector<SIMDWireLabel> &val,
                                        const std::vector<WireLabel> &key,
                                        uint32_t lowmcstatesize, uint32_t round,
                                        SIMDGCEnv &env) {
  for (uint32_t i = 0; i < lowmcstatesize; i++) {
    val[i] = env.XOR(val[i], key[i + (round)*lowmcstatesize]);
  }
}

void SIMDLowMCCircuit::LowMCXORConstant(std::vector<SIMDWireLabel> &state,
                                        const mzd_local_t *constant,
                                        SIMDGCEnv &env) {
  const word *c = CONST_FIRST_ROW(constant);
  for (uint32_t i = 0; i < params->n; i++) {
    if (READ_BIT(c, i)) {
      state[i] = env.NOT(state[i]);
    }
  }
}

void SIMDLowMCCircuit::LowMCPutSBoxLayer(std::vector<SIMDWireLabel> &input,
                                         SIMDGCEnv &env) {
  for (uint32_t i = 0; i < params->m * 3; i += 3) {
    LowMCPutSBox(input[params->n - 1 - (i + 2)], input[params->n - 1 - (i + 1)],
                 input[params->n - 1 - (i + 0)], env);
  }
}

void SIMDLowMCCircuit::LowMCPutSBox(SIMDWireLabel &o1, SIMDWireLabel &o2,
                                    SIMDWireLabel &o3, SIMDGCEnv &env) {
  SIMDWireLabel i1 = o1;
  SIMDWireLabel i2 = o2;
  SIMDWireLabel i3 = o3;

  SIMDWireLabel ni1 = env.NOT(i1);
  SIMDWireLabel ni2 = env.NOT(i2);
  SIMDWireLabel ni3 = env.NOT(i3);

  // C = B * C + A
  o1 = env.XOR(env.AND(i2, i3), i1);

  // E = A * (NOT C) + B
  o2 = env.XOR(env.AND(i1, ni3), i2);

  // F = (NOT ((NOT B) * (NOT A))) + C
  o3 = env.XOR(env.NOT(env.AND(ni2, ni1)), i3);
}

void SIMDLowMCCircuit::LowMCAddRRK(std::vector<SIMDWireLabel> &val,
                                   const std::vector<WireLabel> &nl_part,
                                   uint32_t round, SIMDGCEnv &env) {
  for (uint32_t i = 0; i < 3 * params->m; i++) {
    val[params->n - 3 * params->m + i] = env.XOR(
        val[params->n - 3 * params->m + i], nl_part[3 * params->m * round + i]);
  }
}

void SIMDLowMCCircuit::LowMCRLLMult(std::vector<SIMDWireLabel> &val,
                                    uint32_t round, SIMDGCEnv &env) {
#if defined(REDUCED_LINEAR_LAYER_NEXT)
  std::vector<SIMDWireLabel> tmpstate(
      val.size(), SIMDWireLabel::getZEROLabel(env.SIMDInputs));
  std::swap(val, tmpstate);

  // calculate tmp*Z
  SIMDWireLabel tmp;
  for (uint32_t i = 0; i < 3 * params->m; i++) {
    const word *z = CONST_ROW(params->rounds[round].z_matrix, i);
    tmp = SIMDWireLabel::getZEROLabel(env.SIMDInputs);
    for (uint32_t j = 0; j < params->n; j++) {
      if (READ_BIT(z, j)) {
        tmp = env.XOR(tmp, tmpstate[j]);
      }
    }
    val[params->n - 3 * params->m + i] = tmp;
  }
  // Reorder tmp base on rcols
  for (unsigned j = params->rounds[round].num_fixes; j; j--) {
    for (unsigned k = params->rounds[round].r_cols[j - 1];
         k < params->n - 1 - (3 * params->m - j); k++) {
      std::swap(tmpstate[k], tmpstate[k + 1]);
      //                SIMDWireLabel t = tmpstate[k];
      //                tmpstate[k] = tmpstate[k+1];
      //                tmpstate[k+1] = t;
    }
  }
  // calculate tmp*R
  for (uint32_t i = 0; i < 3 * params->m; i++) {
    const word *z = CONST_ROW(params->rounds[round].r_matrix, i);
    for (uint32_t j = 0; j < params->n - 3 * params->m; j++) {
      if (READ_BIT(z, j)) {
        val[j] = env.XOR(val[j], tmpstate[params->n - 3 * params->m + i]);
      }
    }
  }
  for (uint32_t i = 0; i < params->n - 3 * params->m; i++) {
    val[i] = env.XOR(val[i], tmpstate[i]);
  }
#endif
}

void SIMDLowMCCircuit::FourRussiansMatrixMult(std::vector<SIMDWireLabel> &state,
                                              const mzd_local_t *mat,
                                              SIMDGCEnv &env) {
  // round to nearest square for optimal window size
  constexpr uint32_t wsize =
      FOUR_RUSSIAN_WINDOW_SIZE;  // floor_log2(lowmcstatesize);

  // will only work if the statesize is a multiple of the window size
  assert(params->n % wsize == 0);
  SIMDWireLabel *lut = new SIMDWireLabel[(1 << wsize)];
  uint32_t i, j;
  uint8_t tmp = 0;

  lut[0] = SIMDWireLabel::getZEROLabel(
      env.SIMDInputs);  // circ->PutConstantGate(0, 1);

  std::vector<SIMDWireLabel> tmpstate(ceil_divide(params->n, wsize) * wsize,
                                      lut[0]);
  // pad the state to a multiple of the window size and fill with zeros
  std::vector<SIMDWireLabel> state_pad(ceil_divide(params->n, wsize) * wsize,
                                       lut[0]);
  for (i = 0; i < params->n; i++) state_pad[i] = state[i];

  for (i = 0; i < ceil_divide(params->n, wsize);
       i++) {  // for each column-window
    for (j = 1; j < (1U << wsize); j++) {
      lut[mGrayCode.ord[j]] =
          env.XOR(lut[mGrayCode.ord[j - 1]],
                  state_pad[i * wsize + mGrayCode.inc[j - 1]]);
    }

    for (j = 0; j < params->n; j++) {
      tmp = READ_BIT(CONST_ROW(mat, i * wsize + 0), j) << 0;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 1), j) << 1;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 2), j) << 2;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 3), j) << 3;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 4), j) << 4;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 5), j) << 5;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 6), j) << 6;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 7), j) << 7;
      tmpstate[j] = env.XOR(tmpstate[j], lut[tmp]);
    }
  }

  for (i = 0; i < params->n; i++) state[i] = tmpstate[i];

  delete[] lut;
}

std::vector<WireLabel> SIMDLowMCCircuit::LowMCPrecomputeNLPart(
    std::vector<WireLabel> &key, SIMDGCEnv &env) {
  uint64_t nl_part_size = (params->r * 3 * params->m);
  std::vector<WireLabel> nl_part(nl_part_size, WireLabel::getZEROLabel());
#if defined(REDUCED_LINEAR_LAYER_NEXT)
  if (params->m == 1) {
    for (unsigned i = 0; i < params->n; i++) {
      const word *k = CONST_ROW(params->precomputed_non_linear_part_matrix, i);
      for (uint32_t j = 0; j < nl_part_size; j++) {
        if (READ_BIT(k, 1 + (j / 63) + j)) {
          nl_part[j] = env.XOR(nl_part[j], key[i]);
        }
      }
    }
    const word *c = CONST_FIRST_ROW(params->precomputed_constant_non_linear);
    for (unsigned i = 0; i < nl_part_size; i++) {
      if (READ_BIT(c, 1 + (i / 63) + i)) {
        nl_part[i] = env.NOT(nl_part[i]);
      }
    }
  } else if (params->m == 10) {
    for (unsigned i = 0; i < params->n; i++) {
      const word *k = CONST_ROW(params->precomputed_non_linear_part_matrix, i);
      for (uint32_t j = 0; j < nl_part_size; j++) {
        if (READ_BIT(k, 2 + 2 * (j / 30) + j)) {
          nl_part[j] = env.XOR(nl_part[j], key[i]);
        }
      }
    }
    const word *c = CONST_FIRST_ROW(params->precomputed_constant_non_linear);
    for (unsigned i = 0; i < nl_part_size; i++) {
      if (READ_BIT(c, 2 + 2 * (i / 30) + i)) {
        nl_part[i] = env.NOT(nl_part[i]);
      }
    }
  } else {
    throw std::runtime_error("Only implemented for 10 and 1 atm");
  }
#endif
  return nl_part;
}

void SIMDLowMCCircuit::LowMCMult(std::vector<SIMDWireLabel> &val,
                                 const mzd_local_t *mat, SIMDGCEnv &env) {
  std::vector<SIMDWireLabel> tmp(val.size(),
                                 SIMDWireLabel::getZEROLabel(env.SIMDInputs));
  std::swap(tmp, val);
  for (uint32_t i = 0; i < params->n; i++) {
    const word *k = CONST_ROW(mat, i);
    for (uint32_t j = 0; j < params->n; j++) {
      if (READ_BIT(k, j)) {
        val[j] = env.XOR(val[j], tmp[i]);
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------------------------
// Phased Circuit
SIMDLowMCCircuitPhases::SIMDLowMCCircuitPhases(ChannelWrapper &chan)
    : SIMDCircuitPhases(chan, params->n, params->n, params->n),
      mGrayCode(FOUR_RUSSIAN_WINDOW_SIZE) {}

std::vector<SIMDWireLabel> SIMDLowMCCircuitPhases::computeFunction(
    const std::vector<WireLabel> &keyRev, const std::vector<SIMDWireLabel> &pt,
    SIMDGCEnv &env) {
  uint32_t round, i;
  const uint32_t statesize = params->n;
  const uint32_t nrounds = params->r;

  std::vector<SIMDWireLabel> state(statesize);
  std::vector<SIMDWireLabel> result(statesize);

  // copy the input to the current state, fixing memory representation
  for (i = 0; i < statesize; i++)
    state[(i / 8) * 8 + 7 - i % 8] = pt[statesize - 1 - i];
  // fix key memory representation
  std::vector<WireLabel> key(keyRev.size());
  for (i = 0; i < keyRev.size(); i++)
    key[(i / 8) * 8 + 7 - i % 8] = keyRev[keyRev.size() - 1 - i];

#if defined(REDUCED_LINEAR_LAYER) && defined(REDUCED_LINEAR_LAYER_NEXT)
  LowMCXORConstant(state, params->precomputed_constant_linear, env);
  LowMCAddRoundKeyMult(state, key, params->k0_matrix, env);
  std::vector<WireLabel> nl_part = LowMCPrecomputeNLPart(key, env);
  for (round = 0; round < nrounds - 1; round++) {
    LowMCPutSBoxLayer(state, env);
    LowMCAddRRK(state, nl_part, round, env);
    LowMCRLLMult(state, round, env);
  }
  LowMCPutSBoxLayer(state, env);
  LowMCAddRRK(state, nl_part, round, env);
  FourRussiansMatrixMult(state, params->zr_matrix, env);
//        LowMCMult(state, params->zr_matrix, env);
#else
  LowMCAddRoundKeyMult(state, key, params->k0_matrix, env);  // ARK
  for (round = 1; round <= nrounds; round++) {
    // substitution via 3-bit SBoxes
    LowMCPutSBoxLayer(state, env);

    // multiply state with GF2Matrix
    FourRussiansMatrixMult(
        state, params->rounds[round - 1].l_matrix,
        env);  // 4 Russians version of the state multiplication

    // XOR constants
    LowMCXORConstant(state, params->rounds[round - 1].constant, env);

    // XOR with multiplied key
    LowMCAddRoundKeyMult(state, key, params->rounds[round - 1].k_matrix, env);
  }
#endif
  for (i = 0; i < statesize; i++)
    result[(i / 8) * 8 + 7 - i % 8] = state[statesize - 1 - i];
  return result;
}

void SIMDLowMCCircuitPhases::LowMCAddRoundKeyMult(
    std::vector<SIMDWireLabel> &val, const std::vector<WireLabel> &key,
    const mzd_local_t *keymat, SIMDGCEnv &env) {
  std::vector<WireLabel> tmp(val.size(), WireLabel::getZEROLabel());
  for (uint32_t i = 0; i < params->n; i++) {
    const word *k = CONST_ROW(keymat, i);
    for (uint32_t j = 0; j < params->n; j++) {
      if (READ_BIT(k, j)) {
        tmp[j] = env.XOR(tmp[j], key[i]);
      }
    }
  }
  for (uint32_t i = 0; i < params->n; i++) {
    val[i] = env.XOR(val[i], tmp[i]);
  }
}

void SIMDLowMCCircuitPhases::LowMCAddRoundKey(std::vector<SIMDWireLabel> &val,
                                              const std::vector<WireLabel> &key,
                                              uint32_t lowmcstatesize,
                                              uint32_t round, SIMDGCEnv &env) {
  for (uint32_t i = 0; i < lowmcstatesize; i++) {
    val[i] = env.XOR(val[i], key[i + (round)*lowmcstatesize]);
  }
}

void SIMDLowMCCircuitPhases::LowMCXORConstant(std::vector<SIMDWireLabel> &state,
                                              const mzd_local_t *constant,
                                              SIMDGCEnv &env) {
  const word *c = CONST_FIRST_ROW(constant);
  for (uint32_t i = 0; i < params->n; i++) {
    if (READ_BIT(c, i)) {
      state[i] = env.NOT(state[i]);
    }
  }
}

void SIMDLowMCCircuitPhases::LowMCPutSBoxLayer(
    std::vector<SIMDWireLabel> &input, SIMDGCEnv &env) {
  for (uint32_t i = 0; i < params->m * 3; i += 3) {
    LowMCPutSBox(input[params->n - 1 - (i + 2)], input[params->n - 1 - (i + 1)],
                 input[params->n - 1 - (i + 0)], env);
  }
}

void SIMDLowMCCircuitPhases::LowMCPutSBox(SIMDWireLabel &o1, SIMDWireLabel &o2,
                                          SIMDWireLabel &o3, SIMDGCEnv &env) {
  SIMDWireLabel i1 = o1;
  SIMDWireLabel i2 = o2;
  SIMDWireLabel i3 = o3;

  SIMDWireLabel ni1 = env.NOT(i1);
  SIMDWireLabel ni2 = env.NOT(i2);
  SIMDWireLabel ni3 = env.NOT(i3);

  // C = B * C + A
  o1 = env.XOR(env.AND(i2, i3), i1);

  // E = A * (NOT C) + B
  o2 = env.XOR(env.AND(i1, ni3), i2);

  // F = (NOT ((NOT B) * (NOT A))) + C
  o3 = env.XOR(env.NOT(env.AND(ni2, ni1)), i3);
}

void SIMDLowMCCircuitPhases::LowMCAddRRK(std::vector<SIMDWireLabel> &val,
                                         const std::vector<WireLabel> &nl_part,
                                         uint32_t round, SIMDGCEnv &env) {
  for (uint32_t i = 0; i < 3 * params->m; i++) {
    val[params->n - 3 * params->m + i] = env.XOR(
        val[params->n - 3 * params->m + i], nl_part[3 * params->m * round + i]);
  }
}

void SIMDLowMCCircuitPhases::LowMCRLLMult(std::vector<SIMDWireLabel> &val,
                                          uint32_t round, SIMDGCEnv &env) {
#if defined(REDUCED_LINEAR_LAYER_NEXT)
  std::vector<SIMDWireLabel> tmpstate(
      val.size(), SIMDWireLabel::getZEROLabel(env.SIMDInputs));
  std::swap(val, tmpstate);

  // calculate tmp*Z
  SIMDWireLabel tmp;
  for (uint32_t i = 0; i < 3 * params->m; i++) {
    const word *z = CONST_ROW(params->rounds[round].z_matrix, i);
    tmp = SIMDWireLabel::getZEROLabel(env.SIMDInputs);
    for (uint32_t j = 0; j < params->n; j++) {
      if (READ_BIT(z, j)) {
        tmp = env.XOR(tmp, tmpstate[j]);
      }
    }
    val[params->n - 3 * params->m + i] = tmp;
  }
  // Reorder tmp base on rcols
  for (unsigned j = params->rounds[round].num_fixes; j; j--) {
    for (unsigned k = params->rounds[round].r_cols[j - 1];
         k < params->n - 1 - (3 * params->m - j); k++) {
      std::swap(tmpstate[k], tmpstate[k + 1]);
      //                SIMDWireLabel t = tmpstate[k];
      //                tmpstate[k] = tmpstate[k+1];
      //                tmpstate[k+1] = t;
    }
  }
  // calculate tmp*R
  for (uint32_t i = 0; i < 3 * params->m; i++) {
    const word *z = CONST_ROW(params->rounds[round].r_matrix, i);
    for (uint32_t j = 0; j < params->n - 3 * params->m; j++) {
      if (READ_BIT(z, j)) {
        val[j] = env.XOR(val[j], tmpstate[params->n - 3 * params->m + i]);
      }
    }
  }
  for (uint32_t i = 0; i < params->n - 3 * params->m; i++) {
    val[i] = env.XOR(val[i], tmpstate[i]);
  }
#endif
}

void SIMDLowMCCircuitPhases::FourRussiansMatrixMult(
    std::vector<SIMDWireLabel> &state, const mzd_local_t *mat, SIMDGCEnv &env) {
  // round to nearest square for optimal window size
  uint32_t wsize = FOUR_RUSSIAN_WINDOW_SIZE;

  // will only work if the statesize is a multiple of the window size
  assert(params->n % wsize == 0);
  SIMDWireLabel *lut = new SIMDWireLabel[(1 << wsize)];
  uint32_t i, j;
  uint8_t tmp = 0;

  lut[0] = SIMDWireLabel::getZEROLabel(
      env.SIMDInputs);  // circ->PutConstantGate(0, 1);

  std::vector<SIMDWireLabel> tmpstate(ceil_divide(params->n, wsize) * wsize,
                                      lut[0]);
  // pad the state to a multiple of the window size and fill with zeros
  std::vector<SIMDWireLabel> state_pad(ceil_divide(params->n, wsize) * wsize,
                                       lut[0]);
  for (i = 0; i < params->n; i++) state_pad[i] = state[i];

  for (i = 0; i < ceil_divide(params->n, wsize);
       i++) {  // for each column-window
    for (j = 1; j < (1U << wsize); j++) {
      lut[mGrayCode.ord[j]] =
          env.XOR(lut[mGrayCode.ord[j - 1]],
                  state_pad[i * wsize + mGrayCode.inc[j - 1]]);
    }

    for (j = 0; j < params->n; j++) {
      tmp = READ_BIT(CONST_ROW(mat, i * wsize + 0), j) << 0;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 1), j) << 1;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 2), j) << 2;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 3), j) << 3;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 4), j) << 4;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 5), j) << 5;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 6), j) << 6;
      tmp |= READ_BIT(CONST_ROW(mat, i * wsize + 7), j) << 7;
      tmpstate[j] = env.XOR(tmpstate[j], lut[tmp]);
    }
  }

  for (i = 0; i < params->n; i++) state[i] = tmpstate[i];

  delete[] lut;
}

std::vector<WireLabel> SIMDLowMCCircuitPhases::LowMCPrecomputeNLPart(
    std::vector<WireLabel> &key, SIMDGCEnv &env) {
  uint64_t nl_part_size = (params->r * 3 * params->m);
  std::vector<WireLabel> nl_part(nl_part_size, WireLabel::getZEROLabel());
#if defined(REDUCED_LINEAR_LAYER_NEXT)
  if (params->m == 1) {
    for (unsigned i = 0; i < params->n; i++) {
      const word *k = CONST_ROW(params->precomputed_non_linear_part_matrix, i);
      for (uint32_t j = 0; j < nl_part_size; j++) {
        if (READ_BIT(k, 1 + (j / 63) + j)) {
          nl_part[j] = env.XOR(nl_part[j], key[i]);
        }
      }
    }
    const word *c = CONST_FIRST_ROW(params->precomputed_constant_non_linear);
    for (unsigned i = 0; i < nl_part_size; i++) {
      if (READ_BIT(c, 1 + (i / 63) + i)) {
        nl_part[i] = env.NOT(nl_part[i]);
      }
    }
  } else if (params->m == 10) {
    for (unsigned i = 0; i < params->n; i++) {
      const word *k = CONST_ROW(params->precomputed_non_linear_part_matrix, i);
      for (uint32_t j = 0; j < nl_part_size; j++) {
        if (READ_BIT(k, 2 + 2 * (j / 30) + j)) {
          nl_part[j] = env.XOR(nl_part[j], key[i]);
        }
      }
    }
    const word *c = CONST_FIRST_ROW(params->precomputed_constant_non_linear);
    for (unsigned i = 0; i < nl_part_size; i++) {
      if (READ_BIT(c, 2 + 2 * (i / 30) + i)) {
        nl_part[i] = env.NOT(nl_part[i]);
      }
    }
  } else {
    throw std::runtime_error("Only implemented for 10 and 1 atm");
  }
#endif
  return nl_part;
}

void SIMDLowMCCircuitPhases::LowMCMult(std::vector<SIMDWireLabel> &val,
                                       const mzd_local_t *mat, SIMDGCEnv &env) {
  std::vector<SIMDWireLabel> tmp(val.size(),
                                 SIMDWireLabel::getZEROLabel(env.SIMDInputs));
  std::swap(tmp, val);
  for (uint32_t i = 0; i < params->n; i++) {
    const word *k = CONST_ROW(mat, i);
    for (uint32_t j = 0; j < params->n; j++) {
      if (READ_BIT(k, j)) {
        val[j] = env.XOR(val[j], tmp[i]);
      }
    }
  }
}
}  // namespace droidCrypto

//#define NUM_LOWMC (1<<10)
#define NUM_LOWMC (1 << 8)

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_garbleLowMC(
    JNIEnv *env, jobject /*this*/, jobject channel) {
  //    droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::CSocketChannel chan("127.0.0.1", 1234, 1);

  uint8_t LOWMC_TEST_KEY[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  droidCrypto::BitVector a(LOWMC_TEST_KEY,
                           droidCrypto::SIMDLowMCCircuit::params->n);

  droidCrypto::SIMDLowMCCircuit circ(chan);
  circ.garble(a, NUM_LOWMC);
  droidCrypto::Log::v("GC", "GARBLER: bytes sent: %zu, recv: %zu",
                      chan.getBytesSent(), chan.getBytesRecv());
}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_evaluateLowMC(
    JNIEnv *env, jobject /*this*/, jobject channel) {
  //    droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::CSocketChannel chan("127.0.0.1", 1234, 0);
  uint8_t LOWMC_TEST_INPUT[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00};
  droidCrypto::BitVector a(LOWMC_TEST_INPUT, 128);
  std::vector<droidCrypto::BitVector> aa(NUM_LOWMC, a);

  droidCrypto::SIMDLowMCCircuit circ(chan);
  //    droidCrypto::BitVector ct = circ.evaluate(a);
  std::vector<droidCrypto::BitVector> ct = circ.evaluate(aa);
  std::string time = "Time: " + std::to_string(circ.timeBaseOT.count());
  time += ", " + std::to_string(circ.timeOT.count());
  time += ", " + std::to_string(circ.timeEval.count());
  time += ", " + std::to_string(circ.timeOutput.count());
  time += "; " + std::to_string((circ.timeBaseOT + circ.timeOT + circ.timeEval +
                                 circ.timeOutput)
                                    .count());
  droidCrypto::Log::v("GC", "%s", time.c_str());
  //    for(int i = 0; i < NUM_LOWMC; i++)
  //        droidCrypto::Log::v("GC", "tt: %s", ct[i].hexREV().c_str());
  //    droidCrypto::Log::v("GC", "tt: %s", ct.hexREV().c_str());

  droidCrypto::Log::v("GC", "EVALUATOR: bytes sent: %zu, recv: %zu",
                      chan.getBytesSent(), chan.getBytesRecv());
}
