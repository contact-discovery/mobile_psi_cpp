/**
 \file 		Some parts of this file are taken from
ABY/src/examples/aes/common/aescircuit.cpp \author
michael.zohner@ec-spride.de \copyright	ABY - A Framework for Efficient
Mixed-protocol Secure Two-party Computation Copyright (C) 2019 Engineering
Cryptographic Protocols Group, TU Darmstadt This program is free software: you
can redistribute it and/or modify it under the terms of the GNU Lesser General
Public License as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version. ABY is distributed in the
hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details. You should have received a copy
of the GNU Lesser General Public License along with this program. If not, see
<http://www.gnu.org/licenses/>. \brief		Implementation of AESCircuit

 *  Modified by Daniel Kales, 2019
 *  * adapted AES circuit functions from ABY to circuit framework
 */

#include <assert.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/HalfGate.h>
#include <droidCrypto/gc/WireLabel.h>
#include <droidCrypto/gc/circuits/AESCircuit.h>
#include <droidCrypto/utils/Log.h>

using std::vector;

namespace droidCrypto {

std::vector<WireLabel> AESCircuit::computeFunction(
    const std::vector<WireLabel> &key, const std::vector<WireLabel> &pt,
    GCEnv &env) {
  vector<vector<vector<WireLabel> > > state(
      AES_STATE_COLS);  // the state is treated as a matrix
  vector<vector<vector<WireLabel> > > state_temp(
      AES_STATE_COLS);  // the state is treated as a matrix
  vector<WireLabel> outputs(128);
  uint32_t round, i, j, k;

  for (i = 0; i < AES_STATE_COLS; i++) {
    state[i].resize(AES_STATE_ROWS);
    state_temp[i].resize(AES_STATE_ROWS);

    for (j = 0; j < AES_STATE_ROWS; j++) {
      state[i][j].resize(8);
      state_temp[i][j].resize(8);

      for (k = 0; k < 8; k++) {
        state[i][j][k] = pt[((i * AES_STATE_COLS) + j) * 8 + k];
      }
    }
  }

  for (round = 0; round < AES_ROUNDS; round++) {
    for (i = 0; i < AES_STATE_COLS; i++) {
      for (j = 0; j < AES_STATE_ROWS; j++) {
        state[i][j] = AddAESRoundKey(
            state[i][j], key,
            (round * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8,
            env);  // ARK
        state_temp[(i - j) & 0x3][j] = PutAESSBoxGate(state[i][j], env);
      }
    }

    for (i = 0; i < AES_STATE_COLS; i++) {
      if (round < 9)
        state[i] = PutAESMixColumnGate(state_temp[i], env);  // MixColumns
      else
        state = state_temp;
    }
  }

  for (i = 0; i < AES_STATE_COLS; i++) {
    for (j = 0; j < AES_STATE_ROWS; j++) {
      state[i][j] = AddAESRoundKey(
          state[i][j], key,
          (AES_ROUNDS * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, env);
      for (k = 0; k < 8; k++) {
        outputs[(i * AES_STATE_ROWS + j) * 8 + k] = state[i][j][k];
      }
    }
  }
  return outputs;
}

vector<WireLabel> AESCircuit::AddAESRoundKey(const vector<WireLabel> &val,
                                             const vector<WireLabel> &key,
                                             size_t keyaddr, GCEnv &env) {
  vector<WireLabel> out(8);
  for (uint32_t i = 0; i < 8; i++) {
    out[i] = env.XOR(val[i], key[keyaddr + i]);
  }
  return out;
}

// Pretty straight - forward, shift by 1 to the left and if input_msb is 1, then
// XOR with 0x1b
vector<WireLabel> AESCircuit::Mul2(vector<WireLabel> &element, GCEnv &env) {
  vector<WireLabel> out(8);
  out[0] = element[7];
  out[1] = env.XOR(element[0], element[7]);
  out[2] = element[1];
  out[3] = env.XOR(element[2], element[7]);
  out[4] = env.XOR(element[3], element[7]);
  out[5] = element[4];
  out[6] = element[5];
  out[7] = element[6];
  return out;
}

vector<vector<WireLabel> > AESCircuit::PutAESMixColumnGate(
    vector<vector<WireLabel> > &rows, GCEnv &env) {
  uint32_t i, j;
  WireLabel temp;
  vector<vector<WireLabel> > out(4);
  vector<vector<WireLabel> > temp_mul2(4);

  assert(rows.size() == 4);

  for (j = 0; j < 4; j++) {
    out[j].resize(8);
    temp_mul2[j].resize(8);
    temp_mul2[j] = Mul2(rows[j], env);
  }
  for (j = 0; j < 4; j++) {
    for (i = 0; i < 8; i++) {
      temp = env.XOR(temp_mul2[j][i], temp_mul2[(j + 1) % 4][i]);
      temp = env.XOR(temp, rows[(j + 1) % 4][i]);
      temp = env.XOR(temp, rows[(j + 2) % 4][i]);
      out[j][i] = env.XOR(temp, rows[(j + 3) % 4][i]);
    }
  }

  return out;
}

// The Boyar-Peralta size optimized SBox circuit (32 AND gates, Depth 6)
vector<WireLabel> AESCircuit::PutAESSBoxGate(vector<WireLabel> &input,
                                             GCEnv &env) {
  vector<WireLabel> x(8);
  vector<WireLabel> y(22);
  vector<WireLabel> t(68);
  vector<WireLabel> s(8);
  vector<WireLabel> z(18);
  vector<WireLabel> out(8);

  for (uint32_t i = 0; i < x.size(); i++) {
    x[i] = input[7 - i];
  }

  // Top linear transform
  y[14] = env.XOR(x[3], x[5]);
  y[13] = env.XOR(x[0], x[6]);
  y[9] = env.XOR(x[0], x[3]);

  y[8] = env.XOR(x[0], x[5]);
  t[0] = env.XOR(x[1], x[2]);
  y[1] = env.XOR(t[0], x[7]);

  y[4] = env.XOR(y[1], x[3]);
  y[12] = env.XOR(y[13], y[14]);
  y[2] = env.XOR(y[1], x[0]);

  y[5] = env.XOR(y[1], x[6]);
  y[3] = env.XOR(y[5], y[8]);
  t[1] = env.XOR(x[4], y[12]);

  y[15] = env.XOR(t[1], x[5]);
  y[20] = env.XOR(t[1], x[1]);
  y[6] = env.XOR(y[15], x[7]);

  y[10] = env.XOR(y[15], t[0]);
  y[11] = env.XOR(y[20], y[9]);
  y[7] = env.XOR(x[7], y[11]);

  y[17] = env.XOR(y[10], y[11]);
  y[19] = env.XOR(y[10], y[8]);
  y[16] = env.XOR(t[0], y[11]);

  y[21] = env.XOR(y[13], y[16]);
  y[18] = env.XOR(x[0], y[16]);

  // Middle Non-Linear Transform, Box 1
  t[2] = env.AND(y[12], y[15]);
  t[3] = env.AND(y[3], y[6]);
  t[4] = env.XOR(t[3], t[2]);

  t[5] = env.AND(y[4], x[7]);
  t[6] = env.XOR(t[5], t[2]);
  t[7] = env.AND(y[13], y[16]);

  t[8] = env.AND(y[5], y[1]);
  t[9] = env.XOR(t[8], t[7]);
  t[10] = env.AND(y[2], y[7]);

  t[11] = env.XOR(t[10], t[7]);
  t[12] = env.AND(y[9], y[11]);
  t[13] = env.AND(y[14], y[17]);

  t[14] = env.XOR(t[13], t[12]);
  t[15] = env.AND(y[8], y[10]);
  t[16] = env.XOR(t[15], t[12]);

  t[17] = env.XOR(t[4], t[14]);
  t[18] = env.XOR(t[6], t[16]);
  t[19] = env.XOR(t[9], t[14]);

  t[20] = env.XOR(t[11], t[16]);
  t[21] = env.XOR(t[17], y[20]);
  t[22] = env.XOR(t[18], y[19]);

  t[23] = env.XOR(t[19], y[21]);
  t[24] = env.XOR(t[20], y[18]);

  // Middle Non-Linear Transform, Box 2
  t[25] = env.XOR(t[21], t[22]);
  t[26] = env.AND(t[21], t[23]);
  t[27] = env.XOR(t[24], t[26]);

  t[28] = env.AND(t[25], t[27]);
  t[29] = env.XOR(t[28], t[22]);
  t[30] = env.XOR(t[23], t[24]);

  t[31] = env.XOR(t[22], t[26]);
  t[32] = env.AND(t[31], t[30]);
  t[33] = env.XOR(t[32], t[24]);

  t[34] = env.XOR(t[23], t[33]);
  t[35] = env.XOR(t[27], t[33]);
  t[36] = env.AND(t[24], t[35]);

  t[37] = env.XOR(t[36], t[34]);
  t[38] = env.XOR(t[27], t[36]);
  t[39] = env.AND(t[29], t[38]);

  t[40] = env.XOR(t[25], t[39]);

  // Middle Non-Linear Transform, Box 3
  t[41] = env.XOR(t[40], t[37]);
  t[42] = env.XOR(t[29], t[33]);
  t[43] = env.XOR(t[29], t[40]);

  t[44] = env.XOR(t[33], t[37]);
  t[45] = env.XOR(t[42], t[41]);
  z[0] = env.AND(t[44], y[15]);

  z[1] = env.AND(t[37], y[6]);
  z[2] = env.AND(t[33], x[7]);
  z[3] = env.AND(t[43], y[16]);

  z[4] = env.AND(t[40], y[1]);
  z[5] = env.AND(t[29], y[7]);
  z[6] = env.AND(t[42], y[11]);

  z[7] = env.AND(t[45], y[17]);
  z[8] = env.AND(t[41], y[10]);
  z[9] = env.AND(t[44], y[12]);

  z[10] = env.AND(t[37], y[3]);
  z[11] = env.AND(t[33], y[4]);
  z[12] = env.AND(t[43], y[13]);

  z[13] = env.AND(t[40], y[5]);
  z[14] = env.AND(t[29], y[2]);
  z[15] = env.AND(t[42], y[9]);

  z[16] = env.AND(t[45], y[14]);
  z[17] = env.AND(t[41], y[8]);

  // Bottom Non-Linear Transform
  t[46] = env.XOR(z[15], z[16]);
  t[47] = env.XOR(z[10], z[11]);
  t[48] = env.XOR(z[5], z[13]);

  t[49] = env.XOR(z[9], z[10]);
  t[50] = env.XOR(z[2], z[12]);
  t[51] = env.XOR(z[2], z[5]);

  t[52] = env.XOR(z[7], z[8]);
  t[53] = env.XOR(z[0], z[3]);
  t[54] = env.XOR(z[6], z[7]);

  t[55] = env.XOR(z[16], z[17]);
  t[56] = env.XOR(z[12], t[48]);
  t[57] = env.XOR(t[50], t[53]);

  t[58] = env.XOR(z[4], t[46]);
  t[59] = env.XOR(z[3], t[54]);
  t[60] = env.XOR(t[46], t[57]);

  t[61] = env.XOR(z[14], t[57]);
  t[62] = env.XOR(t[52], t[58]);
  t[63] = env.XOR(t[49], t[58]);

  t[64] = env.XOR(z[4], t[59]);
  t[65] = env.XOR(t[61], t[62]);
  t[66] = env.XOR(z[1], t[63]);

  s[0] = env.XOR(t[59], t[63]);
  s[6] = env.XOR(t[56], env.NOT(t[62]));
  s[7] = env.XOR(t[48], env.NOT(t[60]));

  t[67] = env.XOR(t[64], t[65]);
  s[3] = env.XOR(t[53], t[66]);
  s[4] = env.XOR(t[51], t[66]);

  s[5] = env.XOR(t[47], t[65]);
  s[1] = env.XOR(t[64], env.NOT(s[3]));
  s[2] = env.XOR(t[55], env.NOT(t[67]));

  for (uint32_t i = 0; i < out.size(); i++) {
    out[i] = s[7 - i];
  }

  return out;
}
//------------------------------------------------------------------------------------------------------------------
// SIMD

std::vector<SIMDWireLabel> SIMDAESCircuit::computeFunction(
    const std::vector<WireLabel> &key, const std::vector<SIMDWireLabel> &pt,
    SIMDGCEnv &env) {
  vector<vector<vector<SIMDWireLabel> > > state(
      AES_STATE_COLS);  // the state is treated as a matrix
  vector<vector<vector<SIMDWireLabel> > > state_temp(
      AES_STATE_COLS);  // the state is treated as a matrix
  vector<SIMDWireLabel> outputs(128);
  uint32_t round, i, j, k;

  for (i = 0; i < AES_STATE_COLS; i++) {
    state[i].resize(AES_STATE_ROWS);
    state_temp[i].resize(AES_STATE_ROWS);

    for (j = 0; j < AES_STATE_ROWS; j++) {
      state[i][j].resize(8);
      state_temp[i][j].resize(8);

      for (k = 0; k < 8; k++) {
        state[i][j][k] = pt[((i * AES_STATE_COLS) + j) * 8 + k];
      }
    }
  }

  for (round = 0; round < AES_ROUNDS; round++) {
    for (i = 0; i < AES_STATE_COLS; i++) {
      for (j = 0; j < AES_STATE_ROWS; j++) {
        state[i][j] = AddAESRoundKey(
            state[i][j], key,
            (round * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8,
            env);  // ARK
        state_temp[(i - j) & 0x3][j] = PutAESSBoxGate(state[i][j], env);
      }
    }

    for (i = 0; i < AES_STATE_COLS; i++) {
      if (round < 9)
        state[i] = PutAESMixColumnGate(state_temp[i], env);  // MixColumns
      else
        state = state_temp;
    }
  }

  for (i = 0; i < AES_STATE_COLS; i++) {
    for (j = 0; j < AES_STATE_ROWS; j++) {
      state[i][j] = AddAESRoundKey(
          state[i][j], key,
          (AES_ROUNDS * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, env);
      for (k = 0; k < 8; k++) {
        outputs[(i * AES_STATE_ROWS + j) * 8 + k] = state[i][j][k];
      }
    }
  }
  return outputs;
}

vector<SIMDWireLabel> SIMDAESCircuit::AddAESRoundKey(
    const vector<SIMDWireLabel> &val, const vector<WireLabel> &key,
    size_t keyaddr, SIMDGCEnv &env) {
  vector<SIMDWireLabel> out(8);
  for (uint32_t i = 0; i < 8; i++) {
    out[i] = env.XOR(val[i], key[keyaddr + i]);
  }
  return out;
}

// Pretty straight - forward, shift by 1 to the left and if input_msb is 1, then
// XOR with 0x1b
vector<SIMDWireLabel> SIMDAESCircuit::Mul2(vector<SIMDWireLabel> &element,
                                           SIMDGCEnv &env) {
  vector<SIMDWireLabel> out(8);
  out[0] = element[7];
  out[1] = env.XOR(element[0], element[7]);
  out[2] = element[1];
  out[3] = env.XOR(element[2], element[7]);
  out[4] = env.XOR(element[3], element[7]);
  out[5] = element[4];
  out[6] = element[5];
  out[7] = element[6];
  return out;
}

vector<vector<SIMDWireLabel> > SIMDAESCircuit::PutAESMixColumnGate(
    vector<vector<SIMDWireLabel> > &rows, SIMDGCEnv &env) {
  uint32_t i, j;
  SIMDWireLabel temp;
  vector<vector<SIMDWireLabel> > out(4);
  vector<vector<SIMDWireLabel> > temp_mul2(4);

  assert(rows.size() == 4);

  for (j = 0; j < 4; j++) {
    out[j].resize(8);
    temp_mul2[j].resize(8);
    temp_mul2[j] = Mul2(rows[j], env);
  }
  for (j = 0; j < 4; j++) {
    for (i = 0; i < 8; i++) {
      temp = env.XOR(temp_mul2[j][i], temp_mul2[(j + 1) % 4][i]);
      temp = env.XOR(temp, rows[(j + 1) % 4][i]);
      temp = env.XOR(temp, rows[(j + 2) % 4][i]);
      out[j][i] = env.XOR(temp, rows[(j + 3) % 4][i]);
    }
  }

  return out;
}

// The Boyar-Peralta size optimized SBox circuit (32 AND gates, Depth 6)
vector<SIMDWireLabel> SIMDAESCircuit::PutAESSBoxGate(
    vector<SIMDWireLabel> &input, SIMDGCEnv &env) {
  vector<SIMDWireLabel> x(8);
  vector<SIMDWireLabel> y(22);
  vector<SIMDWireLabel> t(68);
  vector<SIMDWireLabel> s(8);
  vector<SIMDWireLabel> z(18);
  vector<SIMDWireLabel> out(8);

  for (uint32_t i = 0; i < x.size(); i++) {
    x[i] = input[7 - i];
  }

  // Top linear transform
  y[14] = env.XOR(x[3], x[5]);
  y[13] = env.XOR(x[0], x[6]);
  y[9] = env.XOR(x[0], x[3]);

  y[8] = env.XOR(x[0], x[5]);
  t[0] = env.XOR(x[1], x[2]);
  y[1] = env.XOR(t[0], x[7]);

  y[4] = env.XOR(y[1], x[3]);
  y[12] = env.XOR(y[13], y[14]);
  y[2] = env.XOR(y[1], x[0]);

  y[5] = env.XOR(y[1], x[6]);
  y[3] = env.XOR(y[5], y[8]);
  t[1] = env.XOR(x[4], y[12]);

  y[15] = env.XOR(t[1], x[5]);
  y[20] = env.XOR(t[1], x[1]);
  y[6] = env.XOR(y[15], x[7]);

  y[10] = env.XOR(y[15], t[0]);
  y[11] = env.XOR(y[20], y[9]);
  y[7] = env.XOR(x[7], y[11]);

  y[17] = env.XOR(y[10], y[11]);
  y[19] = env.XOR(y[10], y[8]);
  y[16] = env.XOR(t[0], y[11]);

  y[21] = env.XOR(y[13], y[16]);
  y[18] = env.XOR(x[0], y[16]);

  // Middle Non-Linear Transform, Box 1
  t[2] = env.AND(y[12], y[15]);
  t[3] = env.AND(y[3], y[6]);
  t[4] = env.XOR(t[3], t[2]);

  t[5] = env.AND(y[4], x[7]);
  t[6] = env.XOR(t[5], t[2]);
  t[7] = env.AND(y[13], y[16]);

  t[8] = env.AND(y[5], y[1]);
  t[9] = env.XOR(t[8], t[7]);
  t[10] = env.AND(y[2], y[7]);

  t[11] = env.XOR(t[10], t[7]);
  t[12] = env.AND(y[9], y[11]);
  t[13] = env.AND(y[14], y[17]);

  t[14] = env.XOR(t[13], t[12]);
  t[15] = env.AND(y[8], y[10]);
  t[16] = env.XOR(t[15], t[12]);

  t[17] = env.XOR(t[4], t[14]);
  t[18] = env.XOR(t[6], t[16]);
  t[19] = env.XOR(t[9], t[14]);

  t[20] = env.XOR(t[11], t[16]);
  t[21] = env.XOR(t[17], y[20]);
  t[22] = env.XOR(t[18], y[19]);

  t[23] = env.XOR(t[19], y[21]);
  t[24] = env.XOR(t[20], y[18]);

  // Middle Non-Linear Transform, Box 2
  t[25] = env.XOR(t[21], t[22]);
  t[26] = env.AND(t[21], t[23]);
  t[27] = env.XOR(t[24], t[26]);

  t[28] = env.AND(t[25], t[27]);
  t[29] = env.XOR(t[28], t[22]);
  t[30] = env.XOR(t[23], t[24]);

  t[31] = env.XOR(t[22], t[26]);
  t[32] = env.AND(t[31], t[30]);
  t[33] = env.XOR(t[32], t[24]);

  t[34] = env.XOR(t[23], t[33]);
  t[35] = env.XOR(t[27], t[33]);
  t[36] = env.AND(t[24], t[35]);

  t[37] = env.XOR(t[36], t[34]);
  t[38] = env.XOR(t[27], t[36]);
  t[39] = env.AND(t[29], t[38]);

  t[40] = env.XOR(t[25], t[39]);

  // Middle Non-Linear Transform, Box 3
  t[41] = env.XOR(t[40], t[37]);
  t[42] = env.XOR(t[29], t[33]);
  t[43] = env.XOR(t[29], t[40]);

  t[44] = env.XOR(t[33], t[37]);
  t[45] = env.XOR(t[42], t[41]);
  z[0] = env.AND(t[44], y[15]);

  z[1] = env.AND(t[37], y[6]);
  z[2] = env.AND(t[33], x[7]);
  z[3] = env.AND(t[43], y[16]);

  z[4] = env.AND(t[40], y[1]);
  z[5] = env.AND(t[29], y[7]);
  z[6] = env.AND(t[42], y[11]);

  z[7] = env.AND(t[45], y[17]);
  z[8] = env.AND(t[41], y[10]);
  z[9] = env.AND(t[44], y[12]);

  z[10] = env.AND(t[37], y[3]);
  z[11] = env.AND(t[33], y[4]);
  z[12] = env.AND(t[43], y[13]);

  z[13] = env.AND(t[40], y[5]);
  z[14] = env.AND(t[29], y[2]);
  z[15] = env.AND(t[42], y[9]);

  z[16] = env.AND(t[45], y[14]);
  z[17] = env.AND(t[41], y[8]);

  // Bottom Non-Linear Transform
  t[46] = env.XOR(z[15], z[16]);
  t[47] = env.XOR(z[10], z[11]);
  t[48] = env.XOR(z[5], z[13]);

  t[49] = env.XOR(z[9], z[10]);
  t[50] = env.XOR(z[2], z[12]);
  t[51] = env.XOR(z[2], z[5]);

  t[52] = env.XOR(z[7], z[8]);
  t[53] = env.XOR(z[0], z[3]);
  t[54] = env.XOR(z[6], z[7]);

  t[55] = env.XOR(z[16], z[17]);
  t[56] = env.XOR(z[12], t[48]);
  t[57] = env.XOR(t[50], t[53]);

  t[58] = env.XOR(z[4], t[46]);
  t[59] = env.XOR(z[3], t[54]);
  t[60] = env.XOR(t[46], t[57]);

  t[61] = env.XOR(z[14], t[57]);
  t[62] = env.XOR(t[52], t[58]);
  t[63] = env.XOR(t[49], t[58]);

  t[64] = env.XOR(z[4], t[59]);
  t[65] = env.XOR(t[61], t[62]);
  t[66] = env.XOR(z[1], t[63]);

  s[0] = env.XOR(t[59], t[63]);
  s[6] = env.XOR(t[56], env.NOT(t[62]));
  s[7] = env.XOR(t[48], env.NOT(t[60]));

  t[67] = env.XOR(t[64], t[65]);
  s[3] = env.XOR(t[53], t[66]);
  s[4] = env.XOR(t[51], t[66]);

  s[5] = env.XOR(t[47], t[65]);
  s[1] = env.XOR(t[64], env.NOT(s[3]));
  s[2] = env.XOR(t[55], env.NOT(t[67]));

  for (uint32_t i = 0; i < out.size(); i++) {
    out[i] = s[7 - i];
  }

  return out;
}

// Phased Circuit
std::vector<SIMDWireLabel> SIMDAESCircuitPhases::computeFunction(
    const std::vector<WireLabel> &key, const std::vector<SIMDWireLabel> &pt,
    SIMDGCEnv &env) {
  vector<vector<vector<SIMDWireLabel> > > state(
      AES_STATE_COLS);  // the state is treated as a matrix
  vector<vector<vector<SIMDWireLabel> > > state_temp(
      AES_STATE_COLS);  // the state is treated as a matrix
  vector<SIMDWireLabel> outputs(128);
  uint32_t round, i, j, k;

  for (i = 0; i < AES_STATE_COLS; i++) {
    state[i].resize(AES_STATE_ROWS);
    state_temp[i].resize(AES_STATE_ROWS);

    for (j = 0; j < AES_STATE_ROWS; j++) {
      state[i][j].resize(8);
      state_temp[i][j].resize(8);

      for (k = 0; k < 8; k++) {
        state[i][j][k] = pt[((i * AES_STATE_COLS) + j) * 8 + k];
      }
    }
  }

  for (round = 0; round < AES_ROUNDS; round++) {
    for (i = 0; i < AES_STATE_COLS; i++) {
      for (j = 0; j < AES_STATE_ROWS; j++) {
        state[i][j] = AddAESRoundKey(
            state[i][j], key,
            (round * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8,
            env);  // ARK
        state_temp[(i - j) & 0x3][j] = PutAESSBoxGate(state[i][j], env);
      }
    }

    for (i = 0; i < AES_STATE_COLS; i++) {
      if (round < 9)
        state[i] = PutAESMixColumnGate(state_temp[i], env);  // MixColumns
      else
        state = state_temp;
    }
  }

  for (i = 0; i < AES_STATE_COLS; i++) {
    for (j = 0; j < AES_STATE_ROWS; j++) {
      state[i][j] = AddAESRoundKey(
          state[i][j], key,
          (AES_ROUNDS * AES_STATE_SIZE + (i * AES_STATE_COLS) + j) * 8, env);
      for (k = 0; k < 8; k++) {
        outputs[(i * AES_STATE_ROWS + j) * 8 + k] = state[i][j][k];
      }
    }
  }
  return outputs;
}

vector<SIMDWireLabel> SIMDAESCircuitPhases::AddAESRoundKey(
    const vector<SIMDWireLabel> &val, const vector<WireLabel> &key,
    size_t keyaddr, SIMDGCEnv &env) {
  vector<SIMDWireLabel> out(8);
  for (uint32_t i = 0; i < 8; i++) {
    out[i] = env.XOR(val[i], key[keyaddr + i]);
  }
  return out;
}

// Pretty straight - forward, shift by 1 to the left and if input_msb is 1, then
// XOR with 0x1b
vector<SIMDWireLabel> SIMDAESCircuitPhases::Mul2(vector<SIMDWireLabel> &element,
                                                 SIMDGCEnv &env) {
  vector<SIMDWireLabel> out(8);
  out[0] = element[7];
  out[1] = env.XOR(element[0], element[7]);
  out[2] = element[1];
  out[3] = env.XOR(element[2], element[7]);
  out[4] = env.XOR(element[3], element[7]);
  out[5] = element[4];
  out[6] = element[5];
  out[7] = element[6];
  return out;
}

vector<vector<SIMDWireLabel> > SIMDAESCircuitPhases::PutAESMixColumnGate(
    vector<vector<SIMDWireLabel> > &rows, SIMDGCEnv &env) {
  uint32_t i, j;
  SIMDWireLabel temp;
  vector<vector<SIMDWireLabel> > out(4);
  vector<vector<SIMDWireLabel> > temp_mul2(4);

  assert(rows.size() == 4);

  for (j = 0; j < 4; j++) {
    out[j].resize(8);
    temp_mul2[j].resize(8);
    temp_mul2[j] = Mul2(rows[j], env);
  }
  for (j = 0; j < 4; j++) {
    for (i = 0; i < 8; i++) {
      temp = env.XOR(temp_mul2[j][i], temp_mul2[(j + 1) % 4][i]);
      temp = env.XOR(temp, rows[(j + 1) % 4][i]);
      temp = env.XOR(temp, rows[(j + 2) % 4][i]);
      out[j][i] = env.XOR(temp, rows[(j + 3) % 4][i]);
    }
  }

  return out;
}

// The Boyar-Peralta size optimized SBox circuit (32 AND gates, Depth 6)
vector<SIMDWireLabel> SIMDAESCircuitPhases::PutAESSBoxGate(
    vector<SIMDWireLabel> &input, SIMDGCEnv &env) {
  vector<SIMDWireLabel> x(8);
  vector<SIMDWireLabel> y(22);
  vector<SIMDWireLabel> t(68);
  vector<SIMDWireLabel> s(8);
  vector<SIMDWireLabel> z(18);
  vector<SIMDWireLabel> out(8);

  for (uint32_t i = 0; i < x.size(); i++) {
    x[i] = input[7 - i];
  }

  // Top linear transform
  y[14] = env.XOR(x[3], x[5]);
  y[13] = env.XOR(x[0], x[6]);
  y[9] = env.XOR(x[0], x[3]);

  y[8] = env.XOR(x[0], x[5]);
  t[0] = env.XOR(x[1], x[2]);
  y[1] = env.XOR(t[0], x[7]);

  y[4] = env.XOR(y[1], x[3]);
  y[12] = env.XOR(y[13], y[14]);
  y[2] = env.XOR(y[1], x[0]);

  y[5] = env.XOR(y[1], x[6]);
  y[3] = env.XOR(y[5], y[8]);
  t[1] = env.XOR(x[4], y[12]);

  y[15] = env.XOR(t[1], x[5]);
  y[20] = env.XOR(t[1], x[1]);
  y[6] = env.XOR(y[15], x[7]);

  y[10] = env.XOR(y[15], t[0]);
  y[11] = env.XOR(y[20], y[9]);
  y[7] = env.XOR(x[7], y[11]);

  y[17] = env.XOR(y[10], y[11]);
  y[19] = env.XOR(y[10], y[8]);
  y[16] = env.XOR(t[0], y[11]);

  y[21] = env.XOR(y[13], y[16]);
  y[18] = env.XOR(x[0], y[16]);

  // Middle Non-Linear Transform, Box 1
  t[2] = env.AND(y[12], y[15]);
  t[3] = env.AND(y[3], y[6]);
  t[4] = env.XOR(t[3], t[2]);

  t[5] = env.AND(y[4], x[7]);
  t[6] = env.XOR(t[5], t[2]);
  t[7] = env.AND(y[13], y[16]);

  t[8] = env.AND(y[5], y[1]);
  t[9] = env.XOR(t[8], t[7]);
  t[10] = env.AND(y[2], y[7]);

  t[11] = env.XOR(t[10], t[7]);
  t[12] = env.AND(y[9], y[11]);
  t[13] = env.AND(y[14], y[17]);

  t[14] = env.XOR(t[13], t[12]);
  t[15] = env.AND(y[8], y[10]);
  t[16] = env.XOR(t[15], t[12]);

  t[17] = env.XOR(t[4], t[14]);
  t[18] = env.XOR(t[6], t[16]);
  t[19] = env.XOR(t[9], t[14]);

  t[20] = env.XOR(t[11], t[16]);
  t[21] = env.XOR(t[17], y[20]);
  t[22] = env.XOR(t[18], y[19]);

  t[23] = env.XOR(t[19], y[21]);
  t[24] = env.XOR(t[20], y[18]);

  // Middle Non-Linear Transform, Box 2
  t[25] = env.XOR(t[21], t[22]);
  t[26] = env.AND(t[21], t[23]);
  t[27] = env.XOR(t[24], t[26]);

  t[28] = env.AND(t[25], t[27]);
  t[29] = env.XOR(t[28], t[22]);
  t[30] = env.XOR(t[23], t[24]);

  t[31] = env.XOR(t[22], t[26]);
  t[32] = env.AND(t[31], t[30]);
  t[33] = env.XOR(t[32], t[24]);

  t[34] = env.XOR(t[23], t[33]);
  t[35] = env.XOR(t[27], t[33]);
  t[36] = env.AND(t[24], t[35]);

  t[37] = env.XOR(t[36], t[34]);
  t[38] = env.XOR(t[27], t[36]);
  t[39] = env.AND(t[29], t[38]);

  t[40] = env.XOR(t[25], t[39]);

  // Middle Non-Linear Transform, Box 3
  t[41] = env.XOR(t[40], t[37]);
  t[42] = env.XOR(t[29], t[33]);
  t[43] = env.XOR(t[29], t[40]);

  t[44] = env.XOR(t[33], t[37]);
  t[45] = env.XOR(t[42], t[41]);
  z[0] = env.AND(t[44], y[15]);

  z[1] = env.AND(t[37], y[6]);
  z[2] = env.AND(t[33], x[7]);
  z[3] = env.AND(t[43], y[16]);

  z[4] = env.AND(t[40], y[1]);
  z[5] = env.AND(t[29], y[7]);
  z[6] = env.AND(t[42], y[11]);

  z[7] = env.AND(t[45], y[17]);
  z[8] = env.AND(t[41], y[10]);
  z[9] = env.AND(t[44], y[12]);

  z[10] = env.AND(t[37], y[3]);
  z[11] = env.AND(t[33], y[4]);
  z[12] = env.AND(t[43], y[13]);

  z[13] = env.AND(t[40], y[5]);
  z[14] = env.AND(t[29], y[2]);
  z[15] = env.AND(t[42], y[9]);

  z[16] = env.AND(t[45], y[14]);
  z[17] = env.AND(t[41], y[8]);

  // Bottom Non-Linear Transform
  t[46] = env.XOR(z[15], z[16]);
  t[47] = env.XOR(z[10], z[11]);
  t[48] = env.XOR(z[5], z[13]);

  t[49] = env.XOR(z[9], z[10]);
  t[50] = env.XOR(z[2], z[12]);
  t[51] = env.XOR(z[2], z[5]);

  t[52] = env.XOR(z[7], z[8]);
  t[53] = env.XOR(z[0], z[3]);
  t[54] = env.XOR(z[6], z[7]);

  t[55] = env.XOR(z[16], z[17]);
  t[56] = env.XOR(z[12], t[48]);
  t[57] = env.XOR(t[50], t[53]);

  t[58] = env.XOR(z[4], t[46]);
  t[59] = env.XOR(z[3], t[54]);
  t[60] = env.XOR(t[46], t[57]);

  t[61] = env.XOR(z[14], t[57]);
  t[62] = env.XOR(t[52], t[58]);
  t[63] = env.XOR(t[49], t[58]);

  t[64] = env.XOR(z[4], t[59]);
  t[65] = env.XOR(t[61], t[62]);
  t[66] = env.XOR(z[1], t[63]);

  s[0] = env.XOR(t[59], t[63]);
  s[6] = env.XOR(t[56], env.NOT(t[62]));
  s[7] = env.XOR(t[48], env.NOT(t[60]));

  t[67] = env.XOR(t[64], t[65]);
  s[3] = env.XOR(t[53], t[66]);
  s[4] = env.XOR(t[51], t[66]);

  s[5] = env.XOR(t[47], t[65]);
  s[1] = env.XOR(t[64], env.NOT(s[3]));
  s[2] = env.XOR(t[55], env.NOT(t[67]));

  for (uint32_t i = 0; i < out.size(); i++) {
    out[i] = s[7 - i];
  }

  return out;
}
}  // namespace droidCrypto

//#define NUM_AES (1<<10)
#define NUM_AES (1 << 8)

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_garbleAES(
    JNIEnv *env, jobject /*this*/, jobject channel) {
  //    droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::CSocketChannel chan("127.0.0.1", 1234, 1);

  uint8_t AES_TEST_EXPANDED_KEY[AES_EXP_KEY_BYTES] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
      0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x9b, 0x98, 0x98, 0xc9,
      0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
      0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33,
      0x0b, 0x0f, 0xac, 0x99, 0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81,
      0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91, 0xee, 0x2b, 0x7f, 0x2e, 0x2b, 0x88,
      0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90,
      0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c, 0x99, 0xff, 0x09, 0x37,
      0x6a, 0xb4, 0x9b, 0xa7, 0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b,
      0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b, 0xf0, 0x9b, 0x0e, 0xf9, 0x03, 0x33,
      0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f,
      0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde,
      0x4c, 0x66, 0x49, 0x41, 0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11,
      0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e};
  droidCrypto::BitVector a(AES_TEST_EXPANDED_KEY, AES_EXP_KEY_BITS);
  droidCrypto::SIMDAESCircuit circ(chan);
  circ.garble(a, NUM_AES);
}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_evaluateAES(
    JNIEnv *env, jobject /*this*/, jobject channel) {
  //    droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::CSocketChannel chan("127.0.0.1", 1234, 0);
  uint8_t AES_TEST_INPUT[AES_BYTES] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
  droidCrypto::BitVector a(AES_TEST_INPUT, AES_BYTES * 8);
  std::vector<droidCrypto::BitVector> aa(NUM_AES, a);

  droidCrypto::SIMDAESCircuit circ(chan);
  std::vector<droidCrypto::BitVector> ct = circ.evaluate(aa);
  //    droidCrypto::BitVector ct = circ.evaluate(a);
  std::string time = "Time: " + std::to_string(circ.timeBaseOT.count());
  time += ", " + std::to_string(circ.timeOT.count());
  time += ", " + std::to_string(circ.timeEval.count());
  time += ", " + std::to_string(circ.timeOutput.count());
  droidCrypto::Log::v("GC", "%s", time.c_str());
  //        droidCrypto::Log::v("GC", "tt: %s", ct.hex().c_str());
  for (size_t i = 0; i < 1; i++)
    droidCrypto::Log::v("GC", "tt: %s", ct[i].hex().c_str());

  droidCrypto::Log::v("GC", "bytes sent: %zu, recv: %zu", chan.getBytesSent(),
                      chan.getBytesRecv());
}
