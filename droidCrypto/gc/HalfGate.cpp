#include <droidCrypto/PRNG.h>
#include <droidCrypto/SHA1.h>
#include <droidCrypto/gc/HalfGate.h>
#include <droidCrypto/ot/NaorPinkas.h>
#include <droidCrypto/ot/VerifiedSimplestOT.h>
#include <droidCrypto/utils/Log.h>

namespace droidCrypto {

WireLabel Hasher::hash(const WireLabel &wire, uint64_t id) {
  block kid = dupUint64(id) ^ shiftBlock(wire.bytes);
  return WireLabel(mAES.encryptECB(kid) ^ kid);
}

SIMDWireLabel Hasher::hash(const SIMDWireLabel &wire, uint64_t id) {
  block bid = dupUint64(id);
  std::vector<block> kid(wire.bytes);
  std::vector<block> enc;
  enc.resize(kid.size());
  for (block &b : kid) {
    b = shiftBlock(b) ^ bid;
  }
  mAES.encryptECBBlocks(kid.data(), kid.size(), enc.data());
  for (size_t i = 0; i < kid.size(); i++) {
    kid[i] ^= enc[i];
  }

  return SIMDWireLabel(kid);
}

Garbler::Garbler(ChannelWrapper &chan) : GCEnv(chan) {
  block r = rnd.randBlock();
  R = WireLabel(r);
  R.setLSB();
  OTeSender.setDelta(R.bytes);
}

std::vector<WireLabel> Garbler::inputOfAlice(const BitVector &input) {
  std::vector<WireLabel> aliceInput;
  const size_t input_size = input.size();
  aliceInput.reserve(input_size);

  for (auto it = input.begin(); it != input.end(); ++it) {
    aliceInput.emplace_back(rnd.randBlock());
    if (*it)
      (aliceInput.back() ^ R).send(channel);
    else
      aliceInput.back().send(channel);
  }
  return aliceInput;  // Garbler needs the 0-Labels for garbling, not the actual
                      // input
}

std::vector<WireLabel> Garbler::inputOfBob(const size_t size) {
  std::vector<WireLabel> bobInput;
  bobInput.reserve(size);
  doOTPhase(size);

  for (size_t idx = 0; idx < size; idx++) {
    bobInput.emplace_back(OTs[idx][0]);
  }
  return bobInput;  // Garbler needs the 0-Labels for garbling, not the actual
                    // input
}

void Garbler::outputToBob(const std::vector<WireLabel> &outputLabels) {
  BitVector bv;
  bv.reserve(outputLabels.size());
  for (const WireLabel &label : outputLabels) {
    bv.pushBack(label.getLSB());
  }
  channel.send(bv.data(), bv.size());
}

WireLabel Garbler::XOR(const WireLabel &a, const WireLabel &b) {
  numXORs++;
  return a ^ b;
}

WireLabel Garbler::AND(const WireLabel &a, const WireLabel &b) {
  WireLabel G1 = gb.hash(a, gid);
  WireLabel TG = G1 ^ gb.hash(a ^ R, gid);
  if (b.getLSB()) TG = TG ^ R;
  WireLabel WG = G1;
  if (a.getLSB()) WG = WG ^ TG;

  G1 = gb.hash(b, gid);
  WireLabel TE = G1 ^ gb.hash(b ^ R, gid) ^ a;
  WireLabel WE = G1;
  if (b.getLSB()) WE = WE ^ (TE ^ a);

  gid++;
  numANDs++;

  TG.send(channel);
  TE.send(channel);

  return WG ^ WE;
}

WireLabel Garbler::NOT(const WireLabel &a) { return a ^ R; }

void Garbler::performBaseOTs(size_t numBaseOTs /* = 128 */) {
  PRNG p = PRNG::getTestPRNG();  // TODO: use real prngs

  std::vector<block> baseOTs;
  BitVector baseChoices(numBaseOTs);
  baseChoices.randomize(p);
  baseOTs.resize(numBaseOTs);
  span<block> baseOTsSpan(baseOTs.data(), baseOTs.size());

#if defined(ENABLE_SIMPLEST_OT)
  VerifiedSimplestOT ot;
#else
  NaorPinkas ot;
#endif
  ot.receive(baseChoices, baseOTsSpan, p, channel);
  OTeSender.setBaseOts(baseOTsSpan, baseChoices);
}

void Garbler::doOTPhase(size_t numOTs) {
  OTs.resize(numOTs);
  PRNG p = PRNG::getTestPRNG();
  OTeSender.send(span<std::array<block, 2>>(OTs.data(), OTs.size()), p,
                 channel);
}
//----------------------------------------------------------------------------------------------------------------------
// Evaluator
//----------------------------------------------------------------------------------------------------------------------

std::vector<WireLabel> Evaluator::inputOfAlice(const size_t size) {
  std::vector<WireLabel> aliceInput;
  aliceInput.reserve(size);

  for (size_t idx = 0; idx < size; idx++) {
    aliceInput.push_back(WireLabel::recv(channel));
  }
  return aliceInput;
}

std::vector<WireLabel> Evaluator::inputOfBob(const BitVector &input) {
  std::vector<WireLabel> bobInput;
  const size_t input_size = input.size();
  bobInput.reserve(input_size);
  doOTPhase(input);

  for (size_t idx = 0; idx < input_size; idx++) {
    bobInput.push_back(WireLabel(OTs[idx]));
  }
  return bobInput;
}

BitVector Evaluator::outputToBob(const std::vector<WireLabel> &outputLabels) {
  BitVector buf(outputLabels.size());
  BitVector bv;
  bv.reserve(outputLabels.size());
  channel.recv(buf.data(), buf.size());
  for (const WireLabel &label : outputLabels) {
    bv.pushBack(label.getLSB());
  }
  buf ^= bv;
  return buf;
}

WireLabel Evaluator::NOT(const WireLabel &a) {
  return a;  // NOT happens at the garbler
}

WireLabel Evaluator::XOR(const WireLabel &a, const WireLabel &b) {
  numXORs++;
  return a ^ b;
}

WireLabel Evaluator::AND(const WireLabel &a, const WireLabel &b) {
  WireLabel TG = WireLabel::recv(channel);
  WireLabel TE = WireLabel::recv(channel);

  WireLabel WG = gb.hash(a, gid);
  if (a.getLSB()) WG = WG ^ TG;
  WireLabel WE = gb.hash(b, gid);
  if (b.getLSB()) WE = WE ^ (TE ^ a);
  gid++;
  numANDs++;
  return WG ^ WE;
}

void Evaluator::performBaseOTs(size_t numBaseOTs /* = 128 */) {
#if defined(ENABLE_SIMPLEST_OT)
  VerifiedSimplestOT ot;
#else
  NaorPinkas ot;
#endif
  std::vector<std::array<block, 2>> baseOTs;
  baseOTs.resize(numBaseOTs);
  PRNG p = PRNG::getTestPRNG();
  span<std::array<block, 2>> baseOTsSpan(baseOTs.data(), baseOTs.size());
  ot.send(baseOTsSpan, p, channel);
  OTeRecv.setBaseOts(baseOTsSpan);
}

void Evaluator::doOTPhase(const BitVector &choices) {
  OTs.resize(choices.size());
  PRNG p = PRNG::getTestPRNG();
  OTeRecv.receive(choices, span<block>(OTs.data(), OTs.size()), p, channel);
}

//----------------------------------------------------------------------------------------------------------------------
// SIMDGarbler
//----------------------------------------------------------------------------------------------------------------------

SIMDGarbler::SIMDGarbler(ChannelWrapper &chan, size_t numinputs,
                         block delta /*= ZeroBlock */)
    : SIMDGCEnv(chan, numinputs) {
  if (eq(delta, ZeroBlock)) delta = rnd.randBlock();
  R = WireLabel(delta);
  R.setLSB();
#ifdef USE_DOTE
  OTeSender.setDelta(R.bytes);
#endif
}

WireLabel SIMDGarbler::XOR(const WireLabel &a, const WireLabel &b) {
  numXORs++;
  return a ^ b;
}

SIMDWireLabel SIMDGarbler::XOR(const SIMDWireLabel &a, const SIMDWireLabel &b) {
  numXORs++;
  return a ^ b;
}

SIMDWireLabel SIMDGarbler::XOR(const SIMDWireLabel &a, const WireLabel &b) {
  numXORs++;
  return a ^ b;
}

SIMDWireLabel SIMDGarbler::AND(const SIMDWireLabel &a, const SIMDWireLabel &b) {
  SIMDWireLabel G1 = gb.hash(a, gid);
  SIMDWireLabel TG = G1 ^ gb.hash(a ^ R, gid);
  for (size_t i = 0; i < b.bytes.size(); i++) {
    if (b.bytes[i][0] & 1) TG.bytes[i] = TG.bytes[i] ^ R.bytes;
  }
  SIMDWireLabel WG = G1;
  for (size_t i = 0; i < a.bytes.size(); i++) {
    if (a.bytes[i][0] & 1) WG.bytes[i] = WG.bytes[i] ^ TG.bytes[i];
  }

  G1 = gb.hash(b, gid);
  SIMDWireLabel TE = G1 ^ gb.hash(b ^ R, gid) ^ a;
  SIMDWireLabel WE = G1;
  for (size_t i = 0; i < b.bytes.size(); i++) {
    if (b.bytes[i][0] & 1) WE.bytes[i] = WE.bytes[i] ^ TE.bytes[i] ^ a.bytes[i];
  }

  gid++;
  numANDs++;

  TG.send(channel);
  TE.send(channel);

  return WG ^ WE;
}

void SIMDGarbler::PRINT(const char *, const std::vector<SIMDWireLabel> &vec) {
  for (const SIMDWireLabel &label : vec) {
    for (size_t i = 0; i < SIMDInputs; i++) {
      channel.send(label.bytes[i]);
      channel.send(label.bytes[i] ^ R.bytes);
    }
  }
}

void SIMDGarbler::PRINT(const char *, const std::vector<WireLabel> &vec) {
  for (const WireLabel &label : vec) {
    channel.send(label.bytes);
    channel.send(label.bytes ^ R.bytes);
  }
}

WireLabel SIMDGarbler::NOT(const WireLabel &a) { return a ^ R; }

SIMDWireLabel SIMDGarbler::NOT(const SIMDWireLabel &a) { return a ^ R; }

void SIMDGarbler::performBaseOTs(size_t numBaseOTs /* = 128 */) {
  PRNG p = PRNG::getTestPRNG();  // TODO: use real prngs

  std::vector<block> baseOTs;
  BitVector baseChoices(numBaseOTs);
  baseChoices.randomize(p);
  baseOTs.resize(numBaseOTs);
  span<block> baseOTsSpan(baseOTs.data(), baseOTs.size());

#if defined(ENABLE_SIMPLEST_OT)
  VerifiedSimplestOT ot;
#else
  NaorPinkas ot;
#endif
  ot.receive(baseChoices, baseOTsSpan, p, channel);
  OTeSender.setBaseOts(baseOTsSpan, baseChoices);
}

void SIMDGarbler::doOTPhase(size_t numOTs) {
  OTs.resize(numOTs);
  PRNG p = PRNG::getTestPRNG();
  OTeSender.send(span<std::array<block, 2>>(OTs.data(), OTs.size()), p,
                 channel);
}

std::vector<WireLabel> SIMDGarbler::inputOfAlice(const BitVector &input) {
  std::vector<WireLabel> aliceInput;
  const size_t input_size = input.size();
  aliceInput.reserve(input_size);

  for (auto it = input.begin(); it != input.end(); ++it) {
    aliceInput.emplace_back(rnd.randBlock());
    if (*it)
      (aliceInput.back() ^ R).send(channel);
    else
      aliceInput.back().send(channel);
  }
  return aliceInput;  // Garbler needs the 0-Labels for garbling, not the actual
                      // input
}

std::vector<SIMDWireLabel> SIMDGarbler::inputOfAlice(
    const std::vector<BitVector> &input) {
  std::vector<SIMDWireLabel> aliceInput;
  const size_t input_size = input.front().size();
  const size_t num_input = input.size();
  aliceInput.reserve(input_size);

  for (size_t i = 0; i < input_size; i++) {
    aliceInput.emplace_back(rnd.randBlocks(SIMDInputs));
    SIMDWireLabel tmp(aliceInput.back());
    for (size_t input_idx = 0; input_idx < num_input; input_idx++) {
      if (input[input_idx][i]) tmp.bytes[input_idx] ^= R.bytes;
    }
    tmp.send(channel);
  }
  return aliceInput;  // Garbler needs the 0-Labels for garbling, not the actual
                      // input
}

std::vector<SIMDWireLabel> SIMDGarbler::inputOfBob(const size_t size) {
  std::vector<SIMDWireLabel> bobInput;
  bobInput.reserve(size);
  doOTPhase(size * SIMDInputs);

  for (size_t idx = 0; idx < size; idx++) {
    std::vector<block> tmp;
    tmp.reserve(SIMDInputs);
    for (size_t input_idx = 0; input_idx < SIMDInputs; input_idx++) {
      tmp.push_back(OTs[input_idx * size + idx][0]);
    }
    bobInput.emplace_back(tmp);
#ifdef USE_DOTE
#else
    for (size_t input_idx = 0; input_idx < SIMDInputs; input_idx++)
      tmp[input_idx] ^= OTs[input_idx * size + idx][1] ^ R.bytes;
    channel.send(tmp);
#endif
  }
  return bobInput;  // Garbler needs the 0-Labels for garbling, not the actual
                    // input
}

void SIMDGarbler::outputToBob(const std::vector<SIMDWireLabel> &outputLabels) {
  for (const SIMDWireLabel &label : outputLabels) {
    BitVector bv = label.getLSB();
    channel.send(bv.data(), bv.sizeBytes());
  }
}
//----------------------------------------------------------------------------------------------------------------------
// SIMDEvaluator
//----------------------------------------------------------------------------------------------------------------------
void SIMDEvaluator::performBaseOTs(size_t numBaseOTs /* = 128 */) {
#if defined(ENABLE_SIMPLEST_OT)
  VerifiedSimplestOT ot;
#else
  NaorPinkas ot;
#endif

  std::vector<std::array<block, 2>> baseOTs;
  baseOTs.resize(numBaseOTs);
  PRNG p = PRNG::getTestPRNG();
  span<std::array<block, 2>> baseOTsSpan(baseOTs.data(), baseOTs.size());
  ot.send(baseOTsSpan, p, channel);
  OTeRecv.setBaseOts(baseOTsSpan);
}

void SIMDEvaluator::doOTPhase(const BitVector &choices) {
  OTs.resize(choices.size());
  PRNG p = PRNG::getTestPRNG();
  OTeRecv.receive(choices, span<block>(OTs.data(), OTs.size()), p, channel);
}

std::vector<WireLabel> SIMDEvaluator::inputOfAlice(const size_t size) {
  std::vector<WireLabel> aliceInput;
  aliceInput.reserve(size);

  for (size_t idx = 0; idx < size; idx++) {
    aliceInput.push_back(WireLabel::recv(channel));
  }
  return aliceInput;
}

std::vector<SIMDWireLabel> SIMDEvaluator::inputOfAliceSIMD(const size_t size) {
  std::vector<SIMDWireLabel> aliceInput;
  aliceInput.reserve(size);

  for (size_t idx = 0; idx < size; idx++) {
    aliceInput.push_back(SIMDWireLabel::recv(channel, SIMDInputs));
  }
  return aliceInput;
}

std::vector<SIMDWireLabel> SIMDEvaluator::inputOfBob(
    const std::vector<BitVector> &input) {
  std::vector<SIMDWireLabel> bobInput;
  const size_t input_size = input.front().size();
  const size_t num_input = input.size();
  bobInput.reserve(input_size);
  BitVector all;
  for (const BitVector &bv : input) {
    all.append(bv);
  }
  doOTPhase(all);

  for (size_t idx = 0; idx < input_size; idx++) {
    std::vector<block> tmp;
    tmp.reserve(num_input);
#ifdef USE_DOTE
    for (size_t input_idx = 0; input_idx < num_input; input_idx++) {
      tmp.push_back(OTs[input_idx * input_size + idx]);
    }
#else
    std::vector<block> b1(num_input);
    channel.recv(b1);
    for (size_t input_idx = 0; input_idx < num_input; input_idx++) {
      if (input[input_idx][idx])
        tmp.push_back(b1[input_idx] ^ OTs[input_idx * input_size + idx]);
      else
        tmp.push_back(OTs[input_idx * input_size + idx]);
    }
#endif
    bobInput.emplace_back(tmp);
  }
  return bobInput;
}

std::vector<BitVector> SIMDEvaluator::outputToBob(
    const std::vector<SIMDWireLabel> &outputLabels) {
  std::vector<BitVector> output(SIMDInputs);
  for (BitVector &bv : output) bv.reserve(outputLabels.size());

  BitVector buf(SIMDInputs);

  for (const SIMDWireLabel &label : outputLabels) {
    channel.recv(buf.data(), buf.sizeBytes());
    BitVector bv = label.getLSB();
    bv ^= buf;
    for (size_t i = 0; i < SIMDInputs; i++) {
      output[i].pushBack(bv[i]);
    }
  }
  return output;
}

void SIMDEvaluator::PRINT(const char *info,
                          const std::vector<SIMDWireLabel> &vec) {
  std::vector<BitVector> output(SIMDInputs);
  for (BitVector &bv : output) bv.reserve(vec.size());
  block a, b;
  for (const SIMDWireLabel &label : vec) {
    for (size_t i = 0; i < SIMDInputs; i++) {
      channel.recv(a);
      channel.recv(b);
      if (eq(label.bytes[i], a))
        output[i].pushBack(0);
      else if (eq(label.bytes[i], b))
        output[i].pushBack(1);
      else
        Log::e("PRINT", "%s: error, labels not matching up", info);
    }
  }
  for (size_t i = 0; i < SIMDInputs; i++) {
    Log::v("PRINT", "%s: %s", info, output[i].hex().c_str());
  }
}

void SIMDEvaluator::PRINT(const char *info, const std::vector<WireLabel> &vec) {
  BitVector output;
  output.reserve(vec.size());
  block a, b;
  for (const WireLabel &label : vec) {
    channel.recv(a);
    channel.recv(b);
    if (eq(label.bytes, a))
      output.pushBack(0);
    else if (eq(label.bytes, b))
      output.pushBack(1);
    else
      Log::e("PRINT", "%s: error, labels not matching up", info);
  }
  Log::v("PRINT", "%s: %s", info, output.hex().c_str());
}

WireLabel SIMDEvaluator::NOT(const WireLabel &a) {
  return a;  // NOT happens at the garbler
}

SIMDWireLabel SIMDEvaluator::NOT(const SIMDWireLabel &a) {
  return a;  // NOT happens at the garbler
}

WireLabel SIMDEvaluator::XOR(const WireLabel &a, const WireLabel &b) {
  numXORs++;
  return a ^ b;
}

SIMDWireLabel SIMDEvaluator::XOR(const SIMDWireLabel &a,
                                 const SIMDWireLabel &b) {
  numXORs++;
  return a ^ b;
}

SIMDWireLabel SIMDEvaluator::XOR(const SIMDWireLabel &a, const WireLabel &b) {
  numXORs++;
  return a ^ b;
}

SIMDWireLabel SIMDEvaluator::AND(const SIMDWireLabel &a,
                                 const SIMDWireLabel &b) {
  SIMDWireLabel TG = SIMDWireLabel::recv(channel, SIMDInputs);
  SIMDWireLabel TE = SIMDWireLabel::recv(channel, SIMDInputs);

  SIMDWireLabel WG = gb.hash(a, gid);
  for (size_t i = 0; i < a.bytes.size(); i++) {
    if (a.bytes[i][0] & 1) WG.bytes[i] = WG.bytes[i] ^ TG.bytes[i];
  }
  SIMDWireLabel WE = gb.hash(b, gid);
  for (size_t i = 0; i < b.bytes.size(); i++) {
    if (b.bytes[i][0] & 1) WE.bytes[i] = WE.bytes[i] ^ TE.bytes[i] ^ a.bytes[i];
  }
  gid++;
  numANDs++;
  return WG ^ WE;
}

//-----------------------------------------------------------------------------------------------
SIMDGarblerPhases::SIMDGarblerPhases(ChannelWrapper &chan, size_t numinputs,
                                     block delta /*= ZeroBlock */)
    : SIMDGarbler(chan, numinputs, delta) {}

std::vector<WireLabel> SIMDGarblerPhases::inputOfAlice(const BitVector &input) {
  std::vector<WireLabel> aliceInput;
  const size_t input_size = input.size();
  aliceInput.reserve(input_size);

  for (auto it = input.begin(); it != input.end(); ++it) {
    aliceInput.emplace_back(rnd.randBlock());
    if (*it)
      (aliceInput.back() ^ R).send(bufChan);
    else
      aliceInput.back().send(bufChan);
  }
  return aliceInput;  // Garbler needs the 0-Labels for garbling, not the actual
                      // input
}

std::vector<WireLabel> SIMDEvaluatorPhases::inputOfAlice(const size_t size) {
  std::vector<WireLabel> aliceInput;
  aliceInput.reserve(size);

  for (size_t idx = 0; idx < size; idx++) {
    aliceInput.push_back(WireLabel::recv(bufChan));
  }
  return aliceInput;
}

std::vector<SIMDWireLabel> SIMDGarblerPhases::inputOfBobOffline(
    const size_t size) {
  bobInputLabels.clear();
  bobInputLabels.reserve(size);

  for (size_t idx = 0; idx < size; idx++) {
    bobInputLabels.emplace_back(rnd.randBlocks(SIMDInputs));
  }
  // Garbler needs the 0-Labels for garbling, not the actual input
  return bobInputLabels;
}

void SIMDGarblerPhases::inputOfBobOnline() {
  uint64_t size = bobInputLabels.size();
  BitVector all;
  {
    std::vector<uint8_t> tmp(size * SIMDInputs / 8);
    channel.recv(tmp.data(), tmp.size());
    all.append(tmp.data(), size * SIMDInputs);
  }
  for (size_t idx = 0; idx < size; idx++) {
    std::vector<block> tmp(bobInputLabels[idx].bytes);
    for (size_t input_idx = 0; input_idx < SIMDInputs; input_idx++) {
      if (all[input_idx * size + idx])
        tmp[input_idx] ^= OTs[input_idx * size + idx][1];
      else
        tmp[input_idx] ^= OTs[input_idx * size + idx][0];
    }
    channel.send(tmp);
  }
}

std::vector<SIMDWireLabel> SIMDEvaluatorPhases::inputOfBobOnline(
    const std::vector<BitVector> &input, const BitVector &randChoices) {
  std::vector<SIMDWireLabel> bobInput;
  const size_t input_size = input.front().size();
  const size_t num_input = input.size();
  bobInput.reserve(input_size);
  BitVector all;
  for (const BitVector &bv : input) {
    all.append(bv);
  }
  all = all ^ randChoices;
  channel.send(all.data(), all.sizeBytes());

  for (size_t idx = 0; idx < input_size; idx++) {
    std::vector<block> b(num_input);
    channel.recv(b);
    for (size_t input_idx = 0; input_idx < num_input; input_idx++) {
      b[input_idx] ^= OTs[input_idx * input_size + idx];
    }
    bobInput.emplace_back(b);
  }
  return bobInput;
}

void SIMDGarblerPhases::outputToBob(
    const std::vector<SIMDWireLabel> &outputLabels) {
  for (const SIMDWireLabel &label : outputLabels) {
    BitVector bv = label.getLSB();
    bufChan.send(bv.data(), bv.sizeBytes());
  }
}

std::vector<BitVector> SIMDEvaluatorPhases::outputToBob(
    const std::vector<SIMDWireLabel> &outputLabels) {
  std::vector<BitVector> output(SIMDInputs);
  for (BitVector &bv : output) bv.reserve(outputLabels.size());

  BitVector buf(SIMDInputs);
  for (const SIMDWireLabel &label : outputLabels) {
    bufChan.recv(buf.data(), buf.sizeBytes());
    BitVector bv = label.getLSB();
    bv ^= buf;
    for (size_t i = 0; i < SIMDInputs; i++) {
      output[i].pushBack(bv[i]);
    }
  }
  return output;
}

SIMDWireLabel SIMDGarblerPhases::AND(const SIMDWireLabel &a,
                                     const SIMDWireLabel &b) {
  SIMDWireLabel G1 = gb.hash(a, gid);
  SIMDWireLabel TG = G1 ^ gb.hash(a ^ R, gid);
  for (size_t i = 0; i < b.bytes.size(); i++) {
    if (b.bytes[i][0] & 1) TG.bytes[i] = TG.bytes[i] ^ R.bytes;
  }
  SIMDWireLabel WG = G1;
  for (size_t i = 0; i < a.bytes.size(); i++) {
    if (a.bytes[i][0] & 1) WG.bytes[i] = WG.bytes[i] ^ TG.bytes[i];
  }

  G1 = gb.hash(b, gid);
  SIMDWireLabel TE = G1 ^ gb.hash(b ^ R, gid) ^ a;
  SIMDWireLabel WE = G1;
  for (size_t i = 0; i < b.bytes.size(); i++) {
    if (b.bytes[i][0] & 1) WE.bytes[i] = WE.bytes[i] ^ TE.bytes[i] ^ a.bytes[i];
  }

  gid++;
  numANDs++;

  TG.send(bufChan);
  TE.send(bufChan);

  return WG ^ WE;
}

SIMDWireLabel SIMDEvaluatorPhases::AND(const SIMDWireLabel &a,
                                       const SIMDWireLabel &b) {
  SIMDWireLabel TG = SIMDWireLabel::recv(bufChan, SIMDInputs);
  SIMDWireLabel TE = SIMDWireLabel::recv(bufChan, SIMDInputs);

  SIMDWireLabel WG = gb.hash(a, gid);
  for (size_t i = 0; i < a.bytes.size(); i++) {
    if (a.bytes[i][0] & 1) WG.bytes[i] = WG.bytes[i] ^ TG.bytes[i];
  }
  SIMDWireLabel WE = gb.hash(b, gid);
  for (size_t i = 0; i < b.bytes.size(); i++) {
    if (b.bytes[i][0] & 1) WE.bytes[i] = WE.bytes[i] ^ TE.bytes[i] ^ a.bytes[i];
  }
  gid++;
  numANDs++;
  return WG ^ WE;
}
}