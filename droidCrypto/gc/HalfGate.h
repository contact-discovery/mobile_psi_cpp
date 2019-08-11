#pragma once

#include <droidCrypto/AES.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/Defines.h>
#include <droidCrypto/SecureRandom.h>
#include <droidCrypto/gc/WireLabel.h>
#include <droidCrypto/ot/TwoChooseOne/IknpDotExtReceiver.h>
#include <droidCrypto/ot/TwoChooseOne/IknpDotExtSender.h>
#include <droidCrypto/ot/TwoChooseOne/KosDotExtReceiver.h>
#include <droidCrypto/ot/TwoChooseOne/KosDotExtSender.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtReceiver.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtSender.h>

#define USE_DOTE

namespace droidCrypto {

class Hasher {
 public:
  Hasher() : mAES(mAesFixedKey) {}

  WireLabel hash(const WireLabel &wire, uint64_t id);

  SIMDWireLabel hash(const SIMDWireLabel &wire, uint64_t id);

 private:
  const AES &mAES;
};

class GCEnv {
 public:
  GCEnv(ChannelWrapper &chan)
      : channel(chan), gb(), gid(0), numANDs(0), numXORs(0) {}

  virtual WireLabel XOR(const WireLabel &a, const WireLabel &b) = 0;

  virtual WireLabel AND(const WireLabel &a, const WireLabel &b) = 0;

  virtual WireLabel NOT(const WireLabel &a) = 0;

  inline uint64_t getNumANDs() const { return numANDs; }
  inline uint64_t getNumXORs() const { return numXORs; }

 protected:
  ChannelWrapper &channel;
  Hasher gb;
  uint64_t gid;
  uint64_t numANDs;
  uint64_t numXORs;
};

class Garbler : public GCEnv {
 public:
  Garbler(ChannelWrapper &chan);

  std::vector<WireLabel> inputOfAlice(const BitVector &input);

  std::vector<WireLabel> inputOfBob(const size_t size);

  void outputToBob(const std::vector<WireLabel> &outputLabels);

  virtual WireLabel XOR(const WireLabel &a, const WireLabel &b);

  virtual WireLabel AND(const WireLabel &a, const WireLabel &b);

  virtual WireLabel NOT(const WireLabel &a);

  void performBaseOTs(size_t numBaseOTs = 128);

  void doOTPhase(size_t numOTs);

 private:
  SecureRandom rnd;

  WireLabel R;

  KosDotExtSender OTeSender;
  std::vector<std::array<block, 2>> OTs;
};

class Evaluator : public GCEnv {
 public:
  Evaluator(ChannelWrapper &chan) : GCEnv(chan) {}

  std::vector<WireLabel> inputOfAlice(const size_t size);

  std::vector<WireLabel> inputOfBob(const BitVector &input);

  BitVector outputToBob(const std::vector<WireLabel> &outputLabels);

  virtual WireLabel XOR(const WireLabel &a, const WireLabel &b);

  virtual WireLabel AND(const WireLabel &a, const WireLabel &b);

  virtual WireLabel NOT(const WireLabel &a);

  void performBaseOTs(size_t numBaseOTs = 128);

  void doOTPhase(const BitVector &choices);

 private:
  KosDotExtReceiver OTeRecv;
  std::vector<block> OTs;
};

// SIMD

class SIMDGCEnv {
 public:
  SIMDGCEnv(ChannelWrapper &chan, size_t numinputs)
      : SIMDInputs(numinputs),
        channel(chan),
        gb(),
        gid(0),
        numANDs(0),
        numXORs(0) {}

  virtual WireLabel XOR(const WireLabel &a, const WireLabel &b) = 0;
  virtual SIMDWireLabel XOR(const SIMDWireLabel &a, const SIMDWireLabel &b) = 0;
  virtual SIMDWireLabel XOR(const SIMDWireLabel &a, const WireLabel &b) = 0;

  virtual SIMDWireLabel AND(const SIMDWireLabel &a, const SIMDWireLabel &b) = 0;

  virtual SIMDWireLabel NOT(const SIMDWireLabel &a) = 0;
  virtual WireLabel NOT(const WireLabel &a) = 0;

  virtual void PRINT(const char *info,
                     const std::vector<SIMDWireLabel> &vec) = 0;
  virtual void PRINT(const char *info, const std::vector<WireLabel> &vec) = 0;

  inline uint64_t getNumANDs() const { return numANDs; }
  inline uint64_t getNumXORs() const { return numXORs; }

  uint64_t SIMDInputs;

 protected:
  ChannelWrapper &channel;
  Hasher gb;
  uint64_t gid;
  uint64_t numANDs;
  uint64_t numXORs;
};

class SIMDGarbler : public SIMDGCEnv {
 public:
  SIMDGarbler(ChannelWrapper &chan, size_t numinputs, block delta = ZeroBlock);

  virtual std::vector<WireLabel> inputOfAlice(const BitVector &input);
  virtual std::vector<SIMDWireLabel> inputOfAlice(
      const std::vector<BitVector> &input);

  virtual std::vector<SIMDWireLabel> inputOfBob(const size_t size);

  virtual void outputToBob(const std::vector<SIMDWireLabel> &outputLabels);

  virtual WireLabel XOR(const WireLabel &a, const WireLabel &b);
  virtual SIMDWireLabel XOR(const SIMDWireLabel &a, const SIMDWireLabel &b);
  virtual SIMDWireLabel XOR(const SIMDWireLabel &a, const WireLabel &b);

  virtual SIMDWireLabel AND(const SIMDWireLabel &a, const SIMDWireLabel &b);

  virtual SIMDWireLabel NOT(const SIMDWireLabel &a);
  virtual WireLabel NOT(const WireLabel &a);

  virtual void PRINT(const char *info, const std::vector<SIMDWireLabel> &vec);
  virtual void PRINT(const char *info, const std::vector<WireLabel> &vec);

  void performBaseOTs(size_t numBaseOTs = 128);

  virtual void doOTPhase(size_t numOTs);

 protected:
  SecureRandom rnd;

  WireLabel R;
#ifdef USE_DOTE
  KosDotExtSender OTeSender;
#else
  KosOtExtSender OTeSender;
#endif
  std::vector<std::array<block, 2>> OTs;
};

class SIMDEvaluator : public SIMDGCEnv {
 public:
  SIMDEvaluator(ChannelWrapper &chan, size_t numinputs)
      : SIMDGCEnv(chan, numinputs) {}

  virtual std::vector<WireLabel> inputOfAlice(const size_t size);
  virtual std::vector<SIMDWireLabel> inputOfAliceSIMD(const size_t size);

  virtual std::vector<SIMDWireLabel> inputOfBob(
      const std::vector<BitVector> &input);

  virtual std::vector<BitVector> outputToBob(
      const std::vector<SIMDWireLabel> &outputLabels);

  virtual WireLabel XOR(const WireLabel &a, const WireLabel &b);
  virtual SIMDWireLabel XOR(const SIMDWireLabel &a, const SIMDWireLabel &b);
  virtual SIMDWireLabel XOR(const SIMDWireLabel &a, const WireLabel &b);

  virtual SIMDWireLabel AND(const SIMDWireLabel &a, const SIMDWireLabel &b);

  virtual SIMDWireLabel NOT(const SIMDWireLabel &a);
  virtual WireLabel NOT(const WireLabel &a);

  virtual void PRINT(const char *info, const std::vector<SIMDWireLabel> &vec);
  virtual void PRINT(const char *info, const std::vector<WireLabel> &vec);

  void performBaseOTs(size_t numBaseOTs = 128);

  virtual void doOTPhase(const BitVector &choices);

 protected:
#ifdef USE_DOTE
  KosDotExtReceiver OTeRecv;
#else
  KosOtExtReceiver OTeRecv;
#endif
  std::vector<block> OTs;
};

class SIMDGarblerPhases : public SIMDGarbler {
 public:
  SIMDGarblerPhases(ChannelWrapper &chan, size_t numinputs,
                    block delta = ZeroBlock);
  virtual ~SIMDGarblerPhases() = default;

  std::vector<WireLabel> inputOfAlice(const BitVector &input);

  std::vector<SIMDWireLabel> inputOfBobOffline(const size_t size);

  void inputOfBobOnline();

  void outputToBob(const std::vector<SIMDWireLabel> &outputLabels);

  virtual SIMDWireLabel AND(const SIMDWireLabel &a, const SIMDWireLabel &b);

  BufferChannel bufChan;

 private:
  std::vector<SIMDWireLabel> bobInputLabels;
};

class SIMDEvaluatorPhases : public SIMDEvaluator {
 public:
  SIMDEvaluatorPhases(ChannelWrapper &chan, size_t numinputs)
      : SIMDEvaluator(chan, numinputs) {}
  virtual ~SIMDEvaluatorPhases() = default;

  std::vector<WireLabel> inputOfAlice(const size_t size);

  std::vector<SIMDWireLabel> inputOfBobOnline(
      const std::vector<BitVector> &input, const BitVector &randChoices);

  std::vector<BitVector> outputToBob(
      const std::vector<SIMDWireLabel> &outputLabels);

  virtual SIMDWireLabel AND(const SIMDWireLabel &a, const SIMDWireLabel &b);

  BufferChannel bufChan;
};
}