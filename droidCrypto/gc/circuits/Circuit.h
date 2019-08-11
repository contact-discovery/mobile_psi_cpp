#pragma once

#include <droidCrypto/BitVector.h>
#include <droidCrypto/Defines.h>
#include <droidCrypto/gc/WireLabel.h>

#include <droidCrypto/gc/HalfGate.h>
#include <cassert>
#include <chrono>

namespace droidCrypto {
class ChannelWrapper;
class GCEnv;
class SIMDGCEnv;

class Circuit {
 public:
  Circuit(ChannelWrapper &chan, size_t inputA_size, size_t inputB_size,
          size_t output_size)
      : channel(chan),
        mInputA_size(inputA_size),
        mInputB_size(inputB_size),
        mOutput_size(output_size) {}

  void garble(const BitVector &inputA);
  BitVector evaluate(const BitVector &inputB);

  std::chrono::duration<double> timeBaseOT;
  std::chrono::duration<double> timeOT;
  std::chrono::duration<double> timeEval;
  std::chrono::duration<double> timeOutput;

 protected:
  virtual std::vector<WireLabel> computeFunction(
      const std::vector<WireLabel> &inputA,
      const std::vector<WireLabel> &inputB, GCEnv &env) = 0;

  ChannelWrapper &channel;
  const size_t mInputA_size;
  const size_t mInputB_size;
  const size_t mOutput_size;
};

class SIMDCircuit {
 public:
  SIMDCircuit(ChannelWrapper &chan, size_t inputA_size, size_t inputB_size,
              size_t output_size)
      : timeBaseOT(std::chrono::duration<double>::zero()),
        timeOT(std::chrono::duration<double>::zero()),
        timeEval(std::chrono::duration<double>::zero()),
        timeOutput(std::chrono::duration<double>::zero()),
        channel(chan),
        mInputA_size(inputA_size),
        mInputB_size(inputB_size),
        mOutput_size(output_size) {}

  void garble(const BitVector &inputA, const size_t SIMDvalues);
  void garbleSIMD(const std::vector<BitVector> &inputA);
  std::vector<BitVector> evaluate(const std::vector<BitVector> &inputB);
  std::vector<BitVector> evaluateSIMD(const std::vector<BitVector> &inputB);

  std::chrono::duration<double> timeBaseOT;
  std::chrono::duration<double> timeOT;
  std::chrono::duration<double> timeEval;
  std::chrono::duration<double> timeOutput;

 protected:
  virtual std::vector<SIMDWireLabel> computeFunction(
      const std::vector<WireLabel> &inputA,
      const std::vector<SIMDWireLabel> &inputB, SIMDGCEnv &env) {
    assert(false);
    return std::vector<SIMDWireLabel>();
  };
  virtual std::vector<SIMDWireLabel> computeFunction(
      const std::vector<SIMDWireLabel> &inputA,
      const std::vector<SIMDWireLabel> &inputB, SIMDGCEnv &env) {
    assert(false);
    return std::vector<SIMDWireLabel>();
  };

  ChannelWrapper &channel;
  const size_t mInputA_size;
  const size_t mInputB_size;
  const size_t mOutput_size;
};

class SIMDCircuitPhases {
 public:
  SIMDCircuitPhases(ChannelWrapper &chan, size_t inputA_size,
                    size_t inputB_size, size_t output_size)
      : timeBaseOT(std::chrono::duration<double>::zero()),
        timeOT(std::chrono::duration<double>::zero()),
        timeEval(std::chrono::duration<double>::zero()),
        timeSendGC(std::chrono::duration<double>::zero()),
        timeOnline(std::chrono::duration<double>::zero()),
        channel(chan),
        g(nullptr),
        e(nullptr),
        mInputA_size(inputA_size),
        mInputB_size(inputB_size),
        mOutput_size(output_size) {}

  virtual ~SIMDCircuitPhases() {
    delete g;
    delete e;
  }

  void garbleBase(const BitVector &inputA, const size_t SIMDvalues);
  void garbleOnline();
  void evaluateBase(size_t SIMDvalues);
  std::vector<BitVector> evaluateOnline(const std::vector<BitVector> &inputB);

  std::chrono::duration<double> timeBaseOT;
  std::chrono::duration<double> timeOT;
  std::chrono::duration<double> timeEval;
  std::chrono::duration<double> timeSendGC;
  std::chrono::duration<double> timeOnline;

 protected:
  virtual std::vector<SIMDWireLabel> computeFunction(
      const std::vector<WireLabel> &inputA,
      const std::vector<SIMDWireLabel> &inputB, SIMDGCEnv &env) {
    assert(false);
    return std::vector<SIMDWireLabel>();
  };

  ChannelWrapper &channel;
  SIMDGarblerPhases *g;
  SIMDEvaluatorPhases *e;
  BitVector randChoices_;
  const size_t mInputA_size;
  const size_t mInputB_size;
  const size_t mOutput_size;
};
}