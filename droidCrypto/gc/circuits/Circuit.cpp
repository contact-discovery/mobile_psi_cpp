#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/HalfGate.h>
#include <droidCrypto/gc/WireLabel.h>
#include <droidCrypto/gc/circuits/Circuit.h>

#include <assert.h>
#include <droidCrypto/utils/Log.h>
#include <endian.h>
#include <chrono>

namespace droidCrypto {

void Circuit::garble(const BitVector &inputA) {
  Garbler g(channel);
  auto time1 = std::chrono::high_resolution_clock::now();

  g.performBaseOTs();

  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  assert(inputA.size() == mInputA_size);
  std::vector<WireLabel> aliceInput = g.inputOfAlice(inputA);
  std::vector<WireLabel> bobInput = g.inputOfBob(mInputB_size);

  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  std::vector<WireLabel> outputs = computeFunction(aliceInput, bobInput, g);

  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  g.outputToBob(outputs);
  auto time5 = std::chrono::high_resolution_clock::now();
  timeOutput = time5 - time4;

  return;
}

BitVector Circuit::evaluate(const BitVector &inputB) {
  Evaluator e(channel);
  auto time1 = std::chrono::high_resolution_clock::now();

  e.performBaseOTs();

  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  assert(inputB.size() == mInputB_size);
  std::vector<WireLabel> aliceInput = e.inputOfAlice(mInputA_size);
  std::vector<WireLabel> bobInput = e.inputOfBob(inputB);

  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  std::vector<WireLabel> outputs = computeFunction(aliceInput, bobInput, e);

  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  Log::v("GC", "numANDs: %zu", e.getNumANDs());

  BitVector output = e.outputToBob(outputs);
  auto time5 = std::chrono::high_resolution_clock::now();
  timeOutput = time5 - time4;

  return output;
}
//------------------------------------------------------------------------------------------------------------------
// SIMD

void SIMDCircuit::garble(const BitVector &inputA, const size_t SIMDvalues) {
  size_t transfer = htobe64(SIMDvalues);
  channel.send((uint8_t *)&transfer, sizeof(transfer));
  SIMDGarbler g(channel, SIMDvalues);
  auto time1 = std::chrono::high_resolution_clock::now();

  g.performBaseOTs();

  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  assert(inputA.size() == mInputA_size);
  std::vector<WireLabel> aliceInput = g.inputOfAlice(inputA);
  std::vector<SIMDWireLabel> bobInput = g.inputOfBob(mInputB_size);

  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  std::vector<SIMDWireLabel> outputs = computeFunction(aliceInput, bobInput, g);

  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  g.outputToBob(outputs);
  auto time5 = std::chrono::high_resolution_clock::now();
  timeOutput = time5 - time4;

  return;
}

void SIMDCircuit::garbleSIMD(const std::vector<BitVector> &inputA) {
  const size_t SIMDvalues = inputA.size();
  size_t transfer = htobe64(SIMDvalues);
  channel.send((uint8_t *)&transfer, sizeof(transfer));
  SIMDGarbler g(channel, SIMDvalues);
  auto time1 = std::chrono::high_resolution_clock::now();

  g.performBaseOTs();

  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  assert(inputA.front().size() == mInputA_size);
  std::vector<SIMDWireLabel> aliceInput = g.inputOfAlice(inputA);
  std::vector<SIMDWireLabel> bobInput = g.inputOfBob(mInputB_size);

  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  std::vector<SIMDWireLabel> outputs = computeFunction(aliceInput, bobInput, g);

  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  g.outputToBob(outputs);
  auto time5 = std::chrono::high_resolution_clock::now();
  timeOutput = time5 - time4;

  return;
}

std::vector<BitVector> SIMDCircuit::evaluate(
    const std::vector<BitVector> &inputB) {
  size_t transfer;
  channel.recv((uint8_t *)&transfer, sizeof(transfer));
  transfer = be64toh(transfer);
  const size_t SIMDvalues = inputB.size();
  Log::v("GC", "SIMD: %zu, transfer:%zu", SIMDvalues, transfer);
  assert(SIMDvalues == transfer);

  SIMDEvaluator e(channel, SIMDvalues);
  auto time1 = std::chrono::high_resolution_clock::now();

  e.performBaseOTs();
  Log::v("GC", "baseOTs done");

  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  assert(inputB.front().size() == mInputB_size);
  std::vector<WireLabel> aliceInput = e.inputOfAlice(mInputA_size);
  Log::v("GC", "inputA done");

  Log::v("GC", "inputA sent: %zu, recv: %zu", channel.getBytesSent(),
         channel.getBytesRecv());
  std::vector<SIMDWireLabel> bobInput = e.inputOfBob(inputB);

  Log::v("GC", "inputB done");

  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  std::vector<SIMDWireLabel> outputs = computeFunction(aliceInput, bobInput, e);

  Log::v("GC", "compute done");

  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  Log::v("GC", "numANDs: %zu; numXORs: %zu", e.getNumANDs(), e.getNumXORs());

  std::vector<BitVector> output = e.outputToBob(outputs);
  auto time5 = std::chrono::high_resolution_clock::now();
  timeOutput = time5 - time4;
  Log::v("GC", "output done");

  return output;
}

std::vector<BitVector> SIMDCircuit::evaluateSIMD(
    const std::vector<BitVector> &inputB) {
  size_t transfer;
  channel.recv((uint8_t *)&transfer, sizeof(transfer));
  transfer = be64toh(transfer);
  const size_t SIMDvalues = inputB.size();
  Log::v("GC", "SIMD: %zu, transfer:%zu", SIMDvalues, transfer);
  assert(SIMDvalues == transfer);

  SIMDEvaluator e(channel, SIMDvalues);
  auto time1 = std::chrono::high_resolution_clock::now();

  e.performBaseOTs();
  Log::v("GC", "baseOTs done");

  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  assert(inputB.front().size() == mInputB_size);
  std::vector<SIMDWireLabel> aliceInput = e.inputOfAliceSIMD(mInputA_size);
  Log::v("GC", "inputA done");

  Log::v("GC", "inputA sent: %zu, recv: %zu", channel.getBytesSent(),
         channel.getBytesRecv());
  std::vector<SIMDWireLabel> bobInput = e.inputOfBob(inputB);

  Log::v("GC", "inputB done");

  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  std::vector<SIMDWireLabel> outputs = computeFunction(aliceInput, bobInput, e);

  Log::v("GC", "compute done");

  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  Log::v("GC", "numANDs: %zu", e.getNumANDs());

  std::vector<BitVector> output = e.outputToBob(outputs);
  auto time5 = std::chrono::high_resolution_clock::now();
  timeOutput = time5 - time4;
  Log::v("GC", "output done");

  return output;
}

//----------------------------------------------------------------------------------------------------------------------

void SIMDCircuitPhases::garbleBase(const BitVector &inputA,
                                   const size_t SIMDvalues) {
  g = new SIMDGarblerPhases(channel, SIMDvalues);
  auto time1 = std::chrono::high_resolution_clock::now();

  g->performBaseOTs();
  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;
  g->doOTPhase(mInputB_size * SIMDvalues);
  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  assert(inputA.size() == mInputA_size);
  // build GC into bufChan
  std::vector<WireLabel> aliceInput = g->inputOfAlice(inputA);
  std::vector<SIMDWireLabel> bobInput = g->inputOfBobOffline(mInputB_size);
  std::vector<SIMDWireLabel> outputs =
      computeFunction(aliceInput, bobInput, *g);
  g->outputToBob(outputs);
  auto time4 = std::chrono::high_resolution_clock::now();
  timeEval = time4 - time3;

  std::vector<uint8_t> gcs = g->bufChan.getBuffer();
  uint64_t gc_size = gcs.size();
  size_t transfer;
  transfer = htobe64(gc_size);
  channel.send((uint8_t *)&transfer, sizeof(transfer));
  time4 = std::chrono::high_resolution_clock::now();
  channel.send(gcs.data(), gc_size);

  Log::v("GC", "Base comm: %fMiB sent, %fMiB recv",
         channel.getBytesSent() / 1024.0 / 1024.0,
         channel.getBytesRecv() / 1024.0 / 1024.0);
  Log::v("GC", "size of GCs: %zu bytes", gc_size);
  channel.clearStats();
  auto time5 = std::chrono::high_resolution_clock::now();
  timeSendGC = time5 - time4;
  Log::v("GC", "Base phase: %fsec, send: %fsec, total %fsec",
         std::chrono::duration<double>(time4 - time1).count(),
         timeSendGC.count(),
         std::chrono::duration<double>(time5 - time1).count());
}

void SIMDCircuitPhases::garbleOnline() {
  auto time1 = std::chrono::high_resolution_clock::now();
  g->inputOfBobOnline();
  auto time2 = std::chrono::high_resolution_clock::now();
  timeOnline = time2 - time1;

  Log::v("GC", "Online comm: %fKiB sent, %fKiB recv",
         channel.getBytesSent() / 1024.0, channel.getBytesRecv() / 1024.0);
  channel.clearStats();
}

void SIMDCircuitPhases::evaluateBase(size_t SIMDvalues) {
  e = new SIMDEvaluatorPhases(channel, SIMDvalues);
  auto time1 = std::chrono::high_resolution_clock::now();

  e->performBaseOTs();
  auto time2 = std::chrono::high_resolution_clock::now();
  timeBaseOT = time2 - time1;

  PRNG p = PRNG::getTestPRNG();
  randChoices_.reset(SIMDvalues * mInputB_size);
  randChoices_.randomize(p);
  e->doOTPhase(randChoices_);
  //        Log::v("GC", "baseOTs done");
  auto time3 = std::chrono::high_resolution_clock::now();
  timeOT = time3 - time2;

  size_t transfer;
  channel.recv((uint8_t *)&transfer, sizeof(transfer));
  time3 = std::chrono::high_resolution_clock::now();
  uint64_t gc_size = be64toh(transfer);

  std::vector<uint8_t> gcs(gc_size);
  channel.recv(gcs.data(), gcs.size());
  e->bufChan.setBuffer(gcs);

  auto time4 = std::chrono::high_resolution_clock::now();
  timeSendGC = time4 - time3;
}

std::vector<BitVector> SIMDCircuitPhases::evaluateOnline(
    const std::vector<BitVector> &inputB) {
  auto time4 = std::chrono::high_resolution_clock::now();

  assert(inputB.front().size() == mInputB_size);
  std::vector<WireLabel> aliceInput = e->inputOfAlice(mInputA_size);
  //        Log::v("GC", "inputA done");

  std::vector<SIMDWireLabel> bobInput =
      e->inputOfBobOnline(inputB, randChoices_);

  //        Log::v("GC", "inputB done");

  std::vector<SIMDWireLabel> outputs =
      computeFunction(aliceInput, bobInput, *e);

  //        Log::v("GC", "compute done");

  std::vector<BitVector> output = e->outputToBob(outputs);
  //        Log::v("GC", "output done");

  auto time5 = std::chrono::high_resolution_clock::now();
  timeEval = time5 - time4;

  return output;
}
}  // namespace droidCrypto
