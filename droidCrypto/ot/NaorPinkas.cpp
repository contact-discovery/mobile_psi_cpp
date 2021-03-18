#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/RCurve.h>
#include <droidCrypto/RandomOracle.h>
#include <droidCrypto/ot/NaorPinkas.h>

//#include <android/log.h>

namespace droidCrypto {

void NaorPinkas::receive(const BitVector &choices, span<block> messages,
                         PRNG &prng, ChannelWrapper &chan) {
  auto nSndVals(2);

  size_t mStart = 0;
  size_t mEnd = messages.size();
  // Log::v("naor-pinkas-r", "messages: %zu", messages.size());

  REllipticCurve curve;

  auto g = curve.getGenerator();
  REccBrick brick_g(g);
  uint64_t fieldElementSize = g.sizeBytes();

  // Log::v("naor-pinkas-r", "fieldElement: %zu", fieldElementSize);
  std::vector<uint8_t> sendBuff(messages.size() * fieldElementSize);
  std::vector<uint8_t> cBuff(nSndVals * fieldElementSize);

  REccPoint PK0(curve);

  std::vector<REccNumber> pK;
  std::vector<REccPoint> PK_sigma, pC;

  pK.reserve(mEnd - mStart);
  PK_sigma.reserve(mEnd - mStart);
  pC.reserve(nSndVals);

  for (uint64_t i = mStart, j = 0; i < mEnd; ++i, ++j) {
    // get a random value from Z_p
    pK.emplace_back(curve);
    pK[j].randomize(prng);

    // compute
    //
    //      PK_sigma[i] = g ^ pK[i]
    //
    // where pK[i] is just a random number in Z_p
    PK_sigma.emplace_back(curve);
    PK_sigma[j] = brick_g * pK[j];
  }

  // get the values from the channel
  // Log::v("naor-pinkas-r", "Before recv call!");
  chan.recv(cBuff.data(), cBuff.size());
  // Log::v("naor-pinkas-r", "After recv call!");
  auto pBufIdx = cBuff.begin();

  for (auto u = 0; u < nSndVals; u++) {
    pC.emplace_back(curve);

    pC[u].fromBytes(&*pBufIdx);
    pBufIdx += fieldElementSize;
  }

  auto iter = sendBuff.data() + mStart * fieldElementSize;

  for (uint64_t i = mStart, j = 0; i < mEnd; ++i, ++j) {
    uint8_t choice = choices[i];
    if (choice != 0) {
      PK0 = pC[choice] - PK_sigma[j];
    } else {
      PK0 = PK_sigma[j];
    }

    PK0.toBytes(iter);
    iter += fieldElementSize;
  }

  // resuse this space, not the data of PK0...
  auto &gka = PK0;
  REccBrick brick_pc0(pC[0]);
  RandomOracle sha(sizeof(block));

  std::vector<uint8_t> buff(fieldElementSize);

  for (uint64_t i = mStart, j = 0; i < mEnd; ++i, ++j) {
    // now compute g ^(a * k) = (g^a)^k
    gka = brick_pc0 * pK[j];
    gka.toBytes(buff.data());

    sha.Reset();
    sha.Update((uint8_t *)&i, sizeof(i));
    sha.Update(buff.data(), buff.size());
    sha.Final(messages[i]);
  }

  // Log::v("naor-pinkas-r", "Before send call!");
  chan.send(sendBuff.data(), sendBuff.size());
  BitVector test(sendBuff.data(), sendBuff.size() * 8);
  // Log::v("naor-pinkas-r", "%s", test.hex().c_str());
  // Log::v("naor-pinkas-r", "After send call!");
}

void NaorPinkas::send(span<std::array<block, 2>> messages, PRNG &prng,
                      ChannelWrapper &chan) {
  size_t nSndVals(2);
  REllipticCurve curve;
  REccNumber alpha(curve, prng);
  REccNumber tmp(curve);
  std::vector<REccPoint> pC;
  pC.reserve(nSndVals);

  const REccPoint g = curve.getGenerator();
  REccBrick brick_g(g);
  uint64_t fieldElementSize = g.sizeBytes();

  std::vector<uint8_t> sendBuff(nSndVals * fieldElementSize);

  pC.emplace_back(curve);
  pC[0] = brick_g * alpha;
  pC[0].toBytes(sendBuff.data());

  for (uint64_t u = 1; u < nSndVals; u++) {
    pC.emplace_back(curve);
    tmp.randomize(prng);

    pC[u] = brick_g * tmp;
    pC[u].toBytes(sendBuff.data() + u * fieldElementSize);
  }

  // Log::v("naor-pinkas-s", "Before send call!");
  chan.send(sendBuff.data(), sendBuff.size());
  // Log::v("naor-pinkas-s", "After send call!");

  for (uint64_t u = 1; u < nSndVals; u++) pC[u] = pC[u] * alpha;

  std::vector<uint8_t> recvBuff(fieldElementSize * messages.size());
  // Log::v("naor-pinkas-s", "Before recv call!");
  chan.recv(recvBuff.data(), recvBuff.size());
  BitVector test(recvBuff.data(), recvBuff.size() * 8);
  // Log::v("naor-pinkas-s", "%s", test.hex().c_str());
  // Log::v("naor-pinkas-s", "After recv call!");

  REccPoint pPK0(curve), PK0a(curve), fetmp(curve);

  std::vector<uint8_t> hashInBuff(fieldElementSize);
  RandomOracle sha(sizeof(block));

  for (uint64_t i = 0; i < uint64_t(messages.size()); i++) {
    pPK0.fromBytes(recvBuff.data() + i * fieldElementSize);
    PK0a = pPK0 * alpha;
    PK0a.toBytes(hashInBuff.data());

    sha.Reset();
    sha.Update((uint8_t *)&i, sizeof(i));
    sha.Update(hashInBuff.data(), hashInBuff.size());
    sha.Final(messages[i][0]);

    for (uint64_t u = 1; u < nSndVals; u++) {
      fetmp = pC[u] - PK0a;
      fetmp.toBytes(hashInBuff.data());

      sha.Reset();
      sha.Update((uint8_t *)&i, sizeof(i));
      sha.Update(hashInBuff.data(), hashInBuff.size());
      sha.Final(messages[i][u]);
    }
  }
}

}  // namespace droidCrypto

JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_OT_NaorPinkas_recv(JNIEnv *env,
                                                            jobject /*this*/,
                                                            jobject messages,
                                                            jbyteArray choices,
                                                            jobject channel) {
  droidCrypto::NaorPinkas np;
  droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();
  void *msgPtr = env->GetDirectBufferAddress(messages);
  jlong msgLength = env->GetDirectBufferCapacity(messages);

  // Log::v("naor-pinkas-r", "msg: %p, %ld", msgPtr, msgLength);
  jbyte *choicePtr = env->GetByteArrayElements(choices, NULL);
  jlong choiceLength = env->GetArrayLength(choices);
  // Log::v("naor-pinkas-r", "choice: %p, %ld", choicePtr, choiceLength);
  droidCrypto::BitVector choizes((uint8_t *)choicePtr,
                                 choiceLength * 8);  // length is in bits
  env->ReleaseByteArrayElements(choices, choicePtr, JNI_ABORT);

  droidCrypto::span<droidCrypto::block> mes(
      (droidCrypto::block *)msgPtr, msgLength / sizeof(droidCrypto::block));

  // Log::v("naor-pinkas-r", "Casting recv ok!");
  np.receive(choizes, mes, p, chan);
  droidCrypto::BitVector test((uint8_t *)msgPtr, msgLength * 8);
  // Log::v("naor-pinkas-r", "mes: %s", test.hex().c_str());
  // Log::v("naor-pinkas-r", "Native Recv done!");
}

JNIEXPORT void JNICALL
Java_com_example_mobile_1psi_droidCrypto_OT_NaorPinkas_send(JNIEnv *env,
                                                            jobject /*this*/,
                                                            jobject messages,
                                                            jobject channel) {
  droidCrypto::NaorPinkas np;
  droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();
  void *msgPtr = env->GetDirectBufferAddress(messages);
  jlong msgLength = env->GetDirectBufferCapacity(messages);
  droidCrypto::span<std::array<droidCrypto::block, 2>> mes(
      (std::array<droidCrypto::block, 2> *)msgPtr,
      msgLength / sizeof(std::array<droidCrypto::block, 2>));

  // Log::v("naor-pinkas-s", "Casting send ok!");
  // Log::v("naor-pinkas-s", "msg: %p, %ld", msgPtr, msgLength);
  np.send(mes, p, chan);
  droidCrypto::BitVector test((uint8_t *)msgPtr, msgLength * 8);
  // Log::v("naor-pinkas-s", "mes: %s", test.hex().c_str());
  // Log::v("naor-pinkas-s", "Native Send done!");
}
