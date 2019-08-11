#include <droidCrypto/ot/TwoChooseOne/IknpOtExtSender.h>

#include <droidCrypto/AES.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/ot/NaorPinkas.h>
#include <droidCrypto/utils/Log.h>
#include <droidCrypto/utils/Utils.h>

#include <chrono>

//#include <android/log.h>

namespace droidCrypto {

std::unique_ptr<OtExtSender> IknpOtExtSender::split() {
  std::unique_ptr<OtExtSender> ret(new IknpOtExtSender());

  std::array<block, gOtExtBaseOtCount> baseRecvOts;

  for (uint64_t i = 0; i < mGens.size(); ++i) {
    baseRecvOts[i] = mGens[i].get<block>();
  }

  ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

  return std::move(ret);
}

void IknpOtExtSender::setBaseOts(span<block> baseRecvOts,
                                 const BitVector &choices) {
  if (baseRecvOts.size() != gOtExtBaseOtCount ||
      choices.size() != gOtExtBaseOtCount)
    throw std::runtime_error("not supported/implemented");

  mBaseChoiceBits = choices;
  for (uint64_t i = 0; i < gOtExtBaseOtCount; i++) {
    mGens[i].SetSeed(baseRecvOts[i]);
  }
}

void IknpOtExtSender::send(span<std::array<block, 2>> messages, PRNG &prng,
                           ChannelWrapper &chan) {
  // round up
  uint64_t numOtExt = Utils::roundUpTo(messages.size(), 128);
  uint64_t numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
  // uint64_t numBlocks = numSuperBlocks * superBlkSize;

  // a temp that will be used to transpose the sender's matrix
  std::array<std::array<block, superBlkSize>, 128> t;
  std::vector<std::array<block, superBlkSize>> u(128 * commStepSize);

  std::array<block, 128> choiceMask;
  block delta = *(block *)mBaseChoiceBits.data();

  for (uint64_t i = 0; i < 128; ++i) {
    if (mBaseChoiceBits[i])
      choiceMask[i] = AllOneBlock;
    else
      choiceMask[i] = ZeroBlock;
  }

  auto mIter = messages.begin();

  block *uIter = (block *)u.data() + superBlkSize * 128 * commStepSize;
  block *uEnd = uIter;

  for (uint64_t superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    block *tIter = (block *)t.data();
    block *cIter = choiceMask.data();

    if (uIter == uEnd) {
      uint64_t step = std::min<uint64_t>(numSuperBlocks - superBlkIdx,
                                         (uint64_t)commStepSize);

      chan.recv((uint8_t *)u.data(), step * superBlkSize * 128 * sizeof(block));
      uIter = (block *)u.data();
    }

    // transpose 128 columns at at time. Each column will be 128 * superBlkSize
    // = 1024 bits long.
    for (uint64_t colIdx = 0; colIdx < 128; ++colIdx) {
      // generate the columns using AES-NI in counter mode.
      mGens[colIdx].mAes.encryptCTR(mGens[colIdx].mBlockIdx, superBlkSize,
                                    tIter);
      mGens[colIdx].mBlockIdx += superBlkSize;

      uIter[0] = uIter[0] & *cIter;
      uIter[1] = uIter[1] & *cIter;
      uIter[2] = uIter[2] & *cIter;
      uIter[3] = uIter[3] & *cIter;
      uIter[4] = uIter[4] & *cIter;
      uIter[5] = uIter[5] & *cIter;
      uIter[6] = uIter[6] & *cIter;
      uIter[7] = uIter[7] & *cIter;

      tIter[0] = tIter[0] ^ uIter[0];
      tIter[1] = tIter[1] ^ uIter[1];
      tIter[2] = tIter[2] ^ uIter[2];
      tIter[3] = tIter[3] ^ uIter[3];
      tIter[4] = tIter[4] ^ uIter[4];
      tIter[5] = tIter[5] ^ uIter[5];
      tIter[6] = tIter[6] ^ uIter[6];
      tIter[7] = tIter[7] ^ uIter[7];

      ++cIter;
      uIter += 8;
      tIter += 8;
    }

    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
    // each 128 bits wide.
    Utils::transpose128x1024(t);

    auto mEnd =
        mIter + std::min<uint64_t>(128 * superBlkSize, messages.end() - mIter);

    tIter = (block *)t.data();
    block *tEnd = (block *)t.data() + 128 * superBlkSize;

    while (mIter != mEnd) {
      while (mIter != mEnd && tIter < tEnd) {
        (*mIter)[0] = *tIter;
        (*mIter)[1] = *tIter ^ delta;

        tIter += superBlkSize;
        mIter += 1;
      }

      tIter = tIter - 128 * superBlkSize + 1;
    }

#ifdef IKNP_DEBUG
    BitVector choice(128 * superBlkSize);
    chl.recv(u.data(), superBlkSize * 128 * sizeof(block));
    chl.recv(choice.data(), sizeof(block) * superBlkSize);

    uint64_t doneIdx = mStart - messages.data();
    uint64_t xx = std::min<uint64_t>(
        i64(128 * superBlkSize), (messages.data() + messages.size()) - mEnd);
    for (uint64_t rowIdx = doneIdx, j = 0; j < xx; ++rowIdx, ++j) {
      if (neq(((block *)u.data())[j], messages[rowIdx][choice[j]])) {
        std::cout << rowIdx << std::endl;
        throw std::runtime_error("");
      }
    }
#endif
  }

#ifdef IKNP_SHA_HASH
  RandomOracle sha;
  u8 hashBuff[20];
  uint64_t doneIdx = 0;

  uint64_t bb = (messages.size() + 127) / 128;
  for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx) {
    uint64_t stop = std::min<uint64_t>(messages.size(), doneIdx + 128);

    for (uint64_t i = 0; doneIdx < stop; ++doneIdx, ++i) {
      // hash the message without delta
      sha.Reset();
      sha.Update((u8 *)&messages[doneIdx][0], sizeof(block));
      sha.Final(hashBuff);
      messages[doneIdx][0] = *(block *)hashBuff;

      // hash the message with delta
      sha.Reset();
      sha.Update((u8 *)&messages[doneIdx][1], sizeof(block));
      sha.Final(hashBuff);
      messages[doneIdx][1] = *(block *)hashBuff;
    }
  }
#else

  std::array<block, 8> aesHashTemp;

  uint64_t doneIdx = 0;
  uint64_t bb = (messages.size() + 127) / 128;
  for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx) {
    uint64_t stop = std::min<uint64_t>(messages.size(), doneIdx + 128);

    auto length = 2 * (stop - doneIdx);
    auto steps = length / 8;
    block *mIter = messages[doneIdx].data();
    for (uint64_t i = 0; i < steps; ++i) {
      mAesFixedKey.encryptECBBlocks(mIter, 8, aesHashTemp.data());
      mIter[0] = mIter[0] ^ aesHashTemp[0];
      mIter[1] = mIter[1] ^ aesHashTemp[1];
      mIter[2] = mIter[2] ^ aesHashTemp[2];
      mIter[3] = mIter[3] ^ aesHashTemp[3];
      mIter[4] = mIter[4] ^ aesHashTemp[4];
      mIter[5] = mIter[5] ^ aesHashTemp[5];
      mIter[6] = mIter[6] ^ aesHashTemp[6];
      mIter[7] = mIter[7] ^ aesHashTemp[7];

      mIter += 8;
    }

    auto rem = length - steps * 8;
    mAesFixedKey.encryptECBBlocks(mIter, rem, aesHashTemp.data());
    for (uint64_t i = 0; i < rem; ++i) {
      mIter[i] = mIter[i] ^ aesHashTemp[i];
    }

    doneIdx = stop;
  }

#endif

  static_assert(gOtExtBaseOtCount == 128, "expecting 128");
}

}  // namespace droidCrypto

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender
 * Method:    init
 * Signature: (Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)J
 */
jlong Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender_init(
    JNIEnv *env, jobject /* this */, jobject baseOTs, jbyteArray choices) {
  droidCrypto::IknpOtExtSender *sender = new droidCrypto::IknpOtExtSender();
  void *inputPtr = env->GetDirectBufferAddress(baseOTs);
  jlong inputLength = env->GetDirectBufferCapacity(baseOTs);

  jbyte *choicePtr = env->GetByteArrayElements(choices, NULL);
  jlong choiceLength = env->GetArrayLength(choices);
  droidCrypto::BitVector choizes((uint8_t *)choicePtr,
                                 choiceLength * 8);  // length is in bits
  env->ReleaseByteArrayElements(choices, choicePtr, JNI_ABORT);

  droidCrypto::span<droidCrypto::block> baseOTspan(
      (droidCrypto::block *)inputPtr, droidCrypto::gOtExtBaseOtCount);
  sender->setBaseOts(baseOTspan, choizes);
  return (jlong)sender;
}

/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender
 * Method:    send
 * Signature:
 * (JLjava/nio/ByteBuffer;Lcom/example/mobile_1psi/droidCrypto/Networking/Channel;)V
 */
void Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender_send(
    JNIEnv *env, jobject /*this*/, jlong object, jobject messages,
    jobject channel) {
  droidCrypto::IknpOtExtSender *sender = (droidCrypto::IknpOtExtSender *)object;
  //    droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 1);
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();
  // TODO: check if buffer is direct
  void *msgPtr = env->GetDirectBufferAddress(messages);
  jlong msgLength = env->GetDirectBufferCapacity(messages);
  //__android_log_print(ANDROID_LOG_VERBOSE, "Iknp-s", "msg: %p, %ld", msgPtr,
  //msgLength);
  droidCrypto::span<std::array<droidCrypto::block, 2>> mes(
      (std::array<droidCrypto::block, 2> *)msgPtr,
      msgLength / sizeof(std::array<droidCrypto::block, 2>));

  sender->send(mes, p, chan);
}
/*
 * Class:     com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender
 * Method:    deleteNativeObj
 * Signature: (J)V
 */
void Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtSender_deleteNativeObj(
    JNIEnv *env, jobject /* this */, jlong object) {
  droidCrypto::IknpOtExtSender *sender = (droidCrypto::IknpOtExtSender *)object;
  delete sender;
}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_IKNPSend(
    JNIEnv *env, jobject /*this*/) {
  droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 1);
  droidCrypto::NaorPinkas np;
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

  droidCrypto::BitVector choizes(128);  // length is in bits
  choizes.randomize(p);

  auto time1 = std::chrono::high_resolution_clock::now();
  std::array<droidCrypto::block, 128> baseOT;
  np.receive(choizes, baseOT, p, chan);
  auto time2 = std::chrono::high_resolution_clock::now();
  droidCrypto::IknpOtExtSender sender;
  sender.setBaseOts(baseOT, choizes);

  std::vector<std::array<droidCrypto::block, 2>> mesBuf(1024 * 1024 * 16);
  droidCrypto::span<std::array<droidCrypto::block, 2>> mes(mesBuf.data(),
                                                           mesBuf.size());
  sender.send(mes, p, chan);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> baseOTs = time2 - time1;
  std::chrono::duration<double> OTes = time3 - time2;
  droidCrypto::Log::v("OTe", "SENDER: BaseOTs: %fsec, OTe: %fsec", baseOTs,
                      OTes);
}
