#include <droidCrypto/ot/TwoChooseOne/IknpOtExtReceiver.h>

#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/ot/NaorPinkas.h>
#include <droidCrypto/utils/Log.h>
#include <droidCrypto/utils/Utils.h>

#include <chrono>
//#include <android/log.h>

namespace droidCrypto {
void IknpOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs) {
  if (baseOTs.size() != gOtExtBaseOtCount) throw std::runtime_error(LOCATION);

  for (uint64_t i = 0; i < gOtExtBaseOtCount; i++) {
    mGens[i][0].SetSeed(baseOTs[i][0]);
    mGens[i][1].SetSeed(baseOTs[i][1]);
  }

  mHasBase = true;
}
std::unique_ptr<OtExtReceiver> IknpOtExtReceiver::split() {
  std::array<std::array<block, 2>, gOtExtBaseOtCount> baseRecvOts;

  for (uint64_t i = 0; i < mGens.size(); ++i) {
    baseRecvOts[i][0] = mGens[i][0].get<block>();
    baseRecvOts[i][1] = mGens[i][1].get<block>();
  }

  std::unique_ptr<OtExtReceiver> ret(new IknpOtExtReceiver());

  ret->setBaseOts(baseRecvOts);

  return std::move(ret);
}

void IknpOtExtReceiver::receive(const BitVector &choices, span<block> messages,
                                PRNG &prng, ChannelWrapper &chan) {
  if (mHasBase == false) throw std::runtime_error("rt error at " LOCATION);

  // we are going to process OTs in blocks of 128 * superBlkSize messages.
  uint64_t numOtExt = Utils::roundUpTo(choices.size(), 128);
  uint64_t numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
  uint64_t numBlocks = numSuperBlocks * superBlkSize;

  BitVector choices2(numBlocks * 128);
  choices2 = choices;
  choices2.resize(numBlocks * 128);

  auto choiceBlocks = choices2.getSpan<block>();
  // this will be used as temporary buffers of 128 columns,
  // each containing 1024 bits. Once transposed, they will be copied
  // into the T1, T0 buffers for long term storage.
  std::array<std::array<block, superBlkSize>, 128> t0;

  // the index of the OT that has been completed.
  // uint64_t doneIdx = 0;

  auto mIter = messages.begin();

  uint64_t step = std::min<uint64_t>(numSuperBlocks, (uint64_t)commStepSize);
  std::vector<block> uBuff(step * 128 * superBlkSize);

  // get an array of blocks that we will fill.
  auto uIter = (block *)uBuff.data();
  auto uEnd = uIter + uBuff.size();

  // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
  //   Instead we break it down into smaller chunks. We do 128 columns
  //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
  //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
  //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a
  //   time. So that's what we do.
  std::chrono::duration<double> time_aes =
      std::chrono::duration<double>::zero();
  std::chrono::duration<double> time_send =
      std::chrono::duration<double>::zero();
  std::chrono::duration<double> time_trans =
      std::chrono::duration<double>::zero();
  for (uint64_t superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    auto time1 = std::chrono::high_resolution_clock::now();
    // this will store the next 128 rows of the matrix u

    block *tIter = (block *)t0.data();
    block *cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;

    for (uint64_t colIdx = 0; colIdx < 128; ++colIdx) {
      // generate the column indexed by colIdx. This is done with
      // AES in counter mode acting as a PRNG. We don'tIter use the normal
      // PRNG interface because that would result in a data copy when
      // we move it into the T0,T1 matrices. Instead we do it directly.
      mGens[colIdx][0].mAes.encryptCTR(mGens[colIdx][0].mBlockIdx, superBlkSize,
                                       tIter);
      mGens[colIdx][1].mAes.encryptCTR(mGens[colIdx][1].mBlockIdx, superBlkSize,
                                       uIter);

      // increment the counter mode idx.
      mGens[colIdx][0].mBlockIdx += superBlkSize;
      mGens[colIdx][1].mBlockIdx += superBlkSize;

      uIter[0] = uIter[0] ^ cIter[0];
      uIter[1] = uIter[1] ^ cIter[1];
      uIter[2] = uIter[2] ^ cIter[2];
      uIter[3] = uIter[3] ^ cIter[3];
      uIter[4] = uIter[4] ^ cIter[4];
      uIter[5] = uIter[5] ^ cIter[5];
      uIter[6] = uIter[6] ^ cIter[6];
      uIter[7] = uIter[7] ^ cIter[7];

      uIter[0] = uIter[0] ^ tIter[0];
      uIter[1] = uIter[1] ^ tIter[1];
      uIter[2] = uIter[2] ^ tIter[2];
      uIter[3] = uIter[3] ^ tIter[3];
      uIter[4] = uIter[4] ^ tIter[4];
      uIter[5] = uIter[5] ^ tIter[5];
      uIter[6] = uIter[6] ^ tIter[6];
      uIter[7] = uIter[7] ^ tIter[7];

      uIter += 8;
      tIter += 8;
    }
    auto time2 = std::chrono::high_resolution_clock::now();

    if (uIter == uEnd) {
      // send over u buffer
      chan.send(uBuff);

      uint64_t step = std::min<uint64_t>(numSuperBlocks - superBlkIdx - 1,
                                         (uint64_t)commStepSize);

      if (step) {
        uBuff.resize(step * 128 * superBlkSize);
        uIter = (block *)uBuff.data();
        uEnd = uIter + uBuff.size();
      }
    }
    auto time3 = std::chrono::high_resolution_clock::now();

    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
    // each 128 bits wide.
    Utils::transpose128x1024(t0);

    auto time4 = std::chrono::high_resolution_clock::now();

    time_aes += time2 - time1;
    time_send += time3 - time2;
    time_trans += time4 - time3;
    // block* mStart = mIter;
    // block* mEnd = std::min<block*>(mIter + 128 * superBlkSize,
    // &*messages.end());
    auto mEnd =
        mIter + std::min<uint64_t>(128 * superBlkSize, messages.end() - mIter);

    tIter = (block *)t0.data();
    block *tEnd = (block *)t0.data() + 128 * superBlkSize;

    while (mIter != mEnd) {
      while (mIter != mEnd && tIter < tEnd) {
        (*mIter) = *tIter;

        tIter += superBlkSize;
        mIter += 1;
      }

      tIter = tIter - 128 * superBlkSize + 1;
    }
  }
  Log::v("OTE", "AES: %f, SEND: %f, TRANS: %f", time_aes, time_send,
         time_trans);

#ifdef IKNP_SHA_HASH
  RandomOracle sha;
  u8 hashBuff[20];
#else
  std::array<block, 8> aesHashTemp;
#endif

  uint64_t doneIdx = (0);

  uint64_t bb = (messages.size() + 127) / 128;
  for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx) {
    uint64_t stop = std::min<uint64_t>(messages.size(), doneIdx + 128);

#ifdef IKNP_SHA_HASH
    for (uint64_t i = 0; doneIdx < stop; ++doneIdx, ++i) {
      // hash it
      sha.Reset();
      sha.Update((u8 *)&messages[doneIdx], sizeof(block));
      sha.Final(hashBuff);
      messages[doneIdx] = *(block *)hashBuff;
    }
#else
    auto length = stop - doneIdx;
    auto steps = length / 8;
    block *mIter = messages.data() + doneIdx;
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
#endif
  }

  static_assert(gOtExtBaseOtCount == 128, "expecting 128");
}

}  // namespace droidCrypto

jlong Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver_init(
    JNIEnv *env, jobject /* this */, jobject baseOTs) {
  droidCrypto::IknpOtExtReceiver *receiver =
      new droidCrypto::IknpOtExtReceiver();
  void *inputPtr = env->GetDirectBufferAddress(baseOTs);
  jlong inputLength = env->GetDirectBufferCapacity(baseOTs);
  droidCrypto::span<std::array<droidCrypto::block, 2>> baseOTspan(
      (std::array<droidCrypto::block, 2> *)inputPtr,
      droidCrypto::gOtExtBaseOtCount);
  receiver->setBaseOts(baseOTspan);
  return (jlong)receiver;
}

void Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver_recv(
    JNIEnv *env, jobject this_obj, jlong object, jobject messages,
    jbyteArray choices, jobject channel) {
  droidCrypto::IknpOtExtReceiver *receiver =
      (droidCrypto::IknpOtExtReceiver *)object;
  //    droidCrypto::JavaChannelWrapper chan(env, channel);
  droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 0);
  void *msgPtr = env->GetDirectBufferAddress(messages);
  jlong msgLength = env->GetDirectBufferCapacity(messages);

  //__android_log_print(ANDROID_LOG_VERBOSE, "Iknp-r", "msg: %p, %ld", msgPtr,
  //msgLength);
  jbyte *choicePtr = env->GetByteArrayElements(choices, NULL);
  jlong choiceLength = env->GetArrayLength(choices);
  //__android_log_print(ANDROID_LOG_VERBOSE, "Iknp-r", "choice: %p, %ld",
  //choicePtr, choiceLength);
  droidCrypto::BitVector choizes((uint8_t *)choicePtr,
                                 choiceLength * 8);  // length is in bits
  env->ReleaseByteArrayElements(choices, choicePtr, JNI_ABORT);

  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();
  droidCrypto::span<droidCrypto::block> mes(
      (droidCrypto::block *)msgPtr, msgLength / sizeof(droidCrypto::block));
  receiver->receive(choizes, mes, p, chan);
}

void Java_com_example_mobile_1psi_droidCrypto_OT_IknpOTExtReceiver_deleteNativeObj(
    JNIEnv *env, jobject /* this */, jlong object) {
  droidCrypto::IknpOtExtReceiver *receiver =
      (droidCrypto::IknpOtExtReceiver *)object;
  delete receiver;
}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_IKNPRecv(
    JNIEnv *env, jobject /*this*/) {
  droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 0);
  droidCrypto::NaorPinkas np;
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

  auto time1 = std::chrono::high_resolution_clock::now();
  std::array<std::array<droidCrypto::block, 2>, 128> baseOT;
  np.send(baseOT, p, chan);
  auto time2 = std::chrono::high_resolution_clock::now();
  droidCrypto::IknpOtExtReceiver recv;
  recv.setBaseOts(baseOT);

  droidCrypto::BitVector choizes(1024 * 1024 * 16);
  choizes.randomize(p);
  std::vector<droidCrypto::block> mesBuf(1024 * 1024 * 16);
  droidCrypto::span<droidCrypto::block> mes(mesBuf.data(), mesBuf.size());
  recv.receive(choizes, mes, p, chan);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> baseOTs = time2 - time1;
  std::chrono::duration<double> OTes = time3 - time2;
  droidCrypto::Log::v("OTe", "RECVER: BaseOTs: %fsec, OTe: %fsec", baseOTs,
                      OTes);
}
