#include "IknpDotExtReceiver.h"

#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/Matrix.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/ot/NaorPinkas.h>
#include <droidCrypto/utils/LinearCode.h>

#include <droidCrypto/utils/Log.h>
#include <droidCrypto/utils/Utils.h>
#include <chrono>
#include <queue>

namespace droidCrypto {
void IknpDotExtReceiver::setBaseOts(gsl::span<std::array<block, 2>> baseOTs) {
  // PRNG prng(ZeroBlock);
  // mCode.random(prng, baseOTs.size(), 128);

  mGens.resize(baseOTs.size());
  for (uint64_t i = 0; i < uint64_t(baseOTs.size()); i++) {
    mGens[i][0].SetSeed(baseOTs[i][0]);
    mGens[i][1].SetSeed(baseOTs[i][1]);
  }

  mHasBase = true;
}
std::unique_ptr<OtExtReceiver> IknpDotExtReceiver::split() {
  std::vector<std::array<block, 2>> baseRecvOts(mGens.size());

  for (uint64_t i = 0; i < mGens.size(); ++i) {
    baseRecvOts[i][0] = mGens[i][0].get<block>();
    baseRecvOts[i][1] = mGens[i][1].get<block>();
  }

  auto dot = new IknpDotExtReceiver();
  // dot->mCode = mCode;

  std::unique_ptr<OtExtReceiver> ret(dot);

  ret->setBaseOts(baseRecvOts);

  return std::move(ret);
}

void IknpDotExtReceiver::receive(const BitVector &choices,
                                 gsl::span<block> messages, PRNG &prng,
                                 ChannelWrapper &chl) {
  if (mHasBase == false) throw std::runtime_error("rt error at " LOCATION);

  // we are going to process OTs in blocks of 128 * superBlkSize messages.
  uint64_t numOtExt = roundUpTo(choices.size(), 128 * superBlkSize);
  uint64_t numSuperBlocks = numOtExt / 128 / superBlkSize;
  uint64_t numBlocks = numSuperBlocks * superBlkSize;

  // turn the choice vbitVector into an array of blocks.
  BitVector choices2(numBlocks * 128);
  choices2 = choices;
  choices2.resize(numBlocks * 128);

  auto choiceBlocks = choices2.getSpan<block>();
  // this will be used as temporary buffers of 128 columns,
  // each containing 1024 bits. Once transposed, they will be copied
  // into the T1, T0 buffers for long term storage.
  Matrix<uint8_t> t0(mGens.size(), superBlkSize * sizeof(block));

  Matrix<uint8_t> messageTemp(messages.size(), sizeof(block) * 2);
  auto mIter = messageTemp.begin();

  uint64_t step = std::min<uint64_t>(numSuperBlocks, (uint64_t)commStepSize);
  std::vector<block> uBuff(step * mGens.size() * superBlkSize);

  // get an array of blocks that we will fill.
  auto uIter = (block *)uBuff.data();
  auto uEnd = uIter + uBuff.size();

  // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
  //   Instead we break it down into smaller chunks. We do 128 columns
  //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
  //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
  //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a
  //   time. So that's what we do.
  for (uint64_t superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    // the users next 128 choice bits. This will select what message is
    // receiver.
    block *cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;

    block *tIter = (block *)t0.data();
    memset(t0.data(), 0, superBlkSize * 128 * sizeof(block));

    // transpose 128 columns at at time. Each column will be 128 * superBlkSize
    // = 1024 bits long.
    for (uint64_t colIdx = 0; colIdx < mGens.size(); ++colIdx) {
      // generate the column indexed by colIdx. This is done with
      // AES in counter mode acting as a PRNG. We don't use the normal
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

    if (uIter == uEnd) {
      // send over u buffer
      chl.send(std::move(uBuff));

      uint64_t step = std::min<uint64_t>(numSuperBlocks - superBlkIdx - 1,
                                         (uint64_t)commStepSize);

      if (step) {
        uBuff.resize(step * mGens.size() * superBlkSize);
        uIter = (block *)uBuff.data();
        uEnd = uIter + uBuff.size();
      }
    }

    auto mCount = std::min<uint64_t>(
        (messageTemp.end() - mIter) / messageTemp.stride(), 128 * superBlkSize);

    MatrixView<uint8_t> tOut((uint8_t *)&*mIter, mCount, messageTemp.stride());

    mIter += mCount * messageTemp.stride();

    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
    // each 128 bits wide.
    Utils::transpose(t0, tOut);
  }

  // do correlation check and hashing
  // For the malicious secure OTs, we need a random PRNG that is chosen random
  // for both parties. So that is what this is.
  block theirSeed;
  chl.recv((uint8_t *)&theirSeed, sizeof(block));

  block offset;
  chl.recv(offset);

  PRNG codePrng(theirSeed);
  LinearCode code;
  code.random(codePrng, mGens.size(), 128);

  uint64_t doneIdx = (0);

  std::array<block, 2> zeroOneBlk{ZeroBlock, AllOneBlock};

  std::array<block, 8> expendedChoiceBlk;
  std::array<std::array<uint8_t, 16>, 8> &expendedChoice =
      *reinterpret_cast<std::array<std::array<uint8_t, 16>, 8> *>(
          &expendedChoiceBlk);
#ifdef HAVE_NEON
  block mask = vdupq_n_u8(1);
#else
  block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
#endif

  auto msg = (std::array<block, 2> *)messageTemp.data();

  uint64_t bb = (messageTemp.bounds()[0] + 127) / 128;
  for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx) {
    uint64_t stop0 = std::min<uint64_t>(messages.size(), doneIdx + 128);
#ifdef HAVE_NEON
    expendedChoiceBlk[0] = mask & choiceBlocks[blockIdx];
    expendedChoiceBlk[1] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 1);
    expendedChoiceBlk[2] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 2);
    expendedChoiceBlk[3] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 3);
    expendedChoiceBlk[4] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 4);
    expendedChoiceBlk[5] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 5);
    expendedChoiceBlk[6] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 6);
    expendedChoiceBlk[7] = mask & vshrq_n_s16(choiceBlocks[blockIdx], 7);
#else
    expendedChoiceBlk[0] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 0);
    expendedChoiceBlk[1] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 1);
    expendedChoiceBlk[2] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 2);
    expendedChoiceBlk[3] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 3);
    expendedChoiceBlk[4] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 4);
    expendedChoiceBlk[5] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 5);
    expendedChoiceBlk[6] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 6);
    expendedChoiceBlk[7] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 7);
#endif

    uint64_t i = 0, dd = doneIdx;
    for (; dd < stop0; ++dd, ++i) {
      auto maskBlock = zeroOneBlk[expendedChoice[i % 8][i / 8]];

      code.encode((uint8_t *)msg[dd].data(), (uint8_t *)&messages[dd]);

      messages[dd] = messages[dd] ^ (maskBlock & offset);
    }

    doneIdx = stop0;
  }

  static_assert(gOtExtBaseOtCount == 128, "expecting 128");
}

}  // namespace droidCrypto

jlong Java_com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver_init(
    JNIEnv *env, jobject /* this */, jobject baseOTs) {
  droidCrypto::IknpDotExtReceiver *receiver =
      new droidCrypto::IknpDotExtReceiver();
  void *inputPtr = env->GetDirectBufferAddress(baseOTs);
  jlong inputLength = env->GetDirectBufferCapacity(baseOTs);
  droidCrypto::span<std::array<droidCrypto::block, 2>> baseOTspan(
      (std::array<droidCrypto::block, 2> *)inputPtr,
      droidCrypto::gOtExtBaseOtCount);
  receiver->setBaseOts(baseOTspan);
  return (jlong)receiver;
}

void Java_com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver_recv(
    JNIEnv *env, jobject this_obj, jlong object, jobject messages,
    jbyteArray choices, jobject channel) {
  droidCrypto::IknpDotExtReceiver *receiver =
      (droidCrypto::IknpDotExtReceiver *)object;
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

void Java_com_example_mobile_1psi_droidCrypto_OT_IknpDoTExtReceiver_deleteNativeObj(
    JNIEnv *env, jobject /* this */, jlong object) {
  droidCrypto::IknpDotExtReceiver *receiver =
      (droidCrypto::IknpDotExtReceiver *)object;
  delete receiver;
}

void Java_com_example_mobile_1psi_droidCrypto_TestAsyncTask_IKNPDotRecv(
    JNIEnv *env, jobject /*this*/) {
  droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 0);
  droidCrypto::NaorPinkas np;
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

  auto time1 = std::chrono::high_resolution_clock::now();
  std::array<std::array<droidCrypto::block, 2>, 128> baseOT;
  np.send(baseOT, p, chan);
  auto time2 = std::chrono::high_resolution_clock::now();
  droidCrypto::IknpDotExtReceiver recv;
  recv.setBaseOts(baseOT);

  constexpr size_t numOTEs = 1024 * 1024;

  droidCrypto::BitVector choizes(numOTEs);
  choizes.randomize(p);
  std::vector<droidCrypto::block> mesBuf(numOTEs);
  droidCrypto::span<droidCrypto::block> mes(mesBuf.data(), mesBuf.size());
  droidCrypto::Log::v("DOTe", "before recv");
  recv.receive(choizes, mes, p, chan);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::vector<std::array<droidCrypto::block, 2>> buf(numOTEs);
  for (size_t i = 0; i < numOTEs; i++) {
    chan.recv(buf[i][0]);
    chan.recv(buf[i][1]);
    if (droidCrypto::neq(buf[i][uint8_t(choizes[i])], mesBuf[i])) {
      droidCrypto::Log::e("DOTe", "Wrong in %d (%d)!", i, uint8_t(choizes[i]));
      droidCrypto::Log::v("DOTe", buf[i][0]);
      droidCrypto::Log::v("DOTe", buf[i][1]);
      droidCrypto::Log::v("DOTe", mesBuf[i]);
      droidCrypto::Log::v("DOTe", "----------------");
    }
  }

  std::chrono::duration<double> baseOTs = time2 - time1;
  std::chrono::duration<double> OTes = time3 - time2;
  droidCrypto::Log::v("DOTe", "RECVER: BaseOTs: %fsec, OTe: %fsec", baseOTs,
                      OTes);
}
