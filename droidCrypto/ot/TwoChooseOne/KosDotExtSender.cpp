#include "KosDotExtSender.h"

#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/Commit.h>
#include <droidCrypto/Matrix.h>
#include <droidCrypto/utils/Utils.h>

namespace droidCrypto {
//#define KOS_DEBUG

std::unique_ptr<OtExtSender> KosDotExtSender::split() {
  auto dot = new KosDotExtSender();
  std::unique_ptr<OtExtSender> ret(dot);
  std::vector<block> baseRecvOts(mGens.size());
  for (uint64_t i = 0; i < mGens.size(); ++i)
    baseRecvOts[i] = mGens[i].get<block>();
  ret->setBaseOts(baseRecvOts, mBaseChoiceBits);
  return std::move(ret);
}

void KosDotExtSender::setBaseOts(span<block> baseRecvOts,
                                 const BitVector &choices) {
  mBaseChoiceBits = choices;
  mGens.resize(choices.size());
  mBaseChoiceBits.resize(roundUpTo(mBaseChoiceBits.size(), 8));
  for (uint64_t i = mBaseChoiceBits.size() - 1; i >= choices.size(); --i)
    mBaseChoiceBits[i] = 0;

  mBaseChoiceBits.resize(choices.size());
  for (uint64_t i = 0; i < mGens.size(); i++) mGens[i].SetSeed(baseRecvOts[i]);
}

void KosDotExtSender::setDelta(const block &delta) { mDelta = delta; }

void KosDotExtSender::send(span<std::array<block, 2>> messages, PRNG &prng,
                           ChannelWrapper &chl) {
  // round up
  uint64_t numOtExt = roundUpTo(messages.size(), 128);
  uint64_t numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;

  // a temp that will be used to transpose the sender's matrix
  Matrix<uint8_t> t(mGens.size(), superBlkSize * sizeof(block));
  std::vector<std::array<block, superBlkSize>> u(mGens.size() * commStepSize);

  std::vector<block> choiceMask(mBaseChoiceBits.size());
  std::array<block, 2> delta{ZeroBlock, ZeroBlock};

  memcpy(delta.data(), mBaseChoiceBits.data(), mBaseChoiceBits.sizeBytes());

  for (uint64_t i = 0; i < choiceMask.size(); ++i) {
    if (mBaseChoiceBits[i])
      choiceMask[i] = AllOneBlock;
    else
      choiceMask[i] = ZeroBlock;
  }

  std::array<std::array<block, 2>, 128> extraBlocks;
  std::array<block, 2> *xIter = extraBlocks.data();

  Commit theirSeedComm;
  chl.recv(theirSeedComm.data(), theirSeedComm.size());

  auto mIter = messages.begin();
  auto mIterPartial =
      messages.end() - std::min<uint64_t>(128 * superBlkSize, messages.size());

  // set uIter = to the end so that it gets loaded on the first loop.
  block *uIter = (block *)u.data() + superBlkSize * mGens.size() * commStepSize;
  block *uEnd = uIter;

  for (uint64_t superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
    if (uIter == uEnd) {
      uint64_t step = std::min<uint64_t>(numSuperBlocks - superBlkIdx,
                                         (uint64_t)commStepSize);
      chl.recv((uint8_t *)u.data(),
               step * superBlkSize * mGens.size() * sizeof(block));
      uIter = (block *)u.data();
    }

    block *cIter = choiceMask.data();
    block *tIter = (block *)t.data();

    // transpose 128 columns at at time. Each column will be 128 * superBlkSize
    // = 1024 bits long.
    for (uint64_t colIdx = 0; colIdx < mGens.size(); ++colIdx) {
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

    if (mIter >= mIterPartial) {
      Matrix<uint8_t> tOut(128 * superBlkSize, sizeof(block) * 2);

      // transpose our 128 columns of 1024 bits. We will have 1024 rows,
      // each 128 bits wide.
      Utils::transpose(t, tOut);

      auto mCount =
          std::min<uint64_t>(128 * superBlkSize, messages.end() - mIter);
      auto xCount =
          std::min<uint64_t>(128 * superBlkSize - mCount,
                             extraBlocks.data() + extraBlocks.size() - xIter);

      // std::copy(mIter, mIter + mCount, tOut.begin());
      if (mCount) memcpy(&*mIter, tOut.data(), mCount * sizeof(block) * 2);
      mIter += mCount;

      memcpy(xIter, tOut.data() + mCount * sizeof(block) * 2,
             xCount * sizeof(block) * 2);
      xIter += xCount;
    } else {
      MatrixView<uint8_t> tOut((uint8_t *)&*mIter, 128 * superBlkSize,
                               sizeof(block) * 2);

      mIter += std::min<uint64_t>(128 * superBlkSize, messages.end() - mIter);

      // transpose our 128 columns of 1024 bits. We will have 1024 rows,
      // each 128 bits wide.
      Utils::transpose(t, tOut);
    }
  }

  block seed = prng.get<block>();

  PRNG codePrng(seed);
  LinearCode code;
  code.random(codePrng, mBaseChoiceBits.size(), 128);
  block curDelta;
  code.encode((uint8_t *)delta.data(), (uint8_t *)&curDelta);

  if (eq(mDelta, ZeroBlock)) mDelta = prng.get<block>();

  block offset = curDelta ^ mDelta;

  block theirSeed;
  chl.send((uint8_t *)&seed, sizeof(block));
  chl.recv((uint8_t *)&theirSeed, sizeof(block));
  chl.send(offset);

  if (Commit(theirSeed) != theirSeedComm)
    throw std::runtime_error("bad commit " LOCATION);

  PRNG commonPrng(seed ^ theirSeed);

  block qi1, qi2, qi3, qi4, q1(ZeroBlock), q2(ZeroBlock), q3(ZeroBlock),
      q4(ZeroBlock);

  uint64_t doneIdx = 0;

  std::array<block, 128> challenges, challenges2;

  // std::cout << IoStream::lock;
  // std::array<block, 2> small{ delta[0], delta[1] };

  uint64_t xx = 0;
  uint64_t bb = (messages.size() + 127 + 128) / 128;
  for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx) {
    commonPrng.mAes.encryptCTR(doneIdx, 128, challenges.data());
    commonPrng.mAes.encryptCTR(doneIdx, 128, challenges2.data());

    uint64_t stop0 = std::min<uint64_t>(messages.size(), doneIdx + 128);
    uint64_t stop1 = std::min<uint64_t>(messages.size() + 128, doneIdx + 128);

    uint64_t i = 0, dd = doneIdx;
    for (; dd < stop0; ++dd, ++i) {
      Utils::mul256(messages[dd][0], messages[dd][1], challenges[i],
                    challenges2[i], qi1, qi2, qi3, qi4);

      q1 = q1 ^ qi1;
      q2 = q2 ^ qi2;
      q3 = q3 ^ qi3;
      q4 = q4 ^ qi4;

      code.encode((uint8_t *)messages[dd].data(), (uint8_t *)&messages[dd][0]);
      messages[dd][1] = messages[dd][0] ^ mDelta;
      // code.encode((uint8_t*)messages1.data(), (uint8_t*)&messages[dd][1]);
    }

    for (; dd < stop1; ++dd, ++i, ++xx) {
      Utils::mul256(extraBlocks[xx][0], extraBlocks[xx][1], challenges[i],
                    challenges2[i], qi1, qi2, qi3, qi4);
      q1 = q1 ^ qi1;
      q2 = q2 ^ qi2;
      q3 = q3 ^ qi3;
      q4 = q4 ^ qi4;
    }

    doneIdx = stop1;
  }

  block t1, t2, t3, t4;
  std::vector<uint8_t> data(sizeof(block) * 8);

  chl.recv(data.data(), data.size());

  // std::cout << IoStream::unlock;

  auto &received_x = ((std::array<block, 4> *)data.data())[0];
  auto &received_t = ((std::array<block, 4> *)data.data())[1];

  // check t = x * Delta + q
  Utils::mul256(received_x[0], received_x[1], delta[0], delta[1], t1, t2, t3,
                t4);
  t1 = t1 ^ q1;
  t2 = t2 ^ q2;
  t3 = t3 ^ q3;
  t4 = t4 ^ q4;

  if (eq(t1, received_t[0]) && eq(t2, received_t[1]) && eq(t3, received_t[2]) &&
      eq(t4, received_t[3])) {
    // std::cout << "\tCheck passed\n";
  } else {
    //            std::cout << "OT Ext Failed Correlation check failed" <<
    //            std::endl; std::cout << "rec t[0] = " << received_t[0] <<
    //            std::endl; std::cout << "rec t[1] = " << received_t[1] <<
    //            std::endl; std::cout << "rec t[2] = " << received_t[2] <<
    //            std::endl; std::cout << "rec t[3] = " << received_t[3] <<
    //            std::endl << std::endl; std::cout << "exp t[0] = " << t1 <<
    //            std::endl; std::cout << "exp t[1] = " << t2 << std::endl;
    //            std::cout << "exp t[2] = " << t3 << std::endl;
    //            std::cout << "exp t[3] = " << t4 << std::endl << std::endl;
    //            std::cout << "q  = " << q1 << std::endl;
    throw std::runtime_error("Exit");
    ;
  }

  static_assert(gOtExtBaseOtCount == 128, "expecting 128");
}

}  // namespace droidCrypto
