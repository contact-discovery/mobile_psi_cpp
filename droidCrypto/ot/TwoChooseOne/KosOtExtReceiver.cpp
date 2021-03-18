#include "KosOtExtReceiver.h"

#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/Commit.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/utils/Utils.h>


namespace droidCrypto {
void KosOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs) {
  if (baseOTs.size() != gOtExtBaseOtCount) throw std::runtime_error(LOCATION);

  for (uint64_t i = 0; i < gOtExtBaseOtCount; i++) {
    mGens[i][0].SetSeed(baseOTs[i][0]);
    mGens[i][1].SetSeed(baseOTs[i][1]);
  }

  mHasBase = true;
}
std::unique_ptr<OtExtReceiver> KosOtExtReceiver::split() {
  std::array<std::array<block, 2>, gOtExtBaseOtCount> baseRecvOts;

  for (uint64_t i = 0; i < mGens.size(); ++i) {
    baseRecvOts[i][0] = mGens[i][0].get<block>();
    baseRecvOts[i][1] = mGens[i][1].get<block>();
  }

  std::unique_ptr<OtExtReceiver> ret(new KosOtExtReceiver());

  ret->setBaseOts(baseRecvOts);

  return ret;
}

void KosOtExtReceiver::receive(const BitVector &choices, span<block> messages,
                               PRNG &prng, ChannelWrapper &chl) {
  if (mHasBase == false) throw std::runtime_error("rt error at " LOCATION);

  // we are going to process OTs in blocks of 128 * superBlkSize messages.
  uint64_t numOtExt = roundUpTo(choices.size(), 128);
  uint64_t numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;
  uint64_t numBlocks = numSuperBlocks * superBlkSize;

  // commit to as seed which will be used to
  block seed = prng.get<block>();
  Commit myComm(seed);
  chl.send(myComm.data(), myComm.size());

  PRNG zPrng(ZeroBlock);
  // turn the choice vbitVector into an array of blocks.
  BitVector choices2(numBlocks * 128);
  // choices2.randomize(zPrng);
  choices2 = choices;
  choices2.resize(numBlocks * 128);
  for (uint64_t i = 0; i < 128; ++i) {
    choices2[choices.size() + i] = prng.getBit();

    // std::cout << "extra " << i << "  " << choices2[choices.size() + i] <<
    // std::endl;
  }

  auto choiceBlocks = choices2.getSpan<block>();
  // this will be used as temporary buffers of 128 columns,
  // each containing 1024 bits. Once transposed, they will be copied
  // into the T1, T0 buffers for long term storage.
  std::array<std::array<block, superBlkSize>, 128> t0;

  // the index of the OT that has been completed.
  // uint64_t doneIdx = 0;

  std::array<block, 128> extraBlocks;
  block *xIter = extraBlocks.data();
  // uint64_t extraIdx = 0;

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
  for (uint64_t superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx) {
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

    if (uIter == uEnd) {
      // send over u buffer
      chl.send(uBuff);

      uint64_t step = std::min<uint64_t>(numSuperBlocks - superBlkIdx - 1,
                                         (uint64_t)commStepSize);

      if (step) {
        uBuff.resize(step * 128 * superBlkSize);
        uIter = (block *)uBuff.data();
        uEnd = uIter + uBuff.size();
      }
    }

    // transpose our 128 columns of 1024 bits. We will have 1024 rows,
    // each 128 bits wide.
    Utils::transpose128x1024(t0);

    // block* mStart = mIter;
    auto mEnd =
        mIter + std::min<uint64_t>(128 * superBlkSize, messages.end() - mIter);

    // compute how many rows are unused.
    uint64_t unusedCount = mIter - mEnd + 128 * superBlkSize;

    // compute the begin and end index of the extra rows that
    // we will compute in this iters. These are taken from the
    // unused rows what we computed above.
    block *xEnd =
        std::min<block *>(xIter + unusedCount, extraBlocks.data() + 128);

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

    if (tIter < (block *)t0.data()) {
      tIter = tIter + 128 * superBlkSize - 1;
    }

    while (xIter != xEnd) {
      while (xIter != xEnd && tIter < tEnd) {
        *xIter = *tIter;

        tIter += superBlkSize;
        xIter += 1;
      }

      tIter = tIter - 128 * superBlkSize + 1;
    }

#ifdef KOS_DEBUG

    uint64_t doneIdx = mStart - messages.data();
    block *msgIter = messages.data() + doneIdx;
    chl.send(msgIter, sizeof(block) * 128 * superBlkSize);
    cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;
    chl.send(cIter, sizeof(block) * superBlkSize);
#endif
    // doneIdx = stopIdx;
  }

#ifdef KOS_DEBUG
  chl.send(extraBlocks.data(), sizeof(block) * 128);
  BitVector cc;
  cc.copy(choices2, choices.size(), 128);
  chl.send(cc);
#endif
  // std::cout << "uBuff " << (bool)uBuff << "  " << (uEnd - uIter) <<
  // std::endl;

  // do correlation check and hashing
  // For the malicious secure OTs, we need a random PRNG that is chosen random
  // for both parties. So that is what this is.
  PRNG commonPrng;
  // random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
  block theirSeed;
  chl.recv((uint8_t *)&theirSeed, sizeof(block));
  chl.send((uint8_t *)&seed, sizeof(block));
  commonPrng.SetSeed(seed ^ theirSeed);

  // this buffer will be sent to the other party to prove we used the
  // same value of r in all of the column vectors...
  std::vector<block> correlationData(3);
  block &x = correlationData[0];
  block &t = correlationData[1];
  block &t2 = correlationData[2];
  x = t = t2 = ZeroBlock;
  block ti, ti2;

#ifdef KOS_SHA_HASH
  RandomOracle sha;
  uint8_t hashBuff[20];
#endif

  uint64_t doneIdx = (0);
  // std::cout << IoStream::lock;

  std::array<block, 2> zeroOneBlk{ZeroBlock, AllOneBlock};
  std::array<block, 128> challenges;

  std::array<block, 8> expendedChoiceBlk;
  std::array<std::array<uint8_t, 16>, 8> &expendedChoice =
      *reinterpret_cast<std::array<std::array<uint8_t, 16>, 8> *>(
          &expendedChoiceBlk);

#ifdef HAVE_NEON
  block mask = vdupq_n_u8(1);
#else
  block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
#endif

  uint64_t bb = (messages.size() + 127) / 128;
  for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx) {
    commonPrng.mAes.encryptCTR(doneIdx, 128, challenges.data());

    uint64_t stop = std::min<uint64_t>(messages.size(), doneIdx + 128);

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

    for (uint64_t i = 0, dd = doneIdx; dd < stop; ++dd, ++i) {
      x = x ^ (challenges[i] & zeroOneBlk[expendedChoice[i % 8][i / 8]]);

      // multiply over polynomial ring to avoid reduction
      Utils::mul128(messages[dd], challenges[i], ti, ti2);

      t = t ^ ti;
      t2 = t2 ^ ti2;
#ifdef KOS_SHA_HASH
      // hash it
      sha.Reset();
      sha.Update((uint8_t *)&messages[dd], sizeof(block));
      sha.Final(hashBuff);
      messages[dd] = *(block *)hashBuff;
#endif
    }
#ifndef KOS_SHA_HASH
    auto &aesHashTemp = expendedChoiceBlk;
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
#endif

    doneIdx = stop;
  }

  for (block &blk : extraBlocks) {
    // and check for correlation
    block chij = commonPrng.get<block>();

    if (choices2[doneIdx++]) x = x ^ chij;

    // multiply over polynomial ring to avoid reduction
    Utils::mul128(blk, chij, ti, ti2);

    t = t ^ ti;
    t2 = t2 ^ ti2;
  }

  chl.send(correlationData);

  static_assert(gOtExtBaseOtCount == 128, "expecting 128");
}

}  // namespace droidCrypto
