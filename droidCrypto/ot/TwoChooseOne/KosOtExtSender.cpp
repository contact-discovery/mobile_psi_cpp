#include "KosOtExtSender.h"

#include <droidCrypto/Commit.h>
#include <droidCrypto/utils/Utils.h>
#include <droidCrypto/ChannelWrapper.h>


namespace droidCrypto
{
    //#define KOS_DEBUG

    std::unique_ptr<OtExtSender> KosOtExtSender::split()
    {

        std::unique_ptr<OtExtSender> ret(new KosOtExtSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (uint64_t i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void KosOtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");


        mBaseChoiceBits = choices;
        for (uint64_t i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void KosOtExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        ChannelWrapper& chl)
    {

        // round up
        uint64_t numOtExt = roundUpTo(messages.size(), 128);
        uint64_t numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;
        //uint64_t numBlocks = numSuperBlocks * superBlkSize;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t;
        std::vector<std::array<block, superBlkSize>> u(128 * commStepSize);

        std::array<block, 128> choiceMask;
        block delta = *(block*)mBaseChoiceBits.data();

        for (uint64_t i = 0; i < 128; ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }

        std::array<block, 128> extraBlocks;
        block* xIter = extraBlocks.data();


        Commit theirSeedComm;
        chl.recv(theirSeedComm.data(), theirSeedComm.size());

        auto mIter = messages.begin();

        block * uIter = (block*)u.data() + superBlkSize * 128 * commStepSize;
        block * uEnd = uIter;

        for (uint64_t superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            block * tIter = (block*)t.data();
            block * cIter = choiceMask.data();

            if (uIter == uEnd)
            {
                uint64_t step = std::min<uint64_t>(numSuperBlocks - superBlkIdx,(uint64_t) commStepSize);

                chl.recv((uint8_t*)u.data(), step * superBlkSize * 128 * sizeof(block));
                uIter = (block*)u.data();
            }

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (uint64_t colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                mGens[colIdx].mAes.encryptCTR(mGens[colIdx].mBlockIdx, superBlkSize, tIter);
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


            //std::array<block, 2>* mStart = mIter;
            auto mEnd = mIter  + std::min<uint64_t>(128 * superBlkSize, messages.end() - mIter);

            // compute how many rows are unused.
            uint64_t unusedCount = (mIter - mEnd + 128 * superBlkSize);

            // compute the begin and end index of the extra rows that
            // we will compute in this iters. These are taken from the
            // unused rows what we computed above.
            block* xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

            tIter = (block*)t.data();
            block* tEnd = (block*)t.data() + 128 * superBlkSize;

            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter)[0] = *tIter;
                    (*mIter)[1] = *tIter ^ delta;

                    //uint64_t tV = tIter - (block*)t.data();
                    //uint64_t tIdx = tV / 8 + (tV % 8) * 128;
                    //std::cout << "midx " << (mIter - messages.data()) << "   tIdx " << tIdx << std::endl;

                    tIter += superBlkSize;
                    mIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }


            if (tIter < (block*)t.data())
            {
                tIter = tIter + 128 * superBlkSize - 1;
            }

            while (xIter != xEnd)
            {
                while (xIter != xEnd && tIter < tEnd)
                {
                    *xIter = *tIter;

                    //uint64_t tV = tIter - (block*)t.data();
                    //uint64_t tIdx = tV / 8 + (tV % 8) * 128;
                    //std::cout << "xidx " << (xIter - extraBlocks.data()) << "   tIdx " << tIdx << std::endl;

                    tIter += superBlkSize;
                    xIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }

            //std::cout << "blk end " << std::endl;

#ifdef KOS_DEBUG
            BitVector choice(128 * superBlkSize);
            chl.recv(u.data(), superBlkSize * 128 * sizeof(block));
            chl.recv(choice.data(), sizeof(block) * superBlkSize);

            uint64_t doneIdx = mStart - messages.data();
            uint64_t xx = std::min<uint64_t>(i64(128 * superBlkSize), (messages.data() + messages.size()) - mEnd);
            for (uint64_t rowIdx = doneIdx,
                j = 0; j < xx; ++rowIdx, ++j)
            {
                if (neq(((block*)u.data())[j], messages[rowIdx][choice[j]]))
                {
                    std::cout << rowIdx << std::endl;
                    throw std::runtime_error("");
                }
            }
#endif
            //doneIdx = (mEnd - messages.data());
        }


#ifdef KOS_DEBUG
        BitVector choices(128);
        std::vector<block> xtraBlk(128);

        chl.recv(xtraBlk.data(), 128 * sizeof(block));
        choices.resize(128);
        chl.recv(choices);

        for (uint64_t i = 0; i < 128; ++i)
        {
            if (neq(xtraBlk[i] , choices[i] ? extraBlocks[i] ^ delta : extraBlocks[i] ))
            {
                std::cout << "extra " << i << std::endl;
                std::cout << xtraBlk[i] << "  " << (u32)choices[i] << std::endl;
                std::cout << extraBlocks[i] << "  " << (extraBlocks[i] ^ delta) << std::endl;

                throw std::runtime_error("");
            }
        }
#endif

        block seed = prng.get<block>();
        chl.send((uint8_t*)&seed, sizeof(block));
        block theirSeed;
        chl.recv((uint8_t*)&theirSeed, sizeof(block));

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        PRNG commonPrng(seed ^ theirSeed);

        block  qi, qi2;
        block q2 = ZeroBlock;
        block q1 = ZeroBlock;

#ifdef KOS_SHA_HASH
        RandomOracle sha;
        uint8_t hashBuff[20];
#else
        std::array<block, 8> aesHashTemp;
#endif
        uint64_t doneIdx = 0;
        std::array<block, 128> challenges;


        uint64_t bb = (messages.size() + 127) / 128;
        for (uint64_t blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.encryptCTR(doneIdx, 128, challenges.data());
            uint64_t stop = std::min<uint64_t>(messages.size(), doneIdx + 128);

            for (uint64_t i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
            {
                //chii = commonPrng.get<block>();
                //std::cout << "sendIdx' " << dd << "   " << messages[dd][0] << "   " << chii << std::endl;

                Utils::mul128(messages[dd][0], challenges[i], qi, qi2);
                q1 = q1  ^ qi;
                q2 = q2 ^ qi2;
#ifdef KOS_SHA_HASH
                // hash the message without delta
                sha.Reset();
                sha.Update((uint8_t*)&messages[dd][0], sizeof(block));
                sha.Final(hashBuff);
                messages[dd][0] = *(block*)hashBuff;

                // hash the message with delta
                sha.Reset();
                sha.Update((uint8_t*)&messages[dd][1], sizeof(block));
                sha.Final(hashBuff);
                messages[dd][1] = *(block*)hashBuff;
#endif
            }
#ifndef KOS_SHA_HASH
            auto length = 2 *(stop - doneIdx);
            auto steps = length / 8;
            block* mIter = messages[doneIdx].data();
            for (uint64_t i = 0; i < steps; ++i)
            {
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
            for (uint64_t i = 0; i < rem; ++i)
            {
                mIter[i] = mIter[i] ^ aesHashTemp[i];
            }

#endif
            doneIdx = stop;
        }


        for (auto& blk : extraBlocks)
        {
            block chii = commonPrng.get<block>();


            Utils::mul128(blk, chii, qi, qi2);
            q1 = q1  ^ qi;
            q2 = q2 ^ qi2;
        }



        //std::cout << IoStream::unlock;

        block t1, t2;
        std::vector<uint8_t> data(sizeof(block) * 3);

        chl.recv(data.data(), data.size());

        block& received_x = ((block*)data.data())[0];
        block& received_t = ((block*)data.data())[1];
        block& received_t2 = ((block*)data.data())[2];

        // check t = x * Delta + q
        Utils::mul128(received_x, delta, t1, t2);
        t1 = t1 ^ q1;
        t2 = t2 ^ q2;

        if (eq(t1, received_t) && eq(t2, received_t2))
        {
            //std::cout << "\tCheck passed\n";
        }
        else
        {
//            std::cout << "OT Ext Failed Correlation check failed" << std::endl;
//            std::cout << "rec t = " << received_t << std::endl;
//            std::cout << "tmp1  = " << t1 << std::endl;
//            std::cout << "q  = " << q1 << std::endl;
            throw std::runtime_error("Exit");;
        }

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}
