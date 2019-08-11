#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "OTExtInterface.h"
#include <droidCrypto/BitVector.h>
#include <droidCrypto/PRNG.h>

#include <array>
namespace droidCrypto {

    class KosOtExtSender :
        public OtExtSender
    {
    public: 
        std::array<PRNG, gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        std::unique_ptr<OtExtSender> split() override;

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;


        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            ChannelWrapper& chl) override;
    };
}

