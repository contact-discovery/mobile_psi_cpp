#pragma once
#include <droidCrypto/Defines.h>
#include <droidCrypto/utils/Log.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/Curve.h>

#include <vector>


namespace droidCrypto
{
    class ChannelWrapper;

    class ECNRPRF
    {
    public:
        ECNRPRF(PRNG& prng, size_t element_size);
        ~ECNRPRF();
        //ECNRPRF(const ECNRPRF& other);

        size_t getElementSize() const;
        EccPoint prf(block input);
        void oprf(const BitVector& input, span<std::array<block, 2>> otSpan, ChannelWrapper& chan);



    private:
        EllipticCurve curve_;
        EccBrick brick_;
        size_t  element_size_;
        EccNumber a0_;
        std::vector<EccNumber> a_;

    };

}
