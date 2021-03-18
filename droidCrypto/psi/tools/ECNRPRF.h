#pragma once
#include <droidCrypto/BitVector.h>
#include <droidCrypto/Defines.h>
#include <droidCrypto/RCurve.h>
#include <droidCrypto/utils/Log.h>

#include <vector>

namespace droidCrypto {
class ChannelWrapper;

class ECNRPRF {
 public:
  ECNRPRF(PRNG &prng, size_t element_size);
  ~ECNRPRF();
  // ECNRPRF(const ECNRPRF& other);

  size_t getElementSize() const;
  REccPoint prf(block input);
  void oprf(const BitVector &input, span<std::array<block, 2>> otSpan,
            ChannelWrapper &chan);

 private:
  REllipticCurve curve_;
  REccBrick brick_;
  size_t element_size_;
  REccNumber a0_;
  std::vector<REccNumber> a_;
};

}  // namespace droidCrypto
