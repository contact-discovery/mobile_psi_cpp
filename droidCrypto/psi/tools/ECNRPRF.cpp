#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/psi/tools/ECNRPRF.h>

namespace droidCrypto {

ECNRPRF::ECNRPRF(PRNG &prng, size_t element_size)
    : curve_(),
      brick_(curve_.getGenerator()),
      element_size_(element_size),
      a0_(curve_, prng) {
  a_.reserve(element_size);
  for (auto i = 0; i < element_size; i++) {
    REccNumber t(curve_, prng);
    a_.push_back(t);
  }
}

ECNRPRF::~ECNRPRF() {}

size_t ECNRPRF::getElementSize() const { return element_size_; }

REccPoint ECNRPRF::prf(block input) {
  BitVector bv;
  bv.assign(input);
  REccNumber b(curve_, a0_);
  for (auto i = 0; i < element_size_; i++) {
    if (bv[i]) {
      b *= a_[i];
    }
  }
  REccPoint ret = brick_ * b;
  return ret;
}

void ECNRPRF::oprf(const BitVector &input, span<std::array<block, 2>> otSpan,
                   ChannelWrapper &chan) {
  REccNumber r(curve_, 1);
  REccNumber r_0(curve_, 0);
  REccNumber r_1(curve_, 0);
  std::array<uint8_t, 128 * 32 + 33> buf1{};
  std::array<uint8_t, 128 * 32> buf2{};
  std::array<uint8_t, 32> buf{};

  for (auto j = 0; j < 128; j++) {
    PRNG p(otSpan[j][input[j]], 2);
    p.get<uint8_t>(buf.data(), buf.size());
    r_0.fromBytes(buf.data());
    p.SetSeed(otSpan[j][1 - input[j]], 2);
    p.get<uint8_t>(buf.data(), buf.size());
    r_1.fromBytes(buf.data());
    r_1.toBytes(buf1.data() + 32 * j);

    r *= r_0;
    r_0 *= a_[j];
    r_0.toBytes(buf2.data() + 32 * j);
  }
  for (auto j = 0; j < buf2.size(); j++) {
    buf1[j] ^= buf2[j];
  }
  r = r.inverse() * a0_;
  REccPoint ret = brick_ * r;
  ret.toBytes(buf1.data() + 128 * 32);
  chan.send(buf1.data(), buf1.size());
}

}  // namespace droidCrypto
