#pragma once

#include <droidCrypto/BitVector.h>
#include <droidCrypto/psi/PhasedPSIClient.h>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {

class ECNRPSIClient : public PhasedPSIClient {
 public:
  ECNRPSIClient(ChannelWrapper &chan);

  virtual ~ECNRPSIClient();

  void Setup() override;
  void Base(size_t num_elements) override;
  std::vector<size_t> Online(std::vector<block> &elements) override;

 private:
  std::vector<block> ots_;
  BitVector ot_choices_;
  typedef cuckoofilter::CuckooFilter<
      uint64_t *, 32, cuckoofilter::SingleTable,
      cuckoofilter::TwoIndependentMultiplyShift256>
      CuckooFilter;
  CuckooFilter *cf_;
};
}  // namespace droidCrypto
