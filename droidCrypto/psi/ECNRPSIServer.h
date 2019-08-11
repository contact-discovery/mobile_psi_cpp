#pragma once

#include <droidCrypto/psi/PhasedPSIServer.h>
#include <droidCrypto/psi/tools/ECNRPRF.h>

namespace droidCrypto {
class ChannelWrapper;

class ECNRPSIServer : public PhasedPSIServer {
 public:
  ECNRPSIServer(ChannelWrapper &chan, size_t num_threads = 1);

  void Setup(std::vector<block> &elements) override;
  void Base() override;
  void Online() override;

 private:
  PRNG prng_;
  ECNRPRF prf_;
  size_t num_client_elements_;
  std::vector<std::array<block, 2>> ots_;
};
}  // namespace droidCrypto
