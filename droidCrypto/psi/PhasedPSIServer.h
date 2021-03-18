#pragma once

#include <droidCrypto/Defines.h>
#include <chrono>
#include <vector>

namespace droidCrypto {
class ChannelWrapper;

class PhasedPSIServer {
 public:
  PhasedPSIServer(ChannelWrapper &chan, size_t num_threads = 1)
      : channel_(chan),
        num_threads_(num_threads),
        time_setup(0),
        time_base(0),
        time_online(0){};

  virtual ~PhasedPSIServer(){};
  virtual void doPSI(std::vector<block> &elements) {
    Setup(elements);
    Base();
    Online();
  }

  virtual void Setup(std::vector<block> &elements) = 0;
  virtual void Base() = 0;
  virtual void Online() = 0;

 protected:
  ChannelWrapper &channel_;
  size_t num_threads_;
  std::chrono::duration<double> time_setup;
  std::chrono::duration<double> time_base;
  std::chrono::duration<double> time_online;
};
}  // namespace droidCrypto
