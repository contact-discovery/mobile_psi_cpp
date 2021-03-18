#pragma once
// This file and the associated implementation has been placed in the public
// domain, waiving all copyright. No restrictions are placed on its use.

#define ENABLE_SIMPLEST_OT

#ifdef ENABLE_SIMPLEST_OT
#include <droidCrypto/Defines.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/ot/TwoChooseOne/OTExtInterface.h>

namespace droidCrypto {

class SimplestOT : public OtReceiver, public OtSender {
 public:
  void receive(const BitVector &choices, span<block> messages, PRNG &prng,
               ChannelWrapper &chl, uint64_t numThreads) {
    receive(choices, messages, prng, chl);
  }

  void send(span<std::array<block, 2>> messages, PRNG &prng,
            ChannelWrapper &chl, uint64_t numThreads) {
    send(messages, prng, chl);
  }

  void receive(const BitVector &choices, span<block> messages, PRNG &prng,
               ChannelWrapper &chl) override;

  void send(span<std::array<block, 2>> messages, PRNG &prng,
            ChannelWrapper &chl) override;
};
}  // namespace droidCrypto

#endif
