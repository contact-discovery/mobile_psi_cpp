#pragma once
// This file and the associated implementation has been placed in the public
// domain, waiving all copyright. No restrictions are placed on its use.
#include <droidCrypto/Defines.h>
#include <array>
#include <memory>

namespace droidCrypto {
static const uint64_t commStepSize(512);
static const uint64_t superBlkSize(8);

class PRNG;
class BitVector;
class ChannelWrapper;

// The hard coded number of base OT that is expected by the OT Extension
// implementations. This can be changed if the code is adequately adapted.
const uint64_t gOtExtBaseOtCount(128);

class OtReceiver {
 public:
  OtReceiver() = default;
  virtual ~OtReceiver() = default;

  virtual void receive(const BitVector &choices, span<block> messages,
                       PRNG &prng, ChannelWrapper &chan) = 0;
};

class OtSender {
 public:
  OtSender() = default;
  virtual ~OtSender() = default;

  virtual void send(span<std::array<block, 2>> messages, PRNG &prng,
                    ChannelWrapper &chan) = 0;
};

class OtExtReceiver : public OtReceiver {
 public:
  OtExtReceiver() = default;
  virtual ~OtExtReceiver() = default;

  virtual void setBaseOts(span<std::array<block, 2>> baseSendOts) = 0;

  virtual bool hasBaseOts() const = 0;
  virtual std::unique_ptr<OtExtReceiver> split() = 0;
};

class OtExtSender : public OtSender {
 public:
  OtExtSender() = default;
  virtual ~OtExtSender() = default;

  virtual bool hasBaseOts() const = 0;

  virtual void setBaseOts(span<block> baseRecvOts,
                          const BitVector &choices) = 0;

  virtual std::unique_ptr<OtExtSender> split() = 0;
};

}  // namespace droidCrypto
