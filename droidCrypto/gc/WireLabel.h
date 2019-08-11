#pragma once

#include <droidCrypto/Defines.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/BitVector.h>

namespace droidCrypto {
    class WireLabel {

        public:
            WireLabel() = default;
            WireLabel(block b) : bytes(b) {}

            WireLabel(const WireLabel& other);
            WireLabel& operator=(const WireLabel& other);

            inline void setLSB() { bytes[0] |= 1; }
            inline void clrLSB() { bytes[0] &= 0xfe; }
            inline uint8_t getLSB() const { return bytes[0] & 1; }

            WireLabel operator^(const WireLabel& other) const;

            bool operator==(const WireLabel& other) const;
            bool operator!=(const WireLabel& other) const;

            void send(ChannelWrapper& chan) const;
            static WireLabel recv(ChannelWrapper& chan);

            block bytes;

            static WireLabel getZEROLabel();

    };

    class SIMDWireLabel {

        public:
            SIMDWireLabel() = default;
            SIMDWireLabel(std::vector<block> b) : bytes(b) {}

            SIMDWireLabel(const SIMDWireLabel& other);
            SIMDWireLabel& operator=(const SIMDWireLabel& other);

            inline void setLSB() { for(size_t i = 0; i < bytes.size(); i++) { bytes[i][0] |= 1; } }
            inline void clrLSB() { for(size_t i = 0; i < bytes.size(); i++) { bytes[i][0] &= 0xfe; } }
            inline BitVector getLSB() const {
                BitVector bv;
                bv.reserve(bytes.size());
                for(size_t i = 0; i < bytes.size(); i++) { bv.pushBack(bytes[i][0] & 1); }
                return bv;
            }

            SIMDWireLabel operator^(const SIMDWireLabel& other) const;
            SIMDWireLabel operator^(const WireLabel& other) const;

            void send(ChannelWrapper& chan) const;
            static SIMDWireLabel recv(ChannelWrapper& chan, size_t numinputs);

            std::vector<block> bytes;
            static SIMDWireLabel getZEROLabel(uint64_t numvals);

    };
}