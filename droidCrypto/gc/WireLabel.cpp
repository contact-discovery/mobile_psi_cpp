#include <droidCrypto/gc/WireLabel.h>
#include <assert.h>

namespace droidCrypto {

    WireLabel::WireLabel(const WireLabel& other) {
        bytes = other.bytes;
    }

    WireLabel& WireLabel::operator=(const WireLabel& other) {
        bytes = other.bytes;
        return *this;
    }

    WireLabel WireLabel::operator^(const WireLabel& other) const {
        return WireLabel(other.bytes^bytes);
    }

    bool WireLabel::operator==(const WireLabel& other) const {
        return eq(other.bytes, bytes);
    }
    bool WireLabel::operator!=(const WireLabel& other) const {
        return neq(other.bytes, bytes);
    }

    void WireLabel::send(ChannelWrapper& chan) const {
        chan.send(bytes);
    }

    WireLabel WireLabel::recv(ChannelWrapper& chan) {
        block tmp;
        chan.recv(tmp);
        return WireLabel(tmp);
    }

    WireLabel WireLabel::getZEROLabel() {
        return WireLabel(ZeroBlock);
    }

    SIMDWireLabel::SIMDWireLabel(const SIMDWireLabel& other) {
        bytes = other.bytes;
    }

    SIMDWireLabel& SIMDWireLabel::operator=(const SIMDWireLabel& other) {
        bytes = other.bytes;
        return *this;
    }

    SIMDWireLabel SIMDWireLabel::operator^(const SIMDWireLabel& other) const {
        std::vector<block> b(other.bytes);
        for(size_t i = 0; i < b.size(); i++) {
            b[i] ^= bytes[i];
        }
        return SIMDWireLabel(b);
    }

    SIMDWireLabel SIMDWireLabel::operator^(const WireLabel& other) const {
        std::vector<block> b(bytes);
        for(size_t i = 0; i < b.size(); i++) {
            b[i] ^= other.bytes;
        }
        return SIMDWireLabel(b);
    }

    void SIMDWireLabel::send(ChannelWrapper& chan) const {
        chan.send(bytes);
    }

    SIMDWireLabel SIMDWireLabel::recv(ChannelWrapper& chan, size_t numvals) {
        std::vector<block> tmp;
        tmp.resize(numvals);
        chan.recv(tmp);
        return SIMDWireLabel(tmp);
    }

    SIMDWireLabel SIMDWireLabel::getZEROLabel(uint64_t numvals) {
        std::vector<block> tmp(numvals, ZeroBlock);
        return SIMDWireLabel(tmp);
    }
}