#pragma once

#include <chrono>
#include <vector>
#include <droidCrypto/Defines.h>

namespace droidCrypto {
    class ChannelWrapper;

    class PhasedPSIClient {
    public:
        PhasedPSIClient(ChannelWrapper& chan) :
            channel_(chan), time_setup(0), time_base(0), time_online(0) {};

        virtual std::vector<size_t> doPSI(std::vector<block>& elements) {
            Setup();
            Base(elements.size());
            return Online(elements);
        }
        virtual void Setup() = 0;
        virtual void Base(size_t num_elements) = 0;
        virtual std::vector<size_t> Online(std::vector<block>& elements) = 0;

    protected:
        ChannelWrapper& channel_;
        std::chrono::duration<double> time_setup;
        std::chrono::duration<double> time_base;
        std::chrono::duration<double> time_online;
    };
}

