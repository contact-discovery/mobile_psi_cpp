#pragma once

#include <droidCrypto/psi/PhasedPSIServer.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>

namespace droidCrypto {

    class OPRFLowMCPSIServer : public PhasedPSIServer {
    public:
        OPRFLowMCPSIServer(ChannelWrapper& chan, size_t num_threads = 1);

        void Setup(std::vector<block> &elements) override;

        void Base() override;

        void Online() override;

    private:
        std::array<uint8_t, 16> lowmc_key_;
        SIMDLowMCCircuitPhases circ_;
    };
}

