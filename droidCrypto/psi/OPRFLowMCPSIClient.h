#pragma once

#include <droidCrypto/psi/PhasedPSIClient.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {
    class OPRFLowMCPSIClient : public PhasedPSIClient {
    public:
        OPRFLowMCPSIClient(ChannelWrapper& chan);

        virtual ~OPRFLowMCPSIClient();

        void Setup() override;
        void Base(size_t num_elements) override;
        std::vector<size_t> Online(std::vector<block> &elements) override;

    private:
        typedef cuckoofilter::CuckooFilter<uint64_t*, 32, cuckoofilter::SingleTable,
                                   cuckoofilter::TwoIndependentMultiplyShift128> CuckooFilter;
        CuckooFilter* cf_;
        SIMDLowMCCircuitPhases circ_;
    };
}

