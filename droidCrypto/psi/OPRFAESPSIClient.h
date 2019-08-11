#pragma once

#include <droidCrypto/psi/PhasedPSIClient.h>
#include <droidCrypto/gc/circuits/AESCircuit.h>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {
    class OPRFAESPSIClient : public PhasedPSIClient {
    public:
        OPRFAESPSIClient(ChannelWrapper& chan);

        virtual ~OPRFAESPSIClient();

        void Setup() override;
        void Base(size_t num_elements) override;
        std::vector<size_t> Online(std::vector<block> &elements) override;

    private:
        typedef cuckoofilter::CuckooFilter<uint64_t*, 32, cuckoofilter::SingleTable,
                cuckoofilter::TwoIndependentMultiplyShift128> CuckooFilter;
        CuckooFilter* cf_;
        SIMDAESCircuitPhases circ_;
    };
}

