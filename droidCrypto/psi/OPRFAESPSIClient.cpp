#include <droidCrypto/psi/OPRFAESPSIClient.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/utils/Log.h>
#include <assert.h>
#include <endian.h>
#include "cuckoofilter/cuckoofilter.h"


namespace droidCrypto {

    OPRFAESPSIClient::OPRFAESPSIClient(ChannelWrapper& chan) : PhasedPSIClient(chan), cf_(nullptr), circ_(chan) {}

    void OPRFAESPSIClient::Setup() {
        uint64_t num_server_elements;
        uint64_t cfsize;
        channel_.recv((uint8_t*)&num_server_elements, sizeof(num_server_elements));
        num_server_elements = be64toh(num_server_elements);

        uint64_t size_in_tags, step;
        channel_.recv((uint8_t*)&size_in_tags, sizeof(size_in_tags));
        channel_.recv((uint8_t*)&step, sizeof(step));
        size_in_tags = be64toh(size_in_tags);
        step = be64toh(step);
        auto time1 = std::chrono::high_resolution_clock::now();
        cf_ = new CuckooFilter(num_server_elements);
        std::chrono::duration<double> deser = std::chrono::duration<double>::zero();

        for(uint64_t i = 0; i < size_in_tags; i+=step) {
            std::vector<uint8_t> tmp;
            channel_.recv((uint8_t *) &cfsize, sizeof(cfsize));
            cfsize = be64toh(cfsize);
            tmp.resize(cfsize);
            channel_.recv(tmp.data(), cfsize);
            auto time_der1 = std::chrono::high_resolution_clock::now();
            cf_->deserialize(tmp, i);
            auto time_der2 = std::chrono::high_resolution_clock::now();
            deser += (time_der2-time_der1);
        }
        std::vector<unsigned __int128> params(3);
        for(auto& par : params) {
            channel_.recv((uint8_t*)&par, sizeof(par));
        }
        cf_->SetTwoIndependentMultiplyShiftParams(params);
        auto time3 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> trans = time3-time1 - deser;
        Log::v("CF", "%s", cf_->Info().c_str());
        Log::v("PSI", "CF Trans: %fsec, CF deserialize: %fsec", trans.count(), deser.count());
    }

    void OPRFAESPSIClient::Base(size_t num_elements) {
        size_t num_client_elements = htobe64(num_elements);
        channel_.send((uint8_t*)&num_client_elements, sizeof(num_client_elements));

        circ_.evaluateBase(num_elements);
    }

    std::vector<size_t> OPRFAESPSIClient::Online(std::vector<block> &elements) {
        size_t num_client_elements = elements.size();
        //do GC evaluation

        std::vector<BitVector> bit_elements;
        bit_elements.reserve(elements.size());
        for(size_t i = 0; i < elements.size(); i++) {
            BitVector bitinput((uint8_t*)(&elements[i]), 128);
            bit_elements.push_back(bitinput);
        }
        channel_.clearStats();
        std::vector<BitVector> result = circ_.evaluateOnline(bit_elements);

        std::string time = "Time:\n\t OT:   " + std::to_string(circ_.timeBaseOT.count());
        time += ",\n\t OTe:  " + std::to_string(circ_.timeOT.count());
        time += ",\n\t Send: " + std::to_string(circ_.timeSendGC.count());
        time += ",\n\t Eval: " + std::to_string(circ_.timeEval.count());
        time += ";\n\t Total:" + std::to_string((circ_.timeBaseOT+circ_.timeOT+circ_.timeEval+circ_.timeSendGC).count());
        droidCrypto::Log::v("GC", "%s", time.c_str());
        droidCrypto::Log::v("GC", "Sent: %zu, Recv: %zu", channel_.getBytesSent(), channel_.getBytesRecv());

        auto inter_start = std::chrono::high_resolution_clock::now();
        std::vector<size_t> res;
        //do intersection
        for(size_t i = 0; i < num_client_elements; i++) {
            if (cf_->Contain((uint64_t*) result[i].data()) == cuckoofilter::Ok){
                Log::v("PSI", "Intersection C%d", i);
                res.push_back(i);
            }
        }
        auto inter_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> inter_time = inter_end -inter_start;
        Log::v("PSI", "inter: %fsec", inter_time.count());

        return res;
    }

    OPRFAESPSIClient::~OPRFAESPSIClient() {
        delete cf_;
    }

}
