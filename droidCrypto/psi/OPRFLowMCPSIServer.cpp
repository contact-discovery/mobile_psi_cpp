#include <droidCrypto/psi/OPRFLowMCPSIServer.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include <thread>
#include <assert.h>
#include <endian.h>
#include <droidCrypto/utils/Log.h>
#include "cuckoofilter/cuckoofilter.h"

extern "C" {
    #include <droidCrypto/lowmc/lowmc_pars.h>
    #include <droidCrypto/lowmc/io.h>
    #include <droidCrypto/lowmc/lowmc.h>
    #include <droidCrypto/lowmc/lowmc_128_128_192.h>
}


namespace droidCrypto {

    OPRFLowMCPSIServer::OPRFLowMCPSIServer(ChannelWrapper& chan, size_t num_threads /*=1*/) :
        PhasedPSIServer(chan, num_threads), circ_(chan)
    {
    }

    void OPRFLowMCPSIServer::Setup(std::vector<block> &elements) {
        auto time0 = std::chrono::high_resolution_clock::now();
        size_t num_server_elements = elements.size();

        typedef cuckoofilter::CuckooFilter<uint64_t*, 32, cuckoofilter::SingleTable,
                cuckoofilter::TwoIndependentMultiplyShift128> CuckooFilter;

        //MT-bounds
        size_t elements_per_thread = num_server_elements / num_threads_;
        Log::v("PSI", "%zu threads, %zu elements each", num_threads_, elements_per_thread);
        //LOWMC encryption
        // get a random key
        PRNG::getTestPRNG().get(lowmc_key_.data(), lowmc_key_.size());

        const lowmc_t* params = SIMDLowMCCircuitPhases::params;
        lowmc_key_t* key = mzd_local_init(1, params->k);
        mzd_from_char_array(key, lowmc_key_.data(), (params->k)/8);
        expanded_key key_calc = lowmc_expand_key(params, key);

        std::vector<std::thread> threads;
        for(size_t thrd = 0; thrd < num_threads_-1; thrd++) {
            auto t = std::thread([params, key_calc, &elements, elements_per_thread,idx=thrd]{
                lowmc_key_t* pt = mzd_local_init(1, params->n);
                for(size_t i = idx*elements_per_thread; i < (idx+1)*elements_per_thread; i++) {
                    mzd_from_char_array(pt, (uint8_t *) (&elements[i]), params->n / 8);
                    mzd_local_t *ct = lowmc_call(params, key_calc, pt);
                    mzd_to_char_array((uint8_t *) (&elements[i]), ct, params->n / 8);
                    mzd_local_free(ct);
                }
                mzd_local_free(pt);
            });
            threads.emplace_back(std::move(t));
        }
        lowmc_key_t* pt = mzd_local_init(1, params->n);
        for(size_t i = (num_threads_-1)*elements_per_thread; i < num_server_elements; i++) {
            mzd_from_char_array(pt, (uint8_t *) (&elements[i]), params->n / 8);
            mzd_local_t *ct = lowmc_call(params, key_calc, pt);
            mzd_to_char_array((uint8_t *) (&elements[i]), ct, (params->n) / 8);
            mzd_local_free(ct);
        }
        mzd_local_free(pt);
        for(size_t thrd = 0; thrd < num_threads_ -1; thrd++) {
            threads[thrd].join();
        }

        auto time1 = std::chrono::high_resolution_clock::now();
        CuckooFilter cf(num_server_elements);

        for(size_t i = 0; i < num_server_elements; i++) {
            auto success = cf.Add((uint64_t*)&elements[i]);
            (void) success;
            assert(success == cuckoofilter::Ok);
        }
        auto time2 = std::chrono::high_resolution_clock::now();
        Log::v("PSI", "Built CF");
        elements.clear(); // free some memory
        Log::v("CF", "%s", cf.Info().c_str());
        auto time3 = std::chrono::high_resolution_clock::now();

        num_server_elements = htobe64(num_server_elements);
        channel_.send((uint8_t*)&num_server_elements, sizeof(num_server_elements));

        //send cuckoofilter in steps to save memory
        const uint64_t size_in_tags = cf.SizeInTags();
        const uint64_t step = (1<<16);
        uint64_t uint64_send;
        uint64_send = htobe64(size_in_tags);
        channel_.send((uint8_t *) &uint64_send, sizeof(uint64_send));
        uint64_send = htobe64(step);
        channel_.send((uint8_t *) &uint64_send, sizeof(uint64_send));

        for(uint64_t i = 0; i < size_in_tags; i+=step) {
            std::vector<uint8_t> cf_ser = cf.serialize(step, i);
            uint64_t cfsize = cf_ser.size();
            uint64_send = htobe64(cfsize);
            channel_.send((uint8_t *) &uint64_send, sizeof(uint64_send));
            channel_.send(cf_ser.data(), cfsize);
        }

        std::vector<unsigned __int128> hash_params = cf.GetTwoIndependentMultiplyShiftParams();
        for(auto& par : hash_params) {
            channel_.send((uint8_t*)&par, sizeof(par));
        }

        auto time4 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> enc_time = time1-time0;
        std::chrono::duration<double> cf_time = time2-time1;
        std::chrono::duration<double> trans_time = time4-time3;
        Log::v("PSI", "Setup Time:\n\t%fsec ENC, %fsec CF,\n\t%fsec Setup,\n\t%fsec Trans,\n\t Setup Comm: %fMiB sent, %fMiB recv\n",
               enc_time.count(), cf_time.count(), (enc_time+cf_time).count(), trans_time.count(), channel_.getBytesSent()/1024.0/1024.0, channel_.getBytesRecv()/1024.0/1024.0);
        channel_.clearStats();
    }

    void OPRFLowMCPSIServer::Base() {
        size_t num_client_elements;
        channel_.recv((uint8_t*)&num_client_elements, sizeof(num_client_elements));
        num_client_elements = be64toh(num_client_elements);

        droidCrypto::BitVector key_bits(lowmc_key_.data(),
                                        droidCrypto::SIMDLowMCCircuitPhases::params->n);
        circ_.garbleBase(key_bits, num_client_elements);
    }

    void OPRFLowMCPSIServer::Online() {
        circ_.garbleOnline();
        //done on server side
    }
}
