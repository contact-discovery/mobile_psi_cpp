#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/utils/Log.h>
#include <cassert>

std::atomic_flag ready;

#define NUM_LOWMC (1<<10)
int main(int argc, char** argv) {

    std::thread server([]{
        //server
        droidCrypto::CSocketChannel chan("127.0.0.1", 8000, true);

        uint8_t LOWMC_TEST_KEY[] = {  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        droidCrypto::BitVector a(LOWMC_TEST_KEY, droidCrypto::SIMDLowMCCircuit::params->k);
        droidCrypto::SIMDLowMCCircuit circ(chan);
        circ.garble(a, NUM_LOWMC);
        droidCrypto::Log::v("GC", "GARBLER: bytes sent: %zu, recv: %zu", chan.getBytesSent(), chan.getBytesRecv());
    });
    //client
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    droidCrypto::CSocketChannel chan("127.0.0.1", 8000, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    uint8_t LOWMC_TEST_INPUT[] = {0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    droidCrypto::BitVector a(LOWMC_TEST_INPUT, droidCrypto::SIMDLowMCCircuit::params->n);
    std::vector<droidCrypto::BitVector> aa(NUM_LOWMC, a);

    droidCrypto::SIMDLowMCCircuit circ(chan);
//    droidCrypto::BitVector ct = circ.evaluate(a);
    std::vector<droidCrypto::BitVector> ct = circ.evaluate(aa);
    std::string time = "Time: " + std::to_string(circ.timeBaseOT.count());
    time += ", " + std::to_string(circ.timeOT.count());
    time += ", " + std::to_string(circ.timeEval.count());
    time += ", " + std::to_string(circ.timeOutput.count());
    droidCrypto::Log::v("GC", "%s", time.c_str());
//    for(int i = 0; i < NUM_LOWMC; i++)
//        droidCrypto::Log::v("GC", "tt: %s", ct[i].hexREV().c_str());
    droidCrypto::Log::v("GC", "tt: %s", ct[0].hexREV().c_str());

    droidCrypto::Log::v("GC", "EVALUATOR: bytes sent: %zu, recv: %zu", chan.getBytesSent(), chan.getBytesRecv());


    server.join();
    return 0;
}
