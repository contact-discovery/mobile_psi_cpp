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

#define NUM_LOWMC 1024
int main(int argc, char** argv) {

//    auto start = std::chrono::high_resolution_clock::now();
//    std::array<droidCrypto::block, 128> a;
//
//    for(int i = 0; i < 1000000; i++) {
//        droidCrypto::Utils::transpose128(a);
//    }
//
//    auto finish = std::chrono::high_resolution_clock::now();
//    std::chrono::duration<double> elapsed = finish - start;
//    std::string time = "Time: " + std::to_string(elapsed.count());
//    std::cout << time << std::endl;
//    return 0;

    std::thread server([]{
        //server
        droidCrypto::CSocketChannel chan("127.0.0.1", 8000, true);

        uint8_t LOWMC_TEST_KEY[16] = {  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        droidCrypto::BitVector a(LOWMC_TEST_KEY,
                                 droidCrypto::SIMDLowMCCircuitPhases::params->n);
        droidCrypto::SIMDLowMCCircuitPhases circ(chan);
        circ.garbleBase(a, NUM_LOWMC);
        circ.garbleOnline();
        droidCrypto::Log::v("GC", "GARBLER: bytes sent: %zu, recv: %zu", chan.getBytesSent(), chan.getBytesRecv());
    });
    //client
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    droidCrypto::CSocketChannel chan("127.0.0.1", 8000, false);

    uint8_t LOWMC_TEST_INPUT[16] = {0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    droidCrypto::BitVector a(LOWMC_TEST_INPUT, 128);
    std::vector<droidCrypto::BitVector> aa(NUM_LOWMC, a);

    droidCrypto::SIMDLowMCCircuitPhases circ(chan);
//    droidCrypto::BitVector ct = circ.evaluate(a);
    circ.evaluateBase(NUM_LOWMC);
    std::vector<droidCrypto::BitVector> ct = circ.evaluateOnline(aa);
    std::string time = "Time: " + std::to_string(circ.timeBaseOT.count());
    time += ", " + std::to_string(circ.timeOT.count());
    time += ", " + std::to_string(circ.timeEval.count());
    time += ", " + std::to_string(circ.timeSendGC.count());
    droidCrypto::Log::v("GC", "%s", time.c_str());
//    for(int i = 0; i < NUM_LOWMC; i++)
//        droidCrypto::Log::v("GC", "tt: %s", ct[i].hexREV().c_str());
    droidCrypto::Log::v("GC", "tt: %s", ct[0].hexREV().c_str());

    droidCrypto::Log::v("GC", "EVALUATOR: bytes sent: %zu, recv: %zu", chan.getBytesSent(), chan.getBytesRecv());

    server.join();
    return 0;
}
