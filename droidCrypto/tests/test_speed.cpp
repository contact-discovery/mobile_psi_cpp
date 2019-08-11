#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/utils/Log.h>
#include <cassert>


int main(int argc, char** argv) {

    std::vector<uint8_t> giga(1ULL<<27);

    droidCrypto::CSocketChannel chan(nullptr, 8000, true);

    auto time1 = std::chrono::high_resolution_clock::now();
    chan.recv(giga.data(), giga.size());
    auto time2 = std::chrono::high_resolution_clock::now();
    chan.send(giga.data(), giga.size());
    auto time3 = std::chrono::high_resolution_clock::now();
    chan.send(giga.data(), 1);
    chan.recv(giga.data(), 1);
    auto time4 = std::chrono::high_resolution_clock::now();

    double stc_speed = (1ULL << 30) / 1000000.0 / std::chrono::duration<double>(time3-time2).count();
    double cts_speed = (1ULL << 30) / 1000000.0 / std::chrono::duration<double>(time2-time1).count();
    double rtt = std::chrono::duration<double>(time4-time3).count() * 1000;

    droidCrypto::Log::v("TIME", "S->C %fMbit/s, C->S %fMbit/s, %fms RTT", stc_speed, cts_speed, rtt);

    return 0;
}
