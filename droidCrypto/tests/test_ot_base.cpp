#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/utils/Log.h>
#include <assert.h>
#include <droidCrypto/ot/NaorPinkas.h>
#include <droidCrypto/ot/SimplestOT.h>
#include <droidCrypto/ot/VerifiedSimplestOT.h>
#include <droidCrypto/SecureRandom.h>

std::atomic_flag ready;

#define NUM_BASE_OTS (128)
int main(int argc, char** argv) {


    std::thread server([]{
        //server
        droidCrypto::CSocketChannel chan("127.0.0.1", 1233, true);
        //droidCrypto::SimplestOT ot;
        droidCrypto::VerifiedSimplestOT ot;
        //droidCrypto::NaorPinkas ot;
        droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

        droidCrypto::BitVector choizes(NUM_BASE_OTS); //length is in bits
        choizes.randomize(p);

        std::array<droidCrypto::block, NUM_BASE_OTS> baseOT;
        std::array<std::array<droidCrypto::block,2>, NUM_BASE_OTS> buf;
        auto time1 = std::chrono::high_resolution_clock::now();
        ot.receive(choizes, baseOT, p, chan);
        auto time2 = std::chrono::high_resolution_clock::now();

        for(size_t i = 0; i < NUM_BASE_OTS; i++) {
            chan.recv(buf[i][0]);
            chan.recv(buf[i][1]);
            if(droidCrypto::neq(buf[i][uint8_t(choizes[i])], baseOT[i])) {
                droidCrypto::Log::e("OT", "Wrong in %d (%d)!", i, uint8_t(choizes[i]));
                droidCrypto::Log::v("OT", buf[i][0]);
                droidCrypto::Log::v("OT", buf[i][1]);
                droidCrypto::Log::v("OT", baseOT[i]);
                droidCrypto::Log::v("OT", "----------------");
            }
        }
        std::chrono::duration<double> baseOTs = time2-time1;
        droidCrypto::Log::v("OT", "SENDER: BaseOTs: %fsec", baseOTs);
        droidCrypto::Log::v("OT", "S-C: %zu, C-S: %zu", chan.getBytesSent(), chan.getBytesRecv());


    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    //client
    droidCrypto::CSocketChannel chan("127.0.0.1", 1233, false);
    //droidCrypto::SimplestOT ot;
    droidCrypto::VerifiedSimplestOT ot;
    //droidCrypto::NaorPinkas ot;
    droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

    std::array<std::array<droidCrypto::block,2>, NUM_BASE_OTS> baseOT;
    auto time1 = std::chrono::high_resolution_clock::now();
    ot.send(baseOT, p, chan);
    auto time2 = std::chrono::high_resolution_clock::now();
    for(size_t i = 0; i < NUM_BASE_OTS; i++) {
        chan.send(baseOT[i][0]);
        chan.send(baseOT[i][1]);
    }

    std::chrono::duration<double> baseOTs = time2-time1;
    droidCrypto::Log::v("OT", "RECVER: BaseOTs: %fsec", baseOTs);

    server.join();
    return 0;
}
