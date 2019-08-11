#include <assert.h>
#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/SecureRandom.h>
#include <droidCrypto/ot/NaorPinkas.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtReceiver.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtSender.h>
#include <droidCrypto/utils/Log.h>
#include <atomic>
#include <cstring>
#include <iostream>
#include <thread>

std::atomic_flag ready;

#define NUM_OTE (16 * 1024 * 1024)
int main(int argc, char **argv) {
  std::thread server([] {
    // server
    droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 1);
    droidCrypto::NaorPinkas np;
    droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

    droidCrypto::BitVector choizes(128);  // length is in bits
    choizes.randomize(p);

    auto time1 = std::chrono::high_resolution_clock::now();
    std::array<droidCrypto::block, 128> baseOT;
    np.receive(choizes, baseOT, p, chan);
    auto time2 = std::chrono::high_resolution_clock::now();
    droidCrypto::KosOtExtSender sender;
    sender.setBaseOts(baseOT, choizes);

    std::vector<std::array<droidCrypto::block, 2>> mesBuf(NUM_OTE);
    droidCrypto::span<std::array<droidCrypto::block, 2>> mes(mesBuf.data(),
                                                             mesBuf.size());
    droidCrypto::Log::v("DOTe", "before send");
    sender.send(mes, p, chan);
    //    for(size_t a = 0; a < 10; a++) {
    //        droidCrypto::Log::v("DOTe", mesBuf[a][0]);
    //        droidCrypto::Log::v("DOTe", mesBuf[a][1]);
    //        droidCrypto::Log::v("DOTe", mesBuf[a][0]^mesBuf[a][1]);
    //        droidCrypto::Log::v("DOTe", "-----");
    //    }
    auto time3 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_OTE; i++) {
      chan.send(mesBuf[i][0]);
      chan.send(mesBuf[i][1]);
    }
    std::chrono::duration<double> baseOTs = time2 - time1;
    std::chrono::duration<double> OTes = time3 - time2;
    droidCrypto::Log::v("DOTe", "SENDER: BaseOTs: %fsec, OTe: %fsec", baseOTs,
                        OTes);
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  // client
  droidCrypto::CSocketChannel chan("127.0.0.1", 1233, 0);
  droidCrypto::NaorPinkas np;
  droidCrypto::PRNG p = droidCrypto::PRNG::getTestPRNG();

  auto time1 = std::chrono::high_resolution_clock::now();
  std::array<std::array<droidCrypto::block, 2>, 128> baseOT;
  np.send(baseOT, p, chan);
  auto time2 = std::chrono::high_resolution_clock::now();
  droidCrypto::KosOtExtReceiver recv;
  recv.setBaseOts(baseOT);

  droidCrypto::BitVector choizes(NUM_OTE);
  choizes.randomize(p);
  std::vector<droidCrypto::block> mesBuf(NUM_OTE);
  droidCrypto::span<droidCrypto::block> mes(mesBuf.data(), mesBuf.size());
  droidCrypto::Log::v("DOTe", "before recv");
  recv.receive(choizes, mes, p, chan);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::vector<std::array<droidCrypto::block, 2>> buf(NUM_OTE);
  for (size_t i = 0; i < NUM_OTE; i++) {
    chan.recv(buf[i][0]);
    chan.recv(buf[i][1]);
    if (droidCrypto::neq(buf[i][uint8_t(choizes[i])], mesBuf[i])) {
      droidCrypto::Log::e("DOTe", "Wrong in %d (%d)!", i, uint8_t(choizes[i]));
      droidCrypto::Log::v("DOTe", buf[i][0]);
      droidCrypto::Log::v("DOTe", buf[i][1]);
      droidCrypto::Log::v("DOTe", mesBuf[i]);
      droidCrypto::Log::v("DOTe", "----------------");
    }
  }

  std::chrono::duration<double> baseOTs = time2 - time1;
  std::chrono::duration<double> OTes = time3 - time2;
  droidCrypto::Log::v("DOTe", "RECVER: BaseOTs: %fsec, OTe: %fsec", baseOTs,
                      OTes);

  server.join();
  return 0;
}
