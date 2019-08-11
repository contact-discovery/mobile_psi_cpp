#include <assert.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/SHA1.h>
#include <droidCrypto/SHAKE128.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtSender.h>
#include <droidCrypto/ot/VerifiedSimplestOT.h>
#include <droidCrypto/psi/ECNRPSIServer.h>
#include <droidCrypto/utils/Log.h>
#include <endian.h>
#include <thread>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {

ECNRPSIServer::ECNRPSIServer(ChannelWrapper &chan, size_t num_threads /*=1*/)
    : PhasedPSIServer(chan, num_threads),
      prng_(PRNG::getTestPRNG()),
      prf_(prng_, 128),
      num_client_elements_(0) {}

void ECNRPSIServer::Setup(std::vector<block> &elements) {
  typedef cuckoofilter::CuckooFilter<
      uint64_t *, 32, cuckoofilter::SingleTable,
      cuckoofilter::TwoIndependentMultiplyShift256>
      CuckooFilter;

  auto time0 = std::chrono::high_resolution_clock::now();
  size_t num_server_elements = elements.size();
  std::vector<std::array<uint8_t, 33>> prfOut(num_server_elements);

  // MT-bounds
  size_t elements_per_thread = num_server_elements / num_threads_;
  Log::v("PSI", "%zu threads, %zu elements each", num_threads_,
         elements_per_thread);

  // Server-Side exponentiation
  //        std::vector<std::thread> threads;
  //        for(size_t thrd = 0; thrd < num_threads_-1; thrd++) {
  //            auto t = std::thread([&elements, elements_per_thread,idx=thrd,
  //            &prfOut, prf = prf_] {
  //                                     size_t index = idx *
  //                                     elements_per_thread;
  //
  //                                     prfOut[index], elements_per_thread);
  //                                 }
  //
  //            );
  //            threads.emplace_back(std::move(t));
  //        }
  //        //rest in main thread
  //        size_t index = (num_threads_-1)*elements_per_thread;
  //
  //        for(size_t thrd = 0; thrd < num_threads_ -1; thrd++) {
  //            threads[thrd].join();
  //        }
  for (auto i = 0; i < num_server_elements; i++) {
    prf_.prf(elements[i]).toBytes(prfOut[i].data());
  }

  // make some space in memory
  elements.clear();
  CuckooFilter cf(num_server_elements);

  auto time1 = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < num_server_elements; i++) {
    auto success = cf.Add((uint64_t *)prfOut[i].data());
    (void)success;
    assert(success == cuckoofilter::Ok);
  }
  auto time2 = std::chrono::high_resolution_clock::now();
  Log::v("PSI", "Built CF");
  prfOut.clear();  // free some memory
  Log::v("CF", "%s", cf.Info().c_str());
  auto time3 = std::chrono::high_resolution_clock::now();
  num_server_elements = htobe64(num_server_elements);
  channel_.send((uint8_t *)&num_server_elements, sizeof(num_server_elements));

  // send cuckoofilter in steps to save memory
  const uint64_t size_in_tags = cf.SizeInTags();
  const uint64_t step = (1 << 16);
  uint64_t uint64_send;
  uint64_send = htobe64(size_in_tags);
  channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));
  uint64_send = htobe64(step);
  channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> cf_ser = cf.serialize(step, i);
    uint64_t cfsize = cf_ser.size();
    uint64_send = htobe64(cfsize);
    channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));
    channel_.send(cf_ser.data(), cfsize);
  }

  std::vector<unsigned __int128> hash_params =
      cf.GetTwoIndependentMultiplyShiftParams();
  for (auto &par : hash_params) {
    channel_.send((uint8_t *)&par, sizeof(par));
  }

  auto time4 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> enc_time = time1 - time0;
  std::chrono::duration<double> cf_time = time2 - time1;
  std::chrono::duration<double> trans_time = time4 - time3;
  Log::v("PSI",
         "Setup Time:\n\t%fsec ENC, %fsec CF,\n\t%fsec Setup,\n\t%fsec "
         "Trans,\n\t Setup Comm: %fMiB sent, %fMiB recv\n",
         enc_time.count(), cf_time.count(), (enc_time + cf_time).count(),
         trans_time.count(), channel_.getBytesSent() / 1024.0 / 1024.0,
         channel_.getBytesRecv() / 1024.0 / 1024.0);
  channel_.clearStats();
}

void ECNRPSIServer::Base() {
  size_t num_client_elements;
  channel_.recv((uint8_t *)&num_client_elements, sizeof(num_client_elements));
  num_client_elements_ = be64toh(num_client_elements);
  size_t numBaseOTs = 128;
  std::vector<block> baseOTs;
  BitVector baseChoices(numBaseOTs);
  baseChoices.randomize(prng_);
  baseOTs.resize(numBaseOTs);
  span<block> baseOTsSpan(baseOTs.data(), baseOTs.size());

  VerifiedSimplestOT ot;
  ot.receive(baseChoices, baseOTsSpan, prng_, channel_);
  KosOtExtSender otExtSender;
  otExtSender.setBaseOts(baseOTsSpan, baseChoices);

  ots_.resize(num_client_elements_ * 128);
  span<std::array<block, 2>> otSpan(ots_.data(), ots_.size());
  otExtSender.send(otSpan, prng_, channel_);
}

void ECNRPSIServer::Online() {
  std::vector<std::array<uint8_t, 32>> prfInOut;
  BitVector bv(128 * num_client_elements_);

  channel_.recv(bv.data(), num_client_elements_ * 128 / 8);
  for (auto i = 0; i < num_client_elements_; i++) {
    BitVector c;
    c.copy(bv, 128 * i, 128);
    span<std::array<block, 2>> otSpan(&ots_[i * 128], 128);
    prf_.oprf(c, otSpan, channel_);
  }
}
}  // namespace droidCrypto
