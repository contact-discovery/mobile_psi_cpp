#include <assert.h>
#include <droidCrypto/AES.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/circuits/AESCircuit.h>
#include <droidCrypto/psi/OPRFAESPSIServer.h>
#include <droidCrypto/utils/Log.h>
#include <endian.h>
#include <thread>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {

OPRFAESPSIServer::OPRFAESPSIServer(ChannelWrapper &chan,
                                   size_t num_threads /*=1*/)
    : PhasedPSIServer(chan, num_threads), circ_(chan) {}

void OPRFAESPSIServer::Setup(std::vector<block> &elements) {
  typedef cuckoofilter::CuckooFilter<
      uint64_t *, 32, cuckoofilter::SingleTable,
      cuckoofilter::TwoIndependentMultiplyShift128>
      CuckooFilter;

  auto time0 = std::chrono::high_resolution_clock::now();
  size_t num_server_elements = elements.size();

  // MT-bounds
  size_t elements_per_thread = num_server_elements / num_threads_;
  Log::v("PSI", "%zu threads, %zu elements each", num_threads_,
         elements_per_thread);
  uint8_t AES_TEST_KEY[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  AES a;
  a.setKey(AES_TEST_KEY);
  std::vector<std::thread> threads;
  for (size_t thrd = 0; thrd < num_threads_ - 1; thrd++) {
    auto t = std::thread([aes = a, &elements, elements_per_thread, idx = thrd] {
      aes.encryptECBBlocks(elements.data() + idx * elements_per_thread,
                           elements_per_thread,
                           elements.data() + idx * elements_per_thread);
    });
    threads.emplace_back(std::move(t));
  }
  // rest in main thread
  a.encryptECBBlocks(
      elements.data() + (num_threads_ - 1) * elements_per_thread,
      num_server_elements - (num_threads_ - 1) * elements_per_thread,
      elements.data() + (num_threads_ - 1) * elements_per_thread);
  for (size_t thrd = 0; thrd < num_threads_ - 1; thrd++) {
    threads[thrd].join();
  }

  auto time1 = std::chrono::high_resolution_clock::now();
  CuckooFilter cf(num_server_elements);

  for (size_t i = 0; i < num_server_elements; i++) {
    auto success = cf.Add((uint64_t *)&elements[i]);
    (void)success;
    assert(success == cuckoofilter::Ok);
  }
  auto time2 = std::chrono::high_resolution_clock::now();
  Log::v("PSI", "Built CF");
  elements.clear();  // free some memory
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

void OPRFAESPSIServer::Base() {
  size_t num_client_elements;
  channel_.recv((uint8_t *)&num_client_elements, sizeof(num_client_elements));
  num_client_elements = be64toh(num_client_elements);

  uint8_t AES_TEST_EXPANDED_KEY[AES_EXP_KEY_BYTES] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
      0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x9b, 0x98, 0x98, 0xc9,
      0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa,
      0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33,
      0x0b, 0x0f, 0xac, 0x99, 0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81,
      0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91, 0xee, 0x2b, 0x7f, 0x2e, 0x2b, 0x88,
      0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90,
      0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c, 0x99, 0xff, 0x09, 0x37,
      0x6a, 0xb4, 0x9b, 0xa7, 0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b,
      0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b, 0xf0, 0x9b, 0x0e, 0xf9, 0x03, 0x33,
      0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f,
      0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde,
      0x4c, 0x66, 0x49, 0x41, 0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11,
      0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e};
  droidCrypto::BitVector key_bits(AES_TEST_EXPANDED_KEY, AES_EXP_KEY_BITS);
  circ_.garbleBase(key_bits, num_client_elements);
}

void OPRFAESPSIServer::Online() {
  circ_.garbleOnline();
  // done on server side
}
}  // namespace droidCrypto
