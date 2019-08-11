#include <assert.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/Curve.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/SHA1.h>
#include <droidCrypto/SHAKE128.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtReceiver.h>
#include <droidCrypto/ot/VerifiedSimplestOT.h>
#include <droidCrypto/psi/ECNRPSIClient.h>
#include <droidCrypto/utils/Log.h>
#include <endian.h>
#include <chrono>

namespace droidCrypto {

ECNRPSIClient::ECNRPSIClient(ChannelWrapper &chan)
    : PhasedPSIClient(chan), cf_(nullptr) {}

void ECNRPSIClient::Setup() {
  uint64_t num_server_elements;
  uint64_t cfsize;
  channel_.recv((uint8_t *)&num_server_elements, sizeof(num_server_elements));
  num_server_elements = be64toh(num_server_elements);

  uint64_t size_in_tags, step;
  channel_.recv((uint8_t *)&size_in_tags, sizeof(size_in_tags));
  channel_.recv((uint8_t *)&step, sizeof(step));
  size_in_tags = be64toh(size_in_tags);
  step = be64toh(step);
  auto time1 = std::chrono::high_resolution_clock::now();
  cf_ = new CuckooFilter(num_server_elements);
  std::chrono::duration<double> deser = std::chrono::duration<double>::zero();

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> tmp;
    channel_.recv((uint8_t *)&cfsize, sizeof(cfsize));
    cfsize = be64toh(cfsize);
    tmp.resize(cfsize);
    channel_.recv(tmp.data(), cfsize);
    auto time_der1 = std::chrono::high_resolution_clock::now();
    cf_->deserialize(tmp, i);
    auto time_der2 = std::chrono::high_resolution_clock::now();
    deser += (time_der2 - time_der1);
  }
  std::vector<unsigned __int128> params(5);
  for (auto &par : params) {
    channel_.recv((uint8_t *)&par, sizeof(par));
  }
  cf_->SetTwoIndependentMultiplyShiftParams(params);
  auto time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> trans = time3 - time1 - deser;
  Log::v("CF", "%s", cf_->Info().c_str());

  Log::v("PSI", "CF Trans: %fsec, CF deserialize: %fsec", trans.count(),
         deser.count());
}

void ECNRPSIClient::Base(size_t num_elements) {
  size_t num_client_elements = htobe64(num_elements);
  channel_.send((uint8_t *)&num_client_elements, sizeof(num_client_elements));

  VerifiedSimplestOT ot;

  size_t numBaseOTs = 128;
  std::vector<std::array<block, 2>> baseOTs;
  baseOTs.resize(numBaseOTs);
  PRNG p = PRNG::getTestPRNG();
  span<std::array<block, 2>> baseOTsSpan(baseOTs.data(), baseOTs.size());
  ot.send(baseOTsSpan, p, channel_);

  KosOtExtReceiver OTeRecv;
  OTeRecv.setBaseOts(baseOTsSpan);
  ot_choices_.resize(num_elements * 128);
  ot_choices_.randomize(p);
  ots_.resize(num_elements * 128);
  span<block> otSpan(ots_.data(), ots_.size());
  OTeRecv.receive(ot_choices_, otSpan, p, channel_);
}

std::vector<size_t> ECNRPSIClient::Online(std::vector<block> &elements) {
  // do OPRF evaluation
  channel_.clearStats();
  PRNG p = PRNG::getTestPRNG();

  auto time4 = std::chrono::high_resolution_clock::now();
  block *choices = (block *)ot_choices_.data();
  for (auto i = 0; i < elements.size(); i++) {
    choices[i] ^= elements[i];
  }
  auto time5 = std::chrono::high_resolution_clock::now();
  channel_.send(ot_choices_.data(), elements.size() * 128 / 8);
  EllipticCurve curve(P256, p.get<block>());
  std::vector<std::array<uint8_t, 33>> prfOut;
  prfOut.reserve(elements.size());
  for (auto i = 0; i < elements.size(); i++) {
    BitVector bv;
    bv.assign(elements[i]);
    EccNumber r(curve, 1);
    EccNumber rj(curve, 0);
    std::array<uint8_t, 33> buf{};
    std::array<uint8_t, 128 * 32 + 33> buf1{};
    channel_.recv(buf1.data(), buf1.size());

    for (auto j = 0; j < 128; j++) {
      PRNG p_rj(ots_[i * 128 + j], 2);
      p_rj.get(buf.data(), 32);
      rj.fromBytes(buf.data());
      rj.toBytes(buf.data());
      if (bv[j]) {
        for (auto k = 0; k < 32; k++) {
          buf[k] ^= buf1[j * 32 + k];
        }
      }
      rj.fromBytes(buf.data());
      r *= rj;
    }
    EccPoint gT(curve);
    gT.fromBytes(buf1.data() + 128 * 32);
    gT = gT * r;
    // std::cout << gT << "\n";
    gT.toBytes(buf.data());
    prfOut.push_back(buf);
  }
  auto time6 = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> send = time5 - time4;
  std::chrono::duration<double> recv = time6 - time5;

  std::string time = "Time:\n\t prep:   " + std::to_string(send.count());
  time += ",\n\t prf:  " + std::to_string(recv.count());
  Log::v("PSI", "%s", time.c_str());
  droidCrypto::Log::v("ECNR", "Sent: %zu, Recv: %zu", channel_.getBytesSent(),
                      channel_.getBytesRecv());

  auto inter_start = std::chrono::high_resolution_clock::now();
  std::vector<size_t> res;
  // do intersection
  for (size_t i = 0; i < prfOut.size(); i++) {
    if (cf_->Contain((uint64_t *)prfOut[i].data()) == cuckoofilter::Ok) {
      Log::v("PSI", "Intersection C%d", i);
      res.push_back(i);
    }
  }
  auto inter_end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> inter_time = inter_end - inter_start;
  Log::v("PSI", "inter: %fsec", inter_time.count());

  return res;
}

ECNRPSIClient::~ECNRPSIClient() { delete cf_; }
}  // namespace droidCrypto
