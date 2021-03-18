#include "SimplestOT.h"

#ifdef ENABLE_SIMPLEST_OT

extern "C" {
#include "SimplestOT/ref10/ot_config.h"
#include "SimplestOT/ref10/ot_receiver.h"
#include "SimplestOT/ref10/ot_sender.h"
#include "SimplestOT/ref10/randombytes.h"
}

#include <droidCrypto/BitVector.h>
#include <droidCrypto/ChannelWrapper.h>

namespace droidCrypto {
static rand_source makeRandSource(PRNG &prng) {
  rand_source rand;
  rand.get = [](void *ctx, unsigned char *dest, unsigned long long length) {
    PRNG &prng = *(PRNG *)ctx;
    prng.get(dest, length);
  };
  rand.ctx = &prng;

  return rand;
}

void SimplestOT::receive(const BitVector &choices, span<block> msg, PRNG &prng,
                         ChannelWrapper &chl) {
  RECEIVER receiver;

  uint8_t Rs_pack[SIMPLEST_OT_PACKBYTES];
  uint8_t keys[SIMPLEST_OT_HASHBYTES];
  uint8_t cs;

  chl.recv(receiver.S_pack, sizeof(receiver.S_pack));

  receiver_procS(&receiver);

  auto rand = makeRandSource(prng);

  for (uint32_t i = 0; i < msg.size(); i++) {
    cs = choices[i];

    receiver_rsgen(&receiver, Rs_pack, cs, rand);

    chl.send(Rs_pack, sizeof(Rs_pack));

    receiver_keygen(&receiver, keys);

    memcpy(&msg[i], keys, sizeof(block));
  }
}

void SimplestOT::send(span<std::array<block, 2>> msg, PRNG &prng,
                      ChannelWrapper &chl) {
  SENDER sender;

  uint8_t S_pack[SIMPLEST_OT_PACKBYTES];
  uint8_t Rs_pack[SIMPLEST_OT_PACKBYTES];
  uint8_t keys[2][SIMPLEST_OT_HASHBYTES];

  auto rand = makeRandSource(prng);

  // std::cout << "s1 " << std::endl;
  sender_genS(&sender, S_pack, rand);
  // std::cout << "s2 " << std::endl;

  chl.send(S_pack, sizeof(S_pack));
  // std::cout << "s3 " << std::endl;

  for (uint32_t i = 0; i < msg.size(); i++) {
    chl.recv(Rs_pack, sizeof(Rs_pack));
    // std::cout << "s4 " << i << std::endl;

    sender_keygen(&sender, Rs_pack, keys);

    // std::cout << "s5 " << i << std::endl;

    memcpy(&msg[i][0], keys[0], sizeof(block));
    memcpy(&msg[i][1], keys[1], sizeof(block));
  }
}

}  // namespace droidCrypto
#endif
