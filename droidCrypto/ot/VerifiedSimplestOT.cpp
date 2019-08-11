#include "VerifiedSimplestOT.h"

#ifdef ENABLE_SIMPLEST_OT


extern "C"
{
#include "SimplestOT/ref10/ot_sender.h"
#include "SimplestOT/ref10/ot_receiver.h"
#include "SimplestOT/ref10/ot_config.h"
#include "SimplestOT/ref10/randombytes.h"
#include "SimplestOT/ref10/crypto_hash.h"
}

#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/BitVector.h>

namespace droidCrypto
{
    static rand_source makeRandSource(PRNG& prng)
    {
        rand_source rand;
        rand.get = [](void* ctx, unsigned char* dest, unsigned long long length) {
            PRNG& prng = *(PRNG*)ctx;
            prng.get(dest, length);
        };
        rand.ctx = &prng;

        return rand;
    }

    void VerifiedSimplestOT::receive(
        const BitVector& choices,
        span<block> msg,
        PRNG& prng,
        ChannelWrapper& chl)
    {

        RECEIVER receiver;

        uint8_t Rs_pack[SIMPLEST_OT_PACKBYTES];
        uint8_t keys[SIMPLEST_OT_HASHBYTES];
        uint8_t cs;
        uint8_t temp[2][SIMPLEST_OT_HASHBYTES];
        std::pair<std::vector<std::array<uint8_t, SIMPLEST_OT_HASHBYTES>>,
                std::vector<std::array<uint8_t, SIMPLEST_OT_HASHBYTES>>> challenges;
        challenges.first.resize(msg.size());
        challenges.second.resize(msg.size());


        chl.recv(receiver.S_pack, sizeof(receiver.S_pack));
        chl.recv(receiver.A_pack, sizeof(receiver.A_pack));
        chl.recv(receiver.z, sizeof(receiver.z));

        receiver_procSandVerify(&receiver);

        auto rand = makeRandSource(prng);

        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            cs = choices[i];

            receiver_rsgen(&receiver, Rs_pack, cs, rand);

            chl.send(Rs_pack, sizeof(Rs_pack));

            receiver_keygen(&receiver, keys);

            memcpy(&msg[i], keys, sizeof(block));
        }

        // additional verification step
        // receive Xi values
        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            crypto_hash(challenges.first[i].data(), (uint8_t*)&msg[i], sizeof(block));
        }
        chl.recv(challenges.second[0].data(), SIMPLEST_OT_HASHBYTES * msg.size());
        // send response
        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            // calculate response
            crypto_hash(temp[0], challenges.first[i].data(), SIMPLEST_OT_HASHBYTES);
            uint8_t mask = (-choices[i]);
            for(uint32_t j = 0; j < SIMPLEST_OT_HASHBYTES; j++) {
                temp[0][j] ^= mask & challenges.second[i][j];
            }
            chl.send(temp[0], SIMPLEST_OT_HASHBYTES);

        }

        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            // receive openings
            chl.recv(temp[0], SIMPLEST_OT_HASHBYTES);
            chl.recv(temp[1], SIMPLEST_OT_HASHBYTES);
            // verify openings
            if(memcmp(temp[choices[i]], challenges.first[i].data(), SIMPLEST_OT_HASHBYTES) != 0) {
                throw std::runtime_error("bad sender response " LOCATION);
            }
            crypto_hash(temp[0], temp[0], SIMPLEST_OT_HASHBYTES);
            crypto_hash(temp[1], temp[1], SIMPLEST_OT_HASHBYTES);
            for(uint32_t j = 0; j < SIMPLEST_OT_HASHBYTES; j++) {
                temp[0][j] ^= temp[1][j];
            }
            if(memcmp(temp[0], challenges.second[i].data(), SIMPLEST_OT_HASHBYTES) != 0) {
                throw std::runtime_error("bad sender response " LOCATION);
            }
        }
    }


    void VerifiedSimplestOT::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        ChannelWrapper& chl)
    {

        SENDER sender;

        uint8_t S_pack[SIMPLEST_OT_PACKBYTES];
        uint8_t Rs_pack[SIMPLEST_OT_PACKBYTES];
        uint8_t keys[2][SIMPLEST_OT_HASHBYTES];
        std::vector<std::array<std::array<uint8_t, SIMPLEST_OT_HASHBYTES>, 2>> challenges;
        challenges.resize(msg.size());


        auto rand = makeRandSource(prng);

        sender_genSandProof(&sender, S_pack, rand);

        chl.send(S_pack, sizeof(S_pack));
        chl.send(sender.A_pack, sizeof(sender.A_pack));
        chl.send(sender.z, sizeof(sender.z));

        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            chl.recv(Rs_pack, sizeof(Rs_pack));

            sender_keygen(&sender, Rs_pack, keys);

            memcpy(&msg[i][0], keys[0], sizeof(block));
            memcpy(&msg[i][1], keys[1], sizeof(block));
        }

        // calculate challenges Xi
        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            // calculate xi based on the two msg
            crypto_hash(challenges[i][0].data(), (uint8_t*)&msg[i][0], sizeof(block));
            crypto_hash(challenges[i][1].data(), (uint8_t*)&msg[i][1], sizeof(block));
            // reuse key buffer for this
            crypto_hash(keys[0], challenges[i][0].data(), SIMPLEST_OT_HASHBYTES);
            crypto_hash(keys[1], challenges[i][1].data(), SIMPLEST_OT_HASHBYTES);
            for(uint32_t j = 0; j < SIMPLEST_OT_HASHBYTES; j++) {
                keys[0][j] ^= keys[1][j];
            }

            chl.send(keys[0], SIMPLEST_OT_HASHBYTES);
        }
        // receive and verify answers
        for (uint32_t i = 0; i < msg.size(); i ++)
        {
            crypto_hash(keys[0], challenges[i][0].data(), SIMPLEST_OT_HASHBYTES);
            chl.recv(keys[1], SIMPLEST_OT_HASHBYTES);

            if(memcmp(keys[0], keys[1], SIMPLEST_OT_HASHBYTES) != 0) {
                throw std::runtime_error("bad response " LOCATION);
            }
        }
        // open challenge to satisfy verifier
        chl.send(challenges[0][0].data(), SIMPLEST_OT_HASHBYTES*2*msg.size());
    }


}
#endif


