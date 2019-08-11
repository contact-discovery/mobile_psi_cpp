#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include <droidCrypto/Defines.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/RandomOracle.h>

namespace droidCrypto {

#define COMMIT_BUFF_uint32_t_SIZE  5
static_assert(RandomOracle::HashSize == sizeof(uint32_t) * COMMIT_BUFF_uint32_t_SIZE, "buffer need to be the same size as hash size");


class Commit 
    {
    public:

		// Default constructor of a Commitment. The state is undefined.
		Commit() = default;

		// Compute a randomized commitment of input. 
		Commit(const block& in, PRNG& prng)
        {
            block rand = prng.get<block>();
            hash(ByteArray(in), sizeof(block), rand);
        }

		// Compute a randomized commitment of input. 
        Commit(const block& in, block& rand)
        {
             hash(ByteArray(in), sizeof(block), rand);
        }

		// Compute a randomized commitment of input. 
		Commit(const span<uint8_t> in, PRNG& prng)
        {
            block rand = prng.get<block>();
             hash(in.data(), in.size(), rand);
        }
		
		// Compute a randomized commitment of input. 
		Commit(const span<uint8_t> in, block& rand)
        {
             hash(in.data(), in.size(), rand);
        }



		// Compute a non-randomized commitment of input. 
		// Note: insecure if input has low entropy. 
		Commit(const block& input) { hash(ByteArray(input), sizeof(block)); }

		// Compute a non-randomized commitment of input. 
		// Note: insecure if input has low entropy. 
		Commit(const std::array<block, 3>& input)
		{
			hash(ByteArray(input[0]), sizeof(block));
			hash(ByteArray(input[1]), sizeof(block));
			hash(ByteArray(input[2]), sizeof(block));
		}

		// Compute a non-randomized commitment of input. 
		// Note: insecure if input has low entropy. 
		Commit(const span<uint8_t> in)
        {
            hash(in.data(), in.size());
        }


		// Compute a non-randomized commitment of input. 
		// Note: insecure if input has low entropy. 
        Commit(uint8_t* d, uint64_t s)
        {
            hash(d, s);
        }

		// Utility function to test if two commitments are equal.
        bool operator==(const Commit& rhs)
        {
            for (uint64_t i = 0; i < COMMIT_BUFF_uint32_t_SIZE; ++i)
            {
                if (buff[i] != rhs.buff[i])
                    return false;
            }
            return true;
        }

		// Utility function to test if two commitments are not equal.
		bool operator!=(const Commit& rhs)
        {
            return !(*this == rhs);
        }

		// Returns a pointer to the commitment value.
        uint8_t* data() const
        {
            return (uint8_t*)buff;
        }

		// Returns the size of the commitment in bytes.
		static uint64_t size()
        {
            return RandomOracle::HashSize;
        }

    private:
		uint32_t buff[COMMIT_BUFF_uint32_t_SIZE];

        void hash(uint8_t* data, uint64_t size)
        {
            RandomOracle sha;
            sha.Update(data, size);
            sha.Final((uint8_t*)buff);
        }

         void hash(uint8_t* data, uint64_t size, block& rand)
         {
              RandomOracle sha;
              sha.Update(data, size);
              sha.Update(rand);
              sha.Final((uint8_t*)buff);
         }

    };

    static_assert(sizeof(Commit) == RandomOracle::HashSize, "needs to be Pod type");
}
