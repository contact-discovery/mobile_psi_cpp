#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <droidCrypto/Defines.h>
#include <type_traits>
#include <array>
#include <cstring>

extern void sha1_compress(uint32_t state[5], const uint8_t block[64]);

namespace droidCrypto {

	// An implementation of SHA1 based on ARM NEON instructions
    class SHA1
    {
    public:
		// The size of the SHA digest output by Final(...);
        static const uint64_t HashSize = 20;

		// Default constructor of the class. Sets the internal state to zero.
		SHA1(uint64_t outputLength = HashSize) { Reset(outputLength); }

		// Resets the interal state.
		void Reset()
		{
			Reset(outputLength);
		}

		// Resets the interal state and sets the desired output length in bytes.
		void Reset(uint64_t digestByteLength)
		{
			memset(this, 0, sizeof(SHA1));
			outputLength = digestByteLength;
			isNew = true;
		}

		// Add length bytes pointed to by dataIn to the internal SHA1 state.
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value>::type Update(const T* dd, uint64_t ll)
		{
			auto length = ll * sizeof(T);
			uint8_t* dataIn = (uint8_t*)dd;

			while (length)
			{
				uint64_t step = std::min<uint64_t>(length, uint64_t(64) - idx);
				memcpy(buffer.data() + idx, dataIn, step);

				idx += step;
				dataIn += step;
				length -= step;

				if (idx == 64)
				{
					sha1_compress(state.data(), buffer.data());
					idx = 0;
				}
				isNew = false;
			}
		}
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value>::type Update(const T& blk)
		{
			Update((uint8_t*)&blk, sizeof(T));
		}

		// Finalize the SHA1 hash and output the result to DataOut.
		// Required: DataOut must be at least SHA1::HashSize in length.
		void Final(uint8_t* DataOut)
		{
			if (idx || isNew) sha1_compress(state.data(), buffer.data());
			idx = 0;
			memcpy(DataOut, state.data(), outputLength);
		}


		// Finalize the SHA1 hash and output the result to out. 
		// Only sizeof(T) bytes of the output are written.
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value && sizeof(T) <= HashSize && std::is_pointer<T>::value == false>::type
			Final(T& out)
		{
#ifndef NDEBUG
			if (sizeof(T) != outputLength)
				throw std::runtime_error(LOCATION);
#endif
			Final((uint8_t*)&out);
		}

		// Copy the interal state of a SHA1 computation.
        const SHA1& operator=(const SHA1& src);

		uint64_t getOutputLength() const { return  outputLength; }

    private:
        bool isNew;
        std::array<uint32_t,5> state;
        std::array<uint8_t, 64> buffer;
        uint32_t idx, outputLength;
    };
}
