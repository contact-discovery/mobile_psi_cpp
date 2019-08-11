#pragma once

#include <array>
#include <droidCrypto/Defines.h>
#include <droidCrypto/MatrixView.h>
#include "Log.h"

namespace droidCrypto {
    namespace Utils {
        void print(std::array<block, 128>& inOut);
        uint8_t getBit(std::array<block, 128>& inOut, uint64_t i, uint64_t j);
        void transpose128(std::array<block, 128>& inOut);
        void transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);
        void transpose(const MatrixView<block>& in, const MatrixView<block>& out);
        void transpose(const MatrixView<uint8_t>& in, const MatrixView<uint8_t>& out);
        inline uint64_t roundUpTo(uint64_t val, uint64_t step) { return ((val + step - 1) / step) * step; }

#if defined(HAVE_NEON)
        static inline void mul128(block x, block y, block& xy1, block& xy2)
        {
            block t1 = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(x,0), vgetq_lane_u64(y, 0)));
            block t2 = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(x,1), vgetq_lane_u64(y, 0)));
            block t3 = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(x,0), vgetq_lane_u64(y, 1)));
            block t4 = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(x,1), vgetq_lane_u64(y, 1)));

            t2 = veorq_u8(t2, t3);
            t3 = vextq_u8(ZeroBlock, t2, 8);
            t2 = vextq_u8(t2, ZeroBlock, 8);
            t1 = veorq_u8(t1, t3);
            t4 = veorq_u8(t4, t2);

            xy1 = t1;
            xy2 = t4;
        }
        static inline void mul256(block a0, block a1, block b0, block b1, block& c0, block& c1, block& c2, block& c3)
        {
            block c4, c5;
            mul128(a0, b0, c0, c1);
            mul128(a1, b1, c2, c3);
            a0 = veorq_u8(a0, a1);
            b0 = veorq_u8(b0, b1);
            mul128(a0, b0, c4, c5);
            c4 = veorq_u8(c4, c0);
            c4 = veorq_u8(c4, c2);
            c5 = veorq_u8(c5, c1);
            c5 = veorq_u8(c5, c3);
            c1 = veorq_u8(c1, c4);
            c2 = veorq_u8(c2, c5);

        }
#else
        static inline void mul128(block x, block y, block& xy1, block& xy2)
        {
            auto t1 = _mm_clmulepi64_si128(x, y, (int)0x00);
            auto t2 = _mm_clmulepi64_si128(x, y, 0x10);
            auto t3 = _mm_clmulepi64_si128(x, y, 0x01);
            auto t4 = _mm_clmulepi64_si128(x, y, 0x11);

            t2 = _mm_xor_si128(t2, t3);
            t3 = _mm_slli_si128(t2, 8);
            t2 = _mm_srli_si128(t2, 8);
            t1 = _mm_xor_si128(t1, t3);
            t4 = _mm_xor_si128(t4, t2);

            xy1 = t1;
            xy2 = t4;
        }

        static inline void mul256(block a0, block a1, block b0, block b1, block& c0, block& c1, block& c2, block& c3)
        {
            block c4, c5;
            mul128(a0, b0, c0, c1);
            mul128(a1, b1, c2, c3);
            a0 = _mm_xor_si128(a0, a1);
            b0 = _mm_xor_si128(b0, b1);
            mul128(a0, b0, c4, c5);
            c4 = _mm_xor_si128(c4, c0);
            c4 = _mm_xor_si128(c4, c2);
            c5 = _mm_xor_si128(c5, c1);
            c5 = _mm_xor_si128(c5, c3);
            c1 = _mm_xor_si128(c1, c4);
            c2 = _mm_xor_si128(c2, c5);

        }
#endif
    }
}
