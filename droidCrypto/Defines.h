#pragma once
#include <cstdint>
#include <vector>


#if defined(HAVE_NEON)
  #include <arm_neon.h>
  #include <arm_acle.h>
#else
  #include <emmintrin.h>
  #include <wmmintrin.h>
  #include <smmintrin.h>
#endif

#include "gsl/span"

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)

namespace droidCrypto {
    template<typename T> using span = gsl::span<T>;

#if defined(HAVE_NEON)
    typedef uint8x16_t block;

    inline block toBlock(const uint8_t* in) {return vld1q_u8(in);}
    inline void fromBlock(uint8_t* out, const block& in) {vst1q_u8(out, in);}
    inline block dupUint64(uint64_t val) { return vreinterpretq_u8_u64(vmovq_n_u64(val));}
    inline uint64_t reduceBlock(const block& in) { return vreinterpretq_u64_u8(in)[0]^vreinterpretq_u64_u8(in)[1]; }

    inline block shiftBlock(const block& b) { return vreinterpretq_u8_u64(vshlq_n_u64(vreinterpretq_u64_u8(b), 1)); }

    inline bool is_not_zero(const block& lhs) {
        uint64x2_t v64 = vreinterpretq_u64_u8(lhs);
        uint32x2_t v32 = vqmovn_u64(v64);
        uint64x1_t result = vreinterpret_u64_u32(v32);
        return result[0];
    }

    inline bool neq(const block& lhs, const block& rhs) {
        return is_not_zero(veorq_u8(lhs, rhs));
    }

    inline bool eq(const block& lhs, const block& rhs) {
        return !is_not_zero(veorq_u8(lhs, rhs));
    }
#else

    typedef  __m128i block;

    inline block toBlock(const uint8_t* in) { return _mm_set_epi64x(((uint64_t*)in)[1], ((uint64_t*)in)[0]);}
    inline uint64_t reduceBlock(const block& in) { return _mm_extract_epi64(in, 0) ^ _mm_extract_epi64(in, 1);  }
    //inline void fromBlock(uint8_t* out, const block& in) {vst1q_u8(out, in);}
    inline block dupUint64(uint64_t val) { return _mm_set_epi64x(val, val);}

    inline block shiftBlock(const block& b) { return _mm_slli_epi64(b, 1); }

    inline bool eq(const block& lhs, const block& rhs)
    {
      block neq = _mm_xor_si128(lhs, rhs);
      return _mm_test_all_zeros(neq, neq) != 0;
    }

    inline bool neq(const block& lhs, const block& rhs)
    {
      block neq = _mm_xor_si128(lhs, rhs);
      return _mm_test_all_zeros(neq, neq) == 0;
    }
#endif

    extern const block ZeroBlock;
    extern const block AllOneBlock;
    extern const block TestBlock;


    inline uint8_t* ByteArray(const block& b) { return ((uint8_t *)(&b)); }
    inline uint64_t roundUpTo(uint64_t val, uint64_t step) { return ((val + step - 1) / step) * step; }
    void split(const std::string &s, char delim, std::vector<std::string> &elems);
    std::vector<std::string> split(const std::string &s, char delim);

}