#include <droidCrypto/Defines.h>
#include <sstream>
#include <cstring>

namespace droidCrypto {

#if defined(HAVE_NEON)
    const block ZeroBlock = vdupq_n_u8(0x0);
    const block AllOneBlock = vdupq_n_u8(0xff);
    const block TestBlock = vdupq_n_u8(0xaa);

#else
    const block ZeroBlock = _mm_set_epi64x(0, 0);
    const block AllOneBlock = _mm_set_epi64x(uint64_t(-1), uint64_t(-1));
    const block TestBlock = ([]() {block aa; memset(&aa, 0xaa, sizeof(block)); return aa; })();
#endif

    void split(const std::string &s, char delim, std::vector<std::string> &elems) {
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, delim)) {
            elems.push_back(item);
        }
    }

    std::vector<std::string> split(const std::string &s, char delim) {
        std::vector<std::string> elems;
        split(s, delim, elems);
        return elems;
    }
}