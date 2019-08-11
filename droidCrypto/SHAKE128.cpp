#include <droidCrypto/SHAKE128.h>

namespace droidCrypto
{
    SHAKE128& SHAKE128::operator=(const SHAKE128& src)
    {
        this->outputLength = src.outputLength;
        memcpy(&this->ctx, &src.ctx, sizeof(Keccak_HashInstance));
        return *this;
    }
}
