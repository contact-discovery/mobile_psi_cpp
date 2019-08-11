#pragma once

#include "droidCrypto/Defines.h"

namespace droidCrypto {
    class Log {
    public:
        static void e(const char* tag, const char *format, ...);

        static void v(const char* tag, const char *format, ...);
        static void v(const char* tag, const block& b);
    };
}
