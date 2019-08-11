#include <droidCrypto/utils/Log.h>
#include <cstdarg>
#include <cstdio>

#if defined(IS_ANDROID)
#include <android/log.h>
#endif

#define LOG_ERROR
#define LOG_VERBOSE

namespace droidCrypto {
    void Log::e(const char* tag, const char *format, ...) {
#ifdef LOG_ERROR
        va_list args;
        va_start(args, format);

#if defined(IS_ANDROID)
        __android_log_vprint(ANDROID_LOG_ERROR, tag, format, args);
#else
        printf("[%s]E ", tag);
        vprintf(format, args);
        printf("\n");
#endif
#endif
    }

    void Log::v(const char* tag, const char *format, ...) {
#ifdef LOG_VERBOSE
        va_list args;
        va_start(args, format);

#if defined(IS_ANDROID)
        __android_log_vprint(ANDROID_LOG_VERBOSE, tag, format, args);
#else
        printf("[%s] ", tag);
        vprintf(format, args);
        printf("\n");
#endif

#endif
    }

    void Log::v(const char *tag, const block &b) {
#ifdef LOG_VERBOSE
#if defined(IS_ANDROID)
        __android_log_print(ANDROID_LOG_VERBOSE, tag, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
#else
        printf("[%s] ", tag);
        for(size_t i = 0; i < sizeof(block); i++) {
            printf("%02X", ((uint8_t*)&b)[i]);
        }
        printf("\n");
#endif
#endif
    }
}
