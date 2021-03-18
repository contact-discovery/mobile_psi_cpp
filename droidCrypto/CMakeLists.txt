cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(miracl)
add_subdirectory(GSL)

# RELIC configuration
# set RELIC to build Prime EC
set(DOCUM OFF CACHE BOOL "Build RELIC documentation") 
set(WITH "BN;DV;FP;EP;MD" CACHE STRING "RELIC features") 
set(FP_PRIME "256" CACHE STRING "The prime modulus size in bits.")
set(MULTI "PTHREAD" CACHE STRING "Multithreading API.")
if ("${ANDROID}")
set(OPSYS "DROID" CACHE STRING "Operating system.")
else()
set(OPSYS "LINUX" CACHE STRING "Operating system.")
endif()
set(TESTS "0" CACHE STRING "Build and run tests n times.")
set(BENCH "0" CACHE STRING "Build and run benchmarks n*n times.")
SET(SHLIB OFF CACHE BOOL "Build Shared Library")
SET(STLIB ON CACHE BOOL "Build Static Library")
add_subdirectory(relic)
# RELIC configuration end

add_subdirectory(keccak)
add_subdirectory(lowmc)
add_subdirectory(psi/cuckoofilter)
add_subdirectory(ot/SimplestOT)


set(SRCS
  AES.cpp
  PRNG.cpp
  Defines.cpp
  Curve.cpp
  RCurve.cpp
  SHA1.cpp
  utils/Utils.cpp
  utils/Log.cpp
  utils/LinearCode.cpp
  BitVector.cpp
  ot/NaorPinkas.cpp
  ot/SimplestOT.cpp
  ot/VerifiedSimplestOT.cpp
  ot/TwoChooseOne/IknpOtExtSender.cpp
  ot/TwoChooseOne/IknpOtExtReceiver.cpp
  ot/TwoChooseOne/IknpDotExtSender.cpp
  ot/TwoChooseOne/IknpDotExtReceiver.cpp
  ot/TwoChooseOne/KosOtExtReceiver.cpp
  ot/TwoChooseOne/KosOtExtSender.cpp
  ot/TwoChooseOne/KosDotExtReceiver.cpp
  ot/TwoChooseOne/KosDotExtSender.cpp
  ChannelWrapper.cpp
  SecureRandom.cpp
  utils/graycode.cpp
  gc/WireLabel.cpp
  gc/HalfGate.cpp
  gc/circuits/Circuit.cpp
  gc/circuits/TestCircuit.cpp
  gc/circuits/AESCircuit.cpp
  gc/circuits/LowMCCircuit.cpp
  gc/circuits/LowMCCircuit.h
  psi/tools/ECNRPRF.cpp
  psi/ECNRPSIClient.cpp
  psi/OPRFAESPSIClient.cpp
  psi/OPRFLowMCPSIClient.cpp
  SHAKE128.cpp
  )


if ("${ANDROID}")
  set(SRCS ${SRCS}
    android/android_entry.cpp
    )
else ()
  set(SRCS ${SRCS}
    psi/ECNRPSIServer.cpp
    psi/OPRFAESPSIServer.cpp
    psi/OPRFLowMCPSIServer.cpp
    )
endif ()

add_library(droidcrypto SHARED ${SRCS})

if ("${ANDROID}")
  message("Android Build")
  target_compile_definitions(droidcrypto PRIVATE "IS_ANDROID")
  if ("${ANDROID_ABI}" STREQUAL "armeabi-v7a")

    set_property(SOURCE ${SRCS}
      APPEND_STRING PROPERTY COMPILE_FLAGS " -mfpu=neon -Ofast")
    target_compile_definitions(droidcrypto PRIVATE "HAVE_NEON")
    error("Have no HW crypto, SW crypto not implemented atm")

  elseif ("${ANDROID_ABI}" STREQUAL "arm64-v8a")

    set_property(SOURCE ${SRCS}
      APPEND_STRING PROPERTY COMPILE_FLAGS " -march=armv8-a+crypto -Ofast")
    target_compile_definitions(droidcrypto PRIVATE "HAVE_NEON")


  elseif ("${ANDROID_ABI}" STREQUAL "x86")
    set_property(SOURCE ${SRCS} APPEND_STRING PROPERTY COMPILE_FLAGS
      " -mssse3  -Wno-unknown-attributes \
                       -Wno-deprecated-declarations \
                       -Wno-constant-conversion \
                       -Wno-static-in-inline")
    target_compile_definitions(droidcrypto PRIVATE "HAVE_NEON")
    target_compile_definitions(droidcrypto PRIVATE "HAVE_NEON_X86")
  else ()
    error("Invalid Android ABI")
  endif ()
else ()
  # normal x86 build
  find_package(JNI)
  set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -fPIC -Wno-ignored-attributes")
  set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++14")

  SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb -rdynamic")
  SET(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -ggdb -rdynamic")

endif ()

target_include_directories(droidcrypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../")
get_target_property(RELIC_INCLUDES relic_s INCLUDE_DIRECTORIES)
target_include_directories(droidcrypto PUBLIC "${RELIC_INCLUDES}")

target_link_libraries(droidcrypto
  miracl
  SimplestOT
  GSL
  relic_s 
  )

if ("${ANDROID}")
  target_link_libraries(droidcrypto
    android
    log
    )
else ()
  target_include_directories(droidcrypto PUBLIC ${JNI_INCLUDE_DIRS})
  target_include_directories(droidcrypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lowmc")
  target_link_libraries(droidcrypto ${JNI_LIBARIRES})
endif ()
target_link_libraries(droidcrypto lowmc cuckoo keccak)

add_subdirectory(tests)
