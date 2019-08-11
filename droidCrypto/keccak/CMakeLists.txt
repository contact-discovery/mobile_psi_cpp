cmake_minimum_required(VERSION 3.4.1)
project(Keccak C)

set(KECCAK_SRCS
  KeccakSpongeWidth1600.c
  KeccakHash.c
  )

if ("${ANDROID}")
  set(KECCAK_SRCS ${KECCAK_SRCS}
    opt64/KeccakP-1600-opt64.c
    )
else ()
  set(KECCAK_SRCS ${KECCAK_SRCS}
    avx2/KeccakP-1600-AVX2.s
    )
  set_property(SOURCE avx2/KeccakP-1600-AVX2.s PROPERTY LANGUAGE C)
endif ()

add_library(keccak SHARED ${KECCAK_SRCS})
target_include_directories(keccak PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
if ("${ANDROID}")
  target_include_directories(keccak PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/opt64/")
else ()
  target_include_directories(keccak PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/avx2/")
endif ()
set_property(SOURCE ${KECCAK_SRCS}
  APPEND_STRING PROPERTY COMPILE_FLAGS " -O3 -Wall -Wextra")

