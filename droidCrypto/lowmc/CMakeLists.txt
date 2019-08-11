cmake_minimum_required(VERSION 3.3 FATAL_ERROR)
cmake_policy(SET CMP0063 NEW)
if ("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" STRGREATER "3.8")
  cmake_policy(SET CMP0069 NEW)
endif ()

# cmake setup
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# project info
project(lowmc C)

set(LOWMC_MAJOR_VERSION 1)
set(LOWMC_MINOR_VERSION 1)
set(LOWMC_PATCH_VERSION 0)
set(LOWMC_VERSION ${LOWMC_MAJOR_VERSION}.${LOWMC_MINOR_VERSION}.${LOWMC_PATCH_VERSION})

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif ()

# set required C standard version
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# cmake checks and tools
include(GNUInstallDirs)
include(CheckSIMD)
include(CheckFunctionExists)
include(CheckCCompilerFlag)
include(CheckIncludeFiles)
include(CheckSymbolExists)

# required libraries
find_package(OpenSSL)
find_package(m4ri 20140914)

if (APPLE)
  find_path(SECRUTY_INCLUDE_DIR Security/Security.h)
  find_library(SECURITY_LIBRARY Security)
  mark_as_advanced(SECURITY_INCLUDE_DIR SECURITY_LIBRARY)
  set(HAVE_SECURITY_FRAMEWORK TRUE)
endif ()

# check headers
check_include_files(sys/auxv.h HAVE_SYS_AUXV_H)
check_include_files(asm/hwcap.h HAVE_ASM_HWCAP_H)
check_include_files(sys/random.h HAVE_SYS_RANDOM_H)

# check availability of some functions
check_symbol_exists(aligned_alloc stdlib.h HAVE_ALIGNED_ALLOC)
check_symbol_exists(posix_memalign stdlib.h HAVE_POSIX_MEMALIGN)
check_symbol_exists(memalign malloc.h HAVE_MEMALIGN)
check_symbol_exists(getrandom sys/random.h HAVE_GETRANDOM)

# check supported compiler flags
check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
check_c_compiler_flag(-O3 CC_SUPPORTS_03)
check_c_compiler_flag(-Wall CC_SUPPORTS_WALL)
check_c_compiler_flag(-Wextra CC_SUPPORTS_WEXTRA)
check_c_compiler_flag(-fomit-frame-pointer CC_SUPPORTS_FOMIT_FRAME_POINTER)
check_c_compiler_flag(-fvisibility=hidden CC_SUPPORTS_FVISIBILITY)

# check SIMD instructions set
check_simd(SSE2 CC_SUPPORTS_SSE2)
check_simd(AVX2 CC_SUPPORTS_AVX2)
check_simd(NEON CC_SUPPORTS_NEON)

# user-settable options
if (APPLE AND ${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
  # workaround for broken -march=native support on some versions of GCC on OS X.
  set(DEFAULT_WITH_MARCH_NATIVE OFF)
else ()
  set(DEFAULT_WITH_MARCH_NATIVE ON)
endif ()

set(WITH_SIMD_OPT ON CACHE BOOL "Enable optimizations via SIMD.")
set(WITH_AVX2 ON CACHE BOOL "Use AVX2 if available.")
set(WITH_SSE2 ON CACHE BOOL "Use SSE2 if available.")
set(WITH_NEON ON CACHE BOOL "Use NEON if available.")
set(WITH_MARCH_NATIVE ${DEFAULT_WITH_MARCH_NATIVE} CACHE BOOL "Build with -march=native -mtune=native (if supported).")
set(WITH_LTO ON CACHE BOOL "Enable link-time optimization (if supported).")
set(WITH_MUL_M4RI OFF CACHE BOOL "Use method of four russians for matrix multiplication.")
set(ENABLE_VERBOSE_OUTPUT OFF CACHE BOOL "Enable verbose output.")
set(ENABLE_DETAILED_TIMINGS OFF CACHE BOOL "Enable detail timings.")
set(WITH_REDUCED_LINEAR_LAYER ON CACHE BOOL "Enable precomputation of round key.")
set(WITH_RLL_NEXT ON CACHE BOOL "New RLL improvements.")
set(WITH_CUSTOM_INSTANCES OFF CACHE BOOL "Enable large and custom LowMC instances.")
set(WITH_CONFIG_H ON CACHE BOOL "Generate config.h.")

# do not build with -rdynamic
string(REGEX REPLACE "-rdynamic" "" CMAKE_EXE_LINKER_FLAGS
  "${CMAKE_EXE_LINKER_FLAGS}")
string(REGEX REPLACE "-rdynamic" "" CMAKE_SHARED_LIBRARY_LINK_C_FLAGS
  "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS}")

# build with -Wall and -Wextra if supported
if (CC_SUPPORTS_WALL)
  add_compile_options("-Wall")
endif ()
if (CC_SUPPORTS_WEXTRA)
  add_compile_options("-Wextra")
endif ()

# enable -march=native -mtune=native if supported
if (WITH_MARCH_NATIVE)
  if (CC_SUPPORTS_MARCH_NATIVE)
    add_compile_options("-march=native")
  endif ()
  if (CC_SUPPORTS_MTUNE_NATIVE)
    add_compile_options("-mtune=native")
  endif ()
endif ()

# enable LTO if supported
if (WITH_LTO)
  if ("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" STRLESS "3.9")
    if (CMAKE_COMPILER_IS_GNUCC)
      set(CMAKE_AR "gcc-ar")
      set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
      set(CMAKE_C_ARCHIVE_FINISH true)
    endif ()

    check_c_compiler_flag(-flto CC_SUPPORTS_FLTO)
    if (CC_SUPPORTS_FLTO)
      add_compile_options(-flto)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    endif ()
  else ()
    include(CheckIPOSupported)
    check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT LTO_OUTPUT)
    if (LTO_SUPPORTED)
      set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else ()
      message(WARNING "IPO is not supported: ${LTO_OUTPUT}")
    endif ()
  endif ()
endif ()

# enable -O3
if (CC_SUPPORTS_03)
  add_compile_options(-O3)
endif ()
# enable -fomit-frame-pointer
if (CC_SUPPORTS_FOMIT_FRAME_POINTER)
  add_compile_options(-fomit-frame-pointer)
endif ()

if (WITH_CONFIG_H)
  configure_file(config.h.in config.h)
endif ()

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND LOWMC_SOURCES
  aligned_alloc.c
  cpu.c
  io.c
  lowmc.c
  lowmc_pars.c
  lowmc_128_128_21.c
  lowmc_128_128_23.c
  lowmc_128_128_32.c
  lowmc_128_128_192.c
  lowmc_128_128_208.c
  lowmc_128_128_287.c
  lowmc_256_256_537.c
  mzd_additional.c
  )
# static library
add_library(lowmc STATIC ${LOWMC_SOURCES})
if (MSVC)
  set_target_properties(lowmc PROPERTIES OUTPUT_NAME liblowmc)
endif ()


function(apply_base_options lib)
  if (WITH_CONFIG_H)
    target_compile_definitions(${lib} PUBLIC HAVE_CONFIG_H)
  endif ()
  if (WITH_REDUCED_LINEAR_LAYER)
    target_compile_definitions(${lib} PUBLIC REDUCED_LINEAR_LAYER)
    if (WITH_RLL_NEXT)
      target_compile_definitions(${lib} PUBLIC REDUCED_LINEAR_LAYER_NEXT)
    endif ()
  endif ()
  if (WITH_MUL_M4RI)
    target_compile_definitions(${lib} PUBLIC MUL_M4RI)
  endif ()
  if (WITH_CUSTOM_INSTANCES)
    target_compile_definitions(${lib} PUBLIC WITH_CUSTOM_INSTANCES)
  endif ()
endfunction()

function(apply_library_options lib)
  apply_base_options(${lib})

  set_target_properties(${lib} PROPERTIES C_VISIBILITY_PRESET hidden)
  target_compile_definitions(${lib} PUBLIC
    WITH_LOWMC_128_128_21
    WITH_LOWMC_128_128_23
    WITH_LOWMC_128_128_32
    WITH_LOWMC_128_128_192
    WITH_LOWMC_128_128_208
    WITH_LOWMC_128_128_287
    )
  if (WITH_SIMD_OPT)
    target_compile_definitions(${lib} PUBLIC WITH_OPT)
    if (CC_SUPPORTS_SSE2 AND WITH_SSE2)
      target_compile_definitions(${lib} PUBLIC WITH_SSE2)
      if (CC_SUPPORTS_AVX2 AND WITH_AVX2)
        target_compile_definitions(${lib} PUBLIC WITH_AVX2)
      endif ()
    endif ()
    if (CC_SUPPORTS_NEON AND WITH_NEON)
      target_compile_definitions(${lib} PUBLIC WITH_NEON)
    endif ()
  endif ()

endfunction(apply_library_options)

apply_library_options(lowmc)

# tests
#enable_testing()
#add_subdirectory(tests)

