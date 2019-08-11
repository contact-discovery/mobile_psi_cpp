cmake_minimum_required(VERSION 3.4.1)
if ("${ANDROID}")
else ()
  set(TEST_SRCS
    test_gc_aes.cpp
    test_gc_lowmc.cpp
    test_gc_lowmc_phased.cpp
    test_ot_base.cpp
    test_ot_dot.cpp
    test_ot_kos.cpp
    test_psi_oprf_aes.cpp
    test_psi_oprf_lowmc.cpp
    test_psi_oprf_ecnr.cpp
    test_speed.cpp
    )
  foreach (filename ${TEST_SRCS})
    get_filename_component(testname ${filename} NAME_WE)
    add_executable(${testname} ${filename})
    target_link_libraries(${testname} droidcrypto pthread)
  endforeach ()
endif ()



