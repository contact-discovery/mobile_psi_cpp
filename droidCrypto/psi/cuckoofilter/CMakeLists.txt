cmake_minimum_required(VERSION 3.4.1)


set(SRCS
  bitsutil.h
  cuckoofilter.h
  debug.h
  hashutil.cc
  hashutil.h
  packedtable.h
  permencoding.h
  printutil.h
  singletable.h
  )

add_library(cuckoo ${SRCS})

target_include_directories(cuckoo PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(cuckoo PRIVATE --std=c++11 -fno-strict-aliasing -Wall)
