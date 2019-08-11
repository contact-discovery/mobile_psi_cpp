cmake_minimum_required(VERSION 3.4.1)

enable_language(C ASM)
# MIRACL begin ----------------------------------------------------------------
set(MIRACL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(MIRACL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB MIRACL_SOURCE_FILES "${MIRACL_SOURCE_DIR}/*.c")
file(GLOB MIRACL_HEADER_FILES "${MIRACL_INCLUDE_DIR}/*.h")
#message(${MIRACL_SOURCE_FILES})

if (${ANDROID})
  set_property(SOURCE ${MIRACL_SOURCE_FILES}
    APPEND_STRING PROPERTY COMPILE_FLAGS " -Ofast")
else ()
  list(APPEND MIRACL_SOURCE_FILES "${MIRACL_SOURCE_DIR}/mrmuldv.s")
  set_property(SOURCE ${MIRACL_SOURCE_FILES}
    APPEND_STRING PROPERTY COMPILE_FLAGS " -fPIC -Ofast")
endif ()
add_library(miracl STATIC
  ${MIRACL_SOURCE_FILES}
  ${MIRACL_HEADER_FILES}
  )

#set_target_properties(miracl PROPERTIES LINKER_LANGUAGE C)
target_include_directories(miracl PUBLIC ${MIRACL_INCLUDE_DIR})
# MIRACL end   ----------------------------------------------------------------
