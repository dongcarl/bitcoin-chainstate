cmake_minimum_required(VERSION 3.10)

# set the project name and version
project(bitcoin-chainstate VERSION 1.0)

list(APPEND CMAKE_SYSTEM_PREFIX_PATH "/home/dongcarl/src/bitcoin/2021-07-kernel-lib/dest/usr/local")

find_library(BITCOINKERNEL_LIB bitcoinkernel)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CheckIncludeFile)

find_path(BITCOINKERNEL_HEADERS "kernel/bitcoinkernel.h")
set(CMAKE_REQUIRED_INCLUDES ${BITCOINKERNEL_HEADERS})
check_include_file ("config/bitcoin-config.h" HAVE_CONFIG_H)

include(CheckTypeSize)

# Set -DCHAR_EQUALS_INT8=1
check_type_size(char SIZEOF_CHAR LANGUAGE CXX)
check_type_size(int8_t SIZEOF_INT8_T LANGUAGE CXX)
if(SIZEOF_CHAR EQUAL SIZEOF_INT8_T)
  set(CHAR_EQUALS_INT8 1)
  foreach(KEY IN LISTS SIZEOF_CHAR_KEYS SIZEOF_INT8_T_KEYS)
    if(NOT ${SIZEOF_CHAR-${KEY}} EQUAL ${SIZEOF_INT8_T-${KEY}})
      unset(CHAR_EQUALS_INT8)
    endif()
  endforeach()
  if(CHAR_EQUALS_INT8)
    add_compile_definitions(CHAR_EQUALS_INT8=1)
  endif()
endif()

include(CheckCXXSymbolExists)
check_include_file    ("byteswap.h"     HAVE_BYTESWAP_H)
check_cxx_symbol_exists   (bswap_16       "byteswap.h" HAVE_DECL_BSWAP_16)
check_cxx_symbol_exists   (bswap_32       "byteswap.h" HAVE_DECL_BSWAP_32)
check_cxx_symbol_exists   (bswap_64       "byteswap.h" HAVE_DECL_BSWAP_64)

if(CMAKE_CXX_BYTE_ORDER STREQUAL "BIG_ENDIAN")
  set(WORDS_BIGENDIAN 1)
endif()

check_include_file ("endian.h" HAVE_ENDIAN_H)
check_include_file ("sys/endian.h" HAVE_SYS_ENDIAN_H)
if(HAVE_ENDIAN_H)
  set(ENDIAN_H endian.h)
elseif(HAVE_SYS_ENDIAN_H)
  set(ENDIAN_H sys/endian.h)
endif()

check_cxx_symbol_exists   (le16toh "${ENDIAN_H}" HAVE_DECL_LE16TOH)
check_cxx_symbol_exists   (be16toh "${ENDIAN_H}" HAVE_DECL_BE16TOH)
check_cxx_symbol_exists   (be32toh "${ENDIAN_H}" HAVE_DECL_BE32TOH)
check_cxx_symbol_exists   (be64toh "${ENDIAN_H}" HAVE_DECL_BE64TOH)
check_cxx_symbol_exists   (htobe16 "${ENDIAN_H}" HAVE_DECL_HTOBE16)
check_cxx_symbol_exists   (htobe32 "${ENDIAN_H}" HAVE_DECL_HTOBE32)
check_cxx_symbol_exists   (htobe64 "${ENDIAN_H}" HAVE_DECL_HTOBE64)
check_cxx_symbol_exists   (htole16 "${ENDIAN_H}" HAVE_DECL_HTOLE16)
check_cxx_symbol_exists   (htole32 "${ENDIAN_H}" HAVE_DECL_HTOLE32)
check_cxx_symbol_exists   (htole64 "${ENDIAN_H}" HAVE_DECL_HTOLE64)
check_cxx_symbol_exists   (le16toh "${ENDIAN_H}" HAVE_DECL_LE16TOH)
check_cxx_symbol_exists   (le32toh "${ENDIAN_H}" HAVE_DECL_LE32TOH)
check_cxx_symbol_exists   (le64toh "${ENDIAN_H}" HAVE_DECL_LE64TOH)

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
int main(void) {
    (void) __builtin_clzl(0);
    return 0;
}" HAVE_BUILTIN_CLZL)
check_cxx_source_compiles("
int main(void) {
    (void) __builtin_clzll(0);
    return 0;
}" HAVE_BUILTIN_CLZLL)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(MAC_OSX 1)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(DEBUG 1)
  set(DEBUG_LOCKORDER 1)
endif()

configure_file(config.h.in config.h)

# add the executable
add_executable(bitcoin-chainstate bitcoin-chainstate.cpp)

target_link_libraries(bitcoin-chainstate "${BITCOINKERNEL_LIB}")

target_include_directories(bitcoin-chainstate PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )

target_include_directories(bitcoin-chainstate PUBLIC
                           "${BITCOINKERNEL_HEADERS}"
                           )
