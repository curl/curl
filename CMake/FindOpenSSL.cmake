# Extension of the standard FindOpenSSL.cmake
# Adds OPENSSL_INCLUDE_DIRS and libeay32
include("${CMAKE_ROOT}/Modules/FindOpenSSL.cmake")

# Bill Hoffman told that libeay32 is necessary for him:
find_library(SSL_LIBEAY NAMES libeay32)

if(OPENSSL_FOUND)
  if(SSL_LIBEAY)
    list(APPEND OPENSSL_LIBRARIES ${SSL_LIBEAY})
  else()
    set(OPENSSL_FOUND FALSE)
  endif()
endif()


if(OPENSSL_FOUND)
  set(OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
endif()
