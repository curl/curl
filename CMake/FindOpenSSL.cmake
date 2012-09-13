# Extension of the standard FindOpenSSL.cmake
# Adds OPENSSL_INCLUDE_DIRS and libeay32
include("${CMAKE_ROOT}/Modules/FindOpenSSL.cmake")

# starting 2.8 it is better to use standard modules
if(CMAKE_MAJOR_VERSION EQUAL "2" AND CMAKE_MINOR_VERSION LESS "8")
  # Bill Hoffman told that libeay32 is necessary for him:
  find_library(SSL_LIBEAY NAMES libeay32)

  if(OPENSSL_FOUND)
    if(SSL_LIBEAY)
      list(APPEND OPENSSL_LIBRARIES ${SSL_LIBEAY})
    else()
      set(OPENSSL_FOUND FALSE)
    endif()
  endif()
endif() # if (CMAKE_MAJOR_VERSION EQUAL "2" AND CMAKE_MINOR_VERSION LESS "8")

if(OPENSSL_FOUND)
  set(OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
endif()
