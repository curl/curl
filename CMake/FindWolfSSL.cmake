find_path(WolfSSL_INCLUDE_DIR NAMES wolfssl/ssl.h)
find_library(WolfSSL_LIBRARY NAMES wolfssl)
mark_as_advanced(WolfSSL_INCLUDE_DIR WolfSSL_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WolfSSL
  REQUIRED_VARS WolfSSL_INCLUDE_DIR WolfSSL_LIBRARY
  )

if(WolfSSL_FOUND)
  set(WolfSSL_INCLUDE_DIRS ${WolfSSL_INCLUDE_DIR})
  set(WolfSSL_LIBRARIES ${WolfSSL_LIBRARY})
endif()
