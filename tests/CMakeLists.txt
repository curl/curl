# Inherited by libtest, server and unit
include_directories(
  ${CURL_BINARY_DIR}/include/curl # for generated curlbuild.h from curl.h
  ${CURL_BINARY_DIR}/include      # for generated curlbuild.h from lib/curl_setup.h
  ${CURL_SOURCE_DIR}/include      # for libcurl's external include files
  ${CURL_BINARY_DIR}/lib          # for libcurl's generated lib/curl_config.h
  ${CURL_SOURCE_DIR}/lib          # for libcurl's lib/curl_setup.h and other "borrowed" files
)
if(USE_ARES)
  include_directories(${CARES_INCLUDE_DIR})
endif()

add_subdirectory(data)
add_subdirectory(libtest)
add_subdirectory(server)
add_subdirectory(unit)
