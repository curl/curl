# Locate zlib
include("${CMAKE_ROOT}/Modules/FindZLIB.cmake")

find_library(ZLIB_LIBRARY_DEBUG NAMES zd zlibd zdlld zlib1d )

if(ZLIB_FOUND AND ZLIB_LIBRARY_DEBUG)
  set( ZLIB_LIBRARIES optimized "${ZLIB_LIBRARY}" debug ${ZLIB_LIBRARY_DEBUG})
endif()
