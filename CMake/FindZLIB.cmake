# Locate zlib
include("${CMAKE_ROOT}/Modules/FindZLIB.cmake")

# starting 2.8 it is better to use standard modules
if(CMAKE_MAJOR_VERSION EQUAL "2" AND CMAKE_MINOR_VERSION LESS "8")
  find_library(ZLIB_LIBRARY_DEBUG NAMES zd zlibd zdlld zlib1d )
  if(ZLIB_FOUND AND ZLIB_LIBRARY_DEBUG)
    set( ZLIB_LIBRARIES optimized "${ZLIB_LIBRARY}" debug ${ZLIB_LIBRARY_DEBUG})
  endif()
endif()
