# - Find c-ares
# Find the c-ares includes and library
# This module defines
#  CARES_INCLUDE_DIR, where to find ares.h, etc.
#  CARES_LIBRARIES, the libraries needed to use c-ares.
#  CARES_FOUND, If false, do not try to use c-ares.
# also defined, but not for general use are
# CARES_LIBRARY, where to find the c-ares library.

find_path(CARES_INCLUDE_DIR ares.h
  /usr/local/include
  /usr/include
  )

set(CARES_NAMES ${CARES_NAMES} cares)
find_library(CARES_LIBRARY
  NAMES ${CARES_NAMES}
  PATHS /usr/lib /usr/local/lib
  )

if(CARES_LIBRARY AND CARES_INCLUDE_DIR)
  set(CARES_LIBRARIES ${CARES_LIBRARY})
  set(CARES_FOUND "YES")
else()
  set(CARES_FOUND "NO")
endif()


if(CARES_FOUND)
  if(NOT CARES_FIND_QUIETLY)
    message(STATUS "Found c-ares: ${CARES_LIBRARIES}")
  endif()
else()
  if(CARES_FIND_REQUIRED)
    message(FATAL_ERROR "Could not find c-ares library")
  endif()
endif()

mark_as_advanced(
  CARES_LIBRARY
  CARES_INCLUDE_DIR
  )
