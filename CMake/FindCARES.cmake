# - Find c-ares
# Find the c-ares includes and library
# This module defines
#  CARES_INCLUDE_DIR, where to find ares.h, etc.
#  CARES_LIBRARIES, the libraries needed to use c-ares.
#  CARES_FOUND, If false, do not try to use c-ares.
# also defined, but not for general use are
# CARES_LIBRARY, where to find the c-ares library.

FIND_PATH(CARES_INCLUDE_DIR ares.h
  /usr/local/include
  /usr/include
  )

SET(CARES_NAMES ${CARES_NAMES} cares)
FIND_LIBRARY(CARES_LIBRARY
  NAMES ${CARES_NAMES}
  PATHS /usr/lib /usr/local/lib
  )

IF (CARES_LIBRARY AND CARES_INCLUDE_DIR)
  SET(CARES_LIBRARIES ${CARES_LIBRARY})
  SET(CARES_FOUND "YES")
ELSE (CARES_LIBRARY AND CARES_INCLUDE_DIR)
  SET(CARES_FOUND "NO")
ENDIF (CARES_LIBRARY AND CARES_INCLUDE_DIR)


IF (CARES_FOUND)
  IF (NOT CARES_FIND_QUIETLY)
    MESSAGE(STATUS "Found c-ares: ${CARES_LIBRARIES}")
  ENDIF (NOT CARES_FIND_QUIETLY)
ELSE (CARES_FOUND)
  IF (CARES_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find c-ares library")
  ENDIF (CARES_FIND_REQUIRED)
ENDIF (CARES_FOUND)

MARK_AS_ADVANCED(
  CARES_LIBRARY
  CARES_INCLUDE_DIR
  )
