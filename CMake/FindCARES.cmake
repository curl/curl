# - Find c-ares
# Find the c-ares includes and library
# This module defines
#  CARES_INCLUDE_DIR, where to find ares.h, etc.
#  CARES_LIBRARIES, the libraries needed to use c-ares.
#  CARES_FOUND, If false, do not try to use c-ares.
# also defined, but not for general use are
# CARES_LIBRARY, where to find the c-ares library.

find_path(CARES_INCLUDE_DIR ares.h)

set(CARES_NAMES ${CARES_NAMES} cares)
find_library(CARES_LIBRARY
  NAMES ${CARES_NAMES}
  )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CARES
    REQUIRED_VARS CARES_LIBRARY CARES_INCLUDE_DIR)

mark_as_advanced(
  CARES_LIBRARY
  CARES_INCLUDE_DIR
  )
