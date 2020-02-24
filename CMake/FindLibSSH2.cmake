# - Try to find the libssh2 library
# Once done this will define
#
# LIBSSH2_FOUND - system has the libssh2 library
# LIBSSH2_INCLUDE_DIR - the libssh2 include directory
# LIBSSH2_LIBRARY - the libssh2 library name

find_path(LIBSSH2_INCLUDE_DIR libssh2.h)

find_library(LIBSSH2_LIBRARY NAMES ssh2 libssh2)

if(LIBSSH2_INCLUDE_DIR)
  file(STRINGS "${LIBSSH2_INCLUDE_DIR}/libssh2.h" libssh2_version_str REGEX "^#define[\t ]+LIBSSH2_VERSION[\t ]+\"(.*)\"")
  string(REGEX REPLACE "^.*\"([^\"]+)\"" "\\1"  LIBSSH2_VERSION "${libssh2_version_str}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibSSH2
    REQUIRED_VARS LIBSSH2_LIBRARY LIBSSH2_INCLUDE_DIR
    VERSION_VAR LIBSSH2_VERSION)

mark_as_advanced(LIBSSH2_INCLUDE_DIR LIBSSH2_LIBRARY)
