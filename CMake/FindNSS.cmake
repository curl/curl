if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_NSS nss)
endif()
if(NOT PC_NSS_FOUND)
  return()
endif()

set(NSS_LIBRARIES ${PC_NSS_LINK_LIBRARIES})
set(NSS_INCLUDE_DIRS ${PC_NSS_INCLUDE_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NSS
    REQUIRED_VARS NSS_LIBRARIES NSS_INCLUDE_DIRS
    VERSION_VAR PC_NSS_VERSION)

mark_as_advanced(NSS_INCLUDE_DIRS NSS_LIBRARIES)
