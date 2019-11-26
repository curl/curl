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
find_package_handle_standard_args(NSS DEFAULT_MSG NSS_INCLUDE_DIRS NSS_LIBRARIES)

mark_as_advanced(NSS_INCLUDE_DIRS NSS_LIBRARIES)
