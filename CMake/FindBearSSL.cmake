find_path(BEARSSL_INCLUDE_DIRS bearssl.h)

find_library(BEARSSL_LIBRARY bearssl)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BEARSSL DEFAULT_MSG
    BEARSSL_INCLUDE_DIRS BEARSSL_LIBRARY)

mark_as_advanced(BEARSSL_INCLUDE_DIRS BEARSSL_LIBRARY)
