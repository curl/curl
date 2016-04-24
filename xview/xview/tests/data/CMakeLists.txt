# Loads 'TESTCASES' from for the 'make show' target in runtests.pl
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

# Prints all available test cases. Do not quote TESTCASES, it must be displayed
# as a space-separated string rather than comma-separated (a list in CMake).
add_custom_target(show COMMAND echo ${TESTCASES})
