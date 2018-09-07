set(MANPAGE "${CURL_BINARY_DIR}/docs/curl.1")

# Load DPAGES and OTHERPAGES from shared file
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(OUTPUT "${MANPAGE}"
  COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/gen.pl" mainpage "${CMAKE_CURRENT_SOURCE_DIR}" > "${MANPAGE}"
  DEPENDS ${DPAGES} ${OTHERPAGES}
  VERBATIM
)
add_custom_target(generate-curl.1 DEPENDS "${MANPAGE}")
