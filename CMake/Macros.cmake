#File defines convenience macros for available feature testing

# This macro checks if the symbol exists in the library and if it
# does, it prepends library to the list.  It is intended to be called
# multiple times with a sequence of possibly dependent libraries in
# order of least-to-most-dependent.  Some libraries depend on others
# to link correctly.
macro(CHECK_LIBRARY_EXISTS_CONCAT LIBRARY SYMBOL VARIABLE)
  check_library_exists("${LIBRARY};${CURL_LIBS}" ${SYMBOL} "${CMAKE_LIBRARY_PATH}"
    ${VARIABLE})
  if(${VARIABLE})
    set(CURL_LIBS ${LIBRARY} ${CURL_LIBS})
  endif(${VARIABLE})
endmacro(CHECK_LIBRARY_EXISTS_CONCAT)

# Check if header file exists and add it to the list.
# This macro is intended to be called multiple times with a sequence of
# possibly dependent header files.  Some headers depend on others to be
# compiled correctly.
macro(CHECK_INCLUDE_FILE_CONCAT FILE VARIABLE)
  check_include_files("${CURL_INCLUDES};${FILE}" ${VARIABLE})
  if(${VARIABLE})
    set(CURL_INCLUDES ${CURL_INCLUDES} ${FILE})
    set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -D${VARIABLE}")
  endif(${VARIABLE})
endmacro(CHECK_INCLUDE_FILE_CONCAT)

# For other curl specific tests, use this macro.
macro(CURL_INTERNAL_TEST CURL_TEST)
  if(NOT DEFINED "${CURL_TEST}")
    set(MACRO_CHECK_FUNCTION_DEFINITIONS
      "-D${CURL_TEST} ${CURL_TEST_DEFINES} ${CMAKE_REQUIRED_FLAGS}")
    if(CMAKE_REQUIRED_LIBRARIES)
      set(CURL_TEST_ADD_LIBRARIES
        "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
    endif(CMAKE_REQUIRED_LIBRARIES)

    message(STATUS "Performing Curl Test ${CURL_TEST}")
    try_compile(${CURL_TEST}
      ${CMAKE_BINARY_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/CMake/CurlTests.c
      CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${MACRO_CHECK_FUNCTION_DEFINITIONS}
      "${CURL_TEST_ADD_LIBRARIES}"
      OUTPUT_VARIABLE OUTPUT)
    if(${CURL_TEST})
      set(${CURL_TEST} 1 CACHE INTERNAL "Curl test ${FUNCTION}")
      message(STATUS "Performing Curl Test ${CURL_TEST} - Success")
      file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
        "Performing Curl Test ${CURL_TEST} passed with the following output:\n"
        "${OUTPUT}\n")
    else(${CURL_TEST})
      message(STATUS "Performing Curl Test ${CURL_TEST} - Failed")
      set(${CURL_TEST} "" CACHE INTERNAL "Curl test ${FUNCTION}")
      file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
        "Performing Curl Test ${CURL_TEST} failed with the following output:\n"
        "${OUTPUT}\n")
    endif(${CURL_TEST})
  endif()
endmacro(CURL_INTERNAL_TEST)

macro(CURL_INTERNAL_TEST_RUN CURL_TEST)
  if(NOT DEFINED "${CURL_TEST}_COMPILE")
    set(MACRO_CHECK_FUNCTION_DEFINITIONS
      "-D${CURL_TEST} ${CMAKE_REQUIRED_FLAGS}")
    if(CMAKE_REQUIRED_LIBRARIES)
      set(CURL_TEST_ADD_LIBRARIES
        "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
    endif(CMAKE_REQUIRED_LIBRARIES)

    message(STATUS "Performing Curl Test ${CURL_TEST}")
    try_run(${CURL_TEST} ${CURL_TEST}_COMPILE
      ${CMAKE_BINARY_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/CMake/CurlTests.c
      CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${MACRO_CHECK_FUNCTION_DEFINITIONS}
      "${CURL_TEST_ADD_LIBRARIES}"
      OUTPUT_VARIABLE OUTPUT)
    if(${CURL_TEST}_COMPILE AND NOT ${CURL_TEST})
      set(${CURL_TEST} 1 CACHE INTERNAL "Curl test ${FUNCTION}")
      message(STATUS "Performing Curl Test ${CURL_TEST} - Success")
    else(${CURL_TEST}_COMPILE AND NOT ${CURL_TEST})
      message(STATUS "Performing Curl Test ${CURL_TEST} - Failed")
      set(${CURL_TEST} "" CACHE INTERNAL "Curl test ${FUNCTION}")
      file(APPEND "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log"
        "Performing Curl Test ${CURL_TEST} failed with the following output:\n"
        "${OUTPUT}")
      if(${CURL_TEST}_COMPILE)
        file(APPEND
          "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log"
          "There was a problem running this test\n")
      endif(${CURL_TEST}_COMPILE)
      file(APPEND "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log"
        "\n\n")
    endif(${CURL_TEST}_COMPILE AND NOT ${CURL_TEST})
  endif()
endmacro(CURL_INTERNAL_TEST_RUN)

macro(CURL_NROFF_CHECK)
  find_program(NROFF NAMES gnroff nroff)
  if(NROFF)
    # Need a way to write to stdin, this will do
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/nroff-input.txt" "test")
    # Tests for a valid nroff option to generate a manpage
    foreach(_MANOPT "-man" "-mandoc")
      execute_process(COMMAND "${NROFF}" ${_MANOPT}
        OUTPUT_VARIABLE NROFF_MANOPT_OUTPUT
        INPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/nroff-input.txt"
        ERROR_QUIET)
      # Save the option if it was valid
      if(NROFF_MANOPT_OUTPUT)
        message("Found *nroff option: -- ${_MANOPT}")
        set(NROFF_MANOPT ${_MANOPT})
        set(NROFF_USEFUL ON)
        break()
      endif()
    endforeach()
    # No need for the temporary file
    file(REMOVE "${CMAKE_CURRENT_BINARY_DIR}/nroff-input.txt")
    if(NOT NROFF_USEFUL)
      message(WARNING "Found no *nroff option to get plaintext from man pages")
    endif()
  else()
    message(WARNING "Found no *nroff program")
  endif()
endmacro(CURL_NROFF_CHECK)
