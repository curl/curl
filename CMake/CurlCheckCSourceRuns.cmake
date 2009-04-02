# - Check if the source code provided in the SOURCE argument compiles and runs.
# CURL_CHECK_C_SOURCE_RUNS(SOURCE VAR)
# - macro which checks if the source code runs
#  SOURCE   - source code to try to compile
#  VAR - variable to store size if the type exists.
#
# The following variables may be set before calling this macro to
# modify the way the check is run:
#
#  CMAKE_REQUIRED_FLAGS = string of compile command line flags
#  CMAKE_REQUIRED_DEFINITIONS = list of macros to define (-DFOO=bar)
#  CMAKE_REQUIRED_INCLUDES = list of include directories
#  CMAKE_REQUIRED_LIBRARIES = list of libraries to link

MACRO(CURL_CHECK_C_SOURCE_RUNS SOURCE VAR)
  IF("${VAR}" MATCHES "^${VAR}$" OR "${VAR}" MATCHES "UNKNOWN")
    SET(message "${VAR}")
    # If the number of arguments is greater than 2 (SOURCE VAR)
    IF(${ARGC} GREATER 2)
      # then add the third argument as a message
      SET(message "${ARGV2} (${VAR})")
    ENDIF(${ARGC} GREATER 2)
    SET(MACRO_CHECK_FUNCTION_DEFINITIONS
      "-D${VAR} ${CMAKE_REQUIRED_FLAGS}")
    IF(CMAKE_REQUIRED_LIBRARIES)
      SET(CURL_CHECK_C_SOURCE_COMPILES_ADD_LIBRARIES
        "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
    ELSE(CMAKE_REQUIRED_LIBRARIES)
      SET(CURL_CHECK_C_SOURCE_COMPILES_ADD_LIBRARIES)
    ENDIF(CMAKE_REQUIRED_LIBRARIES)
    IF(CMAKE_REQUIRED_INCLUDES)
      SET(CURL_CHECK_C_SOURCE_COMPILES_ADD_INCLUDES
        "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_REQUIRED_INCLUDES}")
    ELSE(CMAKE_REQUIRED_INCLUDES)
      SET(CURL_CHECK_C_SOURCE_COMPILES_ADD_INCLUDES)
    ENDIF(CMAKE_REQUIRED_INCLUDES)
    SET(src "")
    FOREACH(def ${EXTRA_DEFINES})
      SET(src "${src}#define ${def} 1\n")
    ENDFOREACH(def)
    FOREACH(inc ${HEADER_INCLUDES})
      SET(src "${src}#include <${inc}>\n")
    ENDFOREACH(inc)

    SET(src "${src}\nint main() { ${SOURCE} ; return 0; }")
    SET(CMAKE_CONFIGURABLE_FILE_CONTENT "${src}")
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/CMake/CMakeConfigurableFile.in
      "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/src.c"
      IMMEDIATE)
    MESSAGE(STATUS "Performing Test ${message}")
    TRY_RUN(${VAR} ${VAR}_COMPILED
      ${CMAKE_BINARY_DIR}
      ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/src.c
      COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
      CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${MACRO_CHECK_FUNCTION_DEFINITIONS}
      "${CURL_CHECK_C_SOURCE_COMPILES_ADD_LIBRARIES}"
      "${CURL_CHECK_C_SOURCE_COMPILES_ADD_INCLUDES}"
      OUTPUT_VARIABLE OUTPUT)
    # if it did not compile make the return value fail code of 1
    IF(NOT ${VAR}_COMPILED)
      SET(${VAR} 1)
    ENDIF(NOT ${VAR}_COMPILED)
    # if the return value was 0 then it worked
    SET(result_var ${${VAR}})
    IF("${result_var}" EQUAL 0)
      SET(${VAR} 1 CACHE INTERNAL "Test ${message}")
      MESSAGE(STATUS "Performing Test ${message} - Success")
      FILE(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
        "Performing C SOURCE FILE Test ${message} succeded with the following output:\n"
        "${OUTPUT}\n"
        "Return value: ${${VAR}}\n"
        "Source file was:\n${src}\n")
    ELSE("${result_var}" EQUAL 0)
      MESSAGE(STATUS "Performing Test ${message} - Failed")
      SET(${VAR} "" CACHE INTERNAL "Test ${message}")
      FILE(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
        "Performing C SOURCE FILE Test ${message} failed with the following output:\n"
        "${OUTPUT}\n"
        "Return value: ${result_var}\n"
        "Source file was:\n${src}\n")
    ENDIF("${result_var}" EQUAL 0)
  ENDIF("${VAR}" MATCHES "^${VAR}$" OR "${VAR}" MATCHES "UNKNOWN")
ENDMACRO(CURL_CHECK_C_SOURCE_RUNS)
