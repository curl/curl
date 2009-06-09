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

macro(CURL_CHECK_C_SOURCE_RUNS SOURCE VAR)
  if("${VAR}" MATCHES "^${VAR}$" OR "${VAR}" MATCHES "UNKNOWN")
    set(message "${VAR}")
    # If the number of arguments is greater than 2 (SOURCE VAR)
    if(${ARGC} GREATER 2)
      # then add the third argument as a message
      set(message "${ARGV2} (${VAR})")
    endif(${ARGC} GREATER 2)
    set(MACRO_CHECK_FUNCTION_DEFINITIONS
      "-D${VAR} ${CMAKE_REQUIRED_FLAGS}")
    if(CMAKE_REQUIRED_LIBRARIES)
      set(CURL_CHECK_C_SOURCE_COMPILES_ADD_LIBRARIES
        "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
    else(CMAKE_REQUIRED_LIBRARIES)
      set(CURL_CHECK_C_SOURCE_COMPILES_ADD_LIBRARIES)
    endif(CMAKE_REQUIRED_LIBRARIES)
    if(CMAKE_REQUIRED_INCLUDES)
      set(CURL_CHECK_C_SOURCE_COMPILES_ADD_INCLUDES
        "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_REQUIRED_INCLUDES}")
    else(CMAKE_REQUIRED_INCLUDES)
      set(CURL_CHECK_C_SOURCE_COMPILES_ADD_INCLUDES)
    endif(CMAKE_REQUIRED_INCLUDES)
    set(src "")
    foreach(def ${EXTRA_DEFINES})
      set(src "${src}#define ${def} 1\n")
    endforeach(def)
    foreach(inc ${HEADER_INCLUDES})
      set(src "${src}#include <${inc}>\n")
    endforeach(inc)

    set(src "${src}\nint main() { ${SOURCE} ; return 0; }")
    set(CMAKE_CONFIGURABLE_FILE_CONTENT "${src}")
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CMake/CMakeConfigurableFile.in
      "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/src.c"
      IMMEDIATE)
    message(STATUS "Performing Test ${message}")
    try_run(${VAR} ${VAR}_COMPILED
      ${CMAKE_BINARY_DIR}
      ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/src.c
      COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
      CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${MACRO_CHECK_FUNCTION_DEFINITIONS}
      "${CURL_CHECK_C_SOURCE_COMPILES_ADD_LIBRARIES}"
      "${CURL_CHECK_C_SOURCE_COMPILES_ADD_INCLUDES}"
      OUTPUT_VARIABLE OUTPUT)
    # if it did not compile make the return value fail code of 1
    if(NOT ${VAR}_COMPILED)
      set(${VAR} 1)
    endif(NOT ${VAR}_COMPILED)
    # if the return value was 0 then it worked
    set(result_var ${${VAR}})
    if("${result_var}" EQUAL 0)
      set(${VAR} 1 CACHE INTERNAL "Test ${message}")
      message(STATUS "Performing Test ${message} - Success")
      file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
        "Performing C SOURCE FILE Test ${message} succeded with the following output:\n"
        "${OUTPUT}\n"
        "Return value: ${${VAR}}\n"
        "Source file was:\n${src}\n")
    else("${result_var}" EQUAL 0)
      message(STATUS "Performing Test ${message} - Failed")
      set(${VAR} "" CACHE INTERNAL "Test ${message}")
      file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
        "Performing C SOURCE FILE Test ${message} failed with the following output:\n"
        "${OUTPUT}\n"
        "Return value: ${result_var}\n"
        "Source file was:\n${src}\n")
    endif("${result_var}" EQUAL 0)
  endif("${VAR}" MATCHES "^${VAR}$" OR "${VAR}" MATCHES "UNKNOWN")
endmacro(CURL_CHECK_C_SOURCE_RUNS)
