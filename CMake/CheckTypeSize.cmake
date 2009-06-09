# - Check sizeof a type
#  CHECK_TYPE_SIZE(TYPE VARIABLE)
# Check if the type exists and determine size of type.  if the type
# exists, the size will be stored to the variable.
#
#  VARIABLE - variable to store size if the type exists.
#  HAVE_${VARIABLE} - does the variable exists or not

macro(CHECK_TYPE_SIZE TYPE VARIABLE)
  set(CMAKE_ALLOW_UNKNOWN_VARIABLE_READ_ACCESS 1)
  if(NOT DEFINED ${VARIABLE})
    if("HAVE_${VARIABLE}" MATCHES "^HAVE_${VARIABLE}$")
      set(CHECK_TYPE_SIZE_TYPE "${TYPE}")
      set(MACRO_CHECK_TYPE_SIZE_FLAGS 
        "${CMAKE_REQUIRED_FLAGS}")
      foreach(def HAVE_SYS_TYPES_H HAVE_STDINT_H HAVE_STDDEF_H)
        if("${def}")
          set(MACRO_CHECK_TYPE_SIZE_FLAGS 
            "${MACRO_CHECK_TYPE_SIZE_FLAGS} -D${def}")
        endif("${def}")
      endforeach(def)
      set(CHECK_TYPE_SIZE_PREMAIN)
      foreach(def ${CMAKE_EXTRA_INCLUDE_FILES})
        set(CHECK_TYPE_SIZE_PREMAIN "${CHECK_TYPE_SIZE_PREMAIN}#include \"${def}\"\n")
      endforeach(def)
      configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/CMake/CheckTypeSize.c.in"
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/CheckTypeSize.c" 
        IMMEDIATE @ONLY)
      file(READ 
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/CheckTypeSize.c"
        CHECK_TYPE_SIZE_FILE_CONTENT)
      message(STATUS "Check size of ${TYPE}")
      if(CMAKE_REQUIRED_LIBRARIES)
        set(CHECK_TYPE_SIZE_ADD_LIBRARIES 
          "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
      endif(CMAKE_REQUIRED_LIBRARIES)
      try_run(${VARIABLE} HAVE_${VARIABLE}
        ${CMAKE_BINARY_DIR}
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/CheckTypeSize.c"
        CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${MACRO_CHECK_TYPE_SIZE_FLAGS}
        "${CHECK_TYPE_SIZE_ADD_LIBRARIES}"
        OUTPUT_VARIABLE OUTPUT)
      if(HAVE_${VARIABLE})
        message(STATUS "Check size of ${TYPE} - done")
        file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log 
          "Determining size of ${TYPE} passed with the following output:\n${OUTPUT}\n\n")
      else(HAVE_${VARIABLE})
        message(STATUS "Check size of ${TYPE} - failed")
        file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log 
          "Determining size of ${TYPE} failed with the following output:\n${OUTPUT}\nCheckTypeSize.c:\n${CHECK_TYPE_SIZE_FILE_CONTENT}\n\n")
      endif(HAVE_${VARIABLE})
    endif("HAVE_${VARIABLE}" MATCHES "^HAVE_${VARIABLE}$")
  endif(NOT DEFINED ${VARIABLE})
  set(CMAKE_ALLOW_UNKNOWN_VARIABLE_READ_ACCESS )
endmacro(CHECK_TYPE_SIZE)
