# File containing various utilities

#Load check for compiler flags
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# Converts a CMake list to a string containing elements separated by spaces
function(TO_LIST_SPACES _LIST_NAME OUTPUT_VAR)
  set(NEW_LIST_SPACE)
  foreach(ITEM ${${_LIST_NAME}})
    set(NEW_LIST_SPACE "${NEW_LIST_SPACE} ${ITEM}")
  endforeach()
  string(STRIP ${NEW_LIST_SPACE} NEW_LIST_SPACE)
  set(${OUTPUT_VAR} "${NEW_LIST_SPACE}" PARENT_SCOPE)
endfunction()

# Appends a lis of item to a string which is a space-separated list, if they don't already exist.
function(LIST_SPACES_APPEND_ONCE LIST_NAME)
  string(REPLACE " " ";" _LIST ${${LIST_NAME}})
  list(APPEND _LIST ${ARGN})
  list(REMOVE_DUPLICATES _LIST)
  to_list_spaces(_LIST NEW_LIST_SPACE)
  set(${LIST_NAME} "${NEW_LIST_SPACE}" PARENT_SCOPE)
endfunction()

# Convinience function that does the same as LIST(FIND ...) but with a TRUE/FALSE return value.
# Ex: IN_STR_LIST(MY_LIST "Searched item" WAS_FOUND)
function(IN_STR_LIST LIST_NAME ITEM_SEARCHED RETVAL)
  list(FIND ${LIST_NAME} ${ITEM_SEARCHED} FIND_POS)
  if(${FIND_POS} EQUAL -1)
    set(${RETVAL} FALSE PARENT_SCOPE)
  else()
    set(${RETVAL} TRUE PARENT_SCOPE)
  endif()
endfunction()

# Set Compiler flags
function(SET_BUILD_TYPE_FLAGS BUILD_TYPE)
  if(WIN32)
    set(CompilerFlags
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_MINSIZEREL
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELMITDEBINFO
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_MINSIZEREL
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELMITDEBINFO)

    #Set /MT flag for Static compiling, /MD for Shared
    foreach(Flag ${CompilerFlags})
      if("${BUILD_TYPE}" MATCHES "STATIC")
        string(REPLACE "/MD" "/MT" ${Flag} "${${Flag}}")
      else()
        string(REPLACE "/MT" "/MD" ${Flag} "${${Flag}}")
      endif()
    endforeach()
  else()
    if("${BUILD_TYPE}" MATCHES "STATIC")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
      set(CMAKE_EXE_LINKER_FLAGS "")
    else()
      set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
      set(CMAKE_EXE_LINK_DYNAMIC_C_FLAGS "")
      set(CMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS "")
      set(CMAKE_SHARED_LIBRARY_C_FLAGS "")
      set(CMAKE_SHARED_LIBRARY_CXX_FLAGS "")
    endif()
  endif()
endfunction()