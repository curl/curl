# File containing various utilities

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

# Returns a list of arguments that evaluate to true
function(collect_true output_var output_count_var)
  set(${output_var})
  foreach(option_var IN LISTS ARGN)
    if(${option_var})
      list(APPEND ${output_var} ${option_var})
    endif()
  endforeach()
  set(${output_var} ${${output_var}} PARENT_SCOPE)
  list(LENGTH ${output_var} ${output_count_var})
  set(${output_count_var} ${${output_count_var}} PARENT_SCOPE)
endfunction()
