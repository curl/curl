# File containing various utilities

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
