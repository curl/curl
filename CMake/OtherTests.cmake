include(CheckCSourceCompiles)
# The begin of the sources (macros and includes)
set(_source_epilogue "#undef inline")

macro(add_header_include check header)
  if(${check})
    set(_source_epilogue "${_source_epilogue}\n#include <${header}>")
  endif(${check})
endmacro(add_header_include)

set(signature_call_conv)
set(linkage )
if(HAVE_WINDOWS_H)
  add_header_include(HAVE_WINSOCK2_H "winsock2.h")
  add_header_include(HAVE_WINDOWS_H "windows.h")
  add_header_include(HAVE_WINSOCK_H "winsock.h")
  set(_source_epilogue
      "${_source_epilogue}\n#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif")
  set(signature_call_conv "PASCAL")
  set(linkage "WINSOCK_API_LINKAGE")
  if(HAVE_LIBWS2_32)
    set(CMAKE_REQUIRED_LIBRARIES ws2_32)
  endif()
else(HAVE_WINDOWS_H)
  add_header_include(HAVE_SYS_TYPES_H "sys/types.h")
  add_header_include(HAVE_SYS_SOCKET_H "sys/socket.h")
endif(HAVE_WINDOWS_H)

check_cxx_source_compiles("${_source_epilogue}
int main(void) {
    recv(0, 0, 0, 0);
    return 0;
}" curl_cv_recv)
if(curl_cv_recv)
  if(NOT DEFINED curl_cv_func_recv_args OR "${curl_cv_func_recv_args}" STREQUAL "unknown")
    set(curl_recv_test_head
    "${_source_epilogue}
    //C++ includes don't work properly with curl, so define is_same ourselves
    template<class,class>struct is_same{static constexpr bool value=false;};
    template<class T>struct is_same<T,T>{static constexpr bool value=true;};
    template <class Ret, class Arg1, class Arg2, class Arg3, class Arg4>
    void check_args(Ret(${signature_call_conv} *r)(Arg1,Arg2,Arg3,Arg4)) {
      static_assert(is_same<")
    set(curl_recv_test_tail
    ">::value,\"\");
      r(0,0,0,0);
    }
    int main() {
      check_args(&recv);
    }")

    foreach(recv_retv "int" "ssize_t" )
      unset(curl_cv_func_recv_test CACHE)
      check_cxx_source_compiles("${curl_recv_test_head} Ret,${recv_retv} ${curl_recv_test_tail}" curl_cv_func_recv_test)
      message(STATUS "Tested recv return type == ${recv_retv}")
      if(curl_cv_func_recv_test)
        set(RECV_TYPE_RETV "${recv_retv}")
        break()
      endif(curl_cv_func_recv_test)
    endforeach(recv_retv)
    if(NOT DEFINED RECV_TYPE_RETV)
      message(FATAL_ERROR "Cannot determine recv return type")
    endif()

    foreach(recv_arg1 "SOCKET" "int")
      unset(curl_cv_func_recv_test CACHE)
      check_cxx_source_compiles("${curl_recv_test_head} Arg1,${recv_arg1} ${curl_recv_test_tail}" curl_cv_func_recv_test)
      message(STATUS "Tested recv socket type == ${recv_arg1}")
      if(curl_cv_func_recv_test)
        set(RECV_TYPE_ARG1 "${recv_arg1}")
        break()
      endif(curl_cv_func_recv_test)
    endforeach(recv_arg1)
    if(NOT DEFINED RECV_TYPE_ARG1)
      message(FATAL_ERROR "Cannot determine recv socket type")
    endif()

    foreach(recv_arg2 "void *" "char *")
      unset(curl_cv_func_recv_test CACHE)
      check_cxx_source_compiles("${curl_recv_test_head} Arg2,${recv_arg2} ${curl_recv_test_tail}" curl_cv_func_recv_test)
      message(STATUS "Tested recv buffer type == ${recv_arg2}")
      if(curl_cv_func_recv_test)
        set(RECV_TYPE_ARG2 "${recv_arg2}")
        break()
      endif(curl_cv_func_recv_test)
    endforeach(recv_arg2)
    if(NOT DEFINED RECV_TYPE_ARG2)
      message(FATAL_ERROR "Cannot determine recv buffer type")
    endif()

    foreach(recv_arg3 "size_t" "int" "socklen_t" "unsigned int")
      unset(curl_cv_func_recv_test CACHE)
      check_cxx_source_compiles("${curl_recv_test_head} Arg3,${recv_arg3} ${curl_recv_test_tail}" curl_cv_func_recv_test)
      message(STATUS "Tested recv length type == ${recv_arg3}")
      if(curl_cv_func_recv_test)
        set(RECV_TYPE_ARG3 "${recv_arg3}")
        break()
      endif(curl_cv_func_recv_test)
    endforeach(recv_arg3)
    if(NOT DEFINED RECV_TYPE_ARG3)
      message(FATAL_ERROR "Cannot determine recv length type")
    endif()

    foreach(recv_arg4 "int" "unsigned int")
      unset(curl_cv_func_recv_test CACHE)
      check_cxx_source_compiles("${curl_recv_test_head} Arg4,${recv_arg4} ${curl_recv_test_tail}" curl_cv_func_recv_test)
      message(STATUS "Tested recv flags type == ${recv_arg4}")
      if(curl_cv_func_recv_test)
        set(RECV_TYPE_ARG4 "${recv_arg4}")
        break()
      endif(curl_cv_func_recv_test)
    endforeach(recv_arg4)
    if(NOT DEFINED RECV_TYPE_ARG4)
      message(FATAL_ERROR "Cannot determine recv flags type")
    endif()
    set(curl_cv_func_recv_args
            "${RECV_TYPE_ARG1},${RECV_TYPE_ARG2},${RECV_TYPE_ARG3},${RECV_TYPE_ARG4},${RECV_TYPE_RETV}")
    set(HAVE_RECV 1)
    set(curl_cv_func_recv_done 1)

  else()
    string(REGEX REPLACE "^([^,]*),[^,]*,[^,]*,[^,]*,[^,]*$" "\\1" RECV_TYPE_ARG1 "${curl_cv_func_recv_args}")
    string(REGEX REPLACE "^[^,]*,([^,]*),[^,]*,[^,]*,[^,]*$" "\\1" RECV_TYPE_ARG2 "${curl_cv_func_recv_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,([^,]*),[^,]*,[^,]*$" "\\1" RECV_TYPE_ARG3 "${curl_cv_func_recv_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,([^,]*),[^,]*$" "\\1" RECV_TYPE_ARG4 "${curl_cv_func_recv_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,[^,]*,([^,]*)$" "\\1" RECV_TYPE_RETV "${curl_cv_func_recv_args}")
  endif()

  if("${curl_cv_func_recv_args}" STREQUAL "unknown")
    message(FATAL_ERROR "Cannot find proper types to use for recv args")
  endif("${curl_cv_func_recv_args}" STREQUAL "unknown")
else(curl_cv_recv)
  message(FATAL_ERROR "Unable to link function recv")
endif(curl_cv_recv)
set(curl_cv_func_recv_args "${curl_cv_func_recv_args}" CACHE INTERNAL "Arguments for recv")
set(HAVE_RECV 1)

check_cxx_source_compiles("${_source_epilogue}
int main(void) {
    send(0, 0, 0, 0);
    return 0;
}" curl_cv_send)
if(curl_cv_send)
  if(NOT DEFINED curl_cv_func_send_args OR "${curl_cv_func_send_args}" STREQUAL "unknown")
    set(curl_send_test_head
            "${_source_epilogue}
            template <class T, class U>struct is_same{static constexpr bool value=false;};
            template<class T>struct is_same<T,T>{static constexpr bool value=true;};
            template <class Ret, class Arg1, class Arg2, class Arg3, class Arg4>
            void check_args(Ret(${signature_call_conv} *r)(Arg1,Arg2,Arg3,Arg4)) {
              static_assert(is_same<")
    set(curl_send_test_tail
            ">::value,\"\");
              r(0,0,0,0);
            }
            int main() {
              check_args(&send);
            }")

    foreach(send_retv "int" "ssize_t" )
      unset(curl_cv_func_send_test CACHE)
      check_cxx_source_compiles("${curl_send_test_head} Ret,${send_retv} ${curl_send_test_tail}" curl_cv_func_send_test)
      message(STATUS "Tested send return type == ${send_retv}")
      if(curl_cv_func_send_test)
        set(SEND_TYPE_RETV "${send_retv}")
        break()
      endif(curl_cv_func_send_test)
    endforeach(send_retv)
    if(NOT DEFINED SEND_TYPE_RETV)
      message(FATAL_ERROR "Cannot determine send return type")
    endif()

    foreach(send_arg1 "int" "ssize_t" "SOCKET")
      unset(curl_cv_func_send_test CACHE)
      check_cxx_source_compiles("${curl_send_test_head} Arg1,${send_arg1} ${curl_send_test_tail}" curl_cv_func_send_test)
      message(STATUS "Tested send socket type == ${send_arg1}")
      if(curl_cv_func_send_test)
        set(SEND_TYPE_ARG1 "${send_arg1}")
        break()
      endif(curl_cv_func_send_test)
    endforeach(send_arg1)
    if(NOT DEFINED SEND_TYPE_ARG1)
      message(FATAL_ERROR "Cannot determine send socket type")
    endif()

    foreach(send_arg2 "const void *" "void *" "char *" "const char *")
      unset(curl_cv_func_send_test CACHE)
      check_cxx_source_compiles("${curl_send_test_head} Arg2,${send_arg2} ${curl_send_test_tail}" curl_cv_func_send_test)
      message(STATUS "Tested send buffer type == ${send_arg2}")
      if(curl_cv_func_send_test)
        set(SEND_TYPE_ARG2 "${send_arg2}")
        break()
      endif(curl_cv_func_send_test)
    endforeach(send_arg2)
    if(NOT DEFINED SEND_TYPE_ARG2)
      message(FATAL_ERROR "Cannot determine send buffer type")
    endif()
    string(REGEX REPLACE "(const) .*" "\\1" send_qual_arg2 "${SEND_TYPE_ARG2}")
    string(REGEX REPLACE "const (.*)" "\\1" SEND_TYPE_ARG2 "${SEND_TYPE_ARG2}")

    foreach(send_arg3 "size_t" "int" "socklen_t" "unsigned int")
      unset(curl_cv_func_send_test CACHE)
      check_cxx_source_compiles("${curl_send_test_head} Arg3,${send_arg3} ${curl_send_test_tail}" curl_cv_func_send_test)
      message(STATUS "Tested send length type == ${send_arg3}")
      if(curl_cv_func_send_test)
        set(SEND_TYPE_ARG3 "${send_arg3}")
        break()
      endif(curl_cv_func_send_test)
    endforeach(send_arg3)
    if(NOT DEFINED SEND_TYPE_ARG3)
      message(FATAL_ERROR "Cannot determine send length type")
    endif()

    foreach(send_arg4 "int" "unsigned int")
      unset(curl_cv_func_send_test CACHE)
      check_cxx_source_compiles("${curl_send_test_head} Arg4,${send_arg4} ${curl_send_test_tail}" curl_cv_func_send_test)
      message(STATUS "Tested send flags type == ${send_arg4}")
      if(curl_cv_func_send_test)
        set(SEND_TYPE_ARG4 "${send_arg4}")
        break()
      endif(curl_cv_func_send_test)
    endforeach(send_arg4)
    if(NOT DEFINED SEND_TYPE_ARG4)
      message(FATAL_ERROR "Cannot determine send flags type")
    endif()

    set(curl_cv_func_send_args
            "${SEND_TYPE_ARG1},${SEND_TYPE_ARG2},${SEND_TYPE_ARG3},${SEND_TYPE_ARG4},${SEND_TYPE_RETV},${send_qual_arg2}")
    set(HAVE_SEND 1)
    set(curl_cv_func_send_done 1)

  else()
    string(REGEX REPLACE "^([^,]*),[^,]*,[^,]*,[^,]*,[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG1 "${curl_cv_func_send_args}")
    string(REGEX REPLACE "^[^,]*,([^,]*),[^,]*,[^,]*,[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG2 "${curl_cv_func_send_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,([^,]*),[^,]*,[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG3 "${curl_cv_func_send_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,([^,]*),[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG4 "${curl_cv_func_send_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,[^,]*,([^,]*),[^,]*$" "\\1" SEND_TYPE_RETV "${curl_cv_func_send_args}")
    string(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,([^,]*)$" "\\1" SEND_QUAL_ARG2 "${curl_cv_func_send_args}")
  endif()

  if("${curl_cv_func_send_args}" STREQUAL "unknown")
    message(FATAL_ERROR "Cannot find proper types to use for send args")
  endif("${curl_cv_func_send_args}" STREQUAL "unknown")
  set(SEND_QUAL_ARG2 "const")
else(curl_cv_send)
  message(FATAL_ERROR "Unable to link function send")
endif(curl_cv_send)
set(curl_cv_func_send_args "${curl_cv_func_send_args}" CACHE INTERNAL "Arguments for send")
set(HAVE_SEND 1)

check_cxx_source_compiles("${_source_epilogue}
  int main(void) {
    int flag = MSG_NOSIGNAL;
    (void)flag;
    return 0;
  }" HAVE_MSG_NOSIGNAL)

if(NOT HAVE_WINDOWS_H)
  add_header_include(HAVE_SYS_TIME_H "sys/time.h")
  add_header_include(TIME_WITH_SYS_TIME "time.h")
  add_header_include(HAVE_TIME_H "time.h")
endif()
check_cxx_source_compiles("${_source_epilogue}
int main(void) {
  struct timeval ts;
  ts.tv_sec  = 0;
  ts.tv_usec = 0;
  (void)ts;
  return 0;
}" HAVE_STRUCT_TIMEVAL)


include(CheckCSourceRuns)
# See HAVE_POLL in CMakeLists.txt for why poll is disabled on macOS
if(NOT APPLE)
  set(CMAKE_REQUIRED_FLAGS)
  if(HAVE_SYS_POLL_H)
    set(CMAKE_REQUIRED_FLAGS "-DHAVE_SYS_POLL_H")
  endif(HAVE_SYS_POLL_H)
  check_c_source_runs("
    #ifdef HAVE_SYS_POLL_H
    #  include <sys/poll.h>
    #endif
    int main(void) {
      return poll((void *)0, 0, 10 /*ms*/);
    }" HAVE_POLL_FINE)
endif()

set(HAVE_SIG_ATOMIC_T 1)
set(CMAKE_REQUIRED_FLAGS)
if(HAVE_SIGNAL_H)
  set(CMAKE_REQUIRED_FLAGS "-DHAVE_SIGNAL_H")
  set(CMAKE_EXTRA_INCLUDE_FILES "signal.h")
endif(HAVE_SIGNAL_H)
check_type_size("sig_atomic_t" SIZEOF_SIG_ATOMIC_T)
if(HAVE_SIZEOF_SIG_ATOMIC_T)
  check_cxx_source_compiles("
    #ifdef HAVE_SIGNAL_H
    #  include <signal.h>
    #endif
    int main(void) {
      static volatile sig_atomic_t dummy = 0;
      (void)dummy;
      return 0;
    }" HAVE_SIG_ATOMIC_T_NOT_VOLATILE)
  if(NOT HAVE_SIG_ATOMIC_T_NOT_VOLATILE)
    set(HAVE_SIG_ATOMIC_T_VOLATILE 1)
  endif(NOT HAVE_SIG_ATOMIC_T_NOT_VOLATILE)
endif(HAVE_SIZEOF_SIG_ATOMIC_T)

if(HAVE_WINDOWS_H)
  set(CMAKE_EXTRA_INCLUDE_FILES winsock2.h)
else()
  set(CMAKE_EXTRA_INCLUDE_FILES)
  if(HAVE_SYS_SOCKET_H)
    set(CMAKE_EXTRA_INCLUDE_FILES sys/socket.h)
  endif(HAVE_SYS_SOCKET_H)
endif()

check_type_size("struct sockaddr_storage" SIZEOF_STRUCT_SOCKADDR_STORAGE)
if(HAVE_SIZEOF_STRUCT_SOCKADDR_STORAGE)
  set(HAVE_STRUCT_SOCKADDR_STORAGE 1)
endif(HAVE_SIZEOF_STRUCT_SOCKADDR_STORAGE)

if(HAVE_SYS_POLL_H)
	set(CMAKE_EXTRA_INCLUDE_FILES "${CMAKE_EXTRA_INCLUDE_FILES};sys/poll.h")
endif()
if(HAVE_POLL_H)
	set(CMAKE_EXTRA_INCLUDE_FILES "${CMAKE_EXTRA_INCLUDE_FILES};poll.h")
endif()
check_type_size("struct pollfd" SIZEOF_STRUCT_POLLFD)
if(HAVE_SIZEOF_STRUCT_POLLFD)
	set(HAVE_STRUCT_POLLFD 1)
endif()
