INCLUDE(CurlCheckCSourceCompiles)
SET(EXTRA_DEFINES "__unused1\n#undef inline\n#define __unused2")
SET(HEADER_INCLUDES)
SET(headers_hack)

MACRO(add_header_include check header)
  IF(${check})
    SET(headers_hack
      "${headers_hack}\n#include <${header}>")
    #SET(HEADER_INCLUDES
    #  ${HEADER_INCLUDES}
    #  "${header}")
  ENDIF(${check})
ENDMACRO(add_header_include)

SET(signature_call_conv)
IF(HAVE_WINDOWS_H)
  add_header_include(HAVE_WINDOWS_H "windows.h")
  add_header_include(HAVE_WINSOCK2_H "winsock2.h")
  add_header_include(HAVE_WINSOCK_H "winsock.h")
  SET(EXTRA_DEFINES ${EXTRA_DEFINES}
    "__unused7\n#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif\n#define __unused3")
  SET(signature_call_conv "PASCAL")
ELSE(HAVE_WINDOWS_H)
  add_header_include(HAVE_SYS_TYPES_H "sys/types.h")
  add_header_include(HAVE_SYS_SOCKET_H "sys/socket.h")
ENDIF(HAVE_WINDOWS_H)

SET(EXTRA_DEFINES_BACKUP "${EXTRA_DEFINES}")
SET(EXTRA_DEFINES "${EXTRA_DEFINES_BACKUP}\n${headers_hack}\n${extern_line}\n#define __unused5")
CURL_CHECK_C_SOURCE_COMPILES("recv(0, 0, 0, 0)" curl_cv_recv)
IF(curl_cv_recv)
  #    AC_CACHE_CHECK([types of arguments and return type for recv],
  #[curl_cv_func_recv_args], [
  #SET(curl_cv_func_recv_args "unknown")
  #for recv_retv in 'int' 'ssize_t'; do
  IF(NOT DEFINED curl_cv_func_recv_args OR "${curl_cv_func_recv_args}" STREQUAL "unknown")
    FOREACH(recv_retv "int" "ssize_t" )
      FOREACH(recv_arg1 "int" "ssize_t" "SOCKET")
        FOREACH(recv_arg2 "void *" "char *")
          FOREACH(recv_arg3 "size_t" "int" "socklen_t" "unsigned int")
            FOREACH(recv_arg4 "int" "unsigned int")
              IF(NOT curl_cv_func_recv_done)
                SET(curl_cv_func_recv_test "UNKNOWN")
                SET(extern_line "extern ${recv_retv} ${signature_call_conv} recv(${recv_arg1}, ${recv_arg2}, ${recv_arg3}, ${recv_arg4})\;")
                SET(EXTRA_DEFINES "${EXTRA_DEFINES_BACKUP}\n${headers_hack}\n${extern_line}\n#define __unused5")
                CURL_CHECK_C_SOURCE_COMPILES("
                    ${recv_arg1} s=0;
                    ${recv_arg2} buf=0;
                    ${recv_arg3} len=0;
                    ${recv_arg4} flags=0;
                    ${recv_retv} res = recv(s, buf, len, flags)"
                    curl_cv_func_recv_test
                    "${recv_retv} recv(${recv_arg1}, ${recv_arg2}, ${recv_arg3}, ${recv_arg4})")
                IF(curl_cv_func_recv_test)
                  SET(curl_cv_func_recv_args
                    "${recv_arg1},${recv_arg2},${recv_arg3},${recv_arg4},${recv_retv}")
                  SET(RECV_TYPE_ARG1 "${recv_arg1}")
                  SET(RECV_TYPE_ARG2 "${recv_arg2}")
                  SET(RECV_TYPE_ARG3 "${recv_arg3}")
                  SET(RECV_TYPE_ARG4 "${recv_arg4}")
                  SET(RECV_TYPE_RETV "${recv_retv}")
                  SET(HAVE_RECV 1)
                  SET(curl_cv_func_recv_done 1)
                ENDIF(curl_cv_func_recv_test)
              ENDIF(NOT curl_cv_func_recv_done)
            ENDFOREACH(recv_arg4)
          ENDFOREACH(recv_arg3)
        ENDFOREACH(recv_arg2)
      ENDFOREACH(recv_arg1)
    ENDFOREACH(recv_retv) 
  ELSE(NOT DEFINED curl_cv_func_recv_args OR "${curl_cv_func_recv_args}" STREQUAL "unknown")
    STRING(REGEX REPLACE "^([^,]*),[^,]*,[^,]*,[^,]*,[^,]*$" "\\1" RECV_TYPE_ARG1 "${curl_cv_func_recv_args}")
    STRING(REGEX REPLACE "^[^,]*,([^,]*),[^,]*,[^,]*,[^,]*$" "\\1" RECV_TYPE_ARG2 "${curl_cv_func_recv_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,([^,]*),[^,]*,[^,]*$" "\\1" RECV_TYPE_ARG3 "${curl_cv_func_recv_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,([^,]*),[^,]*$" "\\1" RECV_TYPE_ARG4 "${curl_cv_func_recv_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,[^,]*,([^,]*)$" "\\1" RECV_TYPE_RETV "${curl_cv_func_recv_args}")
    #MESSAGE("RECV_TYPE_ARG1 ${RECV_TYPE_ARG1}")
    #MESSAGE("RECV_TYPE_ARG2 ${RECV_TYPE_ARG2}")
    #MESSAGE("RECV_TYPE_ARG3 ${RECV_TYPE_ARG3}")
    #MESSAGE("RECV_TYPE_ARG4 ${RECV_TYPE_ARG4}")
    #MESSAGE("RECV_TYPE_RETV ${RECV_TYPE_RETV}")
  ENDIF(NOT DEFINED curl_cv_func_recv_args OR "${curl_cv_func_recv_args}" STREQUAL "unknown")
  
  IF("${curl_cv_func_recv_args}" STREQUAL "unknown")
    MESSAGE(FATAL_ERROR "Cannot find proper types to use for recv args")
  ENDIF("${curl_cv_func_recv_args}" STREQUAL "unknown")
ELSE(curl_cv_recv)
  MESSAGE(FATAL_ERROR "Unable to link function recv")
ENDIF(curl_cv_recv)
SET(curl_cv_func_recv_args "${curl_cv_func_recv_args}" CACHE INTERNAL "Arguments for recv")
SET(HAVE_RECV 1)

CURL_CHECK_C_SOURCE_COMPILES("send(0, 0, 0, 0)" curl_cv_send)
IF(curl_cv_send)
  #    AC_CACHE_CHECK([types of arguments and return type for send],
  #[curl_cv_func_send_args], [
  #SET(curl_cv_func_send_args "unknown")
  #for send_retv in 'int' 'ssize_t'; do
  IF(NOT DEFINED curl_cv_func_send_args OR "${curl_cv_func_send_args}" STREQUAL "unknown")
    FOREACH(send_retv "int" "ssize_t" )
      FOREACH(send_arg1 "int" "ssize_t" "SOCKET")
        FOREACH(send_arg2 "const void *" "void *" "char *" "const char *")
          FOREACH(send_arg3 "size_t" "int" "socklen_t" "unsigned int")
            FOREACH(send_arg4 "int" "unsigned int")
              IF(NOT curl_cv_func_send_done)
                SET(curl_cv_func_send_test "UNKNOWN")
                SET(extern_line "extern ${send_retv} ${signature_call_conv} send(${send_arg1}, ${send_arg2}, ${send_arg3}, ${send_arg4})\;")
                SET(EXTRA_DEFINES "${EXTRA_DEFINES_BACKUP}\n${headers_hack}\n${extern_line}\n#define __unused5")
                CURL_CHECK_C_SOURCE_COMPILES("
                    ${send_arg1} s=0;
                    ${send_arg2} buf=0;
                    ${send_arg3} len=0;
                    ${send_arg4} flags=0;
                    ${send_retv} res = send(s, buf, len, flags)"
                    curl_cv_func_send_test
                    "${send_retv} send(${send_arg1}, ${send_arg2}, ${send_arg3}, ${send_arg4})")
                IF(curl_cv_func_send_test)
                  #MESSAGE("Found arguments: ${curl_cv_func_send_test}")
                  STRING(REGEX REPLACE "(const) .*" "\\1" send_qual_arg2 "${send_arg2}")
                  STRING(REGEX REPLACE "const (.*)" "\\1" send_arg2 "${send_arg2}")
                  SET(curl_cv_func_send_args
                    "${send_arg1},${send_arg2},${send_arg3},${send_arg4},${send_retv},${send_qual_arg2}")
                  SET(SEND_TYPE_ARG1 "${send_arg1}")
                  SET(SEND_TYPE_ARG2 "${send_arg2}")
                  SET(SEND_TYPE_ARG3 "${send_arg3}")
                  SET(SEND_TYPE_ARG4 "${send_arg4}")
                  SET(SEND_TYPE_RETV "${send_retv}")
                  SET(HAVE_SEND 1)
                  SET(curl_cv_func_send_done 1)
                ENDIF(curl_cv_func_send_test)
              ENDIF(NOT curl_cv_func_send_done)
            ENDFOREACH(send_arg4)
          ENDFOREACH(send_arg3)
        ENDFOREACH(send_arg2)
      ENDFOREACH(send_arg1)
    ENDFOREACH(send_retv) 
  ELSE(NOT DEFINED curl_cv_func_send_args OR "${curl_cv_func_send_args}" STREQUAL "unknown")
    STRING(REGEX REPLACE "^([^,]*),[^,]*,[^,]*,[^,]*,[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG1 "${curl_cv_func_send_args}")
    STRING(REGEX REPLACE "^[^,]*,([^,]*),[^,]*,[^,]*,[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG2 "${curl_cv_func_send_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,([^,]*),[^,]*,[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG3 "${curl_cv_func_send_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,([^,]*),[^,]*,[^,]*$" "\\1" SEND_TYPE_ARG4 "${curl_cv_func_send_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,[^,]*,([^,]*),[^,]*$" "\\1" SEND_TYPE_RETV "${curl_cv_func_send_args}")
    STRING(REGEX REPLACE "^[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,([^,]*)$" "\\1" SEND_QUAL_ARG2 "${curl_cv_func_send_args}")
    #MESSAGE("SEND_TYPE_ARG1 ${SEND_TYPE_ARG1}")
    #MESSAGE("SEND_TYPE_ARG2 ${SEND_TYPE_ARG2}")
    #MESSAGE("SEND_TYPE_ARG3 ${SEND_TYPE_ARG3}")
    #MESSAGE("SEND_TYPE_ARG4 ${SEND_TYPE_ARG4}")
    #MESSAGE("SEND_TYPE_RETV ${SEND_TYPE_RETV}")
    #MESSAGE("SEND_QUAL_ARG2 ${SEND_QUAL_ARG2}")
  ENDIF(NOT DEFINED curl_cv_func_send_args OR "${curl_cv_func_send_args}" STREQUAL "unknown")
  
  IF("${curl_cv_func_send_args}" STREQUAL "unknown")
    MESSAGE(FATAL_ERROR "Cannot find proper types to use for send args")
  ENDIF("${curl_cv_func_send_args}" STREQUAL "unknown")
  SET(SEND_QUAL_ARG2 "const")
ELSE(curl_cv_send)
  MESSAGE(FATAL_ERROR "Unable to link function send")
ENDIF(curl_cv_send)
SET(curl_cv_func_send_args "${curl_cv_func_send_args}" CACHE INTERNAL "Arguments for send")
SET(HAVE_SEND 1)

SET(EXTRA_DEFINES "${EXTRA_DEFINES}\n${headers_hack}\n#define __unused5")
CURL_CHECK_C_SOURCE_COMPILES("int flag = MSG_NOSIGNAL" HAVE_MSG_NOSIGNAL)

SET(EXTRA_DEFINES "__unused1\n#undef inline\n#define __unused2")
SET(HEADER_INCLUDES)
SET(headers_hack)

MACRO(add_header_include check header)
  IF(${check})
    SET(headers_hack
      "${headers_hack}\n#include <${header}>")
    #SET(HEADER_INCLUDES
    #  ${HEADER_INCLUDES}
    #  "${header}")
  ENDIF(${check})
ENDMACRO(add_header_include header)

IF(HAVE_WINDOWS_H)
  SET(EXTRA_DEFINES ${EXTRA_DEFINES}
    "__unused7\n#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif\n#define __unused3")
  add_header_include(HAVE_WINDOWS_H "windows.h")
  add_header_include(HAVE_WINSOCK2_H "winsock2.h")
  add_header_include(HAVE_WINSOCK_H "winsock.h")
ELSE(HAVE_WINDOWS_H)
  add_header_include(HAVE_SYS_TYPES_H "sys/types.h")
  add_header_include(HAVE_SYS_TIME_H "sys/time.h")
  add_header_include(TIME_WITH_SYS_TIME "time.h")
  add_header_include(HAVE_TIME_H "time.h")
ENDIF(HAVE_WINDOWS_H)
SET(EXTRA_DEFINES "${EXTRA_DEFINES}\n${headers_hack}\n#define __unused5")
CURL_CHECK_C_SOURCE_COMPILES("struct timeval ts;\nts.tv_sec  = 0;\nts.tv_usec = 0" HAVE_STRUCT_TIMEVAL)


INCLUDE(CurlCheckCSourceRuns)
SET(EXTRA_DEFINES)
SET(HEADER_INCLUDES)
IF(HAVE_SYS_POLL_H)
  SET(HEADER_INCLUDES "sys/poll.h")
ENDIF(HAVE_SYS_POLL_H)
CURL_CHECK_C_SOURCE_RUNS("return poll((void *)0, 0, 10 /*ms*/)" HAVE_POLL_FINE)

SET(HAVE_SIG_ATOMIC_T 1)
SET(EXTRA_DEFINES)
SET(HEADER_INCLUDES)
IF(HAVE_SIGNAL_H)
  SET(HEADER_INCLUDES "signal.h")
  SET(CMAKE_EXTRA_INCLUDE_FILES "signal.h")
ENDIF(HAVE_SIGNAL_H)
CHECK_TYPE_SIZE("sig_atomic_t" SIZEOF_SIG_ATOMIC_T)
IF(HAVE_SIZEOF_SIG_ATOMIC_T)
  CURL_CHECK_C_SOURCE_COMPILES("static volatile sig_atomic_t dummy = 0" HAVE_SIG_ATOMIC_T_NOT_VOLATILE)
  IF(NOT HAVE_SIG_ATOMIC_T_NOT_VOLATILE)
    SET(HAVE_SIG_ATOMIC_T_VOLATILE 1)
  ENDIF(NOT HAVE_SIG_ATOMIC_T_NOT_VOLATILE)
ENDIF(HAVE_SIZEOF_SIG_ATOMIC_T)

SET(CHECK_TYPE_SIZE_PREINCLUDE
  "#undef inline")

IF(HAVE_WINDOWS_H)
  SET(CHECK_TYPE_SIZE_PREINCLUDE "${CHECK_TYPE_SIZE_PREINCLUDE}
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>")
  IF(HAVE_WINSOCK2_H)
    SET(CHECK_TYPE_SIZE_PREINCLUDE "${CHECK_TYPE_SIZE_PREINCLUDE}\n#include <winsock2.h>")
  ENDIF(HAVE_WINSOCK2_H)
ELSE(HAVE_WINDOWS_H)
  IF(HAVE_SYS_SOCKET_H)
    SET(CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES}
      "sys/socket.h")
  ENDIF(HAVE_SYS_SOCKET_H)
  IF(HAVE_NETINET_IN_H)
    SET(CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES}
      "netinet/in.h")
  ENDIF(HAVE_NETINET_IN_H)
  IF(HAVE_ARPA_INET_H)
    SET(CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES}
      "arpa/inet.h")
  ENDIF(HAVE_ARPA_INET_H)
ENDIF(HAVE_WINDOWS_H)

CHECK_TYPE_SIZE("struct sockaddr_storage" SIZEOF_STRUCT_SOCKADDR_STORAGE)
IF(HAVE_SIZEOF_STRUCT_SOCKADDR_STORAGE)
  SET(HAVE_STRUCT_SOCKADDR_STORAGE 1)
ENDIF(HAVE_SIZEOF_STRUCT_SOCKADDR_STORAGE)

