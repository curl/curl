

dnl CURL_CHECK_HEADER_WINDOWS
dnl -------------------------------------------------
dnl Check for compilable and valid windows.h header 

AC_DEFUN([CURL_CHECK_HEADER_WINDOWS], [
  AC_CACHE_CHECK([for windows.h], [ac_cv_header_windows_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
      ],[
        int dummy=2*WINVER;
      ])
    ],[
      ac_cv_header_windows_h="yes"
    ],[
      ac_cv_header_windows_h="no"
    ])
  ])
  if test "x$ac_cv_header_windows_h" = "xyes"; then
    AC_DEFINE_UNQUOTED(HAVE_WINDOWS_H, 1,
      [Define to 1 if you have the windows.h header file.])
    AC_DEFINE_UNQUOTED(WIN32_LEAN_AND_MEAN, 1,
      [Define to avoid automatic inclusion of winsock.h])
  fi
])


dnl CURL_CHECK_HEADER_WINSOCK
dnl -------------------------------------------------
dnl Check for compilable and valid winsock.h header 

AC_DEFUN([CURL_CHECK_HEADER_WINSOCK], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winsock.h], [ac_cv_header_winsock_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock.h>
      ],[
        int dummy=WSACleanup();
      ])
    ],[
      ac_cv_header_winsock_h="yes"
    ],[
      ac_cv_header_winsock_h="no"
    ])
  ])
  if test "x$ac_cv_header_winsock_h" = "xyes"; then
    AC_DEFINE_UNQUOTED(HAVE_WINSOCK_H, 1,
      [Define to 1 if you have the winsock.h header file.])
  fi
])


dnl CURL_CHECK_HEADER_WINSOCK2
dnl -------------------------------------------------
dnl Check for compilable and valid winsock2.h header 

AC_DEFUN([CURL_CHECK_HEADER_WINSOCK2], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winsock2.h], [ac_cv_header_winsock2_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
      ],[
        int dummy=2*IPPROTO_ESP;
      ])
    ],[
      ac_cv_header_winsock2_h="yes"
    ],[
      ac_cv_header_winsock2_h="no"
    ])
  ])
  if test "x$ac_cv_header_winsock2_h" = "xyes"; then
    AC_DEFINE_UNQUOTED(HAVE_WINSOCK2_H, 1,
      [Define to 1 if you have the winsock2.h header file.])
  fi
])


dnl CURL_CHECK_HEADER_WS2TCPIP
dnl -------------------------------------------------
dnl Check for compilable and valid ws2tcpip.h header

AC_DEFUN([CURL_CHECK_HEADER_WS2TCPIP], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CACHE_CHECK([for ws2tcpip.h], [ac_cv_header_ws2tcpip_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
      ],[
        int dummy=2*IP_PKTINFO;
      ])
    ],[
      ac_cv_header_ws2tcpip_h="yes"
    ],[
      ac_cv_header_ws2tcpip_h="no"
    ])
  ])
  if test "x$ac_cv_header_ws2tcpip_h" = "xyes"; then
    AC_DEFINE_UNQUOTED(HAVE_WS2TCPIP_H, 1,
      [Define to 1 if you have the ws2tcpip.h header file.])
  fi
])


dnl CURL_CHECK_TYPE_SOCKLEN_T
dnl -------------------------------------------------
dnl Check for existing socklen_t type, and provide
dnl an equivalent type if socklen_t not available

AC_DEFUN([CURL_CHECK_TYPE_SOCKLEN_T], [
  AC_REQUIRE([CURL_CHECK_HEADER_WS2TCPIP])dnl
  AC_CHECK_TYPE([socklen_t], ,[
    AC_CACHE_CHECK([for socklen_t equivalent], 
      [curl_cv_socklen_t_equiv], [
      curl_cv_socklen_t_equiv="unknown"
      for arg2 in "struct sockaddr" void; do
        for t in int size_t unsigned long "unsigned long"; do
          AC_COMPILE_IFELSE([
            AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
              int getpeername (int, $arg2 *, $t *);
            ],[
              $t len=0;
              getpeername(0,0,&len);
            ])
          ],[
             curl_cv_socklen_t_equiv="$t"
             break 2
          ])
        done
      done
    ])
    if test "$curl_cv_socklen_t_equiv" = "unknown"; then
      AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
    else
      AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
        [type to use in place of socklen_t if not defined])
    fi
  ],[
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
  ])
])


dnl CURL_CHECK_FUNC_GETNAMEINFO
dnl -------------------------------------------------
dnl Test if the getnameinfo function is available, 
dnl and check the types of five of its arguments.
dnl If the function succeeds HAVE_GETNAMEINFO will be
dnl defined, defining the types of the arguments in
dnl GETNAMEINFO_TYPE_ARG1, GETNAMEINFO_TYPE_ARG2,
dnl GETNAMEINFO_TYPE_ARG46 and GETNAMEINFO_TYPE_ARG7,
dnl and also defining the type qualifier of first 
dnl argument in GETNAMEINFO_QUAL_ARG1.

AC_DEFUN([CURL_CHECK_FUNC_GETNAMEINFO], [
  AC_REQUIRE([CURL_CHECK_HEADER_WS2TCPIP])dnl
  AC_REQUIRE([CURL_CHECK_TYPE_SOCKLEN_T])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h netdb.h)
  #
  AC_MSG_CHECKING([for getnameinfo])
  AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([getnameinfo])
    ],[
      AC_MSG_RESULT([yes])
      curl_cv_getnameinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      curl_cv_getnameinfo="no"
  ])
  #
  if test "$curl_cv_getnameinfo" != "yes"; then
    AC_MSG_CHECKING([deeper for getnameinfo])
    AC_TRY_LINK([
      ],[
        getnameinfo();
      ],[
        AC_MSG_RESULT([yes])
        curl_cv_getnameinfo="yes"
      ],[
        AC_MSG_RESULT([but still no])
        curl_cv_getnameinfo="no"
    ])
  fi
  #
  if test "$curl_cv_getnameinfo" != "yes"; then
    AC_MSG_CHECKING([deeper and deeper for getnameinfo])
    AC_TRY_LINK([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#endif
      ],[
        getnameinfo(0, 0, 0, 0, 0, 0, 0);
      ],[ 
        AC_MSG_RESULT([yes])
        curl_cv_getnameinfo="yes"
      ],[
        AC_MSG_RESULT([but still no])
        curl_cv_getnameinfo="no"
    ])
  fi
  #
  if test "$curl_cv_getnameinfo" = "yes"; then
    AC_CACHE_CHECK([types of arguments for getnameinfo],
      [curl_cv_func_getnameinfo_args], [
      curl_cv_func_getnameinfo_args="unknown"
      for gni_arg1 in 'struct sockaddr *' 'const struct sockaddr *' 'void *'; do
        for gni_arg2 in 'socklen_t' 'size_t' 'int'; do
          for gni_arg46 in 'size_t' 'int' 'socklen_t' 'unsigned int' 'DWORD'; do
            for gni_arg7 in 'int' 'unsigned int'; do
              AC_COMPILE_IFELSE([
                AC_LANG_PROGRAM([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#if (!defined(_WIN32_WINNT)) || (_WIN32_WINNT < 0x0501)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h> 
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif
#define GNICALLCONV WSAAPI
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#define GNICALLCONV
#endif
                  extern int GNICALLCONV getnameinfo($gni_arg1, $gni_arg2,
                                         char *, $gni_arg46,
                                         char *, $gni_arg46,
                                         $gni_arg7);
                ],[
                  $gni_arg2 salen=0;
                  $gni_arg46 hostlen=0;
                  $gni_arg46 servlen=0;
                  $gni_arg7 flags=0;
                  int res = getnameinfo(0, salen, 0, hostlen, 0, servlen, flags);
                ])
              ],[
                 curl_cv_func_getnameinfo_args="$gni_arg1,$gni_arg2,$gni_arg46,$gni_arg7"
                 break 4
              ])
            done
          done
        done
      done
    ]) # AC_CACHE_CHECK
    if test "$curl_cv_func_getnameinfo_args" = "unknown"; then
      AC_MSG_WARN([Cannot find proper types to use for getnameinfo args])
      AC_MSG_WARN([HAVE_GETNAMEINFO will not be defined])
    else
      gni_prev_IFS=$IFS; IFS=','
      set dummy `echo "$curl_cv_func_getnameinfo_args" | sed 's/\*/\*/g'`
      IFS=$gni_prev_IFS
      shift
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG2, $[2],
        [Define to the type of arg 2 for getnameinfo.])
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG46, $[3],
        [Define to the type of args 4 and 6 for getnameinfo.])
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG7, $[4],
        [Define to the type of arg 7 for getnameinfo.])
      #
      gni_qual_type_arg1=$[1]
      #
      case "$gni_qual_type_arg1" in
        const*)
          gni_qual_arg1=const
          gni_type_arg1=`echo $gni_qual_type_arg1 | sed 's/^const //'`
        ;;
        *)
          gni_qual_arg1=
          gni_type_arg1=$gni_qual_type_arg1
        ;;
      esac
      #
      AC_DEFINE_UNQUOTED(GETNAMEINFO_QUAL_ARG1, $gni_qual_arg1,
        [Define to the type qualifier of arg 1 for getnameinfo.])
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG1, $gni_type_arg1,
        [Define to the type of arg 1 for getnameinfo.])
      #
      AC_DEFINE_UNQUOTED(HAVE_GETNAMEINFO, 1,
        [Define to 1 if you have the getnameinfo function.])
      ac_cv_func_getnameinfo="yes"
    fi
  fi
]) # AC_DEFUN


dnl CURL_CHECK_NONBLOCKING_SOCKET
dnl -------------------------------------------------
dnl Check for how to set a socket to non-blocking state. There seems to exist
dnl four known different ways, with the one used almost everywhere being POSIX
dnl and XPG3, while the other different ways for different systems (old BSD,
dnl Windows and Amiga).
dnl
dnl There are two known platforms (AIX 3.x and SunOS 4.1.x) where the
dnl O_NONBLOCK define is found but does not work. This condition is attempted
dnl to get caught in this script by using an excessive number of #ifdefs...
dnl
AC_DEFUN([CURL_CHECK_NONBLOCKING_SOCKET],
[
  AC_MSG_CHECKING([non-blocking sockets style])

  AC_TRY_COMPILE([
/* headers for O_NONBLOCK test */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
],[
/* try to compile O_NONBLOCK */

#if defined(sun) || defined(__sun__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# if defined(__SVR4) || defined(__srv4__)
#  define PLATFORM_SOLARIS
# else
#  define PLATFORM_SUNOS4
# endif
#endif
#if (defined(_AIX) || defined(__xlC__)) && !defined(_AIX4)
# define PLATFORM_AIX_V3
#endif

#if defined(PLATFORM_SUNOS4) || defined(PLATFORM_AIX_V3) || defined(__BEOS__)
#error "O_NONBLOCK does not work on this platform"
#endif
  int socket;
  int flags = fcntl(socket, F_SETFL, flags | O_NONBLOCK);
],[
dnl the O_NONBLOCK test was fine
nonblock="O_NONBLOCK"
AC_DEFINE(HAVE_O_NONBLOCK, 1, [use O_NONBLOCK for non-blocking sockets])
],[
dnl the code was bad, try a different program now, test 2

  AC_TRY_COMPILE([
/* headers for FIONBIO test */
#include <unistd.h>
#include <stropts.h>
],[
/* FIONBIO source test (old-style unix) */
 int socket;
 int flags = ioctl(socket, FIONBIO, &flags);
],[
dnl FIONBIO test was good
nonblock="FIONBIO"
AC_DEFINE(HAVE_FIONBIO, 1, [use FIONBIO for non-blocking sockets])
],[
dnl FIONBIO test was also bad
dnl the code was bad, try a different program now, test 3

  AC_TRY_COMPILE([
/* headers for ioctlsocket test (Windows) */
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#endif
],[
/* ioctlsocket source code */
 SOCKET sd;
 unsigned long flags = 0;
 sd = socket(0, 0, 0);
 ioctlsocket(sd, FIONBIO, &flags);
],[
dnl ioctlsocket test was good
nonblock="ioctlsocket"
AC_DEFINE(HAVE_IOCTLSOCKET, 1, [use ioctlsocket() for non-blocking sockets])
],[
dnl ioctlsocket didnt compile!, go to test 4

  AC_TRY_LINK([
/* headers for IoctlSocket test (Amiga?) */
#include <sys/ioctl.h>
],[
/* IoctlSocket source code */
 int socket;
 int flags = IoctlSocket(socket, FIONBIO, (long)1);
],[
dnl ioctlsocket test was good
nonblock="IoctlSocket"
AC_DEFINE(HAVE_IOCTLSOCKET_CASE, 1, [use Ioctlsocket() for non-blocking sockets])
],[
dnl Ioctlsocket didnt compile, do test 5!
  AC_TRY_COMPILE([
/* headers for SO_NONBLOCK test (BeOS) */
#include <socket.h>
],[
/* SO_NONBLOCK source code */
 long b = 1;
 int socket;
 int flags = setsockopt(socket, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
],[
dnl the SO_NONBLOCK test was good
nonblock="SO_NONBLOCK"
AC_DEFINE(HAVE_SO_NONBLOCK, 1, [use SO_NONBLOCK for non-blocking sockets])
],[
dnl test 5 didnt compile!
nonblock="nada"
AC_DEFINE(HAVE_DISABLED_NONBLOCKING, 1, [disabled non-blocking sockets])
])
dnl end of fifth test

])
dnl end of forth test

])
dnl end of third test

])
dnl end of second test

])
dnl end of non-blocking try-compile test
  AC_MSG_RESULT($nonblock)

  if test "$nonblock" = "nada"; then
    AC_MSG_WARN([non-block sockets disabled])
  fi
])


dnl TYPE_SOCKADDR_STORAGE
dnl -------------------------------------------------
dnl Check for struct sockaddr_storage. Most IPv6-enabled hosts have it, but
dnl AIX 4.3 is one known exception.
AC_DEFUN([TYPE_SOCKADDR_STORAGE],
[
   AC_CHECK_TYPE([struct sockaddr_storage],
        AC_DEFINE(HAVE_STRUCT_SOCKADDR_STORAGE, 1,
                  [if struct sockaddr_storage is defined]), ,
   [
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#endif
   ])
])


dnl TYPE_IN_ADDR_T
dnl -------------------------------------------------
dnl Check for in_addr_t: it is used to receive the return code of inet_addr()
dnl and a few other things.
AC_DEFUN([TYPE_IN_ADDR_T],
[
   AC_CHECK_TYPE([in_addr_t], ,[
      AC_MSG_CHECKING([for in_addr_t equivalent])
      AC_CACHE_VAL([curl_cv_in_addr_t_equiv],
      [
         curl_cv_in_addr_t_equiv=
         for t in "unsigned long" int size_t unsigned long; do
            AC_TRY_COMPILE([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#endif
            ],[
               $t data = inet_addr ("1.2.3.4");
            ],[
               curl_cv_in_addr_t_equiv="$t"
               break
            ])
         done

         if test "x$curl_cv_in_addr_t_equiv" = x; then
            AC_MSG_ERROR([Cannot find a type to use in place of in_addr_t])
         fi
      ])
      AC_MSG_RESULT($curl_cv_in_addr_t_equiv)
      AC_DEFINE_UNQUOTED(in_addr_t, $curl_cv_in_addr_t_equiv,
			[type to use in place of in_addr_t if not defined])],
      [
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#endif
  ]) dnl AC_CHECK_TYPE
]) dnl AC_DEFUN


dnl We create a function for detecting which compiler we use and then set as
dnl pendantic compiler options as possible for that particular compiler. The
dnl options are only used for debug-builds.

dnl This is a copy of the original found in curl's configure script. Don't
dnl modify this one, edit the one in curl and copy it back here when that one
dnl is changed.

AC_DEFUN([CURL_CC_DEBUG_OPTS],
[
    if test "$GCC" = "yes"; then

       dnl figure out gcc version!
       AC_MSG_CHECKING([gcc version])
       gccver=`$CC -dumpversion`
       num1=`echo $gccver | cut -d . -f1`
       num2=`echo $gccver | cut -d . -f2`
       gccnum=`(expr $num1 "*" 100 + $num2) 2>/dev/null`
       AC_MSG_RESULT($gccver)

       AC_MSG_CHECKING([if this is icc in disguise])
       AC_EGREP_CPP([^__INTEL_COMPILER], [__INTEL_COMPILER],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         ICC="no"
         AC_MSG_RESULT([no]),
         dnl the text was not found, it was replaced by the cpp
         ICC="yes"
         AC_MSG_RESULT([yes])
       )

       if test "$ICC" = "yes"; then
         dnl this is icc, not gcc.

         dnl ICC warnings we ignore:
         dnl * 279 warns on static conditions in while expressions
         dnl * 269 warns on our "%Od" printf formatters for curl_off_t output:
         dnl   "invalid format string conversion"

         WARN="-wd279,269"

         if test "$gccnum" -gt "600"; then
            dnl icc 6.0 and older doesn't have the -Wall flag
            WARN="-Wall $WARN"
         fi
       else dnl $ICC = yes
         dnl 
         WARN="-W -Wall -Wwrite-strings -pedantic -Wno-long-long -Wundef -Wpointer-arith -Wnested-externs -Winline -Wmissing-declarations -Wmissing-prototypes -Wsign-compare"

         dnl -Wcast-align is a bit too annoying ;-)

         if test "$gccnum" -ge "296"; then
           dnl gcc 2.96 or later
           WARN="$WARN -Wfloat-equal"

           if test "$gccnum" -gt "296"; then
             dnl this option does not exist in 2.96
             WARN="$WARN -Wno-format-nonliteral"
           fi

           dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
           dnl on i686-Linux as it gives us heaps with false positives
           if test "$gccnum" -ge "303"; then
             dnl gcc 3.3 and later
             WARN="$WARN -Wendif-labels -Wstrict-prototypes"
           fi
         fi

         for flag in $CPPFLAGS; do
           case "$flag" in
            -I*)
              dnl include path
              add=`echo $flag | sed 's/^-I/-isystem /g'`
              WARN="$WARN $add"
              ;;
           esac
         done

       fi dnl $ICC = no

       CFLAGS="$CFLAGS $WARN"

    fi dnl $GCC = yes

    dnl strip off optimizer flags
    NEWFLAGS=""
    for flag in $CFLAGS; do
      case "$flag" in
      -O*)
        dnl echo "cut off $flag"
        ;;
      *)
        NEWFLAGS="$NEWFLAGS $flag"
        ;;
      esac
    done
    CFLAGS=$NEWFLAGS

]) dnl end of AC_DEFUN()


dnl This macro determines if the specified struct exists in the specified file
dnl Syntax:
dnl CARES_CHECK_STRUCT(headers, struct name, if found, [if not found])

AC_DEFUN([CARES_CHECK_STRUCT], [
  AC_MSG_CHECKING([for struct $2])
  AC_TRY_COMPILE([$1], 
    [
      struct $2 struct_instance;
    ], ac_struct="yes", ac_found="no")
  if test "$ac_struct" = "yes" ; then
    AC_MSG_RESULT(yes)
    $3
  else
    AC_MSG_RESULT(no)
    $4
  fi
])

dnl This macro determines if the specified constant exists in the specified file
dnl Syntax:
dnl CARES_CHECK_CONSTANT(headers, constant name, if found, [if not found])

AC_DEFUN([CARES_CHECK_CONSTANT], [
  AC_MSG_CHECKING([for $2])
  AC_EGREP_CPP(VARIABLEWASDEFINED,
   [
      $1

      #ifdef $2
        VARIABLEWASDEFINED
      #else
        NJET
      #endif
    ], ac_constant="yes", ac_constant="no"
  )
  if test "$ac_constant" = "yes" ; then
    AC_MSG_RESULT(yes)
    $3
  else
    AC_MSG_RESULT(no)
    $4
  fi
])


dnl This macro determines how many parameters getservbyport_r takes
AC_DEFUN([CARES_CHECK_GETSERVBYPORT_R], [
  AC_MSG_CHECKING([how many arguments getservbyport_r takes])
  AC_TRY_LINK(
    [#include <netdb.h>],
    [
      int p1, p5;
      char *p2, p4[4096];
      struct servent *p3, *p6;
      getservbyport_r(p1, p2, p3, p4, p5, &p6);
    ], ac_func_getservbyport_r=6,
    [AC_TRY_LINK(
      [#include <netdb.h>],
      [
        int p1, p5;
        char *p2, p4[4096];
        struct servent *p3;
        getservbyport_r(p1, p2, p3, p4, p5);
      ], ac_func_getservbyport_r=5,
      [AC_TRY_LINK(
        [#include <netdb.h>],
        [
          int p1;
          char *p2;
          struct servent *p3;
          struct servent_data p4;
          getservbyport_r(p1, p2, p3, &p4);
        ], ac_func_getservbyport_r=4, ac_func_getservbyport_r=0
      )]
    )]
  )
if test $ac_func_getservbyport_r != "0" ; then
  AC_MSG_RESULT($ac_func_getservbyport_r)
  AC_DEFINE(HAVE_GETSERVBYPORT_R, 1, [Specifies whether getservbyport_r is present])
  AC_DEFINE_UNQUOTED(GETSERVBYPORT_R_ARGS, $ac_func_getservbyport_r, [Specifies the number of arguments to 
getservbyport_r])
  if test $ac_func_getservbyport_r = "4" ; then
   AC_DEFINE(GETSERVBYPORT_R_BUFSIZE, sizeof(struct servent_data), [Specifies the size of the buffer to pass to 
getservbyport_r])
  else
   AC_DEFINE(GETSERVBYPORT_R_BUFSIZE, 4096, [Specifies the size of the buffer to pass to getservbyport_r])
  fi
else
  AC_MSG_RESULT([not found])
fi
])

# Prevent libtool for checking how to run C++ compiler and check for other
# tools we don't want to use. We do this by m4-defining the _LT_AC_TAGCONFIG
# variable to the code to run, as by default it uses a much more complicated
# approach. The code below that is actually added seems to be used for cases
# where configure has trouble figuring out what C compiler to use but where
# the installed libtool has an idea.
#
# This function is a re-implemented version of the Paolo Bonzini fix posted to
# the c-ares mailing list by Bram Matthys on May 6 2006. My version removes
# redundant code but also adds the LTCFLAGS check that wasn't in that patch.
#
# Some code in this function was extracted from the generated configure script.
#
# CARES_CLEAR_LIBTOOL_TAGS
AC_DEFUN([CARES_CLEAR_LIBTOOL_TAGS],
  [m4_define([_LT_AC_TAGCONFIG], [
  if test -f "$ltmain"; then
    if test ! -f "${ofile}"; then
      AC_MSG_WARN([output file `$ofile' does not exist])
    fi

    if test -z "$LTCC"; then
      eval "`$SHELL ${ofile} --config | grep '^LTCC='`"
      if test -z "$LTCC"; then
        AC_MSG_WARN([output file `$ofile' does not look like a libtool
script])
      else
        AC_MSG_WARN([using `LTCC=$LTCC', extracted from `$ofile'])
      fi
    fi
    if test -z "$LTCFLAGS"; then
      eval "`$SHELL ${ofile} --config | grep '^LTCFLAGS='`"
    fi
  fi
  ])]
)
