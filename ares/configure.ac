
dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.57)
AC_INIT(ares_init.c)
AC_CONFIG_SRCDIR([ares_ipv6.h])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE(c-ares, CVS)

AC_PROG_CC
AC_PROG_INSTALL

case $host_os in
solaris*)
	AC_DEFINE(ETC_INET, 1, [if a /etc/inet dir is being used])
	;;
esac

AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)

dnl check for cygwin stuff
AC_LIBTOOL_WIN32_DLL

dnl ************************************************************
dnl Option to switch on debug options. This makes an assumption that
dnl this is built as an 'ares' subdir in the curl source tree. Subject for
dnl improval in the future!
dnl
AC_MSG_CHECKING([whether to enable debug options])
AC_ARG_ENABLE(debug,
AC_HELP_STRING([--enable-debug],[Enable pedantic debug options])
AC_HELP_STRING([--disable-debug],[Disable debug options]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ;;
  *)   AC_MSG_RESULT(yes)

    dnl when doing the debug stuff, use static library only
    AC_DISABLE_SHARED

    dnl the entire --enable-debug is a hack that lives and runs on top of
    dnl libcurl stuff so this BUILDING_LIBCURL is not THAT much uglier
    AC_DEFINE(BUILDING_LIBCURL, 1, [when building as static part of libcurl])

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG -I$srcdir/../include"
    CFLAGS="$CFLAGS -g" 

    dnl check for how to do large files, needed to get the curl_off_t check
    dnl done right
    AC_SYS_LARGEFILE

    AC_CHECK_SIZEOF(curl_off_t, ,[
#include <stdio.h>
#include "$srcdir/../include/curl/curl.h"
    ])

    dnl set compiler "debug" options to become more picky, and remove
    dnl optimize options from CFLAGS
    CURL_CC_DEBUG_OPTS

       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl libtool setup
CARES_CLEAR_LIBTOOL_TAGS
AC_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC

dnl **********************************************************************
dnl Make sure that our checks for headers windows.h winsock.h winsock2.h 
dnl and ws2tcpip.h take precedence over any other further checks which 
dnl could be done later using AC_CHECK_HEADER or AC_CHECK_HEADERS for
dnl this specific header files. And do them before its results are used.
dnl **********************************************************************

CURL_CHECK_HEADER_WINDOWS
CURL_CHECK_HEADER_WINSOCK
CURL_CHECK_HEADER_WINSOCK2
CURL_CHECK_HEADER_WS2TCPIP

dnl check for a few basic system headers we need
AC_CHECK_HEADERS(
       sys/types.h \
       sys/time.h \
       sys/select.h \
       sys/socket.h \
       sys/ioctl.h \
       netdb.h \
       netinet/in.h \
       net/if.h \
       arpa/nameser.h \
       arpa/nameser_compat.h \
       arpa/inet.h,
dnl to do if not found
[],
dnl to do if found
[],
dnl default includes
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
dnl We do this default-include simply to make sure that the nameser_compat.h
dnl header *REALLY* can be include after the new nameser.h. It seems AIX 5.1
dnl (and others?) is not designed to allow this.
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

dnl *Sigh* these are needed in order for net/if.h to get properly detected.
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]
)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(time_t)

AC_CHECK_TYPE(long long,
   [AC_DEFINE(HAVE_LONGLONG, 1, [if your compiler supports long long])]
   longlong="yes"  
)

if test "xyes" = "x$longlong"; then
  AC_MSG_CHECKING([if numberLL works])
  AC_COMPILE_IFELSE([long long val = 1000LL;],
   [AC_DEFINE(HAVE_LL, 1, [if your compiler supports LL])]
   AC_MSG_RESULT(yes),
   AC_MSG_RESULT(no)
  )
fi


# check for ssize_t
AC_CHECK_TYPE(ssize_t, ,
   AC_DEFINE(ssize_t, int, [the signed version of size_t]))

# Check for socklen_t or equivalent
CURL_CHECK_TYPE_SOCKLEN_T

TYPE_IN_ADDR_T

TYPE_SOCKADDR_STORAGE


dnl check for AF_INET6
CARES_CHECK_CONSTANT(
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
#endif
  ], [PF_INET6], 
     AC_DEFINE_UNQUOTED(HAVE_PF_INET6,1,[Define to 1 if you have PF_INET6.])
)

dnl check for PF_INET6
CARES_CHECK_CONSTANT(
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
#endif
  ], [AF_INET6], 
     AC_DEFINE_UNQUOTED(HAVE_AF_INET6,1,[Define to 1 if you have AF_INET6.])
)


dnl check for the in6_addr structure
CARES_CHECK_STRUCT(
  [
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#endif
  ], [in6_addr], 
     AC_DEFINE_UNQUOTED(HAVE_STRUCT_IN6_ADDR,1,[Define to 1 if you have struct in6_addr.])
)

dnl check for the sockaddr_in6 structure
CARES_CHECK_STRUCT(
  [
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#endif
  ], [sockaddr_in6], 
     AC_DEFINE_UNQUOTED(HAVE_STRUCT_SOCKADDR_IN6,1,
       [Define to 1 if you have struct sockaddr_in6.]) ac_have_sockaddr_in6=yes
)

AC_CHECK_MEMBER(struct sockaddr_in6.sin6_scope_id,
    AC_DEFINE_UNQUOTED(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID,1,
      [Define to 1 if your struct sockaddr_in6 has sin6_scope_id.])
   , ,
  [
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#endif
  ])

dnl check for the addrinfo structure
AC_CHECK_MEMBER(struct addrinfo.ai_flags,
     AC_DEFINE_UNQUOTED(HAVE_STRUCT_ADDRINFO,1,
       [Define to 1 if you have struct addrinfo.]),,
  [
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#endif
  ]
)


AC_CHECK_FUNCS( bitncmp \
                if_indextoname,
dnl if found
[],
dnl if not found, $ac_func is the name we check for
func="$ac_func"
AC_MSG_CHECKING([deeper for $func])
AC_TRY_LINK( [],
             [ $func ();],
             AC_MSG_RESULT(yes!)
             eval "ac_cv_func_$func=yes"
             def=`echo "HAVE_$func" | tr 'a-z' 'A-Z'`
             AC_DEFINE_UNQUOTED($def, 1, [If you have $func]),
             AC_MSG_RESULT(but still no)
             )
)


dnl check for inet_pton
AC_CHECK_FUNCS(inet_pton)
dnl Some systems have it, but not IPv6
if test "$ac_cv_func_inet_pton" = "yes" ; then
AC_MSG_CHECKING(if inet_pton supports IPv6)
AC_TRY_RUN(
  [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
int main()
  {
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, "::1", &addr6) < 1)
      exit(1);
    else
      exit(0);
  }
  ], [
       AC_MSG_RESULT(yes)
       AC_DEFINE_UNQUOTED(HAVE_INET_PTON_IPV6,1,[Define to 1 if inet_pton supports IPv6.])
     ], AC_MSG_RESULT(no),AC_MSG_RESULT(no))
fi
dnl Check for inet_net_pton
AC_CHECK_FUNCS(inet_net_pton)
dnl Again, some systems have it, but not IPv6
if test "$ac_cv_func_inet_net_pton" = "yes" ; then
AC_MSG_CHECKING(if inet_net_pton supports IPv6)
AC_TRY_RUN(
  [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
int main()
  {
    struct in6_addr addr6;
    if (inet_net_pton(AF_INET6, "::1", &addr6, sizeof(addr6)) < 1)
      exit(1);
    else
      exit(0);
  }
  ], [
       AC_MSG_RESULT(yes)
       AC_DEFINE_UNQUOTED(HAVE_INET_NET_PTON_IPV6,1,[Define to 1 if inet_net_pton supports IPv6.])
     ], AC_MSG_RESULT(no),AC_MSG_RESULT(no))
fi


dnl Check for inet_ntop
AC_CHECK_FUNCS(inet_ntop)
dnl Again, some systems have it, but not IPv6
if test "$ac_cv_func_inet_ntop" = "yes" ; then
AC_MSG_CHECKING(if inet_ntop supports IPv6)
AC_TRY_RUN(
  [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <errno.h>
int main()
  {
    struct in6_addr addr6;
    char buf[128];
    if (inet_ntop(AF_INET6, &addr6, buf, 128) == 0 && errno == EAFNOSUPPORT)
      exit(1);
    else
      exit(0);
  }
  ], [
       AC_MSG_RESULT(yes)
       AC_DEFINE_UNQUOTED(HAVE_INET_NTOP_IPV6,1,
          [Define to 1 if inet_ntop supports IPv6.])
     ], AC_MSG_RESULT(no),AC_MSG_RESULT(no))
fi

AC_CHECK_SIZEOF(struct in6_addr, ,
[
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#endif
]
)

AC_CHECK_SIZEOF(struct in_addr, ,
[
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#endif
]
)


dnl Check if the getnameinfo function is available
dnl and get the types of five of its arguments.
CURL_CHECK_FUNC_GETNAMEINFO


dnl God bless non-standardized functions! We need to see which getservbyport_r
dnl variant is available
CARES_CHECK_GETSERVBYPORT_R

CURL_CHECK_NONBLOCKING_SOCKET

AC_C_BIGENDIAN(
    [AC_DEFINE(ARES_BIG_ENDIAN, 1,
      [define this if ares is built for a big endian system])],
    ,
    [AC_MSG_WARN([couldn't figure out endianess, assuming little endian!])]
)

AC_OUTPUT(Makefile)
