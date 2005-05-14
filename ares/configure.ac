dnl Process this file with autoconf to produce a configure script.
AC_INIT(ares_init.c)
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

# check for ssize_t
AC_CHECK_TYPE(ssize_t, ,
   AC_DEFINE(ssize_t, int, [the signed version of size_t]))

AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)

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

    dnl Checks for standard header files, to make memdebug.h inclusions bettter
    AC_HEADER_STDC

    dnl the entire --enable-debug is a hack that lives and runs on top of
    dnl libcurl stuff so this BUILDING_LIBCURL is not THAT much uglier
    AC_DEFINE(BUILDING_LIBCURL, 1, [when building as static part of libcurl])

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG -I$srcdir/../include"
    CFLAGS="$CFLAGS -g" 

    dnl set compiler "debug" options to become more picky, and remove
    dnl optimize options from CFLAGS
    CURL_CC_DEBUG_OPTS

       ;;
  esac ],
       AC_MSG_RESULT(no)
)

AC_PROG_LIBTOOL

dnl check for a few basic system headers we need
AC_CHECK_HEADERS(
       sys/types.h \
       sys/time.h \
       sys/select.h \
       sys/socket.h \
       winsock.h \
       netinet/in.h \
       arpa/nameser.h \
       arpa/nameser_compat.h \
       arpa/inet.h, , ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
dnl We do this default-include simply to make sure that the nameser_compat.h
dnl header *REALLY* can be include after the new nameser.h. It seems AIX 5.1
dnl (and others?) is not designed to allow this.
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
]
  )

dnl check for AF_INET6
CARES_CHECK_CONSTANT(
  [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

  ], [PF_INET6], 
     AC_DEFINE_UNQUOTED(HAVE_PF_INET6,1,[Define to 1 if you have PF_INET6.])
)

dnl check for PF_INET6
CARES_CHECK_CONSTANT(
  [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

  ], [AF_INET6], 
     AC_DEFINE_UNQUOTED(HAVE_AF_INET6,1,[Define to 1 if you have AF_INET6.])
)


dnl check for the in6_addr structure
CARES_CHECK_STRUCT(
  [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
  ], [in6_addr], 
     AC_DEFINE_UNQUOTED(HAVE_STRUCT_IN6_ADDR,1,[Define to 1 if you have struct in6_addr.])
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
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
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
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
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
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
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
       AC_DEFINE_UNQUOTED(HAVE_INET_NTOP_IPV6,1,[Define to 1 if inet_ntop supports IPv6.])
     ], AC_MSG_RESULT(no),AC_MSG_RESULT(no))
fi

AC_CHECK_SIZEOF(struct in6_addr, ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]
)
AC_CHECK_SIZEOF(struct in_addr, ,
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]
)

AC_CHECK_FUNCS(bitncmp)


AC_OUTPUT(Makefile)
