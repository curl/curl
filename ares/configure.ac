dnl Process this file with autoconf to produce a configure script.
AC_INIT(ares_init.c)

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB

AC_CANONICAL_HOST
case $host_os in
solaris*)
	AC_DEFINE(ETC_INET)
	;;
esac

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

    dnl Checks for standard header files, to make memdebug.h inclusions bettter
    AC_HEADER_STDC

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG -I../include"
    CFLAGS="$CFLAGS -g" 

    dnl set compiler "debug" options to become more picky, and remove
    dnl optimize options from CFLAGS
    CURL_CC_DEBUG_OPTS

       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl check for a few basic system headers we need
dnl AC_CHECK_HEADERS(
dnl        sys/types.h \
dnl        sys/time.h \
dnl        sys/select.h \
dnl        sys/socket.h \
dnl        )

AC_OUTPUT(Makefile)
