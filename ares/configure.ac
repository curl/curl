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
dnl lame option to switch on debug options
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

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG"
    CFLAGS="$CFLAGS -g" 
    if test "$GCC" = "yes"; then
       dnl these work for gcc 2.95
       CFLAGS="$CFLAGS -W -Wall -Wwrite-strings -pedantic -Wno-long-long -Wundef -Wpointer-arith -Wnested-externs -Wcast-align -Winline -Wstrict-prototypes -Wmissing-declarations -Wmissing-prototypes -Wshadow -Wsign-compare"
       dnl 2.96 or higher: -Wfloat-equal -Wunreachable-code
    fi
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
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

AC_OUTPUT(Makefile)
