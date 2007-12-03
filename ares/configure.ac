
dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.57)
AC_INIT(ares_init.c)
AC_CONFIG_SRCDIR([ares_ipv6.h])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE(c-ares, CVS)

dnl
dnl Detect the canonical host and target build environment
dnl

AC_CANONICAL_HOST
dnl Get system canonical name
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

AC_AIX
AC_PROG_CC
AC_PROG_INSTALL

case $host_os in
solaris*)
	AC_DEFINE(ETC_INET, 1, [if a /etc/inet dir is being used])
	;;
esac

dnl support building of Windows DLLs
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

dnl skip libtool C++ and Fortran compiler checks
m4_ifdef([AC_PROG_CXX], [m4_undefine([AC_PROG_CXX])])
m4_defun([AC_PROG_CXX],[])
m4_ifdef([AC_PROG_F77], [m4_undefine([AC_PROG_F77])])
m4_defun([AC_PROG_F77],[])

dnl skip libtool C++ and Fortran linker checks
m4_ifdef([AC_LIBTOOL_CXX], [m4_undefine([AC_LIBTOOL_CXX])])
m4_defun([AC_LIBTOOL_CXX],[])
m4_ifdef([AC_LIBTOOL_F77], [m4_undefine([AC_LIBTOOL_F77])])
m4_defun([AC_LIBTOOL_F77],[])

dnl force libtool to build static libraries with PIC on AMD64-linux
AC_MSG_CHECKING([if arch-OS host is AMD64-linux (to build static libraries with PIC)])
case $host in
  x86_64*linux*)
    AC_MSG_RESULT([yes])
    with_pic=yes
    ;;
  *)
    AC_MSG_RESULT([no])
    ;;
esac

dnl libtool setup
AC_PROG_LIBTOOL

AC_MSG_CHECKING([if we need -no-undefined])
case $host in
  *-*-cygwin | *-*-mingw* | *-*-pw32*)
    need_no_undefined=yes
    ;;
  *)
    need_no_undefined=no
    ;;
esac
AC_MSG_RESULT($need_no_undefined)
AM_CONDITIONAL(NO_UNDEFINED, test x$need_no_undefined = xyes)

dnl **********************************************************************
dnl check if this is the Intel ICC compiler, and if so make it stricter
dnl (convert warning 147 into an error) so that it properly can detect the
dnl gethostbyname_r() version
dnl **********************************************************************
CURL_DETECT_ICC([CFLAGS="$CFLAGS -we 147"])

dnl **********************************************************************
dnl platform/compiler/architecture specific checks/flags
dnl **********************************************************************

case $host in
  #
  x86_64*linux*)
    #
    dnl find out if icc is being used
    if test "z$ICC" = "z"; then
      CURL_DETECT_ICC
    fi
    #
    if test "$ICC" = "yes"; then
      dnl figure out icc version
      AC_MSG_CHECKING([icc version])
      iccver=`$CC -dumpversion`
      iccnhi=`echo $iccver | cut -d . -f1`
      iccnlo=`echo $iccver | cut -d . -f2`
      iccnum=`(expr $iccnhi "*" 100 + $iccnlo) 2>/dev/null`
      AC_MSG_RESULT($iccver)
      #
      if test "$iccnum" -ge "900" && test "$iccnum" -lt "1000"; then
        dnl icc 9.X specific
        CFLAGS="$CFLAGS -i-dynamic"
      fi
      #
      if test "$iccnum" -ge "1000"; then
        dnl icc 10.X or later
        CFLAGS="$CFLAGS -shared-intel"
      fi
      #
    fi
    ;;
  #
esac

dnl **********************************************************************
dnl Checks for libraries.
dnl **********************************************************************

dnl gethostbyname without lib or in the nsl lib?
AC_CHECK_FUNC(gethostbyname,
              [HAVE_GETHOSTBYNAME="1"
              ],
              [ AC_CHECK_LIB(nsl, gethostbyname,
                             [HAVE_GETHOSTBYNAME="1"
                             LIBS="$LIBS -lnsl"
                             ])
              ])

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the socket lib?
  AC_CHECK_LIB(socket, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="$LIBS -lsocket"
               ])
fi

dnl At least one system has been identified to require BOTH nsl and socket
dnl libs at the same time to link properly.
if test "$HAVE_GETHOSTBYNAME" != "1"
then
  AC_MSG_CHECKING([for gethostbyname with both nsl and socket libs])
  my_ac_save_LIBS=$LIBS
  LIBS="-lnsl -lsocket $LIBS"
  AC_TRY_LINK( ,
             [gethostbyname();],
             [ dnl found it!
             HAVE_GETHOSTBYNAME="1"
             AC_MSG_RESULT([yes])],
             [ dnl failed!
             AC_MSG_RESULT([no])
             dnl restore LIBS
             LIBS=$my_ac_save_LIBS]
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for Msys/Mingw
  AC_MSG_CHECKING([for gethostbyname in ws2_32])
  my_ac_save_LIBS=$LIBS
  LIBS="-lws2_32 $LIBS"
  AC_TRY_LINK([#include <winsock2.h>],
               [gethostbyname("www.dummysite.com");],
               [ dnl worked!
               ws2="yes"
               AC_MSG_RESULT([yes])
               HAVE_GETHOSTBYNAME="1"],
               [ dnl failed, restore LIBS
               LIBS=$my_ac_save_LIBS
               AC_MSG_RESULT(no)]
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for eCos with a stubbed DNS implementation
  AC_MSG_CHECKING([for gethostbyname for eCos])
  AC_TRY_LINK([
#include <stdio.h>
#include <netdb.h>],
               [gethostbyname("www.dummysite.com");],
               [ dnl worked!
               AC_MSG_RESULT([yes])
               HAVE_GETHOSTBYNAME="1"],
               AC_MSG_RESULT(no)
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the net lib - for BeOS
  AC_CHECK_LIB(net, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="$LIBS -lnet"
               ])
fi


if test "$HAVE_GETHOSTBYNAME" = "1"; then
  AC_DEFINE(HAVE_GETHOSTBYNAME, 1, [If you have gethostbyname])
else
  AC_MSG_ERROR([couldn't find libraries for gethostbyname()])
fi

dnl resolve lib?
AC_CHECK_FUNC(strcasecmp, , [ AC_CHECK_LIB(resolve, strcasecmp) ])

if test "$ac_cv_lib_resolve_strcasecmp" = "$ac_cv_func_strcasecmp"; then
  AC_CHECK_LIB(resolve, strcasecmp,
              [LIBS="-lresolve $LIBS"],
               ,
               -lnsl)
fi

dnl socket lib?
AC_CHECK_FUNC(connect, , [ AC_CHECK_LIB(socket, connect) ])

AC_MSG_CHECKING([whether to use libgcc])
AC_ARG_ENABLE(libgcc,
AC_HELP_STRING([--enable-libgcc],[use libgcc when linking]),
[ case "$enableval" in
  yes)
        LIBS="$LIBS -lgcc"
       AC_MSG_RESULT(yes)
       ;;
  *)   AC_MSG_RESULT(no)
       ;;
  esac ],
       AC_MSG_RESULT(no)
)


dnl Default is to try the thread-safe versions of a few functions
OPT_THREAD=on

dnl detect AIX 4.3 or later
AC_MSG_CHECKING([AIX 4.3 or later])
AC_PREPROC_IFELSE([
#if defined(_AIX) && defined(_AIX43)
printf("just fine");
#else
#error "this is not AIX 4.3 or later"
#endif
],
 [ AC_MSG_RESULT([yes])
   RECENTAIX=yes
   OPT_THREAD=off ],
 [ AC_MSG_RESULT([no]) ]
)

AC_ARG_ENABLE(thread,dnl
AC_HELP_STRING([--disable-thread],[don't look for thread-safe functions])
AC_HELP_STRING([--enable-thread],[look for thread-safe functions]),
[ case "$enableval" in
  no)
    OPT_THREAD=off
    AC_MSG_WARN(c-ares will not get built using thread-safe functions)
    ;;
  *)
    ;;
  esac
]
)

if test X"$OPT_THREAD" = Xoff
then
  AC_DEFINE(DISABLED_THREADSAFE, 1,
    [Set to explicitly specify we don't want to use thread-safe functions])
fi

dnl for recent AIX versions, we skip all the thread-safe checks above since
dnl they claim a thread-safe libc using the standard API. But there are
dnl some functions still not thread-safe. Check for these!

dnl Let's hope this split URL remains working:
dnl http://publibn.boulder.ibm.com/doc_link/en_US/a_doc_lib/aixprggd/ \
dnl genprogc/thread_quick_ref.htm

if test "x$RECENTAIX" = "xyes"; then

  AC_DEFINE(_THREAD_SAFE, 1, [define this if you need it to compile thread-safe code])

  dnl check if this is the IBM xlc compiler
  dnl Details thanks to => http://predef.sourceforge.net/
  AC_MSG_CHECKING([if this is the xlc compiler])
  AC_EGREP_CPP([^__xlC__], [__xlC__],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         XLC="no"
         AC_MSG_RESULT([no]),
         dnl the text was not found, it was replaced by the cpp
         XLC="yes"
         AC_MSG_RESULT([yes])
         CFLAGS="$CFLAGS -qthreaded"
         dnl AIX xlc has to have strict aliasing turned off. If not,
         dnl the optimizer assumes that pointers can only point to
         dnl an object of the same type.
         CFLAGS="$CFLAGS -qnoansialias"
       )
fi


dnl **********************************************************************
dnl Back to "normal" configuring
dnl **********************************************************************

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

CURL_CHECK_HEADER_MALLOC

dnl check for a few basic system headers we need
AC_CHECK_HEADERS(
       sys/types.h \
       sys/time.h \
       sys/select.h \
       sys/socket.h \
       sys/ioctl.h \
       sys/param.h \
       netdb.h \
       netinet/in.h \
       netinet/tcp.h \
       net/if.h \
       errno.h \
       stdbool.h \
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
CURL_CHECK_STRUCT_TIMEVAL

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

# check for bool type
AC_CHECK_TYPE([bool],[
  AC_DEFINE(HAVE_BOOL_T, 1,
    [Define to 1 if bool is an available type.])
], ,[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
])

# Check for socklen_t or equivalent
CURL_CHECK_TYPE_SOCKLEN_T

TYPE_IN_ADDR_T

TYPE_SOCKADDR_STORAGE

TYPE_SIG_ATOMIC_T

AC_TYPE_SIGNAL

CURL_CHECK_FUNC_RECV

CURL_CHECK_FUNC_SEND

CURL_CHECK_MSG_NOSIGNAL

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
                gettimeofday \
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

dnl Check for user-specified random device
AC_ARG_WITH(random,
AC_HELP_STRING([--with-random=FILE],
               [read randomness from FILE (default=/dev/urandom)]),
    [ RANDOM_FILE="$withval" ],
    [
        dnl Check for random device.  If we're cross compiling, we can't
        dnl check, and it's better to assume it doesn't exist than it is
        dnl to fail on AC_CHECK_FILE or later.
        if test "$cross_compiling" = "no"; then
          AC_CHECK_FILE("/dev/urandom", [ RANDOM_FILE="/dev/urandom"] )
        else
          AC_MSG_WARN([cannot check for /dev/urandom while cross compiling; assuming none])
        fi
        
    ]
)
if test -n "$RANDOM_FILE" && test X"$RANDOM_FILE" != Xno ; then
        AC_SUBST(RANDOM_FILE)
        AC_DEFINE_UNQUOTED(RANDOM_FILE, "$RANDOM_FILE",
        [a suitable file/device to read random data from])
fi

AC_OUTPUT(Makefile libcares.pc)
