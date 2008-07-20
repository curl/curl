AC_PREREQ(2.57)

dnl Version not hardcoded here. Fetched later from ares_version.h
AC_INIT([c-ares], [-],
  [c-ares mailing list => http://cool.haxx.se/mailman/listinfo/c-ares])

AC_CONFIG_SRCDIR([ares_ipv6.h])
AM_CONFIG_HEADER([config.h])
AM_MAINTAINER_MODE

dnl SED is mandatory for configure process and libtool.
dnl Set it now and prevent it from being changed later.
AC_PATH_PROG([SED], [sed], [not_found],
  [$PATH:/usr/bin:/usr/local/bin])
if test -z "$SED" || test "$SED" = "not_found"; then
  AC_MSG_ERROR([sed not found in PATH. Cannot continue without sed.])
fi
ac_cv_prog_sed="$SED"
ac_cv_prog_SED="$SED"
AC_SUBST([SED])

dnl GREP is mandatory for configure process and libtool.
dnl Set it now and prevent it from being changed later.
AC_PATH_PROG([GREP], [grep], [not_found],
  [$PATH:/usr/bin:/usr/local/bin])
if test -z "$GREP" || test "$GREP" = "not_found"; then
  AC_MSG_ERROR([grep not found in PATH. Cannot continue without grep.])
fi
ac_cv_prog_grep="$GREP"
ac_cv_prog_GREP="$GREP"
AC_SUBST([GREP])

dnl EGREP is mandatory for configure process and libtool.
dnl Set it now and prevent it from being changed later.
if echo a | ($GREP -E '(a|b)') >/dev/null 2>&1; then
  AC_MSG_CHECKING([for egrep])
  EGREP="$GREP -E"
  AC_MSG_RESULT([$EGREP])
else
  AC_PATH_PROG([EGREP], [egrep], [not_found],
    [$PATH:/usr/bin:/usr/local/bin])
fi
if test -z "$EGREP" || test "$EGREP" = "not_found"; then
  AC_MSG_ERROR([egrep not found in PATH. Cannot continue without egrep.])
fi
ac_cv_prog_egrep="$EGREP"
ac_cv_prog_EGREP="$EGREP"
AC_SUBST([EGREP])

dnl AR is mandatory for configure process and libtool.
dnl This is target dependant, so check it as a tool.
AC_PATH_TOOL([AR], [ar], [not_found],
  [$PATH:/usr/bin:/usr/local/bin])
if test -z "$AR" || test "$AR" = "not_found"; then
  AC_MSG_ERROR([ar not found in PATH. Cannot continue without ar.])
fi
AC_SUBST([AR])

dnl Fetch c-ares version from ares_version.h
VERSION=`$SED -ne 's/^#define ARES_VERSION_STR "\(.*\)"/\1/p' ${srcdir}/ares_version.h`
AM_INIT_AUTOMAKE([c-ares], [$VERSION])
AC_MSG_CHECKING([c-ares version])
AC_MSG_RESULT([$VERSION])

dnl
dnl Detect the canonical host and target build environment
dnl

AC_CANONICAL_HOST
dnl Get system canonical name
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

AC_AIX
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

dnl check for how to do large files
AC_SYS_LARGEFILE

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

    debugbuild="yes"

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
AM_CONDITIONAL(DEBUGBUILD, test x$debugbuild = xyes)

dnl skip libtool C++ and Fortran compiler checks
m4_ifdef([AC_PROG_CXX], [m4_undefine([AC_PROG_CXX])])
m4_defun([AC_PROG_CXX],[])
m4_ifdef([AC_PROG_CXXCPP], [m4_undefine([AC_PROG_CXXCPP])])
m4_defun([AC_PROG_CXXCPP],[true])
m4_ifdef([AC_PROG_F77], [m4_undefine([AC_PROG_F77])])
m4_defun([AC_PROG_F77],[])

dnl skip libtool C++ and Fortran linker checks
m4_ifdef([AC_LIBTOOL_CXX], [m4_undefine([AC_LIBTOOL_CXX])])
m4_defun([AC_LIBTOOL_CXX],[])
m4_ifdef([AC_LIBTOOL_CXXCPP], [m4_undefine([AC_LIBTOOL_CXXCPP])])
m4_defun([AC_LIBTOOL_CXXCPP],[true])
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
  *-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-cegcc*)
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

AC_MSG_CHECKING([whether we are using the IBM C compiler])
CURL_CHECK_DEF([__IBMC__], [], [silent])
CURL_CHECK_DEF([__IBMCPP__], [], [silent])
if test "$curl_cv_have_def___IBMC__" = "yes" ||
  test "$curl_cv_have_def___IBMCPP__" = "yes"; then
  AC_MSG_RESULT([yes])
  dnl Ensure that compiler optimizations are always thread-safe.
  CFLAGS="$CFLAGS -qthreaded"
  dnl Disable type based strict aliasing optimizations, using worst
  dnl case aliasing assumptions when compiling. Type based aliasing
  dnl would restrict the lvalues that could be safely used to access
  dnl a data object.
  CFLAGS="$CFLAGS -qnoansialias"
  dnl Force compiler to stop after the compilation phase, without
  dnl generating an object code file when compilation has errors.
  CFLAGS="$CFLAGS -qhalt=e"
else
  AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([whether we are using the DEC/Compaq C compiler])
CURL_CHECK_DEF([__DECC], [], [silent])
CURL_CHECK_DEF([__DECC_VER], [], [silent])
if test "$curl_cv_have_def___DECC" = "yes" ||
  test "$curl_cv_have_def___DECC_VER" = "yes"; then
  AC_MSG_RESULT([yes])
  dnl Select strict ANSI C compiler mode
  CFLAGS="$CFLAGS -std1"
  dnl Select a higher warning level than default level2
  CFLAGS="$CFLAGS -msg_enable level3"
  dnl Generate warnings for missing function prototypes
  CFLAGS="$CFLAGS -warnprotos"
  dnl Change some warnings into fatal errors
  CFLAGS="$CFLAGS -msg_fatal toofewargs,toomanyargs"
else
  AC_MSG_RESULT([no])
fi

CURL_CHECK_COMPILER_HALT_ON_ERROR
CURL_CHECK_COMPILER_ARRAY_SIZE_NEGATIVE

dnl **********************************************************************
dnl Compilation based checks should not be done before this point.
dnl **********************************************************************

dnl **********************************************************************
dnl Make sure that our checks for headers windows.h winsock.h winsock2.h 
dnl and ws2tcpip.h take precedence over any other further checks which 
dnl could be done later using AC_CHECK_HEADER or AC_CHECK_HEADERS for
dnl this specific header files. And do them before its results are used.
dnl **********************************************************************

CURL_CHECK_HEADER_WINDOWS
CURL_CHECK_NATIVE_WINDOWS
case X-"$ac_cv_native_windows" in
  X-yes)
    CURL_CHECK_HEADER_WINSOCK
    CURL_CHECK_HEADER_WINSOCK2
    CURL_CHECK_HEADER_WS2TCPIP
    ;;
  *)
    ac_cv_header_winsock_h="no"
    ac_cv_header_winsock2_h="no"
    ac_cv_header_ws2tcpip_h="no"
    ;;
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
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      gethostbyname();
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
  ],[
    AC_MSG_RESULT([no])
    LIBS=$my_ac_save_LIBS
  ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for winsock systems
  if test "$ac_cv_header_windows_h" = "yes"; then
    if test "$ac_cv_header_winsock_h" = "yes"; then
      case $host in
        *-*-mingw32ce*)
          winsock_LIB="-lwinsock"
          ;;
        *)
          winsock_LIB="-lwsock32"
          ;;
      esac
    fi
    if test "$ac_cv_header_winsock2_h" = "yes"; then
      winsock_LIB="-lws2_32"
    fi
    if test ! -z "$winsock_LIB"; then
      my_ac_save_LIBS=$LIBS
      LIBS="$winsock_LIB $LIBS"
      AC_MSG_CHECKING([for gethostbyname in $winsock_LIB])
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
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
        ]],[[
          gethostbyname("www.dummysite.com");
        ]])
      ],[
        AC_MSG_RESULT([yes])
        HAVE_GETHOSTBYNAME="1"
      ],[
        AC_MSG_RESULT([no])
        winsock_LIB=""
        LIBS=$my_ac_save_LIBS
      ])
    fi
  fi
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for Minix 3.1
  AC_MSG_CHECKING([for gethostbyname for Minix 3])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
/* Older Minix versions may need <net/gen/netdb.h> here instead */
#include <netdb.h>
    ]],[[
      gethostbyname("www.dummysite.com");
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
  ],[
    AC_MSG_RESULT([no])
  ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for eCos with a stubbed DNS implementation
  AC_MSG_CHECKING([for gethostbyname for eCos])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
#include <stdio.h>
#include <netdb.h>
    ]],[[
      gethostbyname("www.dummysite.com");
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
  ],[
    AC_MSG_RESULT([no])
  ])
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

dnl **********************************************************************
dnl In case that function clock_gettime with monotonic timer is available,
dnl check for additional required libraries.
dnl **********************************************************************
CURL_CHECK_LIBS_CLOCK_GETTIME_MONOTONIC

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

fi


dnl **********************************************************************
dnl Back to "normal" configuring
dnl **********************************************************************

dnl Checks for header files.
AC_HEADER_STDC

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
       strings.h \
       stdbool.h \
       time.h \
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
CURL_CHECK_FUNC_RECVFROM
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

CARES_PRIVATE_LIBS="$LIBS"
AC_SUBST(CARES_PRIVATE_LIBS)

AC_CONFIG_FILES([Makefile libcares.pc])
AC_OUTPUT
