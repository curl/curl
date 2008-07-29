

dnl CARES_CHECK_NEED_REENTRANT_GMTIME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function gmtime_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_GMTIME_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gmtime_r])
  ],[
    tmp_gmtime_r="yes"
  ],[
    tmp_gmtime_r="no"
  ])
  if test "$tmp_gmtime_r" = "yes"; then
    AC_EGREP_CPP([gmtime_r],[
#include <sys/types.h>
#include <time.h>
    ],[
      tmp_gmtime_r="proto_declared"
    ],[
      AC_EGREP_CPP([gmtime_r],[
#define _REENTRANT
#include <sys/types.h>
#include <time.h>
      ],[
        tmp_gmtime_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_LOCALTIME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function localtime_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_LOCALTIME_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([localtime_r])
  ],[
    tmp_localtime_r="yes"
  ],[
    tmp_localtime_r="no"
  ])
  if test "$tmp_localtime_r" = "yes"; then
    AC_EGREP_CPP([localtime_r],[
#include <sys/types.h>
#include <time.h>
    ],[
      tmp_localtime_r="proto_declared"
    ],[
      AC_EGREP_CPP([localtime_r],[
#define _REENTRANT
#include <sys/types.h>
#include <time.h>
      ],[
        tmp_localtime_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_STRERROR_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function strerror_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_STRERROR_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strerror_r])
  ],[
    tmp_strerror_r="yes"
  ],[
    tmp_strerror_r="no"
  ])
  if test "$tmp_strerror_r" = "yes"; then
    AC_EGREP_CPP([strerror_r],[
#include <sys/types.h>
#include <string.h>
    ],[
      tmp_strerror_r="proto_declared"
    ],[
      AC_EGREP_CPP([strerror_r],[
#define _REENTRANT
#include <sys/types.h>
#include <string.h>
      ],[
        tmp_strerror_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_STRTOK_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function strtok_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_STRTOK_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strtok_r])
  ],[
    tmp_strtok_r="yes"
  ],[
    tmp_strtok_r="no"
  ])
  if test "$tmp_strtok_r" = "yes"; then
    AC_EGREP_CPP([strtok_r],[
#include <sys/types.h>
#include <string.h>
    ],[
      tmp_strtok_r="proto_declared"
    ],[
      AC_EGREP_CPP([strtok_r],[
#define _REENTRANT
#include <sys/types.h>
#include <string.h>
      ],[
        tmp_strtok_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_INET_NTOA_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function inet_ntoa_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_INET_NTOA_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([inet_ntoa_r])
  ],[
    tmp_inet_ntoa_r="yes"
  ],[
    tmp_inet_ntoa_r="no"
  ])
  if test "$tmp_inet_ntoa_r" = "yes"; then
    AC_EGREP_CPP([inet_ntoa_r],[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
    ],[
      tmp_inet_ntoa_r="proto_declared"
    ],[
      AC_EGREP_CPP([inet_ntoa_r],[
#define _REENTRANT
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
      ],[
        tmp_inet_ntoa_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_GETHOSTBYADDR_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function gethostbyaddr_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_GETHOSTBYADDR_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostbyaddr_r])
  ],[
    tmp_gethostbyaddr_r="yes"
  ],[
    tmp_gethostbyaddr_r="no"
  ])
  if test "$tmp_gethostbyaddr_r" = "yes"; then
    AC_EGREP_CPP([gethostbyaddr_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      tmp_gethostbyaddr_r="proto_declared"
    ],[
      AC_EGREP_CPP([gethostbyaddr_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        tmp_gethostbyaddr_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_GETHOSTBYNAME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function gethostbyname_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_GETHOSTBYNAME_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostbyname_r])
  ],[
    tmp_gethostbyname_r="yes"
  ],[
    tmp_gethostbyname_r="no"
  ])
  if test "$tmp_gethostbyname_r" = "yes"; then
    AC_EGREP_CPP([gethostbyname_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      tmp_gethostbyname_r="proto_declared"
    ],[
      AC_EGREP_CPP([gethostbyname_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        tmp_gethostbyname_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_GETPROTOBYNAME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function getprotobyname_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_GETPROTOBYNAME_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getprotobyname_r])
  ],[
    tmp_getprotobyname_r="yes"
  ],[
    tmp_getprotobyname_r="no"
  ])
  if test "$tmp_getprotobyname_r" = "yes"; then
    AC_EGREP_CPP([getprotobyname_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      tmp_getprotobyname_r="proto_declared"
    ],[
      AC_EGREP_CPP([getprotobyname_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        tmp_getprotobyname_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_GETSERVBYPORT_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function getservbyport_r compiler visible.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_GETSERVBYPORT_R], [
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getservbyport_r])
  ],[
    tmp_getservbyport_r="yes"
  ],[
    tmp_getservbyport_r="no"
  ])
  if test "$tmp_getservbyport_r" = "yes"; then
    AC_EGREP_CPP([getservbyport_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      tmp_getservbyport_r="proto_declared"
    ],[
      AC_EGREP_CPP([getservbyport_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        tmp_getservbyport_r="proto_needs_reentrant"
        tmp_need_reentrant="yes"
      ])
    ])
  fi
])


dnl CARES_CHECK_NEED_REENTRANT_FUNCTIONS_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes several _r functions compiler visible.
dnl Internal macro for CARES_CONFIGURE_REENTRANT.

AC_DEFUN([CARES_CHECK_NEED_REENTRANT_FUNCTIONS_R], [
  #
  tmp_need_reentrant="no"
  #
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_GMTIME_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_LOCALTIME_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_STRERROR_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_STRTOK_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_INET_NTOA_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_GETHOSTBYADDR_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_GETHOSTBYNAME_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_GETPROTOBYNAME_R
  fi
  if test "$tmp_need_reentrant" = "no"; then
    CARES_CHECK_NEED_REENTRANT_GETSERVBYPORT_R
  fi
])


dnl CARES_CONFIGURE_FROM_NOW_ON_WITH_REENTRANT
dnl -------------------------------------------------
dnl This macro ensures that configuration tests done
dnl after this will execute with preprocessor symbol
dnl _REENTRANT defined. This macro also ensures that
dnl the generated config file defines NEED_REENTRANT
dnl and that in turn setup.h will define _REENTRANT.
dnl Internal macro for CARES_CONFIGURE_REENTRANT.

AC_DEFUN([CARES_CONFIGURE_FROM_NOW_ON_WITH_REENTRANT], [
AC_DEFINE(NEED_REENTRANT, 1,
  [Define to 1 if _REENTRANT preprocessor symbol must be defined.])
cat >>confdefs.h <<_ACEOF
[#ifndef _REENTRANT
# define _REENTRANT
#endif]
_ACEOF
])


dnl CARES_CONFIGURE_REENTRANT
dnl -------------------------------------------------
dnl This first checks if the preprocessor _REENTRANT
dnl symbol is already defined. If it isn't currently
dnl defined a set of checks are performed to verify
dnl if its definition is required to make visible to
dnl the compiler a set of *_r functions. Finally, if
dnl _REENTRANT is already defined or needed it takes
dnl care of making adjustments necessary to ensure
dnl that it is defined equally for further configure
dnl tests and generated config file.

AC_DEFUN([CARES_CONFIGURE_REENTRANT], [
  AC_PREREQ([2.57])dnl
  #
  AC_MSG_CHECKING([if _REENTRANT is already defined])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
#ifdef _REENTRANT
      int dummy=1;
#else
      force compilation error
#endif
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tmp_reentrant_initially_defined="yes"
  ],[
    AC_MSG_RESULT([no])
    tmp_reentrant_initially_defined="no"
  ])
  #
  if test "$tmp_reentrant_initially_defined" = "no"; then
    AC_MSG_CHECKING([if _REENTRANT is actually needed])
    CARES_CHECK_NEED_REENTRANT_FUNCTIONS_R
    if test "$tmp_need_reentrant" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  AC_MSG_CHECKING([if _REENTRANT is onwards defined])
  if test "$tmp_reentrant_initially_defined" = "yes" ||
    test "$tmp_need_reentrant" = "yes"; then
    CARES_CONFIGURE_FROM_NOW_ON_WITH_REENTRANT
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
  #
])

