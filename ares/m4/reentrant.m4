

dnl CHECK_NEED_REENTRANT_STRERROR_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function strerror_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_STRERROR_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strerror_r])
  ],[
    AC_MSG_NOTICE([DEBUG: strerror_r links... yes])
    tmp_strerror_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: strerror_r links... no])
    tmp_strerror_r="no"
  ])
  #
  if test "$tmp_strerror_r" = "yes"; then
    AC_EGREP_CPP([strerror_r],[
#include <sys/types.h>
#include <string.h>
    ],[
      AC_MSG_NOTICE([DEBUG: strerror_r proto... without our definition])
      tmp_strerror_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([strerror_r],[
#define _REENTRANT
#include <sys/types.h>
#include <string.h>
      ],[
        AC_MSG_NOTICE([DEBUG: strerror_r proto... with our _reentrant])
        tmp_strerror_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: strerror_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_strerror_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <string.h>
      ]],[[
        strerror_r(0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: strerror_r proto wout finds... 3 args])
      tmp_strerror_r="done"
    ])
  fi
  #
  if test "$tmp_strerror_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <string.h>
      ]],[[
        strerror_r(0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: strerror_r proto with finds... 3 args])
      tmp_strerror_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_strerror_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_STRTOK_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function strtok_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_STRTOK_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strtok_r])
  ],[
    AC_MSG_NOTICE([DEBUG: strtok_r links... yes])
    tmp_strtok_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: strtok_r links... no])
    tmp_strtok_r="no"
  ])
  #
  if test "$tmp_strtok_r" = "yes"; then
    AC_EGREP_CPP([strtok_r],[
#include <sys/types.h>
#include <string.h>
    ],[
      AC_MSG_NOTICE([DEBUG: strtok_r proto... without our definition])
      tmp_strtok_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([strtok_r],[
#define _REENTRANT
#include <sys/types.h>
#include <string.h>
      ],[
        AC_MSG_NOTICE([DEBUG: strtok_r proto... with our _reentrant])
        tmp_strtok_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: strtok_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_strtok_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <string.h>
      ]],[[
        strtok_r(0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: strtok_r proto wout finds... 3 args])
      tmp_strtok_r="done"
    ])
  fi
  #
  if test "$tmp_strtok_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <string.h>
      ]],[[
        strtok_r(0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: strtok_r proto with finds... 3 args])
      tmp_strtok_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_strtok_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_LOCALTIME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function localtime_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_LOCALTIME_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([localtime_r])
  ],[
    AC_MSG_NOTICE([DEBUG: localtime_r links... yes])
    tmp_localtime_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: localtime_r links... no])
    tmp_localtime_r="no"
  ])
  #
  if test "$tmp_localtime_r" = "yes"; then
    AC_EGREP_CPP([localtime_r],[
#include <sys/types.h>
#include <time.h>
    ],[
      AC_MSG_NOTICE([DEBUG: localtime_r proto... without our definition])
      tmp_localtime_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([localtime_r],[
#define _REENTRANT
#include <sys/types.h>
#include <time.h>
      ],[
        AC_MSG_NOTICE([DEBUG: localtime_r proto... with our _reentrant])
        tmp_localtime_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: localtime_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_localtime_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <time.h>
      ]],[[
        localtime_r(0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: localtime_r proto wout finds... 2 args])
      tmp_localtime_r="done"
    ])
  fi
  #
  if test "$tmp_localtime_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <time.h>
      ]],[[
        localtime_r(0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: localtime_r proto with finds... 2 args])
      tmp_localtime_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_localtime_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_GMTIME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function gmtime_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_GMTIME_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gmtime_r])
  ],[
    AC_MSG_NOTICE([DEBUG: gmtime_r links... yes])
    tmp_gmtime_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: gmtime_r links... no])
    tmp_gmtime_r="no"
  ])
  #
  if test "$tmp_gmtime_r" = "yes"; then
    AC_EGREP_CPP([gmtime_r],[
#include <sys/types.h>
#include <time.h>
    ],[
      AC_MSG_NOTICE([DEBUG: gmtime_r proto... without our definition])
      tmp_gmtime_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([gmtime_r],[
#define _REENTRANT
#include <sys/types.h>
#include <time.h>
      ],[
        AC_MSG_NOTICE([DEBUG: gmtime_r proto... with our _reentrant])
        tmp_gmtime_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: gmtime_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_gmtime_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <time.h>
      ]],[[
        gmtime_r(0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gmtime_r proto wout finds... 2 args])
      tmp_gmtime_r="done"
    ])
  fi
  #
  if test "$tmp_gmtime_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <time.h>
      ]],[[
        gmtime_r(0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gmtime_r proto with finds... 2 args])
      tmp_gmtime_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_gmtime_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_INET_NTOA_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function inet_ntoa_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_INET_NTOA_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([inet_ntoa_r])
  ],[
    AC_MSG_NOTICE([DEBUG: inet_ntoa_r links... yes])
    tmp_inet_ntoa_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: inet_ntoa_r links... no])
    tmp_inet_ntoa_r="no"
  ])
  #
  if test "$tmp_inet_ntoa_r" = "yes"; then
    AC_EGREP_CPP([inet_ntoa_r],[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
    ],[
      AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto... without our definition])
      tmp_inet_ntoa_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([inet_ntoa_r],[
#define _REENTRANT
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
      ],[
        AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto... with our _reentrant])
        tmp_inet_ntoa_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_inet_ntoa_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
      ]],[[
        struct in_addr addr;
        inet_ntoa_r(addr, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto wout finds... 2 args])
      tmp_inet_ntoa_r="done"
    ])
  fi
  if test "$tmp_inet_ntoa_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
      ]],[[
        struct in_addr addr;
        inet_ntoa_r(addr, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto wout finds... 3 args])
      tmp_inet_ntoa_r="done"
    ])
  fi
  #
  if test "$tmp_inet_ntoa_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
      ]],[[
        struct in_addr addr;
        inet_ntoa_r(addr, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto with finds... 2 args])
      tmp_inet_ntoa_r="needs_reentrant"
    ])
  fi
  if test "$tmp_inet_ntoa_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
      ]],[[
        struct in_addr addr;
        inet_ntoa_r(addr, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: inet_ntoa_r proto with finds... 3 args])
      tmp_inet_ntoa_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_inet_ntoa_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_GETHOSTBYADDR_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function gethostbyaddr_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_GETHOSTBYADDR_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostbyaddr_r])
  ],[
    AC_MSG_NOTICE([DEBUG: gethostbyaddr_r links... yes])
    tmp_gethostbyaddr_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: gethostbyaddr_r links... no])
    tmp_gethostbyaddr_r="no"
  ])
  #
  if test "$tmp_gethostbyaddr_r" = "yes"; then
    AC_EGREP_CPP([gethostbyaddr_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto... without our definition])
      tmp_gethostbyaddr_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([gethostbyaddr_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto... with our _reentrant])
        tmp_gethostbyaddr_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_gethostbyaddr_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyaddr_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto wout finds... 5 args])
      tmp_gethostbyaddr_r="done"
    ])
  fi
  if test "$tmp_gethostbyaddr_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyaddr_r(0, 0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto wout finds... 7 args])
      tmp_gethostbyaddr_r="done"
    ])
  fi
  if test "$tmp_gethostbyaddr_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyaddr_r(0, 0, 0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto wout finds... 8 args])
      tmp_gethostbyaddr_r="done"
    ])
  fi
  #
  if test "$tmp_gethostbyaddr_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyaddr_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto with finds... 5 args])
      tmp_gethostbyaddr_r="needs_reentrant"
    ])
  fi
  if test "$tmp_gethostbyaddr_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyaddr_r(0, 0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto with finds... 7 args])
      tmp_gethostbyaddr_r="needs_reentrant"
    ])
  fi
  if test "$tmp_gethostbyaddr_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyaddr_r(0, 0, 0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyaddr_r proto with finds... 8 args])
      tmp_gethostbyaddr_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_gethostbyaddr_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_GETHOSTBYNAME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function gethostbyname_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_GETHOSTBYNAME_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostbyname_r])
  ],[
    AC_MSG_NOTICE([DEBUG: gethostbyname_r links... yes])
    tmp_gethostbyname_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: gethostbyname_r links... no])
    tmp_gethostbyname_r="no"
  ])
  #
  if test "$tmp_gethostbyname_r" = "yes"; then
    AC_EGREP_CPP([gethostbyname_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto... without our definition])
      tmp_gethostbyname_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([gethostbyname_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        AC_MSG_NOTICE([DEBUG: gethostbyname_r proto... with our _reentrant])
        tmp_gethostbyname_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: gethostbyname_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_gethostbyname_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyname_r(0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto wout finds... 3 args])
      tmp_gethostbyname_r="done"
    ])
  fi
  if test "$tmp_gethostbyname_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyname_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto wout finds... 5 args])
      tmp_gethostbyname_r="done"
    ])
  fi
  if test "$tmp_gethostbyname_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyname_r(0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto wout finds... 6 args])
      tmp_gethostbyname_r="done"
    ])
  fi
  #
  if test "$tmp_gethostbyname_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyname_r(0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto with finds... 3 args])
      tmp_gethostbyname_r="needs_reentrant"
    ])
  fi
  if test "$tmp_gethostbyname_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyname_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto with finds... 5 args])
      tmp_gethostbyname_r="needs_reentrant"
    ])
  fi
  if test "$tmp_gethostbyname_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        gethostbyname_r(0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: gethostbyname_r proto with finds... 6 args])
      tmp_gethostbyname_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_gethostbyname_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_GETPROTOBYNAME_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function getprotobyname_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_GETPROTOBYNAME_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getprotobyname_r])
  ],[
    AC_MSG_NOTICE([DEBUG: getprotobyname_r links... yes])
    tmp_getprotobyname_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: getprotobyname_r links... no])
    tmp_getprotobyname_r="no"
  ])
  #
  if test "$tmp_getprotobyname_r" = "yes"; then
    AC_EGREP_CPP([getprotobyname_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      AC_MSG_NOTICE([DEBUG: getprotobyname_r proto... without our definition])
      tmp_getprotobyname_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([getprotobyname_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        AC_MSG_NOTICE([DEBUG: getprotobyname_r proto... with our _reentrant])
        tmp_getprotobyname_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: getprotobyname_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_getprotobyname_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getprotobyname_r(0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getprotobyname_r proto wout finds... 4 args])
      tmp_getprotobyname_r="done"
    ])
  fi
  if test "$tmp_getprotobyname_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getprotobyname_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getprotobyname_r proto wout finds... 5 args])
      tmp_getprotobyname_r="done"
    ])
  fi
  #
  if test "$tmp_getprotobyname_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getprotobyname_r(0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getprotobyname_r proto with finds... 4 args])
      tmp_getprotobyname_r="needs_reentrant"
    ])
  fi
  if test "$tmp_getprotobyname_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getprotobyname_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getprotobyname_r proto with finds... 5 args])
      tmp_getprotobyname_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_getprotobyname_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_GETSERVBYPORT_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes function getservbyport_r compiler visible.

AC_DEFUN([CHECK_NEED_REENTRANT_GETSERVBYPORT_R], [
  #
  AC_MSG_NOTICE([DEBUG:])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getservbyport_r])
  ],[
    AC_MSG_NOTICE([DEBUG: getservbyport_r links... yes])
    tmp_getservbyport_r="yes"
  ],[
    AC_MSG_NOTICE([DEBUG: getservbyport_r links... no])
    tmp_getservbyport_r="no"
  ])
  #
  if test "$tmp_getservbyport_r" = "yes"; then
    AC_EGREP_CPP([getservbyport_r],[
#include <sys/types.h>
#include <netdb.h>
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto... without our definition])
      tmp_getservbyport_r="proto_wout_def"
    ],[
      AC_EGREP_CPP([getservbyport_r],[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ],[
        AC_MSG_NOTICE([DEBUG: getservbyport_r proto... with our _reentrant])
        tmp_getservbyport_r="proto_with_def"
      ],[
        AC_MSG_NOTICE([DEBUG: getservbyport_r proto... not found])
      ])
    ])
  fi
  #
  if test "$tmp_getservbyport_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getservbyport_r(0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto wout finds... 4 args])
      tmp_getservbyport_r="done"
    ])
  fi
  if test "$tmp_getservbyport_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getservbyport_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto wout finds... 5 args])
      tmp_getservbyport_r="done"
    ])
  fi
  if test "$tmp_getservbyport_r" = "proto_wout_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getservbyport_r(0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto wout finds... 6 args])
      tmp_getservbyport_r="done"
    ])
  fi
  #
  if test "$tmp_getservbyport_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getservbyport_r(0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto with finds... 4 args])
      tmp_getservbyport_r="needs_reentrant"
    ])
  fi
  if test "$tmp_getservbyport_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getservbyport_r(0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto with finds... 5 args])
      tmp_getservbyport_r="needs_reentrant"
    ])
  fi
  if test "$tmp_getservbyport_r" = "proto_with_def"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
      ]],[[
        getservbyport_r(0, 0, 0, 0, 0, 0);
      ]])
    ],[
      AC_MSG_NOTICE([DEBUG: getservbyport_r proto with finds... 6 args])
      tmp_getservbyport_r="needs_reentrant"
    ])
  fi
  #
  if test "$tmp_getservbyport_r" = "needs_reentrant"; then
    ac_cv_need_reentrant="yes"
  fi
])


dnl CHECK_NEED_REENTRANT_FUNCTIONS_R
dnl -------------------------------------------------
dnl Checks if the preprocessor _REENTRANT definition
dnl makes several _r functions compiler visible.
dnl Internal macro for CONFIGURE_REENTRANT.

AC_DEFUN([CHECK_NEED_REENTRANT_FUNCTIONS_R], [
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_STRERROR_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_STRTOK_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_LOCALTIME_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_GMTIME_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_INET_NTOA_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_GETHOSTBYADDR_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_GETHOSTBYNAME_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_GETPROTOBYNAME_R
  fi
  if test "$ac_cv_need_reentrant" = "no"; then
    CHECK_NEED_REENTRANT_GETSERVBYPORT_R
  fi
])

AC_DEFUN([CHECK_NEED_REENTRANT_FUNCTIONS_R_DEBUG], [
    CHECK_NEED_REENTRANT_STRERROR_R
    CHECK_NEED_REENTRANT_STRTOK_R
    CHECK_NEED_REENTRANT_LOCALTIME_R
    CHECK_NEED_REENTRANT_GMTIME_R
    CHECK_NEED_REENTRANT_INET_NTOA_R
    CHECK_NEED_REENTRANT_GETHOSTBYADDR_R
    CHECK_NEED_REENTRANT_GETHOSTBYNAME_R
    CHECK_NEED_REENTRANT_GETPROTOBYNAME_R
    CHECK_NEED_REENTRANT_GETSERVBYPORT_R
])


dnl CONFIGURE_FROM_NOW_ON_WITH_REENTRANT
dnl -------------------------------------------------
dnl This macro ensures that configuration tests done
dnl after this will execute with preprocessor symbol
dnl _REENTRANT defined. This macro also ensures that
dnl the generated config file will equally define it.
dnl Internal macro for CONFIGURE_REENTRANT.

AC_DEFUN([CONFIGURE_FROM_NOW_ON_WITH_REENTRANT], [
AH_VERBATIM([NEED_REENTRANT],
[/* Configure process defines NEED_REENTRANT to 1 when it finds out that */
/* _REENTRANT is required or already defined for proper configuration.  */
@%:@undef NEED_REENTRANT
@%:@if defined(NEED_REENTRANT) && !defined(_REENTRANT)
@%:@ define _REENTRANT
@%:@endif])
cat >>confdefs.h <<_ACEOF
[@%:@ifndef _REENTRANT
@%:@ define _REENTRANT
@%:@endif]
_ACEOF
AC_DEFINE(NEED_REENTRANT, 1, [])
])


dnl CONFIGURE_REENTRANT
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

AC_DEFUN([CONFIGURE_REENTRANT], [
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
    ac_cv_need_reentrant="no"
    CHECK_NEED_REENTRANT_FUNCTIONS_R_DEBUG
    if test "$ac_cv_need_reentrant" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  AC_MSG_CHECKING([if _REENTRANT is onwards defined])
  if test "$tmp_reentrant_initially_defined" = "yes" ||
    test "$ac_cv_need_reentrant" = "yes"; then
    CONFIGURE_FROM_NOW_ON_WITH_REENTRANT
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
  #
])

