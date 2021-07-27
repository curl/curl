dnl ----------------------------------------------------
dnl check for unitytls
dnl ----------------------------------------------------

AC_DEFUN([CURL_WITH_UNITYTLS], [

if test "$curl_ssl_msg" = "$init_ssl_msg"; then

  if test X"$OPT_UNITYTLS" != Xno; then
    AC_DEFINE(USE_UNITYTLS, 1, [if unitytls is enabled])
    UNITYTLS_ENABLED=1
    USE_UNITYTLS="yes"
    curl_ssl_msg="enabled (unitytls)"
  fi

fi

])
