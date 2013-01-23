#---------------------------------------------------------------------------
#
# zz40-xc-ovr.m4
#
# Copyright (c) 2013 Daniel Stenberg <daniel@haxx.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#---------------------------------------------------------------------------

# serial 1


dnl The funny name of this file is intentional in order to make it
dnl sort alphabetically after any libtool, autoconf or automake
dnl provided .m4 macro file that might get copied into this same
dnl subdirectory. This allows that macro (re)definitions from this
dnl file may override those provided in other files.


dnl _XC_CONFIGURE_PREAMBLE_COMMENT
dnl -------------------------------------------------
dnl Private macro.

AC_DEFUN([_XC_CONFIGURE_PREAMBLE_COMMENT],
[
## ---------------------------- ##
## XC_CONFIGURE_PREAMBLE rev: 1 ##
## ---------------------------- ##
])


dnl _XC_CHECK_COMMAND_TEST
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Check that 'test' command is available, else abort.

AC_DEFUN([_XC_CHECK_COMMAND_TEST],
[dnl
#
# Require that 'test' command is available.
#

xc_tst_str='unknown'
test -n "$xc_tst_str" && xc_tst_str='success'
case "x$xc_tst_str" in
  xsuccess)
    :
    ;;
  *)
    echo "configure: error: 'test' command not found. Can not continue."
    exit 1
    ;;
esac
])


dnl _XC_CHECK_PATH
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Check that PATH is set, otherwise abort.

AC_DEFUN([_XC_CHECK_PATH],
[dnl
AC_REQUIRE([_XC_CHECK_COMMAND_TEST])dnl
#
# Require that PATH variable is set.
#

xc_tst_str='unknown'
test -n "$PATH" && xc_tst_str='success'
case "x$xc_tst_str" in
  xsuccess)
    :
    ;;
  *)
    echo "configure: error: PATH variable not set. Can not continue."
    exit 1
    ;;
esac
])


dnl _XC_CHECK_COMMAND_EXPR
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Check that 'expr' command is available, else abort.

AC_DEFUN([_XC_CHECK_COMMAND_EXPR],
[dnl
#
# Require that 'expr' command is available.
#

xc_tst_str='unknown'
xc_tst_str=`expr "$xc_tst_str" : '.*'`
case "x$xc_tst_str" in
  x7)
    :
    ;;
  *)
    echo "configure: error: 'expr' command not found. Can not continue."
    exit 1
    ;;
esac
])


dnl _XC_CHECK_UTILITY_SED
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Check that 'sed' utility is found within PATH. This
dnl 'sed' is required in order to allow configure script
dnl bootstrapping itself. No fancy testing for a proper
dnl 'sed' this early please, that should be done later.

AC_DEFUN([_XC_CHECK_UTILITY_SED],
[dnl
#
# Require that 'sed' utility is found within PATH.
#

xc_tst_str='unknown'
xc_tst_str=`echo "$xc_tst_str" | sed -e 's:unknown:success:'`
case "x$xc_tst_str" in
  xsuccess)
    :
    ;;
  *)
    echo "configure: error: 'sed' utility not in PATH. Can not continue."
    exit 1
    ;;
esac
])


dnl _XC_CHECK_UTILITY_GREP
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Check that 'grep' utility is found within PATH. This
dnl 'grep' is required in order to allow configure script
dnl bootstrapping itself. No fancy testing for a proper
dnl 'grep' this early please, that should be done later.

AC_DEFUN([_XC_CHECK_UTILITY_GREP],
[dnl
#
# Require that 'grep' utility is found within PATH.
#

xc_tst_str='unknown'
echo "$xc_tst_str" | grep 'unknown' >/dev/null 2>&1 && xc_tst_str='success'
case "x$xc_tst_str" in
  xsuccess)
    :
    ;;
  *)
    echo "configure: error: 'grep' utility not in PATH. Can not continue."
    exit 1
    ;;
esac
])


dnl _XC_CHECK_PATH_SEPARATOR
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Check and compute the path separator for us. This
dnl path separator is the symbol used to diferentiate
dnl or separate paths inside the PATH environment var.
dnl
dnl User provided PATH_SEPARATOR always overrides the
dnl auto-detected one.

AC_DEFUN([_XC_CHECK_PATH_SEPARATOR],
[dnl
AC_REQUIRE([_XC_CHECK_COMMAND_TEST])dnl
AC_REQUIRE([_XC_CHECK_PATH])dnl
AC_REQUIRE([_XC_CHECK_COMMAND_EXPR])dnl
#
# Auto-detect and set PATH_SEPARATOR, unless it is already set.
#

# Directory count in PATH when using a colon separator.
xc_tst_dirs_col=0
xc_tst_prev_IFS=$IFS; IFS=':'
for xc_tst_dir in $PATH; do
  IFS=$xc_tst_prev_IFS
  test -d "$xc_tst_dir" && xc_tst_dirs_col=`expr $xc_tst_dirs_col + 1`
done
IFS=$xc_tst_prev_IFS

# Directory count in PATH when using a semicolon separator.
xc_tst_dirs_sem=0
xc_tst_prev_IFS=$IFS; IFS=';'
for xc_tst_dir in $PATH; do
  IFS=$xc_tst_prev_IFS
  test -d "$xc_tst_dir" && xc_tst_dirs_sem=`expr $xc_tst_dirs_sem + 1`
done
IFS=$xc_tst_prev_IFS

if test $xc_tst_dirs_sem -eq $xc_tst_dirs_col; then
  # When both counting methods give the same result we do not want to
  # chose one over the other, and consider auto-detection not possible.
  if test -z "$PATH_SEPARATOR"; then
    # Stop dead until user provides PATH_SEPARATOR definition.
    echo "configure: error: PATH_SEPARATOR variable not set. Can not continue."
    exit 1
  fi
else
  # Separator with the greater directory count is the auto-detected one.
  if test $xc_tst_dirs_sem -gt $xc_tst_dirs_col; then
    xc_tst_auto_separator=';'
  else
    xc_tst_auto_separator=':'
  fi
  if test -z "$PATH_SEPARATOR"; then
    # Simply use the auto-detected one when not already set.
    PATH_SEPARATOR="$xc_tst_auto_separator"
  elif "x$PATH_SEPARATOR" != "x$xc_tst_auto_separator"; then
    echo "configure: warning: PATH_SEPARATOR does not match auto-detected one."
  fi
fi
AC_SUBST([PATH_SEPARATOR])dnl
])


dnl _XC_CONFIGURE_PREAMBLE
dnl -------------------------------------------------
dnl Private macro.

AC_DEFUN([_XC_CONFIGURE_PREAMBLE],
[dnl
AC_REQUIRE([_XC_CONFIGURE_PREAMBLE_COMMENT])dnl
AC_REQUIRE([_XC_CHECK_COMMAND_TEST])dnl
AC_REQUIRE([_XC_CHECK_PATH])dnl
AC_REQUIRE([_XC_CHECK_COMMAND_EXPR])dnl
AC_REQUIRE([_XC_CHECK_UTILITY_SED])dnl
AC_REQUIRE([_XC_CHECK_UTILITY_GREP])dnl
AC_REQUIRE([_XC_CHECK_PATH_SEPARATOR])dnl
echo "checking whether some basic commands and utilities are available... yes"
])


dnl XC_CONFIGURE_PREAMBLE
dnl -------------------------------------------------
dnl Public macro.
dnl
dnl This macro macro emits shell code which does some
dnl very basic checks related with the availability
dnl of some commands and utilities needed to allow
dnl configure script bootstrapping itself when using
dnl these to figure out other settings. Also performs
dnl PATH_SEPARATOR auto-detection and sets its value
dnl unless it is already set.
dnl
dnl These basic checks are intended to be placed and
dnl executed as early as possible in the resulting
dnl configure script, and as such these must be pure
dnl shell code.
dnl
dnl Although this is a public macro it should not be
dnl used directly from configure.ac given that in this
dnl way its expansion is not placed early enough in
dnl generated configure script, it simply makes little
dnl sense to perform these basic checks once the script
dnl is into more serious business.
dnl
dnl The proper way of making this macro expand early
dnl enough in configure script is using XC_OVR_ZZ40
dnl in configure.ac which takes care of everything.

AC_DEFUN([XC_CONFIGURE_PREAMBLE],
[dnl
AC_PREREQ([2.50])dnl
AC_BEFORE([$0],[_XC_CONFIGURE_PREAMBLE])dnl
AC_BEFORE([$0],[_XC_CHECK_COMMAND_TEST])dnl
AC_BEFORE([$0],[_XC_CHECK_PATH])dnl
AC_BEFORE([$0],[_XC_CHECK_COMMAND_EXPR])dnl
AC_BEFORE([$0],[_XC_CHECK_UTILITY_SED])dnl
AC_BEFORE([$0],[_XC_CHECK_UTILITY_GREP])dnl
AC_BEFORE([$0],[_XC_CHECK_PATH_SEPARATOR])dnl
AC_REQUIRE([_XC_CONFIGURE_PREAMBLE])dnl
m4_define([$0],[])dnl
])


dnl Override autoconf's PATH_SEPARATOR check
dnl -------------------------------------------------
dnl This is done to ensure that the same check is
dnl used across different autoconf versions and to
dnl allow us to expand XC_CONFIGURE_PREAMBLE macro
dnl early enough in the generated configure script.

dnl
dnl Override when using autoconf 2.53 and newer.
dnl

m4_defun([_AS_PATH_SEPARATOR_PREPARE],
[dnl
AC_REQUIRE([XC_CONFIGURE_PREAMBLE])dnl
m4_define([$0],[])dnl
])

dnl
dnl Override when using autoconf 2.50 to 2.52
dnl

m4_defun([_AC_INIT_PREPARE_FS_SEPARATORS],
[dnl
AC_REQUIRE([XC_CONFIGURE_PREAMBLE])dnl
ac_path_separator=$PATH_SEPARATOR
m4_define([$0],[])dnl
])

dnl
dnl Override when using libtool 1.4.2
dnl

m4_defun([_LT_AC_LIBTOOL_SYS_PATH_SEPARATOR],
[dnl
AC_REQUIRE([XC_CONFIGURE_PREAMBLE])dnl
lt_cv_sys_path_separator=$PATH_SEPARATOR
m4_define([$0],[])dnl
])


dnl XC_OVR_ZZ40
dnl -------------------------------------------------
dnl Placing a call to this macro in configure.ac will
dnl make macros in this file visible to other macros
dnl used for same configure script, overriding those
dnl provided elsewhere.
dnl
dnl This is the proper and intended way in which macro
dnl XC_CONFIGURE_PREAMBLE will expand early enough in
dnl generated configure script.

AC_DEFUN([XC_OVR_ZZ40],
[dnl
AC_BEFORE([$0],[AC_CHECK_TOOL])dnl
AC_BEFORE([$0],[AC_CHECK_PROG])dnl
AC_BEFORE([$0],[AC_CHECK_TOOLS])dnl
AC_BEFORE([$0],[AC_CHECK_PROGS])dnl
dnl
AC_BEFORE([$0],[AC_PATH_TOOL])dnl
AC_BEFORE([$0],[AC_PATH_PROG])dnl
AC_BEFORE([$0],[AC_PATH_PROGS])dnl
dnl
AC_BEFORE([$0],[AC_PROG_SED])dnl
AC_BEFORE([$0],[AC_PROG_GREP])dnl
AC_BEFORE([$0],[AC_PROG_LN_S])dnl
AC_BEFORE([$0],[AC_PROG_INSTALL])dnl
AC_BEFORE([$0],[AC_PROG_MAKE_SET])dnl
AC_BEFORE([$0],[AC_PROG_LIBTOOL])dnl
dnl
AC_BEFORE([$0],[LT_INIT])dnl
AC_BEFORE([$0],[AM_INIT_AUTOMAKE])dnl
AC_BEFORE([$0],[AC_LIBTOOL_WIN32_DLL])dnl
dnl
AC_BEFORE([$0],[AC_CONFIG_SRCDIR])dnl
AC_BEFORE([$0],[AC_CONFIG_HEADERS])dnl
AC_BEFORE([$0],[AC_CONFIG_MACRO_DIR])dnl
AC_BEFORE([$0],[AC_CONFIG_MACRO_DIRS])dnl
dnl
m4_define([$0],[])dnl
])

