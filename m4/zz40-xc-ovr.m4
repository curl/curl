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


dnl _XC_CFG_PRE_PREAMBLE
dnl -------------------------------------------------
dnl Private macro.

AC_DEFUN([_XC_CFG_PRE_PREAMBLE],
[
## ---------------------------- ##
## XC_CONFIGURE_PREAMBLE rev: 1 ##
## ---------------------------- ##

xc_configure_preamble_prev_IFS=$IFS

xc_msg_warn='configure: WARNING:'
xc_msg_abrt='Can not continue.'
xc_msg_err='configure: error:'
])

dnl _XC_CFG_PRE_BASIC_CHK_CMD_ECHO
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that verifies that 'echo' command
dnl is available, otherwise aborts execution.

AC_DEFUN([_XC_CFG_PRE_BASIC_CHK_CMD_ECHO],
[dnl
#
# Verify that 'echo' command is available, otherwise abort.
#

xc_tst_str='unknown'
(`echo "$xc_tst_str" >/dev/null 2>&1`) && xc_tst_str='success'
case "x$xc_tst_str" in @%:@((
  xsuccess)
    :
    ;;
  *)
    # Try built-in echo, and fail.
    echo "$xc_msg_err 'echo' command not found. $xc_msg_abrt" >&2
    exit 1
    ;;
esac
])


dnl _XC_CFG_PRE_BASIC_CHK_CMD_TEST
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that verifies that 'test' command
dnl is available, otherwise aborts execution.

AC_DEFUN([_XC_CFG_PRE_BASIC_CHK_CMD_TEST],
[dnl
#
# Verify that 'test' command is available, otherwise abort.
#

xc_tst_str='unknown'
(`test -n "$xc_tst_str" >/dev/null 2>&1`) && xc_tst_str='success'
case "x$xc_tst_str" in @%:@((
  xsuccess)
    :
    ;;
  *)
    echo "$xc_msg_err 'test' command not found. $xc_msg_abrt" >&2
    exit 1
    ;;
esac
])


dnl _XC_CFG_PRE_BASIC_CHK_VAR_PATH
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that verifies that 'PATH' variable
dnl is set, otherwise aborts execution.

AC_DEFUN([_XC_CFG_PRE_BASIC_CHK_VAR_PATH],
[dnl
#
# Verify that 'PATH' variable is set, otherwise abort.
#

xc_tst_str='unknown'
(`test -n "$PATH" >/dev/null 2>&1`) && xc_tst_str='success'
case "x$xc_tst_str" in @%:@((
  xsuccess)
    :
    ;;
  *)
    echo "$xc_msg_err 'PATH' variable not set. $xc_msg_abrt" >&2
    exit 1
    ;;
esac
])


dnl _XC_CFG_PRE_BASIC_CHK_CMD_EXPR
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that verifies that 'expr' command
dnl is available, otherwise aborts execution.

AC_DEFUN([_XC_CFG_PRE_BASIC_CHK_CMD_EXPR],
[dnl
#
# Verify that 'expr' command is available, otherwise abort.
#

xc_tst_str='unknown'
xc_tst_str=(`expr "$xc_tst_str" : '.*' 2>/dev/null`)
case "x$xc_tst_str" in @%:@((
  x7)
    :
    ;;
  *)
    echo "$xc_msg_err 'expr' command not found. $xc_msg_abrt" >&2
    exit 1
    ;;
esac
])


dnl _XC_CFG_PRE_BASIC_CHK_UTIL_SED
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that verifies that 'sed' utility
dnl is found within 'PATH', otherwise aborts execution.
dnl
dnl This 'sed' is required in order to allow configure
dnl script bootstrapping itself. No fancy testing for a
dnl proper 'sed' this early, that should be done later.

AC_DEFUN([_XC_CFG_PRE_BASIC_CHK_UTIL_SED],
[dnl
#
# Verify that 'sed' utility is found within 'PATH', otherwise abort.
#

xc_tst_str='unknown'
xc_tst_str=(`echo "$xc_tst_str" 2>/dev/null \
  | sed -e 's:unknown:success:' 2>/dev/null`)
case "x$xc_tst_str" in @%:@((
  xsuccess)
    :
    ;;
  *)
    echo "$xc_msg_err 'sed' utility not found in 'PATH'. $xc_msg_abrt" >&2
    exit 1
    ;;
esac
])


dnl _XC_CFG_PRE_BASIC_CHK_UTIL_GREP
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that verifies that 'grep' utility
dnl is found within 'PATH', otherwise aborts execution.
dnl
dnl This 'grep' is required in order to allow configure
dnl script bootstrapping itself. No fancy testing for a
dnl proper 'grep' this early, that should be done later.

AC_DEFUN([_XC_CFG_PRE_BASIC_CHK_UTIL_GREP],
[dnl
#
# Verify that 'grep' utility is found within 'PATH', otherwise abort.
#

xc_tst_str='unknown'
(`echo "$xc_tst_str" 2>/dev/null \
  | grep 'unknown' >/dev/null 2>&1`) && xc_tst_str='success'
case "x$xc_tst_str" in @%:@((
  xsuccess)
    :
    ;;
  *)
    echo "$xc_msg_err 'grep' utility not found in 'PATH'. $xc_msg_abrt" >&2
    exit 1
    ;;
esac
])


dnl _XC_CFG_PRE_CHECK_PATH_SEPARATOR
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl Emits shell code that computes the path separator
dnl and stores the result in 'PATH_SEPARATOR', unless
dnl the user has already set it with a non-empty value.
dnl
dnl This path separator is the symbol used to separate
dnl or diferentiate paths inside the 'PATH' environment
dnl environment variable.
dnl
dnl Non-empty user provided 'PATH_SEPARATOR' always
dnl overrides the auto-detected one.

AC_DEFUN([_XC_CFG_PRE_CHECK_PATH_SEPARATOR],
[dnl
#
# Auto-detect and set 'PATH_SEPARATOR', unless it is already non-empty set.
#

# Directory count in 'PATH' when using a colon separator.
xc_tst_dirs_col=''
xc_tst_prev_IFS=$IFS; IFS=':'
for xc_tst_dir in $PATH; do
  IFS=$xc_tst_prev_IFS
  xc_tst_dirs_col="x$xc_tst_dirs_col"
done
IFS=$xc_tst_prev_IFS
xc_tst_dirs_col=(`expr "$xc_tst_dirs_col" : '.*'`)

# Directory count in 'PATH' when using a semicolon separator.
xc_tst_dirs_sem=''
xc_tst_prev_IFS=$IFS; IFS=';'
for xc_tst_dir in $PATH; do
  IFS=$xc_tst_prev_IFS
  xc_tst_dirs_sem="x$xc_tst_dirs_sem"
done
IFS=$xc_tst_prev_IFS
xc_tst_dirs_sem=(`expr "$xc_tst_dirs_sem" : '.*'`)

if test $xc_tst_dirs_sem -eq $xc_tst_dirs_col; then
  # When both counting methods give the same result we do not want to
  # chose one over the other, and consider auto-detection not possible.
  if test -z "$PATH_SEPARATOR"; then
    # Stop dead until user provides 'PATH_SEPARATOR' definition.
    echo "$xc_msg_err 'PATH_SEPARATOR' variable not set. $xc_msg_abrt" >&2
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
  elif test "x$PATH_SEPARATOR" != "x$xc_tst_auto_separator"; then
    echo "$xc_msg_warn 'PATH_SEPARATOR' does not match auto-detected one." >&2
  fi
fi
AC_SUBST([PATH_SEPARATOR])dnl
])


dnl _XC_CFG_PRE_POSTLUDE
dnl -------------------------------------------------
dnl Private macro.

AC_DEFUN([_XC_CFG_PRE_POSTLUDE],
[dnl
echo "checking whether some basic commands and utilities are available... yes"

IFS=$xc_configure_preamble_prev_IFS
])


dnl _XC_CONFIGURE_PREAMBLE
dnl -------------------------------------------------
dnl Private macro.

AC_DEFUN([_XC_CONFIGURE_PREAMBLE],
[dnl
AC_REQUIRE([_XC_CFG_PRE_PREAMBLE])dnl
AC_REQUIRE([_XC_CFG_PRE_BASIC_CHK_CMD_ECHO])dnl
AC_REQUIRE([_XC_CFG_PRE_BASIC_CHK_CMD_TEST])dnl
AC_REQUIRE([_XC_CFG_PRE_BASIC_CHK_VAR_PATH])dnl
AC_REQUIRE([_XC_CFG_PRE_BASIC_CHK_CMD_EXPR])dnl
AC_REQUIRE([_XC_CFG_PRE_BASIC_CHK_UTIL_SED])dnl
AC_REQUIRE([_XC_CFG_PRE_BASIC_CHK_UTIL_GREP])dnl
AC_REQUIRE([_XC_CFG_PRE_CHECK_PATH_SEPARATOR])dnl
AC_REQUIRE([_XC_CFG_PRE_POSTLUDE])dnl
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
dnl unless it is already set with a non-empty value.
dnl
dnl These basic checks are intended to be placed and
dnl executed as early as possible in the resulting
dnl configure script, and as such these must be pure
dnl shell code.
dnl
dnl Although this is a public macro it should not be
dnl used directly from configure.ac given that in this
dnl way its expansion may not be placed early enough in
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
AC_BEFORE([$0],[_XC_CFG_PRE_PREAMBLE])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_BASIC_CHK_CMD_ECHO])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_BASIC_CHK_CMD_TEST])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_BASIC_CHK_VAR_PATH])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_BASIC_CHK_CMD_EXPR])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_BASIC_CHK_UTIL_SED])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_BASIC_CHK_UTIL_GREP])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_CHECK_PATH_SEPARATOR])dnl
AC_BEFORE([$0],[_XC_CFG_PRE_POSTLUDE])dnl
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

