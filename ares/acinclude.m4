dnl Check for how to set a socket to non-blocking state. There seems to exist
dnl four known different ways, with the one used almost everywhere being POSIX
dnl and XPG3, while the other different ways for different systems (old BSD,
dnl Windows and Amiga).
dnl
dnl There are two known platforms (AIX 3.x and SunOS 4.1.x) where the
dnl O_NONBLOCK define is found but does not work. This condition is attempted
dnl to get caught in this script by using an excessive number of #ifdefs...
dnl
AC_DEFUN([CURL_CHECK_NONBLOCKING_SOCKET],
[
  AC_MSG_CHECKING([non-blocking sockets style])

  AC_TRY_COMPILE([
/* headers for O_NONBLOCK test */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
],[
/* try to compile O_NONBLOCK */

#if defined(sun) || defined(__sun__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# if defined(__SVR4) || defined(__srv4__)
#  define PLATFORM_SOLARIS
# else
#  define PLATFORM_SUNOS4
# endif
#endif
#if (defined(_AIX) || defined(__xlC__)) && !defined(_AIX4)
# define PLATFORM_AIX_V3
#endif

#if defined(PLATFORM_SUNOS4) || defined(PLATFORM_AIX_V3) || defined(__BEOS__)
#error "O_NONBLOCK does not work on this platform"
#endif
  int socket;
  int flags = fcntl(socket, F_SETFL, flags | O_NONBLOCK);
],[
dnl the O_NONBLOCK test was fine
nonblock="O_NONBLOCK"
AC_DEFINE(HAVE_O_NONBLOCK, 1, [use O_NONBLOCK for non-blocking sockets])
],[
dnl the code was bad, try a different program now, test 2

  AC_TRY_COMPILE([
/* headers for FIONBIO test */
#include <unistd.h>
#include <stropts.h>
],[
/* FIONBIO source test (old-style unix) */
 int socket;
 int flags = ioctl(socket, FIONBIO, &flags);
],[
dnl FIONBIO test was good
nonblock="FIONBIO"
AC_DEFINE(HAVE_FIONBIO, 1, [use FIONBIO for non-blocking sockets])
],[
dnl FIONBIO test was also bad
dnl the code was bad, try a different program now, test 3

  AC_TRY_COMPILE([
/* headers for ioctlsocket test (cygwin?) */
#include <windows.h>
],[
/* ioctlsocket source code */
 int socket;
 unsigned long flags = ioctlsocket(socket, FIONBIO, &flags);
],[
dnl ioctlsocket test was good
nonblock="ioctlsocket"
AC_DEFINE(HAVE_IOCTLSOCKET, 1, [use ioctlsocket() for non-blocking sockets])
],[
dnl ioctlsocket didnt compile!, go to test 4

  AC_TRY_LINK([
/* headers for IoctlSocket test (Amiga?) */
#include <sys/ioctl.h>
],[
/* IoctlSocket source code */
 int socket;
 int flags = IoctlSocket(socket, FIONBIO, (long)1);
],[
dnl ioctlsocket test was good
nonblock="IoctlSocket"
AC_DEFINE(HAVE_IOCTLSOCKET_CASE, 1, [use Ioctlsocket() for non-blocking sockets])
],[
dnl Ioctlsocket didnt compile, do test 5!
  AC_TRY_COMPILE([
/* headers for SO_NONBLOCK test (BeOS) */
#include <socket.h>
],[
/* SO_NONBLOCK source code */
 long b = 1;
 int socket;
 int flags = setsockopt(socket, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
],[
dnl the SO_NONBLOCK test was good
nonblock="SO_NONBLOCK"
AC_DEFINE(HAVE_SO_NONBLOCK, 1, [use SO_NONBLOCK for non-blocking sockets])
],[
dnl test 5 didnt compile!
nonblock="nada"
AC_DEFINE(HAVE_DISABLED_NONBLOCKING, 1, [disabled non-blocking sockets])
])
dnl end of fifth test

])
dnl end of forth test

])
dnl end of third test

])
dnl end of second test

])
dnl end of non-blocking try-compile test
  AC_MSG_RESULT($nonblock)

  if test "$nonblock" = "nada"; then
    AC_MSG_WARN([non-block sockets disabled])
  fi
])

dnl We create a function for detecting which compiler we use and then set as
dnl pendantic compiler options as possible for that particular compiler. The
dnl options are only used for debug-builds.

dnl This is a copy of the original found in curl's configure script. Don't
dnl modify this one, edit the one in curl and copy it back here when that one
dnl is changed.

AC_DEFUN([CURL_CC_DEBUG_OPTS],
[
    if test "$GCC" = "yes"; then

       dnl figure out gcc version!
       AC_MSG_CHECKING([gcc version])
       gccver=`$CC -dumpversion`
       num1=`echo $gccver | cut -d . -f1`
       num2=`echo $gccver | cut -d . -f2`
       gccnum=`(expr $num1 "*" 100 + $num2) 2>/dev/null`
       AC_MSG_RESULT($gccver)

       AC_MSG_CHECKING([if this is icc in disguise])
       AC_EGREP_CPP([^__INTEL_COMPILER], [__INTEL_COMPILER],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         ICC="no"
         AC_MSG_RESULT([no]),
         dnl the text was not found, it was replaced by the cpp
         ICC="yes"
         AC_MSG_RESULT([yes])
       )

       if test "$ICC" = "yes"; then
         dnl this is icc, not gcc.

         dnl ICC warnings we ignore:
         dnl * 279 warns on static conditions in while expressions
         dnl * 269 warns on our "%Od" printf formatters for curl_off_t output:
         dnl   "invalid format string conversion"

         WARN="-wd279,269"

         if test "$gccnum" -gt "600"; then
            dnl icc 6.0 and older doesn't have the -Wall flag
            WARN="-Wall $WARN"
         fi
       else dnl $ICC = yes
         dnl 
         WARN="-W -Wall -Wwrite-strings -pedantic -Wno-long-long -Wundef -Wpointer-arith -Wnested-externs -Winline -Wmissing-declarations -Wmissing-prototypes -Wsign-compare"

         dnl -Wcast-align is a bit too annoying ;-)

         if test "$gccnum" -ge "296"; then
           dnl gcc 2.96 or later
           WARN="$WARN -Wfloat-equal"

           if test "$gccnum" -gt "296"; then
             dnl this option does not exist in 2.96
             WARN="$WARN -Wno-format-nonliteral"
           fi

           dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
           dnl on i686-Linux as it gives us heaps with false positives
           if test "$gccnum" -ge "303"; then
             dnl gcc 3.3 and later
             WARN="$WARN -Wendif-labels -Wstrict-prototypes"
           fi
         fi

         for flag in $CPPFLAGS; do
           case "$flag" in
            -I*)
              dnl include path
              add=`echo $flag | sed 's/^-I/-isystem /g'`
              WARN="$WARN $add"
              ;;
           esac
         done

       fi dnl $ICC = no

       CFLAGS="$CFLAGS $WARN"

    fi dnl $GCC = yes

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

]) dnl end of AC_DEFUN()


dnl This macro determines if the specified struct exists in the specified file
dnl Syntax:
dnl CARES_CHECK_STRUCT(headers, struct name, if found, [if not found])

AC_DEFUN([CARES_CHECK_STRUCT], [
  AC_MSG_CHECKING([for struct $2])
  AC_TRY_COMPILE([$1], 
    [
      struct $2 struct_instance;
    ], ac_struct="yes", ac_found="no")
  if test "$ac_struct" = "yes" ; then
    AC_MSG_RESULT(yes)
    $3
  else
    AC_MSG_RESULT(no)
    $4
  fi
])

dnl This macro determines if the specified constant exists in the specified file
dnl Syntax:
dnl CARES_CHECK_CONSTANT(headers, constant name, if found, [if not found])

AC_DEFUN([CARES_CHECK_CONSTANT], [
  AC_MSG_CHECKING([for $2])
  AC_EGREP_CPP(VARIABLEWASDEFINED,
   [
      $1

      #ifdef $2
        VARIABLEWASDEFINED
      #else
        NJET
      #endif
    ], ac_constant="yes", ac_constant="no"
  )
  if test "$ac_constant" = "yes" ; then
    AC_MSG_RESULT(yes)
    $3
  else
    AC_MSG_RESULT(no)
    $4
  fi
])


