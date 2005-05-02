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

dnl Check for struct sockaddr_storage. Most IPv6-enabled hosts have it, but
dnl AIX 4.3 is one known exception.
AC_DEFUN([TYPE_SOCKADDR_STORAGE],
[
   AC_CHECK_TYPE([struct sockaddr_storage],
        AC_DEFINE(HAVE_STRUCT_SOCKADDR_STORAGE, 1,
                  [if struct sockaddr_storage is defined]), ,
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
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
   ])

])

dnl Check for socklen_t: historically on BSD it is an int, and in
dnl POSIX 1g it is a type of its own, but some platforms use different
dnl types for the argument to getsockopt, getpeername, etc.  So we
dnl have to test to find something that will work.
AC_DEFUN([TYPE_SOCKLEN_T],
[
   AC_CHECK_TYPE([socklen_t], ,[
      AC_MSG_CHECKING([for socklen_t equivalent])
      AC_CACHE_VAL([curl_cv_socklen_t_equiv],
      [
         # Systems have either "struct sockaddr *" or
         # "void *" as the second argument to getpeername
         curl_cv_socklen_t_equiv=
         for arg2 in "struct sockaddr" void; do
            for t in int size_t unsigned long "unsigned long"; do
               AC_TRY_COMPILE([
                  #ifdef HAVE_SYS_TYPES_H
                  #include <sys/types.h>
                  #endif
                  #ifdef HAVE_SYS_SOCKET_H
                  #include <sys/socket.h>
                  #endif

                  int getpeername (int, $arg2 *, $t *);
               ],[
                  $t len;
                  getpeername(0,0,&len);
               ],[
                  curl_cv_socklen_t_equiv="$t"
                  break
               ])
            done
         done

         if test "x$curl_cv_socklen_t_equiv" = x; then
            AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
         fi
      ])
      AC_MSG_RESULT($curl_cv_socklen_t_equiv)
      AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
			[type to use in place of socklen_t if not defined])],
      [#include <sys/types.h>
#include <sys/socket.h>])
])

dnl Check for in_addr_t: it is used to receive the return code of inet_addr()
dnl and a few other things. If not found, we set it to unsigned int, as even
dnl 64-bit implementations use to set it to a 32-bit type.
AC_DEFUN([TYPE_IN_ADDR_T],
[
   AC_CHECK_TYPE([in_addr_t], ,[
      AC_MSG_CHECKING([for in_addr_t equivalent])
      AC_CACHE_VAL([curl_cv_in_addr_t_equiv],
      [
         curl_cv_in_addr_t_equiv=
         for t in "unsigned long" int size_t unsigned long; do
            AC_TRY_COMPILE([
               #ifdef HAVE_SYS_TYPES_H
               #include <sys/types.h>
               #endif
               #ifdef HAVE_SYS_SOCKET_H
               #include <sys/socket.h>
               #endif
               #ifdef HAVE_ARPA_INET_H
               #include <arpa/inet.h>
               #endif
            ],[
               $t data = inet_addr ("1.2.3.4");
            ],[
               curl_cv_in_addr_t_equiv="$t"
               break
            ])
         done

         if test "x$curl_cv_in_addr_t_equiv" = x; then
            AC_MSG_ERROR([Cannot find a type to use in place of in_addr_t])
         fi
      ])
      AC_MSG_RESULT($curl_cv_in_addr_t_equiv)
      AC_DEFINE_UNQUOTED(in_addr_t, $curl_cv_in_addr_t_equiv,
			[type to use in place of in_addr_t if not defined])],
      [#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>])
])

dnl ************************************************************
dnl check for "localhost", if it doesn't exist, we can't do the
dnl gethostbyname_r tests!
dnl 

AC_DEFUN([CURL_CHECK_WORKING_RESOLVER],[
AC_MSG_CHECKING([if "localhost" resolves])
AC_TRY_RUN([
#include <string.h>
#include <sys/types.h>
#include <netdb.h>

int
main () {
struct hostent *h;
h = gethostbyname("localhost");
exit (h == NULL ? 1 : 0); }],[
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_ERROR([can't figure out gethostbyname_r() since localhost doesn't resolve])

      ]
)
])

dnl ************************************************************
dnl check for working getaddrinfo() that works with AI_NUMERICHOST
dnl
AC_DEFUN([CURL_CHECK_WORKING_GETADDRINFO],[
  AC_CACHE_CHECK(for working getaddrinfo, ac_cv_working_getaddrinfo,[
  AC_TRY_RUN( [
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(void)
{
    struct addrinfo hints, *ai;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo("127.0.0.1", "8080", &hints, &ai);
    if (error) {
        return 1;
    }
    return 0;
}
],[
  ac_cv_working_getaddrinfo="yes"
],[
  ac_cv_working_getaddrinfo="no"
],[
  ac_cv_working_getaddrinfo="yes"
])])
if test "$ac_cv_working_getaddrinfo" = "yes"; then
  AC_DEFINE(HAVE_GETADDRINFO, 1, [Define if getaddrinfo exists and works])
  AC_DEFINE(ENABLE_IPV6, 1, [Define if you want to enable IPv6 support])

  IPV6_ENABLED=1
  AC_SUBST(IPV6_ENABLED)
fi
])

dnl ************************************************************
dnl check for working NI_WITHSCOPEID in getnameinfo()
dnl
AC_DEFUN([CURL_CHECK_NI_WITHSCOPEID],[
  AC_CACHE_CHECK(for working NI_WITHSCOPEID, ac_cv_working_ni_withscopeid,[

 AC_RUN_IFELSE([[
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
int main()
{
#ifdef NI_WITHSCOPEID
   struct sockaddr_storage ss;
   int sslen = sizeof(ss);
   int rc;
   char hbuf[NI_MAXHOST];
   int fd = socket(AF_INET6, SOCK_STREAM, 0);
   if(fd < 0) {
     perror("socket()");
     return 1; /* couldn't create socket of either kind */
   }

   rc = getsockname(fd, (struct sockaddr *)&ss, &sslen);
   if(rc) {
     perror("getsockname()");
     return 2;
   }

   rc = getnameinfo((struct sockaddr *)&ss, sslen, hbuf, sizeof(hbuf),
                     NULL, 0,
                     NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID);

   if(rc) {
     printf("rc = %s\n", gai_strerror(rc));
     return 3;
   }

   return 0; /* everything works fine, use NI_WITHSCOPEID! */
#else
   return 4; /* we don't seem to have the definition, don't use it */
#endif
}
]],
dnl program worked:
[ ac_cv_working_ni_withscopeid="yes" ],
dnl program failed:
[ ac_cv_working_ni_withscopeid="no" ],
dnl we cross-compile, check the headers using the preprocessor
[

 AC_EGREP_CPP(WORKS,
[
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef NI_WITHSCOPEID
WORKS
#endif
],
  ac_cv_working_ni_withscopeid="yes",
  ac_cv_working_ni_withscopeid="no" )

 ]
) dnl end of AC_RUN_IFELSE

]) dnl end of AC_CACHE_CHECK

if test "$ac_cv_working_ni_withscopeid" = "yes"; then
  AC_DEFINE(HAVE_NI_WITHSCOPEID, 1,
            [Define if NI_WITHSCOPEID exists and works])
fi

]) dnl end of AC_DEFUN


AC_DEFUN([CURL_CHECK_LOCALTIME_R],
[
  dnl check for localtime_r
  AC_CHECK_FUNCS(localtime_r,[
    AC_MSG_CHECKING(whether localtime_r is declared)
    AC_EGREP_CPP(localtime_r,[
#include <time.h>],[
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether localtime_r with -D_REENTRANT is declared)
      AC_EGREP_CPP(localtime_r,[
#define _REENTRANT
#include <time.h>],[
	AC_DEFINE(NEED_REENTRANT)
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no))])])
])

dnl
dnl This function checks for strerror_r(). If it isn't found at first, it
dnl retries with _THREAD_SAFE defined, as that is what AIX seems to require
dnl in order to find this function.
dnl
dnl If the function is found, it will then proceed to check how the function
dnl actually works: glibc-style or POSIX-style.
dnl
dnl glibc:
dnl      char *strerror_r(int errnum, char *buf, size_t n);
dnl  
dnl  What this one does is to return the error string (no surprises there),
dnl  but it doesn't usually copy anything into buf!  The 'buf' and 'n'
dnl  parameters are only meant as an optional working area, in case strerror_r
dnl  needs it.  A quick test on a few systems shows that it's generally not
dnl  touched at all.
dnl
dnl POSIX:
dnl      int strerror_r(int errnum, char *buf, size_t n);
dnl
AC_DEFUN([CURL_CHECK_STRERROR_R],
[
  dnl determine of strerror_r is present
  AC_CHECK_FUNCS(strerror_r,[
    AC_MSG_CHECKING(whether strerror_r is declared)
    AC_EGREP_CPP(strerror_r,[
#include <string.h>],[
      strerror_r="yes"
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether strerror_r with -D_THREAD_SAFE is declared)
      AC_EGREP_CPP(strerror_r,[
#define _THREAD_SAFE
#include <string.h>],[
        strerror_r="yes"
	CPPFLAGS="-D_THREAD_SAFE $CPPFLAGS"
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no))])])

  if test "x$strerror_r" = "xyes"; then

    dnl check if strerror_r is properly declared in the headers
    AC_CHECK_DECL(strerror_r, ,
     AC_DEFINE(HAVE_NO_STRERROR_R_DECL, 1, [we have no strerror_r() proto])
,
[#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
])

    dnl determine if this strerror_r() is glibc or POSIX
    AC_MSG_CHECKING([for a glibc strerror_r API])
    AC_TRY_RUN([
#include <string.h>
#include <errno.h>
int
main () {
  char buffer[1024]; /* big enough to play with */
  char *string =
    strerror_r(EACCES, buffer, sizeof(buffer));
    /* this should've returned a string */
    if(!string || !string[0])
      return 99;
    return 0;
}
],
    GLIBC_STRERROR_R="1"
    AC_DEFINE(HAVE_GLIBC_STRERROR_R, 1, [we have a glibc-style strerror_r()])
    AC_MSG_RESULT([yes]),
    AC_MSG_RESULT([no]),
    dnl cross-compiling!
    AC_MSG_NOTICE([cannot determine strerror_r() style: edit lib/config.h manually!])
    )

    if test -z "$GLIBC_STRERROR_R"; then

      AC_MSG_CHECKING([for a POSIX strerror_r API])
      AC_TRY_RUN([
#include <string.h>
#include <errno.h>
int
main () {
  char buffer[1024]; /* big enough to play with */
  int error =
    strerror_r(EACCES, buffer, sizeof(buffer));
    /* This should've returned zero, and written an error string in the
       buffer.*/
    if(!buffer[0] || error)
      return 99;
    return 0;
}
],
      AC_DEFINE(HAVE_POSIX_STRERROR_R, 1, [we have a POSIX-style strerror_r()])
      AC_MSG_RESULT([yes]),
      AC_MSG_RESULT([no]) ,
      dnl cross-compiling!
      AC_MSG_NOTICE([cannot determine strerror_r() style: edit lib/config.h manually!])
    )

    fi dnl if not using glibc API

  fi dnl we have a strerror_r

])

AC_DEFUN([CURL_CHECK_INET_NTOA_R],
[
  dnl determine if function definition for inet_ntoa_r exists.
  AC_CHECK_FUNCS(inet_ntoa_r,[
    AC_MSG_CHECKING(whether inet_ntoa_r is declared)
    AC_EGREP_CPP(inet_ntoa_r,[
#include <arpa/inet.h>],[
      AC_DEFINE(HAVE_INET_NTOA_R_DECL, 1, [inet_ntoa_r() is declared])
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether inet_ntoa_r with -D_REENTRANT is declared)
      AC_EGREP_CPP(inet_ntoa_r,[
#define _REENTRANT
#include <arpa/inet.h>],[
	AC_DEFINE(HAVE_INET_NTOA_R_DECL, 1, [inet_ntoa_r() is declared])
	AC_DEFINE(NEED_REENTRANT, 1, [need REENTRANT defined])
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no))])])
])

AC_DEFUN([CURL_CHECK_GETHOSTBYADDR_R],
[
  dnl check for number of arguments to gethostbyaddr_r. it might take
  dnl either 5, 7, or 8 arguments.
  AC_CHECK_FUNCS(gethostbyaddr_r,[
    AC_MSG_CHECKING(if gethostbyaddr_r takes 5 arguments)
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
rc = gethostbyaddr_r(address, length, type, &h, &hdata);],[
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_5, 1, [gethostbyaddr_r() takes 5 args])
      ac_cv_gethostbyaddr_args=5],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(if gethostbyaddr_r with -D_REENTRANT takes 5 arguments)
      AC_TRY_COMPILE([
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
rc = gethostbyaddr_r(address, length, type, &h, &hdata);],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_GETHOSTBYADDR_R_5, 1, [gethostbyaddr_r() takes 5 args])
	AC_DEFINE(NEED_REENTRANT, 1, [need REENTRANT])
	ac_cv_gethostbyaddr_args=5],[
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING(if gethostbyaddr_r takes 7 arguments)
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;

hp = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &h_errnop);],[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_GETHOSTBYADDR_R_7, 1, [gethostbyaddr_r() takes 7 args] )
	  ac_cv_gethostbyaddr_args=7],[
	  AC_MSG_RESULT(no)
	  AC_MSG_CHECKING(if gethostbyaddr_r takes 8 arguments)
	  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;
int rc;

rc = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &hp, &h_errnop);],[
	    AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_GETHOSTBYADDR_R_8, 1, [gethostbyaddr_r() takes 8 args])
	    ac_cv_gethostbyaddr_args=8],[
	    AC_MSG_RESULT(no)
	    have_missing_r_funcs="$have_missing_r_funcs gethostbyaddr_r"])])])])])
])

AC_DEFUN([CURL_CHECK_GETHOSTBYNAME_R],
[
  dnl check for number of arguments to gethostbyname_r. it might take
  dnl either 3, 5, or 6 arguments.
  AC_CHECK_FUNCS(gethostbyname_r,[
    AC_MSG_CHECKING([if gethostbyname_r takes 3 arguments])
    AC_TRY_COMPILE([
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
gethostbyname_r(const char *, struct hostent *, struct hostent_data *);],[
struct hostent_data data;
gethostbyname_r(NULL, NULL, NULL);],[
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_3, 1, [gethostbyname_r() takes 3 args])
      ac_cv_gethostbyname_args=3],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING([if gethostbyname_r with -D_REENTRANT takes 3 arguments])
      AC_TRY_COMPILE([
#define _REENTRANT

#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
gethostbyname_r(const char *,struct hostent *, struct hostent_data *);],[
struct hostent_data data;
gethostbyname_r(NULL, NULL, NULL);],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_GETHOSTBYNAME_R_3, 1, [gethostbyname_r() takes 3 args])
	AC_DEFINE(NEED_REENTRANT, 1, [needs REENTRANT])
	ac_cv_gethostbyname_args=3],[
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([if gethostbyname_r takes 5 arguments])
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

struct hostent *
gethostbyname_r(const char *, struct hostent *, char *, int, int *);],[
gethostbyname_r(NULL, NULL, NULL, 0, NULL);],[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_GETHOSTBYNAME_R_5, 1, [gethostbyname_r() takes 5 args])
          ac_cv_gethostbyname_args=5],[
	  AC_MSG_RESULT(no)
	  AC_MSG_CHECKING([if gethostbyname_r takes 6 arguments])
	  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
gethostbyname_r(const char *, struct hostent *, char *, size_t,
struct hostent **, int *);],[
gethostbyname_r(NULL, NULL, NULL, 0, NULL, NULL);],[
	    AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_GETHOSTBYNAME_R_6, 1, [gethostbyname_r() takes 6 args])
            ac_cv_gethostbyname_args=6],[
	    AC_MSG_RESULT(no)
	    have_missing_r_funcs="$have_missing_r_funcs gethostbyname_r"],
	    [ac_cv_gethostbyname_args=0])],
	  [ac_cv_gethostbyname_args=0])],
	[ac_cv_gethostbyname_args=0])],
      [ac_cv_gethostbyname_args=0])])

if test "$ac_cv_func_gethostbyname_r" = "yes"; then
  if test "$ac_cv_gethostbyname_args" = "0"; then
    dnl there's a gethostbyname_r() function, but we don't know how
    dnl many arguments it wants!
    AC_MSG_ERROR([couldn't figure out how to use gethostbyname_r()])
  fi
fi
])

dnl We create a function for detecting which compiler we use and then set as
dnl pendantic compiler options as possible for that particular compiler. The
dnl options are only used for debug-builds.

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
         dnl * 269 warns on our "%Od" printf formatters for curl_off_t output:
         dnl   "invalid format string conversion"
         dnl * 279 warns on static conditions in while expressions
         dnl * 981 warns on "operands are evaluated in unspecified order"
         dnl * 1418 "external definition with no prior declaration"
         dnl * 1419 warns on "external declaration in primary source file"
         dnl   which we know and do on purpose.

         WARN="-wd279,269,981,1418,1419"

         if test "$gccnum" -gt "600"; then
            dnl icc 6.0 and older doesn't have the -Wall flag
            WARN="-Wall $WARN"
         fi
       else dnl $ICC = yes
         dnl this is a set of options we believe *ALL* gcc versions support:
         WARN="-W -Wall -Wwrite-strings -pedantic -Wpointer-arith -Wnested-externs -Winline -Wmissing-prototypes"

         dnl -Wcast-align is a bit too annoying on all gcc versions ;-)

         if test "$gccnum" -ge "207"; then
           dnl gcc 2.7 or later
           WARN="$WARN -Wmissing-declarations"
         fi

         if test "$gccnum" -gt "295"; then
           dnl only if the compiler is newer than 2.95 since we got lots of
           dnl "`_POSIX_C_SOURCE' is not defined" in system headers with
           dnl gcc 2.95.4 on FreeBSD 4.9!
           WARN="$WARN -Wundef -Wno-long-long -Wsign-compare"
         fi

         if test "$gccnum" -ge "296"; then
           dnl gcc 2.96 or later
           WARN="$WARN -Wfloat-equal"
         fi

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

         if test "$gccnum" -ge "304"; then
           # try -Wunreachable-code on gcc 3.4
           WARN="$WARN -Wunreachable-code"
         fi

         for flag in $CPPFLAGS; do
           case "$flag" in
            -I*)
              dnl Include path, provide a -isystem option for the same dir
              dnl to prevent warnings in those dirs. The -isystem was not very
              dnl reliable on earlier gcc versions.
              add=`echo $flag | sed 's/^-I/-isystem /g'`
              WARN="$WARN $add"
              ;;
           esac
         done

       fi dnl $ICC = no

       CFLAGS="$CFLAGS $WARN"

      AC_MSG_NOTICE([Added this set of compiler options: $WARN])

    else dnl $GCC = yes

      AC_MSG_NOTICE([Added no extra compiler options])

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


dnl Determine the name of the library to pass to dlopen() based on the name
dnl that would normally be given to AC_CHECK_LIB.  The preprocessor symbol
dnl given is set to the quoted library file name. 
dnl The standard dynamic library file name is first generated, based on the
dnl current system type, then a search is performed for that file on the
dnl standard dynamic library path.  If it is a symbolic link, the destination
dnl of the link is used as the file name, after stripping off any minor
dnl version numbers. If a library file can't be found, a guess is made.
dnl This macro assumes AC_PROG_LIBTOOL has been called and requires perl
dnl to be available in the PATH, or $PERL to be set to its location.
dnl
dnl CURL_DLLIB_NAME(VARIABLE, library_name)
dnl e.g. CURL_DLLIB_NAME(LDAP_NAME, ldap) on a Linux system might result
dnl in LDAP_NAME holding the string "libldap.so.2".

AC_DEFUN([CURL_DLLIB_NAME],
[
AC_MSG_CHECKING([name of dynamic library $2])
dnl The shared library extension variable name changes from version to
dnl version of libtool.  Try a few names then just set one statically.
test -z "$shared_ext" && shared_ext="$shrext_cmds"
test -z "$shared_ext" && shared_ext="$shrext"
test -z "$shared_ext" && shared_ext=".so"

dnl Create the library link name of the correct form for this platform
LIBNAME_LINK_SPEC=`echo "$library_names_spec" | $SED 's/^.* //'`
DLGUESSLIB=`name=$2 eval echo "$libname_spec"`
DLGUESSFILE=`libname="$DLGUESSLIB" release="" major="" versuffix="" eval echo "$LIBNAME_LINK_SPEC"`

dnl Synthesize a likely dynamic library name in case we can't find an actual one
SO_NAME_SPEC="$soname_spec"
dnl soname_spec undefined when identical to the 1st entry in library_names_spec
test -z "$SO_NAME_SPEC" && SO_NAME_SPEC=`echo "$library_names_spec" | $SED 's/ .*$//'`
DLGUESSSOFILE=`libname="$DLGUESSLIB" release="" major="" versuffix="" eval echo "$SO_NAME_SPEC"`

if test "$cross_compiling" = yes; then
  dnl Can't look at filesystem when cross-compiling
  AC_DEFINE_UNQUOTED($1, "$DLGUESSSOFILE", [$2 dynamic library file])
  AC_MSG_RESULT([$DLGUESSSOFILE (guess while cross-compiling)])
else

  DLFOUNDFILE=""
  if test "$sys_lib_dlsearch_path_spec" ; then
    dnl Search for the link library name and see what it points to.
    for direc in $sys_lib_dlsearch_path_spec ; do
      DLTRYFILE="$direc/$DLGUESSFILE"
      dnl Find where the symbolic link for this name points
      changequote(<<, >>)dnl
      <<
      DLFOUNDFILE=`${PERL:-perl} -e 'use File::Basename; (basename(readlink($ARGV[0])) =~ /^(.*[^\d]\.\d+)[\d\.]*$/ && print ${1}) || exit 1;' "$DLTRYFILE" 2>&5`
      >>
      changequote([, ])dnl
      if test "$?" -eq "0"; then
        dnl Found the file link
        break
      fi
    done
  fi

  if test -z "$DLFOUNDFILE" ; then
    dnl Couldn't find a link library, so guess at a name.
    DLFOUNDFILE="$DLGUESSSOFILE"
  fi

  AC_DEFINE_UNQUOTED($1, "$DLFOUNDFILE", [$2 dynamic library file])
  AC_MSG_RESULT($DLFOUNDFILE)
fi
])
