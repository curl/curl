dnl Check for how to set a socket to non-blocking state. There seems to exist
dnl four known different ways, with the one used almost everywhere being POSIX
dnl and XPG3, while the other different ways for different systems (old BSD,
dnl Windows and Amiga).
dnl
dnl There are two known platforms (AIX 3.x and SunOS 4.1.x) where the
dnl O_NONBLOCK define is found but does not work. This condition is attempted
dnl to get caught in this script by using an excessive number of #ifdefs...
dnl
AC_DEFUN(CURL_CHECK_NONBLOCKING_SOCKET,
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

#if defined(PLATFORM_SUNOS4) || defined(PLATFORM_AIX_V3)
#error "O_NONBLOCK does not work on this platform"
#endif
  int socket;
  int flags = fcntl(socket, F_SETFL, flags | O_NONBLOCK);
],[
dnl the O_NONBLOCK test was fine
nonblock="O_NONBLOCK"
AC_DEFINE(HAVE_O_NONBLOCK)
],[
dnl the code was bad, try a different program now, test 2

  AC_TRY_COMPILE([
/* headers for FIONBIO test */
#include <unistd.h>
#include <stropts.h>
],[
/* FIONBIO source test */
 int flags = ioctl(socket, FIONBIO, &flags);
],[
dnl FIONBIO test was good
nonblock="FIONBIO"
AC_DEFINE(HAVE_FIONBIO)
],[
dnl FIONBIO test was also bad
dnl the code was bad, try a different program now, test 3

  AC_TRY_COMPILE([
/* headers for ioctlsocket test (cygwin?) */
#include <windows.h>
],[
/* ioctlsocket source code */
 int flags = ioctlsocket(socket, FIONBIO, &flags);
],[
dnl ioctlsocket test was good
nonblock="ioctlsocket"
AC_DEFINE(HAVE_IOCTLSOCKET)
],[
dnl ioctlsocket didnt compile!

  AC_TRY_COMPILE([
/* headers for IoctlSocket test (Amiga?) */
#include <sys/ioctl.h>
],[
/* IoctlSocket source code */
 int flags = IoctlSocket(socket, FIONBIO, (long)1);
],[
dnl ioctlsocket test was good
nonblock="IoctlSocket"
AC_DEFINE(HAVE_IOCTLSOCKET_CASE)
],[
dnl ioctlsocket didnt compile!
nonblock="nada"
AC_DEFINE(HAVE_DISABLED_NONBLOCKING)
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
                  #include <sys/types.h>
                  #include <sys/socket.h>

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
         # Systems have either "struct sockaddr *" or
         # "void *" as the second argument to getpeername
         curl_cv_in_addr_t_equiv=
         for t in int size_t unsigned long "unsigned long"; do
            AC_TRY_COMPILE([
               #include <sys/types.h>
               #include <sys/socket.h>
               #include <arpa/inet.h>
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

AC_DEFUN(CURL_CHECK_WORKING_RESOLVER,[
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
dnl check for working getaddrinfo()
dnl
AC_DEFUN(CURL_CHECK_WORKING_GETADDRINFO,[
  AC_CACHE_CHECK(for working getaddrinfo, ac_cv_working_getaddrinfo,[
  AC_TRY_RUN( [
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

void main(void) {
    struct addrinfo hints, *ai;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo("127.0.0.1", "8080", &hints, &ai);
    if (error) {
        exit(1);
    }
    else {
        exit(0);
    }
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


AC_DEFUN(CURL_CHECK_LOCALTIME_R,
[
  dnl check for a few thread-safe functions
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

AC_DEFUN(CURL_CHECK_INET_NTOA_R,
[
  dnl determine if function definition for inet_ntoa_r exists.
  AC_CHECK_FUNCS(inet_ntoa_r,[
    AC_MSG_CHECKING(whether inet_ntoa_r is declared)
    AC_EGREP_CPP(inet_ntoa_r,[
#include <arpa/inet.h>],[
      AC_DEFINE(HAVE_INET_NTOA_R_DECL)
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether inet_ntoa_r with -D_REENTRANT is declared)
      AC_EGREP_CPP(inet_ntoa_r,[
#define _REENTRANT
#include <arpa/inet.h>],[
	AC_DEFINE(HAVE_INET_NTOA_R_DECL)
	AC_DEFINE(NEED_REENTRANT)
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no))])])
])

AC_DEFUN(CURL_CHECK_GETHOSTBYADDR_R,
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
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_5)
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
	AC_DEFINE(HAVE_GETHOSTBYADDR_R_5)
	AC_DEFINE(NEED_REENTRANT)
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
	  AC_DEFINE(HAVE_GETHOSTBYADDR_R_7)
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
	    AC_DEFINE(HAVE_GETHOSTBYADDR_R_8)
	    ac_cv_gethostbyaddr_args=8],[
	    AC_MSG_RESULT(no)
	    have_missing_r_funcs="$have_missing_r_funcs gethostbyaddr_r"])])])])])
])

AC_DEFUN(CURL_CHECK_GETHOSTBYNAME_R,
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
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_3)
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
	AC_DEFINE(HAVE_GETHOSTBYNAME_R_3)
	AC_DEFINE(NEED_REENTRANT)
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
	  AC_DEFINE(HAVE_GETHOSTBYNAME_R_5)
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
	    AC_DEFINE(HAVE_GETHOSTBYNAME_R_6)
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
