#ifdef TIME_WITH_SYS_TIME
/* Time with sys/time test */

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

int
main ()
{
if ((struct tm *) 0)
return 0;
  ;
  return 0;
}

#endif

#ifdef HAVE_FCNTL_O_NONBLOCK

/* headers for FCNTL_O_NONBLOCK test */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
/* */
#if defined(sun) || defined(__sun__) || \
    defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# if defined(__SVR4) || defined(__srv4__)
#  define PLATFORM_SOLARIS
# else
#  define PLATFORM_SUNOS4
# endif
#endif
#if (defined(_AIX) || defined(__xlC__)) && !defined(_AIX41)
# define PLATFORM_AIX_V3
#endif
/* */
#if defined(PLATFORM_SUNOS4) || defined(PLATFORM_AIX_V3) || defined(__BEOS__)
#error "O_NONBLOCK does not work on this platform"
#endif

int
main ()
{
      /* O_NONBLOCK source test */
      int flags = 0;
      if(0 != fcntl(0, F_SETFL, flags | O_NONBLOCK))
          return 1;
      return 0;
}
#endif

#ifdef HAVE_GETHOSTBYADDR_R_5
#include <sys/types.h>
#include <netdb.h>
int
main ()
{

char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
#ifndef gethostbyaddr_r
  (void)gethostbyaddr_r;
#endif
rc = gethostbyaddr_r(address, length, type, &h, &hdata);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYADDR_R_5_REENTRANT
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
int
main ()
{

char * address;
int length;q
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
#ifndef gethostbyaddr_r
  (void)gethostbyaddr_r;
#endif
rc = gethostbyaddr_r(address, length, type, &h, &hdata);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYADDR_R_7
#include <sys/types.h>
#include <netdb.h>
int
main ()
{

char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;

#ifndef gethostbyaddr_r
  (void)gethostbyaddr_r;
#endif
hp = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &h_errnop);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYADDR_R_7_REENTRANT
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
int
main ()
{

char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;

#ifndef gethostbyaddr_r
  (void)gethostbyaddr_r;
#endif
hp = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &h_errnop);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYADDR_R_8
#include <sys/types.h>
#include <netdb.h>
int
main ()
{

char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;
int rc;

#ifndef gethostbyaddr_r
  (void)gethostbyaddr_r;
#endif
rc = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &hp, &h_errnop);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYADDR_R_8_REENTRANT
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
int
main ()
{

char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;
int rc;

#ifndef gethostbyaddr_r
  (void)gethostbyaddr_r;
#endif
rc = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &hp, &h_errnop);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYNAME_R_3
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
main ()
{

struct hostent_data data;
#ifndef gethostbyname_r
  (void)gethostbyname_r;
#endif
gethostbyname_r(NULL, NULL, NULL);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYNAME_R_3_REENTRANT
#define _REENTRANT
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
main ()
{

struct hostent_data data;
#ifndef gethostbyname_r
  (void)gethostbyname_r;
#endif
gethostbyname_r(NULL, NULL, NULL);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYNAME_R_5
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
main ()
{
#ifndef gethostbyname_r
  (void)gethostbyname_r;
#endif
gethostbyname_r(NULL, NULL, NULL, 0, NULL);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYNAME_R_5_REENTRANT
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
main ()
{

#ifndef gethostbyname_r
  (void)gethostbyname_r;
#endif
gethostbyname_r(NULL, NULL, NULL, 0, NULL);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYNAME_R_6
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
main ()
{

#ifndef gethostbyname_r
  (void)gethostbyname_r;
#endif
gethostbyname_r(NULL, NULL, NULL, 0, NULL, NULL);
  ;
  return 0;
}
#endif
#ifdef HAVE_GETHOSTBYNAME_R_6_REENTRANT
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
main ()
{

#ifndef gethostbyname_r
  (void)gethostbyname_r;
#endif
gethostbyname_r(NULL, NULL, NULL, 0, NULL, NULL);
  ;
  return 0;
}
#endif
#ifdef HAVE_SOCKLEN_T
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif
int
main ()
{
if ((socklen_t *) 0)
  return 0;
if (sizeof (socklen_t))
  return 0;
  ;
  return 0;
}
#endif
#ifdef HAVE_IN_ADDR_T
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int
main ()
{
if ((in_addr_t *) 0)
  return 0;
if (sizeof (in_addr_t))
  return 0;
  ;
  return 0;
}
#endif

#ifdef HAVE_BOOL_T
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
int
main ()
{
if (sizeof (bool *) )
  return 0;
  ;
  return 0;
}
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>
int main() { return 0; }
#endif
#ifdef RETSIGTYPE_TEST
#include <sys/types.h>
#include <signal.h>
#ifdef signal
# undef signal
#endif
#ifdef __cplusplus
extern "C" void (*signal (int, void (*)(int)))(int);
#else
void (*signal ()) ();
#endif

int
main ()
{
  return 0;
}
#endif
#ifdef HAVE_INET_NTOA_R_DECL
#include <arpa/inet.h>

typedef void (*func_type)();

int main()
{
#ifndef inet_ntoa_r
  func_type func;
  func = (func_type)inet_ntoa_r;
#endif
  return 0;
}
#endif
#ifdef HAVE_INET_NTOA_R_DECL_REENTRANT
#define _REENTRANT
#include <arpa/inet.h>

typedef void (*func_type)();

int main()
{
#ifndef inet_ntoa_r
  func_type func;
  func = (func_type)&inet_ntoa_r;
#endif
  return 0;
}
#endif
#ifdef HAVE_GETADDRINFO
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(void) {
    struct addrinfo hints, *ai;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
#ifndef getaddrinfo
    (void)getaddrinfo;
#endif
    error = getaddrinfo("127.0.0.1", "8080", &hints, &ai);
    if (error) {
        return 1;
    }
    return 0;
}
#endif
#ifdef HAVE_FILE_OFFSET_BITS
#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif
#define _FILE_OFFSET_BITS 64
#include <sys/types.h>
 /* Check that off_t can represent 2**63 - 1 correctly.
    We can't simply define LARGE_OFF_T to be 9223372036854775807,
    since some C++ compilers masquerading as C compilers
    incorrectly reject 9223372036854775807.  */
#define LARGE_OFF_T (((off_t) 1 << 62) - 1 + ((off_t) 1 << 62))
  int off_t_is_large[(LARGE_OFF_T % 2147483629 == 721
                       && LARGE_OFF_T % 2147483647 == 1)
                      ? 1 : -1];
int main () { ; return 0; }
#endif
#ifdef HAVE_IOCTLSOCKET
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif

int
main ()
{

/* ioctlsocket source code */
 int socket;
 unsigned long flags = ioctlsocket(socket, FIONBIO, &flags);

  ;
  return 0;
}

#endif
#ifdef HAVE_IOCTLSOCKET_CAMEL
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif

int
main ()
{

/* IoctlSocket source code */
    if(0 != IoctlSocket(0, 0, 0))
      return 1;
  ;
  return 0;
}
#endif
#ifdef HAVE_IOCTLSOCKET_CAMEL_FIONBIO
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif

int
main ()
{

/* IoctlSocket source code */
        long flags = 0;
        if(0 != ioctlsocket(0, FIONBIO, &flags))
          return 1;
  ;
  return 0;
}
#endif
#ifdef HAVE_IOCTLSOCKET_FIONBIO
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif

int
main ()
{

        int flags = 0;
        if(0 != ioctlsocket(0, FIONBIO, &flags))
          return 1;

  ;
  return 0;
}
#endif
#ifdef HAVE_IOCTL_FIONBIO
/* headers for FIONBIO test */
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_STROPTS_H
#  include <stropts.h>
#endif

int
main ()
{

        int flags = 0;
        if(0 != ioctl(0, FIONBIO, &flags))
          return 1;

  ;
  return 0;
}
#endif
#ifdef HAVE_IOCTL_SIOCGIFADDR
/* headers for FIONBIO test */
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_STROPTS_H
#  include <stropts.h>
#endif
#include <net/if.h>

int
main ()
{
        struct ifreq ifr;
        if(0 != ioctl(0, SIOCGIFADDR, &ifr))
          return 1;

  ;
  return 0;
}
#endif
#ifdef HAVE_SETSOCKOPT_SO_NONBLOCK
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
/* includes end */

int
main ()
{
        if(0 != setsockopt(0, SOL_SOCKET, SO_NONBLOCK, 0, 0))
          return 1;
  ;
  return 0;
}
#endif
#ifdef HAVE_GLIBC_STRERROR_R
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
#endif
#ifdef HAVE_POSIX_STRERROR_R
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
#endif
