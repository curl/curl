#ifndef __LIB_CONFIG_WIN32_H
#define __LIB_CONFIG_WIN32_H

/* ================================================================ */
/*    lib/config-win32.h - Hand crafted config file for Windows     */
/* ================================================================ */

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

/* Define if you have the <arpa/inet.h> header file.  */
/* #define HAVE_ARPA_INET_H 1 */

/* Define if you have the <assert.h> header file.  */
#define HAVE_ASSERT_H 1

/* Define if you have the <crypto.h> header file.  */
/* #define HAVE_CRYPTO_H 1 */

/* Define if you have the <err.h> header file.  */
/* #define HAVE_ERR_H 1 */

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
/* #define HAVE_GETOPT_H 1 */

/* Define if you have the <io.h> header file.  */
#define HAVE_IO_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you need the malloc.h header file even with stdlib.h  */
#if !defined(__SALFORDC__) && !defined(__POCC__)
#define NEED_MALLOC_H 1
#endif

/* Define if you have the <netdb.h> header file.  */
/* #define HAVE_NETDB_H 1 */

/* Define if you have the <netinet/in.h> header file.  */
/* #define HAVE_NETINET_IN_H 1 */

/* Define if you have the <process.h> header file.  */
#ifndef __SALFORDC__
#define HAVE_PROCESS_H 1
#endif

/* Define if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define if you have the <sgtty.h> header file.  */
/* #define HAVE_SGTTY_H 1 */

/* Define if you have the <ssl.h> header file.  */
/* #define HAVE_SSL_H 1 */

/* Define if you have the <stdlib.h> header file.  */
#define HAVE_STDLIB_H 1

/* Define if you have the <sys/param.h> header file.  */
/* #define HAVE_SYS_PARAM_H 1 */

/* Define if you have the <sys/select.h> header file.  */
/* #define HAVE_SYS_SELECT_H 1 */

/* Define if you have the <sys/socket.h> header file.  */
/* #define HAVE_SYS_SOCKET_H 1 */

/* Define if you have the <sys/sockio.h> header file.  */
/* #define HAVE_SYS_SOCKIO_H 1 */

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file */
/* #define HAVE_SYS_TIME_H 1 */

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <sys/utime.h> header file.  */
#ifndef __BORLANDC__
#define HAVE_SYS_UTIME_H 1
#endif

/* Define if you have the <termio.h> header file.  */
/* #define HAVE_TERMIO_H 1 */

/* Define if you have the <termios.h> header file.  */
/* #define HAVE_TERMIOS_H 1 */

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <unistd.h> header file.  */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__LCC__) || \
    defined(__POCC__)
#define HAVE_UNISTD_H 1
#endif

/* Define if you have the <windows.h> header file.  */
#define HAVE_WINDOWS_H 1

/* Define if you have the <winsock.h> header file.  */
#define HAVE_WINSOCK_H 1

/* Define if you have the <winsock2.h> header file.  */
#ifndef __SALFORDC__
#define HAVE_WINSOCK2_H 1
#endif

/* Define if you have the <ws2tcpip.h> header file.  */
#ifndef __SALFORDC__
#define HAVE_WS2TCPIP_H 1
#endif

/* ---------------------------------------------------------------- */
/*                        OTHER HEADER INFO                         */
/* ---------------------------------------------------------------- */

/* Define if sig_atomic_t is an available typedef. */
#define HAVE_SIG_ATOMIC_T 1

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
/* #define TIME_WITH_SYS_TIME 1 */

/* ---------------------------------------------------------------- */
/*                             FUNCTIONS                            */
/* ---------------------------------------------------------------- */

/* Define if you have the closesocket function.  */
#define HAVE_CLOSESOCKET 1

/* Define if you don't have vprintf but do have _doprnt.  */
/* #define HAVE_DOPRNT 1 */

/* Define if you have the gethostbyaddr function.  */
#define HAVE_GETHOSTBYADDR 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getpass function.  */
/* #define HAVE_GETPASS 1 */

/* Define if you have the getservbyname function.  */
#define HAVE_GETSERVBYNAME 1

/* Define if you have the getprotobyname function.  */
#define HAVE_GETPROTOBYNAME

/* Define if you have the gettimeofday function.  */
/* #define HAVE_GETTIMEOFDAY 1 */

/* Define if you have the inet_addr function.  */
#define HAVE_INET_ADDR 1

/* Define if you have the ioctlsocket function. */
#define HAVE_IOCTLSOCKET 1

/* Define if you have a working ioctlsocket FIONBIO function. */
#define HAVE_IOCTLSOCKET_FIONBIO 1

/* Define if you have the perror function.  */
#define HAVE_PERROR 1

/* Define if you have the RAND_screen function when using SSL  */
#define HAVE_RAND_SCREEN 1

/* Define if you have the `RAND_status' function when using SSL. */
#define HAVE_RAND_STATUS 1

/* Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function.
   This is present in OpenSSL versions after 0.9.6b */
#define HAVE_CRYPTO_CLEANUP_ALL_EX_DATA 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the setvbuf function.  */
#define HAVE_SETVBUF 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strcasecmp function.  */
/* #define HAVE_STRCASECMP 1 */

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the strftime function.  */
#define HAVE_STRFTIME 1

/* Define if you have the stricmp function. */
#define HAVE_STRICMP 1

/* Define if you have the strncasecmp function. */
/* #define HAVE_STRNCASECMP 1 */

/* Define if you have the strnicmp function. */
#define HAVE_STRNICMP 1

/* Define if you have the strstr function.  */
#define HAVE_STRSTR 1

/* Define if you have the strtoll function.  */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__POCC__)
#define HAVE_STRTOLL 1
#endif

/* Define if you have the tcgetattr function.  */
/* #define HAVE_TCGETATTR 1 */

/* Define if you have the tcsetattr function.  */
/* #define HAVE_TCSETATTR 1 */

/* Define if you have the utime function */
#ifndef __BORLANDC__
#define HAVE_UTIME 1
#endif

/* Define to the type qualifier of arg 1 for getnameinfo. */
#define GETNAMEINFO_QUAL_ARG1 const

/* Define to the type of arg 1 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG1 struct sockaddr *

/* Define to the type of arg 2 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG2 socklen_t

/* Define to the type of args 4 and 6 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG46 DWORD

/* Define to the type of arg 7 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG7 int

/* Define if you have the recv function. */
#define HAVE_RECV 1

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 SOCKET

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 char *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 int

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 int

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV int

/* Define if you have the recvfrom function. */
#define HAVE_RECVFROM 1

/* Define to the type of arg 1 for recvfrom. */
#define RECVFROM_TYPE_ARG1 SOCKET

/* Define to the type pointed by arg 2 for recvfrom. */
#define RECVFROM_TYPE_ARG2 char

/* Define to the type of arg 3 for recvfrom. */
#define RECVFROM_TYPE_ARG3 int

/* Define to the type of arg 4 for recvfrom. */
#define RECVFROM_TYPE_ARG4 int

/* Define to the type pointed by arg 5 for recvfrom. */
#define RECVFROM_TYPE_ARG5 struct sockaddr

/* Define to the type pointed by arg 6 for recvfrom. */
#define RECVFROM_TYPE_ARG6 int

/* Define to the function return type for recvfrom. */
#define RECVFROM_TYPE_RETV int

/* Define if you have the send function. */
#define HAVE_SEND 1

/* Define to the type of arg 1 for send. */
#define SEND_TYPE_ARG1 SOCKET

/* Define to the type qualifier of arg 2 for send. */
#define SEND_QUAL_ARG2 const

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 char *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 int

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV int

/* ---------------------------------------------------------------- */
/*                       TYPEDEF REPLACEMENTS                       */
/* ---------------------------------------------------------------- */

/* Define this if in_addr_t is not an available 'typedefed' type */
#define in_addr_t unsigned long

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define ssize_t if it is not an available 'typedefed' type */
#ifndef _SSIZE_T_DEFINED
#  if (defined(__WATCOMC__) && (__WATCOMC__ >= 1240)) || \
      defined(__POCC__) || \
      defined(__MINGW32__)
#  elif defined(_WIN64)
#    define _SSIZE_T_DEFINED
#    define ssize_t __int64
#  else
#    define _SSIZE_T_DEFINED
#    define ssize_t int
#  endif
#endif

/* ---------------------------------------------------------------- */
/*                            TYPE SIZES                            */
/* ---------------------------------------------------------------- */

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long double', as computed by sizeof. */
#define SIZEOF_LONG_DOUBLE 16

/* The size of `long long', as computed by sizeof. */
/* #define SIZEOF_LONG_LONG 8 */

/* The size of `short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* The size of `size_t', as computed by sizeof. */
#if defined(_WIN64)
#  define SIZEOF_SIZE_T 8
#else
#  define SIZEOF_SIZE_T 4
#endif

/* ---------------------------------------------------------------- */
/*                          STRUCT RELATED                          */
/* ---------------------------------------------------------------- */

/* Define this if you have struct sockaddr_storage */
#ifndef __SALFORDC__
#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#endif

/* Define this if you have struct timeval */
#define HAVE_STRUCT_TIMEVAL 1

/* ---------------------------------------------------------------- */
/*                        Watt-32 tcp/ip SPECIFIC                   */
/* ---------------------------------------------------------------- */

#ifdef USE_WATT32
  #include <tcp.h>
  #undef byte
  #undef word
  #undef USE_WINSOCK
  #undef HAVE_WINSOCK_H
  #undef HAVE_WINSOCK2_H
  #undef HAVE_WS2TCPIP_H
  #define HAVE_GETADDRINFO
  #define HAVE_GETNAMEINFO
  #define HAVE_SYS_IOCTL_H
  #define HAVE_SYS_SOCKET_H
  #define HAVE_NETINET_IN_H
  #define HAVE_NETDB_H
  #define HAVE_ARPA_INET_H
  #define HAVE_FREEADDRINFO
  #define SOCKET int
#endif


/* ---------------------------------------------------------------- */
/*                        COMPILER SPECIFIC                         */
/* ---------------------------------------------------------------- */

/* Undef keyword 'const' if it does not work.  */
/* #undef const */

/* Windows should not have HAVE_GMTIME_R defined */
/* #undef HAVE_GMTIME_R */

/* Define if the compiler supports C99 variadic macro style. */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#define HAVE_VARIADIC_MACROS_C99 1
#endif

/* Define if the compiler supports the 'long long' data type. */
#if defined(__MINGW32__) || defined(__WATCOMC__)
#define HAVE_LONGLONG 1
#endif

/* Define to avoid VS2005 complaining about portable C functions */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_NONSTDC_NO_DEPRECATE 1
#endif

/* VS2005 and later dafault size for time_t is 64-bit, unless */
/* _USE_32BIT_TIME_T has been defined to get a 32-bit time_t. */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#  ifndef _USE_32BIT_TIME_T
#    define SIZEOF_TIME_T 8
#  else
#    define SIZEOF_TIME_T 4
#  endif
#endif

/* Officially, Microsoft's Windows SDK versions 6.X do not support Windows
   2000 as a supported build target. VS2008 default installations provide an
   embedded Windows SDK v6.0A along with the claim that Windows 2000 is a
   valid build target for VS2008. Popular belief is that binaries built using
   Windows SDK versions 6.X and Windows 2000 as a build target are functional */
#if defined(_MSC_VER) && (_MSC_VER >= 1500)
#  define VS2008_MINIMUM_TARGET 0x0500
#endif

/* When no build target is specified VS2008 default build target is Windows
   Vista, which leaves out even Winsows XP. If no build target has been given
   for VS2008 we will target the minimum Officially supported build target,
   which happens to be Windows XP. */
#if defined(_MSC_VER) && (_MSC_VER >= 1500)
#  define VS2008_DEFAULT_TARGET  0x0501
#endif

/* VS2008 default target settings and minimum build target check */
#if defined(_MSC_VER) && (_MSC_VER >= 1500)
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT VS2008_DEFAULT_TARGET
#  endif
#  ifndef WINVER
#    define WINVER VS2008_DEFAULT_TARGET
#  endif
#  if (_WIN32_WINNT < VS2008_MINIMUM_TARGET) || (WINVER < VS2008_MINIMUM_TARGET)
#    error VS2008 does not support Windows build targets prior to Windows 2000
#  endif
#endif

/* When no build target is specified Pelles C 5.00 and later default build
   target is Windows Vista. We override default target to be Windows 2000. */
#if defined(__POCC__) && (__POCC__ >= 500)
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0500
#  endif
#  ifndef WINVER
#    define WINVER 0x0500
#  endif
#endif

/* Availability of freeaddrinfo, getaddrinfo and getnameinfo functions is
   quite convoluted, compiler dependent and even build target dependent. */
#if defined(HAVE_WS2TCPIP_H)
#  if defined(__POCC__)
#    define HAVE_FREEADDRINFO           1
#    define HAVE_GETADDRINFO            1
#    define HAVE_GETADDRINFO_THREADSAFE 1
#    define HAVE_GETNAMEINFO            1
#  elif defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0501)
#    define HAVE_FREEADDRINFO           1
#    define HAVE_GETADDRINFO            1
#    define HAVE_GETADDRINFO_THREADSAFE 1
#    define HAVE_GETNAMEINFO            1
#  elif defined(_MSC_VER) && (_MSC_VER >= 1200)
#    define HAVE_FREEADDRINFO           1
#    define HAVE_GETADDRINFO            1
#    define HAVE_GETADDRINFO_THREADSAFE 1
#    define HAVE_GETNAMEINFO            1
#  endif
#endif

#if defined(__POCC__)
#  ifndef _MSC_VER
#    error Microsoft extensions /Ze compiler option is required
#  endif
#  ifndef __POCC__OLDNAMES
#    error Compatibility names /Go compiler option is required
#  endif
#endif

/* ---------------------------------------------------------------- */
/*                        LARGE FILE SUPPORT                        */
/* ---------------------------------------------------------------- */

#if defined(_MSC_VER) && !defined(_WIN32_WCE)
#  if (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64)
#    define USE_WIN32_LARGE_FILES
#  else
#    define USE_WIN32_SMALL_FILES
#  endif
#endif

#if defined(__MINGW32__) && !defined(USE_WIN32_LARGE_FILES)
#  define USE_WIN32_LARGE_FILES
#endif

#if defined(__WATCOMC__) && !defined(USE_WIN32_LARGE_FILES)
#  define USE_WIN32_LARGE_FILES
#endif

#if defined(__POCC__)
#  undef USE_WIN32_LARGE_FILES
#endif

#if !defined(USE_WIN32_LARGE_FILES) && !defined(USE_WIN32_SMALL_FILES)
#  define USE_WIN32_SMALL_FILES
#endif

/* ---------------------------------------------------------------- */
/*                       DNS RESOLVER SPECIALTY                     */
/* ---------------------------------------------------------------- */

/*
 * Undefine both USE_ARES and USE_THREADS_WIN32 for synchronous DNS
 */

/* Define USE_ARES to enable c-ares asynchronous DNS lookups */
/* #define USE_ARES 1 */

/* Define USE_THREADS_WIN32 to enable threaded asynchronous DNS lookups */
#define USE_THREADS_WIN32 1

#if defined(USE_ARES) && defined(USE_THREADS_WIN32)
#  error "Only one DNS lookup specialty may be defined at most"
#endif

/* ---------------------------------------------------------------- */
/*                           LDAP SUPPORT                           */
/* ---------------------------------------------------------------- */

#if defined(CURL_HAS_NOVELL_LDAPSDK) || defined(CURL_HAS_MOZILLA_LDAPSDK)
#undef CURL_LDAP_WIN
#define HAVE_LDAP_SSL_H 1
#define HAVE_LDAP_URL_PARSE 1
#elif defined(CURL_HAS_OPENLDAP_LDAPSDK)
#undef CURL_LDAP_WIN
#define HAVE_LDAP_URL_PARSE 1
#else
#undef HAVE_LDAP_URL_PARSE
#define CURL_LDAP_WIN 1
#endif

#if defined(__WATCOMC__) && defined(CURL_LDAP_WIN)
#if __WATCOMC__ < 1280
#define WINBERAPI  __declspec(cdecl)
#define WINLDAPAPI __declspec(cdecl)
#endif
#endif

#if defined(__POCC__) && defined(CURL_LDAP_WIN)
#  define CURL_DISABLE_LDAP 1
#endif

/* ---------------------------------------------------------------- */
/*                       ADDITIONAL DEFINITIONS                     */
/* ---------------------------------------------------------------- */

/* Define cpu-machine-OS */
#undef OS
#if defined(_M_IX86) || defined(__i386__) /* x86 (MSVC or gcc) */
#define OS "i386-pc-win32"
#elif defined(_M_IA64) /* Itanium */
#define OS "ia64-pc-win32"
#elif defined(_M_X64) /* AMD64/EM64T - Not defined until MSVC 2005 */
#define OS "amd64-pc-win32"
#else
#define OS "unknown-pc-win32"
#endif

/* Name of package */
#define PACKAGE "curl"

#if defined(__POCC__) || (USE_IPV6)
#  define ENABLE_IPV6 1
#endif

#endif /* __LIB_CONFIG_WIN32_H */
