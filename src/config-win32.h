#ifndef __SRC_CONFIG_WIN32_H
#define __SRC_CONFIG_WIN32_H

/* ================================================================ */
/*    src/config-win32.h - Hand crafted config file for windows     */
/* ================================================================ */

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <io.h> header file.  */
#define HAVE_IO_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <locale.h> header file.  */
#define HAVE_LOCALE_H 1

/* Define if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define if you have the <sys/time.h> header file */
/* #define HAVE_SYS_TIME_H 1 */

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <sys/utime.h> header file.  */
#ifndef __BORLANDC__
#define HAVE_SYS_UTIME_H 1
#endif

/* Define if you have the <unistd.h> header file.  */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__LCC__)
#define HAVE_UNISTD_H 1
#endif

/* Define if you have the <windows.h> header file.  */
#define HAVE_WINDOWS_H 1

/* Define if you have the <winsock.h> header file.  */
#define HAVE_WINSOCK_H 1

/* Define if you have the <winsock2.h> header file.  */
#define HAVE_WINSOCK2_H 1

/* Define if you have the <ws2tcpip.h> header file.  */
#define HAVE_WS2TCPIP_H 1

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

/* Define if you have the setmode function. */
#define HAVE_SETMODE 1

/* Define if you have the ftruncate function.  */
#define HAVE_FTRUNCATE 1

/* Define if you have the setlocale function.  */
#define HAVE_SETLOCALE 1

/* Define if you have the strcasecmp function. */
/* #define HAVE_STRCASECMP 1 */

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the stricmp function.  */
#define HAVE_STRICMP 1

/* Define if you have the strncasecmp function. */
/* #define HAVE_STRNCASECMP 1 */

/* Define if you have the strnicmp function. */
#define HAVE_STRNICMP 1

/* Define if you have the utime function */
#ifndef __BORLANDC__
#define HAVE_UTIME 1
#endif

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

#if (defined(__WATCOMC__) && (__WATCOMC__ >= 1240)) || defined(__POCC__) || \
    defined(__MINGW32__)
#elif defined(_WIN64)
#define ssize_t __int64
#else
#define ssize_t int
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

/* VS2008 does not support Windows build targets prior to WinXP, */
/* so, if no build target has been defined we will target WinXP. */
#if defined(_MSC_VER) && (_MSC_VER >= 1500)
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0501
#  endif
#  ifndef WINVER
#    define WINVER 0x0501
#  endif
#  if (_WIN32_WINNT < 0x0501) || (WINVER < 0x0501)
#    error VS2008 does not support Windows build targets prior to WinXP
#  endif
#endif

/* Availability of freeaddrinfo, getaddrinfo and getnameinfo functions is quite */
/* convoluted, compiler dependant and in some cases even build target dependat. */
#if defined(HAVE_WS2TCPIP_H)
#  if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0501)
#    define HAVE_FREEADDRINFO 1
#    define HAVE_GETADDRINFO  1
#    define HAVE_GETNAMEINFO  1
#  elif defined(_MSC_VER) && (_MSC_VER >= 1200)
#    define HAVE_FREEADDRINFO 1
#    define HAVE_GETADDRINFO  1
#    define HAVE_GETNAMEINFO  1
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

#if !defined(USE_WIN32_LARGE_FILES) && !defined(USE_WIN32_SMALL_FILES)
#  define USE_WIN32_SMALL_FILES
#endif

/* ---------------------------------------------------------------- */
/*                       ADDITIONAL DEFINITIONS                     */
/* ---------------------------------------------------------------- */

/* Define cpu-machine-OS */
#ifndef OS
#define OS "i386-pc-win32"
#endif

/* Define to 1 if you want the built-in manual */
#define USE_MANUAL 1


#endif /* __SRC_CONFIG_WIN32_H */
