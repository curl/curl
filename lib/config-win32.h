/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

#ifndef __CONFIG_WIN32_H
#define __CONFIG_WIN32_H

/* Define if on AIX 3.
   System headers sometimes define this.
   We just want to avoid a redefinition error message.  */
#ifndef _ALL_SOURCE
/* #undef _ALL_SOURCE */
#endif

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define if you don't have vprintf but do have _doprnt.  */
/* #undef HAVE_DOPRNT */

/* Define if you have the vprintf function.  */
#define HAVE_VPRINTF 1

/* Define as the return type of signal handlers (int or void).  */
/*#define RETSIGTYPE void */

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* Define this to 'int' if ssize_t is not an available typedefed type */
#define ssize_t int

/* Define this to 'int' if socklen_t is not an available typedefed type */
#if !defined(ENABLE_IPV6) && ((_MSC_VER < 1300) || !defined(USE_SSLEAY))
#define socklen_t int
#endif

/* The size of a `curl_off_t', as computed by sizeof. */
#ifdef SIZEOF_CURL_OFF_T
#undef SIZEOF_CURL_OFF_T
#endif

/* Borland lacks _lseeki64(), so we don't support >2GB files */
#ifdef __BORLANDC__
#define SIZEOF_CURL_OFF_T 4
#else
#define SIZEOF_CURL_OFF_T 8
#endif

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
/* #define TIME_WITH_SYS_TIME 1 */

/* Define cpu-machine-OS */
#define OS "i386-pc-win32"

/* The number of bytes in a long double.  */
#define SIZEOF_LONG_DOUBLE 16

/* The number of bytes in a long long.  */
/* #define SIZEOF_LONG_LONG 8 */

/* Define if you have the gethostbyaddr function.  */
#define HAVE_GETHOSTBYADDR 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getpass function.  */
/*#define HAVE_GETPASS 1*/

/* Define if you have the getservbyname function.  */
#define HAVE_GETSERVBYNAME 1

/* Define if you have the gettimeofday function.  */
/*  #define HAVE_GETTIMEOFDAY 1 */

/* Define if you have the inet_addr function.  */
#define HAVE_INET_ADDR 1

/* Define if you have the inet_ntoa function.  */
#define HAVE_INET_NTOA 1

/* Define if you have the perror function.  */
#define HAVE_PERROR 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strcasecmp function.  */
/*#define HAVE_STRCASECMP 1*/

/* Define if you have the stricmp function.  */
#define HAVE_STRICMP 1

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the strftime function.  */
#define HAVE_STRFTIME 1

/* Define if you have the strstr function.  */
#define HAVE_STRSTR 1

/* Define if you have the strtoll function.  */
#if defined(__MINGW32__) || defined(__WATCOMC__)
#define HAVE_STRTOLL 1
#endif

/* Define if you have the tcgetattr function.  */
/*#define HAVE_TCGETATTR 1*/

/* Define if you have the tcsetattr function.  */
/*#define HAVE_TCSETATTR 1*/

/* Define if you have the uname function.  */
/*#define HAVE_UNAME 1*/

/* Define if you have utime() */
#ifndef __BORLANDC__
#define HAVE_UTIME 1
#endif

/* Define if you have the <alloca.h> header file.  */
/*#define HAVE_ALLOCA_H 1*/

/* Define if you have the malloc.h file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <arpa/inet.h> header file.  */
/* #define HAVE_ARPA_INET_H 1 */

/* Define if you have the <assert.h> header file.  */
#define HAVE_ASSERT_H 1

/* Define if you have the <crypto.h> header file.  */
/* #undef HAVE_CRYPTO_H */

/* Define if you have the <dlfcn.h> header file.  */
/*#define HAVE_DLFCN_H 1*/

/* Define if you have the <err.h> header file.  */
/* #undef HAVE_ERR_H */

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
/* #undef HAVE_GETOPT_H */

/* Define if you have the <netdb.h> header file.  */
/* #define HAVE_NETDB_H 1 */

/* Define if you have the <netinet/in.h> header file.  */
/*#define HAVE_NETINET_IN_H 1*/

/* Define if you have the <sgtty.h> header file.  */
/*#define HAVE_SGTTY_H 1*/

/* Define if you have the <ssl.h> header file.  */
/* #undef HAVE_SSL_H */

/* Define if you have the <sys/param.h> header file.  */
/*#define HAVE_SYS_PARAM_H 1*/

/* Define if you have the <sys/select.h> header file.  */
/*  #define HAVE_SYS_SELECT_H 1 */

/* Define if you have the <sys/socket.h> header file.  */
/*#define HAVE_SYS_SOCKET_H 1*/

/* Define if you have the <sys/sockio.h> header file.  */
/* #define HAVE_SYS_SOCKIO_H 1 */

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/utime.h> header file */
#ifndef __BORLANDC__
#define HAVE_SYS_UTIME_H 1
#endif

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <termio.h> header file.  */
/* #define HAVE_TERMIO_H 1 */

/* Define if you have the <termios.h> header file.  */
/* #define HAVE_TERMIOS_H 1 */

/* Name of package */
#define PACKAGE "curl"

/* Define if you have the <io.h> header file.  */
#define HAVE_IO_H 1

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <winsock.h> header file.  */
#define HAVE_WINSOCK_H 1

/* Define if you have the <winsock2.h> header file.  */
#define HAVE_WINSOCK2_H 1

/* Define if you have the <ws2tcpip.h> header file.  */
#define HAVE_WS2TCPIP_H 1

/* Define if you have the <stdlib.h> header file.  */
#define HAVE_STDLIB_H 1

/* Define if you have the closesocket function.  */
#define HAVE_CLOSESOCKET 1

/* Define if you have the setvbuf function.  */
#define HAVE_SETVBUF 1

/* Define if you have the RAND_screen function when using SSL  */
#define HAVE_RAND_SCREEN 1

/* Define if you have the `RAND_status' function. */
#define HAVE_RAND_STATUS 1

/* Define this to if in_addr_t is not an available typedefed type */
#define in_addr_t unsigned long

/* use ioctlsocket() for non-blocking sockets */
#define HAVE_IOCTLSOCKET

/* lber dynamic library file */
/* #undef DL_LBER_FILE */

/* Defines set for VS2005 to _not_ deprecate a few functions we use. */
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE

/* ldap dynamic library file */
#define DL_LDAP_FILE "wldap32.dll"

/*************************************************
 * This section is for compiler specific defines.*
 *************************************************/
/* Borland and MS don't have this */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__LCC__)

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

#else

#endif

#endif
