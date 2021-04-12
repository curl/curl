#ifndef CURL_CONFIG_FREERTOS_H
#define CURL_CONFIG_FREERTOS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 ***************************************************************************/

/* to disable cookies support */
#define CURL_DISABLE_COOKIES 1

/* disable HTTP authentication */
#define CURL_DISABLE_HTTP_AUTH 1

/* disable DoH */
#define CURL_DISABLE_DOH 1

/* disable mime API */
#define CURL_DISABLE_MIME 1

/* disable date parsing */
#define CURL_DISABLE_PARSEDATE 1

/* disable netrc parsing */
#define CURL_DISABLE_NETRC 1

/* disable DNS shuffling */
#define CURL_DISABLE_SHUFFLE_DNS 1

/* disable progress-meter */
#define CURL_DISABLE_PROGRESS_METER 1

/* to disable cryptographic authentication */
#define CURL_DISABLE_CRYPTO_AUTH 1

/* to disable DICT */
#define CURL_DISABLE_DICT 1

/* to disable FILE */
#define CURL_DISABLE_FILE 1

/* to disable FTP */
#define CURL_DISABLE_FTP 1

/* to disable Gopher */
#define CURL_DISABLE_GOPHER 1

/* to disable IMAP */
#define CURL_DISABLE_IMAP 1

/* to disable LDAP */
#define CURL_DISABLE_LDAP 1

/* to disable LDAPS */
#define CURL_DISABLE_LDAPS 1

/* to disable POP3 */
#define CURL_DISABLE_POP3 1

/* to disable proxies */
#define CURL_DISABLE_PROXY 1

/* to disable RTSP */
#define CURL_DISABLE_RTSP 1

/* to disable SMB/CIFS */
#define CURL_DISABLE_SMB 1

/* to disable SMTP */
#define CURL_DISABLE_SMTP 1

/* to disable TELNET */
#define CURL_DISABLE_TELNET 1

/* to disable TFTP */
#define CURL_DISABLE_TFTP 1

/* to disable verbose strings */
#define CURL_DISABLE_VERBOSE_STRINGS 1

/* Definition to make a library symbol externally visible. */
#define CURL_EXTERN_SYMBOL __attribute__ ((__visibility__ ("default")))

/* IP address type in sockaddr */
#define CURL_SA_FAMILY_T uint8_t

/* lack of non-blocking support */
#define USE_BLOCKING_SOCKETS 1

/* Define to the type of arg 2 for gethostname. */
#define GETHOSTNAME_TYPE_ARG2 size_t

/* Specifies the number of arguments to getservbyport_r */
#define GETSERVBYPORT_R_ARGS 6

/* Specifies the size of the buffer to pass to getservbyport_r */
#define GETSERVBYPORT_R_BUFSIZE 4096

/* Define to 1 if you have the <alloca.h> header file. */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the <arpa/inet.h> header file. */

/* Define to 1 if you have the <arpa/tftp.h> header file. */

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the basename function. */
#define HAVE_BASENAME 1

/* Define to 1 if bool is an available type. */
#define HAVE_BOOL_T 1

/* Define to 1 if you have the connect function. */
#define HAVE_CONNECT 1

/* Define to 1 if you have the <cyassl/error-ssl.h> header file. */
#define HAVE_CYASSL_ERROR_SSL_H 1

/* Define to 1 if you have the <cyassl/options.h> header file. */
#define HAVE_CYASSL_OPTIONS_H 1

/* Define to 1 if you have the declaration of `getpwuid_r', and to 0 if you
   don't. */
#define HAVE_DECL_GETPWUID_R 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the gethostbyname function. */
#define HAVE_GETHOSTBYNAME 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <linux/tcp.h> header file. */

/* if your compiler supports LL */
#define HAVE_LL 1

/* Define to 1 if the compiler supports the 'long long' data type. */
#define HAVE_LONGLONG 1

/* Define to 1 if you have the malloc.h header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the memory.h header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */

/* Define to 1 if you have the <netinet/in.h> header file. */

/* Define to 1 if you have the <netinet/tcp.h> header file. */

/* Define to 1 if you have the <net/if.h> header file. */

/* Define to 1 if you have the recv function. */
#define HAVE_RECV 1

/* Define to 1 if you have the select function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the send function. */
#define HAVE_SEND 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/* Define to 1 if you have the setsockopt function. */
#define HAVE_SETSOCKOPT 1

/* Define to 1 if you have the socket function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stdbool.h> header file. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the strcasecmp function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the strdup function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the strncasecmp function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the <stropts.h> header file. */

/* Define to 1 if you have the strstr function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the strtok_r function. */
#define HAVE_STRTOK_R 1

/* Define to 1 if you have the strtoll function. */
#define HAVE_STRTOLL 1

/* if struct sockaddr_storage is defined */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define to 1 if you have the timeval struct. */
#define HAVE_STRUCT_TIMEVAL 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/un.h> header file. */

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <sys/xattr.h> header file. */
#define HAVE_SYS_XATTR_H 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the <termio.h> header file. */
#define HAVE_TERMIO_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `utime' function. */
#define HAVE_UTIME 1

/* Define to 1 if you have the `utimes' function. */
#define HAVE_UTIMES 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if compiler supports C99 variadic macro style. */
#define HAVE_VARIADIC_MACROS_C99 1

/* Define to 1 if compiler supports old gcc variadic macro style. */
#define HAVE_VARIADIC_MACROS_GCC 1

/* Define to 1 if you have the `wolfSSL_CTX_UseSupportedCurve' function. */
#define HAVE_WOLFSSL_CTX_USESUPPORTEDCURVE 1

/* Define to 1 if you have the `wolfSSL_get_peer_certificate' function. */
#define HAVE_WOLFSSL_GET_PEER_CERTIFICATE 1

/* Define to 1 if you have the writev function. */
#define HAVE_WRITEV 1

/* cpu-machine-OS */
#define OS "x86_64-freertos"

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 Socket_t

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 void *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 size_t

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 long

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV long

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to the type qualifier of arg 5 for select. */
#define SELECT_QUAL_ARG5

/* Define to the type of arg 1 for select. */
#define SELECT_TYPE_ARG1 int

/* Define to the type of args 2, 3 and 4 for select. */
#define SELECT_TYPE_ARG234 fd_set *

/* Define to the type of arg 5 for select. */
#define SELECT_TYPE_ARG5 struct timeval *

/* Define to the function return type for select. */
#define SELECT_TYPE_RETV int

/* Define to the type qualifier of arg 2 for send. */
#define SEND_QUAL_ARG2 const

/* Define to the type of arg 1 for send. */
#define SEND_TYPE_ARG1 int

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 void *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 size_t

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV ssize_t

#define ssize_t int

/* The number of bytes in type curl_off_t */
#define SIZEOF_CURL_OFF_T 8

/* The number of bytes in type int */
#define SIZEOF_INT 4

/* The number of bytes in type long */
#define SIZEOF_LONG 4

/* The number of bytes in type long long */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in type off_t */
#define SIZEOF_OFF_T 8

/* The number of bytes in type short */
#define SIZEOF_SHORT 2

/* The number of bytes in type size_t */
#define SIZEOF_SIZE_T 8

/* The number of bytes in type time_t */
#define SIZEOF_TIME_T 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* if CyaSSL/WolfSSL is enabled */
#define USE_CYASSL 1

/* Version number of package */
#define VERSION "-"

/* Define to 1 if OS is AIX. */
#ifndef _ALL_SOURCE
/* #  undef _ALL_SOURCE */
#endif

/* Work-around to allow building the Windows FreeRTOS simulator */
#define ALLOW_MSVC6_WITHOUT_PSDK 1

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

#endif /* CURL_CONFIG_FREERTOS_H */
