/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* lib/curl_config.h.in. Generated somehow by cmake.  */

/* Location of default ca bundle */
#cmakedefine CURL_CA_BUNDLE "${CURL_CA_BUNDLE}"

/* define "1" to use built-in ca store of TLS backend */
#cmakedefine CURL_CA_FALLBACK 1

/* Location of default ca path */
#cmakedefine CURL_CA_PATH "${CURL_CA_PATH}"

/* Default SSL backend */
#cmakedefine CURL_DEFAULT_SSL_BACKEND "${CURL_DEFAULT_SSL_BACKEND}"

/* disables alt-svc */
#cmakedefine CURL_DISABLE_ALTSVC 1

/* disables cookies support */
#cmakedefine CURL_DISABLE_COOKIES 1

/* disables Basic authentication */
#cmakedefine CURL_DISABLE_BASIC_AUTH 1

/* disables Bearer authentication */
#cmakedefine CURL_DISABLE_BEARER_AUTH 1

/* disables Digest authentication */
#cmakedefine CURL_DISABLE_DIGEST_AUTH 1

/* disables Kerberos authentication */
#cmakedefine CURL_DISABLE_KERBEROS_AUTH 1

/* disables negotiate authentication */
#cmakedefine CURL_DISABLE_NEGOTIATE_AUTH 1

/* disables AWS-SIG4 */
#cmakedefine CURL_DISABLE_AWS 1

/* disables DICT */
#cmakedefine CURL_DISABLE_DICT 1

/* disables DNS-over-HTTPS */
#cmakedefine CURL_DISABLE_DOH 1

/* disables FILE */
#cmakedefine CURL_DISABLE_FILE 1

/* disables form api */
#cmakedefine CURL_DISABLE_FORM_API 1

/* disables FTP */
#cmakedefine CURL_DISABLE_FTP 1

/* disables curl_easy_options API for existing options to curl_easy_setopt */
#cmakedefine CURL_DISABLE_GETOPTIONS 1

/* disables GOPHER */
#cmakedefine CURL_DISABLE_GOPHER 1

/* disables headers-api support */
#cmakedefine CURL_DISABLE_HEADERS_API 1

/* disables HSTS support */
#cmakedefine CURL_DISABLE_HSTS 1

/* disables HTTP */
#cmakedefine CURL_DISABLE_HTTP 1

/* disabled all HTTP authentication methods */
#cmakedefine CURL_DISABLE_HTTP_AUTH 1

/* disables IMAP */
#cmakedefine CURL_DISABLE_IMAP 1

/* disables LDAP */
#cmakedefine CURL_DISABLE_LDAP 1

/* disables LDAPS */
#cmakedefine CURL_DISABLE_LDAPS 1

/* disables --libcurl option from the curl tool */
#cmakedefine CURL_DISABLE_LIBCURL_OPTION 1

/* disables MIME support */
#cmakedefine CURL_DISABLE_MIME 1

/* disables local binding support */
#cmakedefine CURL_DISABLE_BINDLOCAL 1

/* disables MQTT */
#cmakedefine CURL_DISABLE_MQTT 1

/* disables netrc parser */
#cmakedefine CURL_DISABLE_NETRC 1

/* disables NTLM support */
#cmakedefine CURL_DISABLE_NTLM 1

/* disables date parsing */
#cmakedefine CURL_DISABLE_PARSEDATE 1

/* disables POP3 */
#cmakedefine CURL_DISABLE_POP3 1

/* disables built-in progress meter */
#cmakedefine CURL_DISABLE_PROGRESS_METER 1

/* disables proxies */
#cmakedefine CURL_DISABLE_PROXY 1

/* disables RTSP */
#cmakedefine CURL_DISABLE_RTSP 1

/* disables SHA-512/256 hash algorithm */
#cmakedefine CURL_DISABLE_SHA512_256 1

/* disabled shuffle DNS feature */
#cmakedefine CURL_DISABLE_SHUFFLE_DNS 1

/* disables SMB */
#cmakedefine CURL_DISABLE_SMB 1

/* disables SMTP */
#cmakedefine CURL_DISABLE_SMTP 1

/* disables use of socketpair for curl_multi_poll */
#cmakedefine CURL_DISABLE_SOCKETPAIR 1

/* disables TELNET */
#cmakedefine CURL_DISABLE_TELNET 1

/* disables TFTP */
#cmakedefine CURL_DISABLE_TFTP 1

/* disables verbose strings */
#cmakedefine CURL_DISABLE_VERBOSE_STRINGS 1

/* to make a symbol visible */
#cmakedefine CURL_EXTERN_SYMBOL ${CURL_EXTERN_SYMBOL}
/* Ensure using CURL_EXTERN_SYMBOL is possible */
#ifndef CURL_EXTERN_SYMBOL
#define CURL_EXTERN_SYMBOL
#endif

/* Allow SMB to work on Windows */
#cmakedefine USE_WIN32_CRYPTO 1

/* Use Windows LDAP implementation */
#cmakedefine USE_WIN32_LDAP 1

/* Define if you want to enable IPv6 support */
#cmakedefine USE_IPV6 1

/* Define to 1 if you have the alarm function. */
#cmakedefine HAVE_ALARM 1

/* Define to 1 if you have the arc4random function. */
#cmakedefine HAVE_ARC4RANDOM 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#cmakedefine HAVE_ARPA_INET_H 1

/* Define to 1 if you have _Atomic support. */
#cmakedefine HAVE_ATOMIC 1

/* Define to 1 if you have the `fnmatch' function. */
#cmakedefine HAVE_FNMATCH 1

/* Define to 1 if you have the `basename' function. */
#cmakedefine HAVE_BASENAME 1

/* Define to 1 if bool is an available type. */
#cmakedefine HAVE_BOOL_T 1

/* Define to 1 if you have the __builtin_available function. */
#cmakedefine HAVE_BUILTIN_AVAILABLE 1

/* Define to 1 if you have the clock_gettime function and monotonic timer. */
#cmakedefine HAVE_CLOCK_GETTIME_MONOTONIC 1

/* Define to 1 if you have the clock_gettime function and raw monotonic timer.
   */
#cmakedefine HAVE_CLOCK_GETTIME_MONOTONIC_RAW 1

/* Define to 1 if you have the `closesocket' function. */
#cmakedefine HAVE_CLOSESOCKET 1

/* Define to 1 if you have the <dirent.h> header file. */
#cmakedefine HAVE_DIRENT_H 1

/* Define to 1 if you have the `opendir' function. */
#cmakedefine HAVE_OPENDIR 1

/* Define to 1 if you have the fcntl function. */
#cmakedefine HAVE_FCNTL 1

/* Define to 1 if you have the <fcntl.h> header file. */
#cmakedefine HAVE_FCNTL_H 1

/* Define to 1 if you have a working fcntl O_NONBLOCK function. */
#cmakedefine HAVE_FCNTL_O_NONBLOCK 1

/* Define to 1 if you have the freeaddrinfo function. */
#cmakedefine HAVE_FREEADDRINFO 1

/* Define to 1 if you have the fseeko function. */
#cmakedefine HAVE_FSEEKO 1

/* Define to 1 if you have the fseeko declaration. */
#cmakedefine HAVE_DECL_FSEEKO 1

/* Define to 1 if you have the _fseeki64 function. */
#cmakedefine HAVE__FSEEKI64 1

/* Define to 1 if you have the ftruncate function. */
#cmakedefine HAVE_FTRUNCATE 1

/* Define to 1 if you have a working getaddrinfo function. */
#cmakedefine HAVE_GETADDRINFO 1

/* Define to 1 if the getaddrinfo function is threadsafe. */
#cmakedefine HAVE_GETADDRINFO_THREADSAFE 1

/* Define to 1 if you have the `geteuid' function. */
#cmakedefine HAVE_GETEUID 1

/* Define to 1 if you have the `getppid' function. */
#cmakedefine HAVE_GETPPID 1

/* Define to 1 if you have the gethostbyname_r function. */
#cmakedefine HAVE_GETHOSTBYNAME_R 1

/* gethostbyname_r() takes 3 args */
#cmakedefine HAVE_GETHOSTBYNAME_R_3 1

/* gethostbyname_r() takes 5 args */
#cmakedefine HAVE_GETHOSTBYNAME_R_5 1

/* gethostbyname_r() takes 6 args */
#cmakedefine HAVE_GETHOSTBYNAME_R_6 1

/* Define to 1 if you have the gethostname function. */
#cmakedefine HAVE_GETHOSTNAME 1

/* Define to 1 if you have a working getifaddrs function. */
#cmakedefine HAVE_GETIFADDRS 1

/* Define to 1 if you have the `getpass_r' function. */
#cmakedefine HAVE_GETPASS_R 1

/* Define to 1 if you have the `getpeername' function. */
#cmakedefine HAVE_GETPEERNAME 1

/* Define to 1 if you have the `getsockname' function. */
#cmakedefine HAVE_GETSOCKNAME 1

/* Define to 1 if you have the `if_nametoindex' function. */
#cmakedefine HAVE_IF_NAMETOINDEX 1

/* Define to 1 if you have the `getpwuid' function. */
#cmakedefine HAVE_GETPWUID 1

/* Define to 1 if you have the `getpwuid_r' function. */
#cmakedefine HAVE_GETPWUID_R 1

/* Define to 1 if you have the `getrlimit' function. */
#cmakedefine HAVE_GETRLIMIT 1

/* Define to 1 if you have the `gettimeofday' function. */
#cmakedefine HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have a working glibc-style strerror_r function. */
#cmakedefine HAVE_GLIBC_STRERROR_R 1

/* Define to 1 if you have a working gmtime_r function. */
#cmakedefine HAVE_GMTIME_R 1

/* if you have the gssapi libraries */
#cmakedefine HAVE_GSSAPI 1

/* Define to 1 if you have the <gssapi/gssapi_generic.h> header file. */
#cmakedefine HAVE_GSSAPI_GSSAPI_GENERIC_H 1

/* Define to 1 if you have the <gssapi/gssapi.h> header file. */
#cmakedefine HAVE_GSSAPI_GSSAPI_H 1

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
#cmakedefine HAVE_GSSAPI_GSSAPI_KRB5_H 1

/* if you have the GNU gssapi libraries */
#cmakedefine HAVE_GSSGNU 1

/* Define to 1 if you have the <ifaddrs.h> header file. */
#cmakedefine HAVE_IFADDRS_H 1

/* Define to 1 if you have a IPv6 capable working inet_ntop function. */
#cmakedefine HAVE_INET_NTOP 1

/* Define to 1 if you have a IPv6 capable working inet_pton function. */
#cmakedefine HAVE_INET_PTON 1

/* Define to 1 if symbol `sa_family_t' exists */
#cmakedefine HAVE_SA_FAMILY_T 1

/* Define to 1 if symbol `ADDRESS_FAMILY' exists */
#cmakedefine HAVE_ADDRESS_FAMILY 1

/* Define to 1 if you have the ioctlsocket function. */
#cmakedefine HAVE_IOCTLSOCKET 1

/* Define to 1 if you have the IoctlSocket camel case function. */
#cmakedefine HAVE_IOCTLSOCKET_CAMEL 1

/* Define to 1 if you have a working IoctlSocket camel case FIONBIO function.
   */
#cmakedefine HAVE_IOCTLSOCKET_CAMEL_FIONBIO 1

/* Define to 1 if you have a working ioctlsocket FIONBIO function. */
#cmakedefine HAVE_IOCTLSOCKET_FIONBIO 1

/* Define to 1 if you have a working ioctl FIONBIO function. */
#cmakedefine HAVE_IOCTL_FIONBIO 1

/* Define to 1 if you have a working ioctl SIOCGIFADDR function. */
#cmakedefine HAVE_IOCTL_SIOCGIFADDR 1

/* Define to 1 if you have the <io.h> header file. */
#cmakedefine HAVE_IO_H 1

/* Define to 1 if you have the lber.h header file. */
#cmakedefine HAVE_LBER_H 1

/* Define to 1 if you have the ldap.h header file. */
#cmakedefine HAVE_LDAP_H 1

/* Use LDAPS implementation */
#cmakedefine HAVE_LDAP_SSL 1

/* Define to 1 if you have the ldap_ssl.h header file. */
#cmakedefine HAVE_LDAP_SSL_H 1

/* Define to 1 if you have the `ldap_url_parse' function. */
#cmakedefine HAVE_LDAP_URL_PARSE 1

/* Define to 1 if you have the <libgen.h> header file. */
#cmakedefine HAVE_LIBGEN_H 1

/* Define to 1 if you have the `idn2' library (-lidn2). */
#cmakedefine HAVE_LIBIDN2 1

/* Define to 1 if you have the idn2.h header file. */
#cmakedefine HAVE_IDN2_H 1

/* if zlib is available */
#cmakedefine HAVE_LIBZ 1

/* if brotli is available */
#cmakedefine HAVE_BROTLI 1

/* if zstd is available */
#cmakedefine HAVE_ZSTD 1

/* Define to 1 if you have the <locale.h> header file. */
#cmakedefine HAVE_LOCALE_H 1

/* Define to 1 if the compiler supports the 'long long' data type. */
#cmakedefine HAVE_LONGLONG 1

/* Define to 1 if you have the 'suseconds_t' data type. */
#cmakedefine HAVE_SUSECONDS_T 1

/* Define to 1 if you have the MSG_NOSIGNAL flag. */
#cmakedefine HAVE_MSG_NOSIGNAL 1

/* Define to 1 if you have the <netdb.h> header file. */
#cmakedefine HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#cmakedefine HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#cmakedefine HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <netinet/udp.h> header file. */
#cmakedefine HAVE_NETINET_UDP_H 1

/* Define to 1 if you have the <linux/tcp.h> header file. */
#cmakedefine HAVE_LINUX_TCP_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#cmakedefine HAVE_NET_IF_H 1

/* if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE */
#cmakedefine HAVE_OLD_GSSMIT 1

/* Define to 1 if you have the `pipe' function. */
#cmakedefine HAVE_PIPE 1

/* Define to 1 if you have the `eventfd' function. */
#cmakedefine HAVE_EVENTFD 1

/* If you have a fine poll */
#cmakedefine HAVE_POLL_FINE 1

/* Define to 1 if you have the <poll.h> header file. */
#cmakedefine HAVE_POLL_H 1

/* Define to 1 if you have a working POSIX-style strerror_r function. */
#cmakedefine HAVE_POSIX_STRERROR_R 1

/* Define to 1 if you have the <pthread.h> header file */
#cmakedefine HAVE_PTHREAD_H 1

/* Define to 1 if you have the <pwd.h> header file. */
#cmakedefine HAVE_PWD_H 1

/* Define to 1 if OpenSSL has the `SSL_set0_wbio` function. */
#cmakedefine HAVE_SSL_SET0_WBIO 1

/* Define to 1 if you have the recv function. */
#cmakedefine HAVE_RECV 1

/* Define to 1 if you have the select function. */
#cmakedefine HAVE_SELECT 1

/* Define to 1 if you have the sched_yield function. */
#cmakedefine HAVE_SCHED_YIELD 1

/* Define to 1 if you have the send function. */
#cmakedefine HAVE_SEND 1

/* Define to 1 if you have the sendmsg function. */
#cmakedefine HAVE_SENDMSG 1

/* Define to 1 if you have the 'fsetxattr' function. */
#cmakedefine HAVE_FSETXATTR 1

/* fsetxattr() takes 5 args */
#cmakedefine HAVE_FSETXATTR_5 1

/* fsetxattr() takes 6 args */
#cmakedefine HAVE_FSETXATTR_6 1

/* Define to 1 if you have the `setlocale' function. */
#cmakedefine HAVE_SETLOCALE 1

/* Define to 1 if you have the `setmode' function. */
#cmakedefine HAVE_SETMODE 1

/* Define to 1 if you have the `setrlimit' function. */
#cmakedefine HAVE_SETRLIMIT 1

/* Define to 1 if you have a working setsockopt SO_NONBLOCK function. */
#cmakedefine HAVE_SETSOCKOPT_SO_NONBLOCK 1

/* Define to 1 if you have the sigaction function. */
#cmakedefine HAVE_SIGACTION 1

/* Define to 1 if you have the siginterrupt function. */
#cmakedefine HAVE_SIGINTERRUPT 1

/* Define to 1 if you have the signal function. */
#cmakedefine HAVE_SIGNAL 1

/* Define to 1 if you have the sigsetjmp function or macro. */
#cmakedefine HAVE_SIGSETJMP 1

/* Define to 1 if you have the `snprintf' function. */
#cmakedefine HAVE_SNPRINTF 1

/* Define to 1 if struct sockaddr_in6 has the sin6_scope_id member */
#cmakedefine HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1

/* Define to 1 if you have the `socket' function. */
#cmakedefine HAVE_SOCKET 1

/* Define to 1 if you have the socketpair function. */
#cmakedefine HAVE_SOCKETPAIR 1

/* Define to 1 if you have the <stdatomic.h> header file. */
#cmakedefine HAVE_STDATOMIC_H 1

/* Define to 1 if you have the <stdbool.h> header file. */
#cmakedefine HAVE_STDBOOL_H 1

/* Define to 1 if you have the strcasecmp function. */
#cmakedefine HAVE_STRCASECMP 1

/* Define to 1 if you have the strcmpi function. */
#cmakedefine HAVE_STRCMPI 1

/* Define to 1 if you have the strdup function. */
#cmakedefine HAVE_STRDUP 1

/* Define to 1 if you have the strerror_r function. */
#cmakedefine HAVE_STRERROR_R 1

/* Define to 1 if you have the stricmp function. */
#cmakedefine HAVE_STRICMP 1

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H 1

/* Define to 1 if you have the <stropts.h> header file. */
#cmakedefine HAVE_STROPTS_H 1

/* Define to 1 if you have the strtok_r function. */
#cmakedefine HAVE_STRTOK_R 1

/* Define to 1 if you have the strtoll function. */
#cmakedefine HAVE_STRTOLL 1

/* Define to 1 if you have the memrchr function. */
#cmakedefine HAVE_MEMRCHR 1

/* if struct sockaddr_storage is defined */
#cmakedefine HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define to 1 if you have the timeval struct. */
#cmakedefine HAVE_STRUCT_TIMEVAL 1

/* Define to 1 if you have the <sys/eventfd.h> header file. */
#cmakedefine HAVE_SYS_EVENTFD_H 1

/* Define to 1 if you have the <sys/filio.h> header file. */
#cmakedefine HAVE_SYS_FILIO_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#cmakedefine HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#cmakedefine HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#cmakedefine HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/poll.h> header file. */
#cmakedefine HAVE_SYS_POLL_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#cmakedefine HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#cmakedefine HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#cmakedefine HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
#cmakedefine HAVE_SYS_SOCKIO_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#cmakedefine HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#cmakedefine HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/utime.h> header file. */
#cmakedefine HAVE_SYS_UTIME_H 1

/* Define to 1 if you have the <termios.h> header file. */
#cmakedefine HAVE_TERMIOS_H 1

/* Define to 1 if you have the <termio.h> header file. */
#cmakedefine HAVE_TERMIO_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H 1

/* Define to 1 if you have the `utime' function. */
#cmakedefine HAVE_UTIME 1

/* Define to 1 if you have the `utimes' function. */
#cmakedefine HAVE_UTIMES 1

/* Define to 1 if you have the <utime.h> header file. */
#cmakedefine HAVE_UTIME_H 1

/* Define this symbol if your OS supports changing the contents of argv */
#cmakedefine HAVE_WRITABLE_ARGV 1

/* Define to 1 if you need the lber.h header file even with ldap.h */
#cmakedefine NEED_LBER_H 1

/* Define to 1 if you need the malloc.h header file even with stdlib.h */
#cmakedefine NEED_MALLOC_H 1

/* Define to 1 if _REENTRANT preprocessor symbol must be defined. */
#cmakedefine NEED_REENTRANT 1

/* cpu-machine-OS */
#cmakedefine OS ${OS}

/* Name of package */
#cmakedefine PACKAGE ${PACKAGE}

/* Define to the address where bug reports for this package should be sent. */
#cmakedefine PACKAGE_BUGREPORT ${PACKAGE_BUGREPORT}

/* Define to the full name of this package. */
#cmakedefine PACKAGE_NAME ${PACKAGE_NAME}

/* Define to the full name and version of this package. */
#cmakedefine PACKAGE_STRING ${PACKAGE_STRING}

/* Define to the one symbol short name of this package. */
#cmakedefine PACKAGE_TARNAME ${PACKAGE_TARNAME}

/* Define to the version of this package. */
#cmakedefine PACKAGE_VERSION ${PACKAGE_VERSION}

/*
 Note: SIZEOF_* variables are fetched with CMake through check_type_size().
 As per CMake documentation on CheckTypeSize, C preprocessor code is
 generated by CMake into SIZEOF_*_CODE. This is what we use in the
 following statements.

 Reference: https://cmake.org/cmake/help/latest/module/CheckTypeSize.html
*/

/* The size of `int', as computed by sizeof. */
${SIZEOF_INT_CODE}

/* The size of `long', as computed by sizeof. */
${SIZEOF_LONG_CODE}

/* The size of `long long', as computed by sizeof. */
${SIZEOF_LONG_LONG_CODE}

/* The size of `off_t', as computed by sizeof. */
${SIZEOF_OFF_T_CODE}

/* The size of `curl_off_t', as computed by sizeof. */
${SIZEOF_CURL_OFF_T_CODE}

/* The size of `curl_socket_t', as computed by sizeof. */
${SIZEOF_CURL_SOCKET_T_CODE}

/* The size of `size_t', as computed by sizeof. */
${SIZEOF_SIZE_T_CODE}

/* The size of `time_t', as computed by sizeof. */
${SIZEOF_TIME_T_CODE}

/* Define to 1 if you have the ANSI C header files. */
#cmakedefine STDC_HEADERS 1

/* Define if you want to enable c-ares support */
#cmakedefine USE_ARES 1

/* Define if you want to enable POSIX threaded DNS lookup */
#cmakedefine USE_THREADS_POSIX 1

/* Define if you want to enable Win32 threaded DNS lookup */
#cmakedefine USE_THREADS_WIN32 1

/* if GnuTLS is enabled */
#cmakedefine USE_GNUTLS 1

/* if Secure Transport is enabled */
#cmakedefine USE_SECTRANSP 1

/* if mbedTLS is enabled */
#cmakedefine USE_MBEDTLS 1

/* if BearSSL is enabled */
#cmakedefine USE_BEARSSL 1

/* if Rustls is enabled */
#cmakedefine USE_RUSTLS 1

/* if wolfSSL is enabled */
#cmakedefine USE_WOLFSSL 1

/* if wolfSSL has the wolfSSL_DES_ecb_encrypt function. */
#cmakedefine HAVE_WOLFSSL_DES_ECB_ENCRYPT 1

/* if wolfSSL has the wolfSSL_BIO_set_shutdown function. */
#cmakedefine HAVE_WOLFSSL_FULL_BIO 1

/* if libssh is in use */
#cmakedefine USE_LIBSSH 1

/* if libssh2 is in use */
#cmakedefine USE_LIBSSH2 1

/* if wolfssh is in use */
#cmakedefine USE_WOLFSSH 1

/* if libpsl is in use */
#cmakedefine USE_LIBPSL 1

/* if you want to use OpenLDAP code instead of legacy ldap implementation */
#cmakedefine USE_OPENLDAP 1

/* if OpenSSL is in use */
#cmakedefine USE_OPENSSL 1

/* if librtmp/rtmpdump is in use */
#cmakedefine USE_LIBRTMP 1

/* if GSASL is in use */
#cmakedefine USE_GSASL 1

/* if libuv is in use */
#cmakedefine USE_LIBUV 1

/* Define to 1 if you have the <uv.h> header file. */
#cmakedefine HAVE_UV_H 1

/* Define to 1 if you do not want the OpenSSL configuration to be loaded
   automatically */
#cmakedefine CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG 1

/* to enable NGHTTP2  */
#cmakedefine USE_NGHTTP2 1

/* to enable NGTCP2 */
#cmakedefine USE_NGTCP2 1

/* to enable NGHTTP3  */
#cmakedefine USE_NGHTTP3 1

/* to enable quiche */
#cmakedefine USE_QUICHE 1

/* to enable openssl + nghttp3 */
#cmakedefine USE_OPENSSL_QUIC 1

/* Define to 1 if you have the quiche_conn_set_qlog_fd function. */
#cmakedefine HAVE_QUICHE_CONN_SET_QLOG_FD 1

/* to enable msh3 */
#cmakedefine USE_MSH3 1

/* if Unix domain sockets are enabled  */
#cmakedefine USE_UNIX_SOCKETS 1

/* Define to 1 if you are building a Windows target with large file support. */
#cmakedefine USE_WIN32_LARGE_FILES 1

/* to enable SSPI support */
#cmakedefine USE_WINDOWS_SSPI 1

/* to enable Windows SSL  */
#cmakedefine USE_SCHANNEL 1

/* enable multiple SSL backends */
#cmakedefine CURL_WITH_MULTI_SSL 1

/* Version number of package */
#cmakedefine VERSION ${VERSION}

/* Number of bits in a file offset, on hosts where this is settable. */
#cmakedefine _FILE_OFFSET_BITS ${_FILE_OFFSET_BITS}

/* Define for large files, on AIX-style hosts. */
#cmakedefine _LARGE_FILES ${_LARGE_FILES}

/* define this if you need it to compile thread-safe code */
#cmakedefine _THREAD_SAFE ${_THREAD_SAFE}

/* Define to empty if `const' does not conform to ANSI C. */
#cmakedefine const ${const}

/* Type to use in place of in_addr_t when system does not provide it. */
#cmakedefine in_addr_t ${in_addr_t}

/* Define to `unsigned int' if <sys/types.h> does not define. */
#cmakedefine size_t ${size_t}

/* the signed version of size_t */
#cmakedefine ssize_t ${ssize_t}

/* Define to 1 if you have the mach_absolute_time function. */
#cmakedefine HAVE_MACH_ABSOLUTE_TIME 1

/* to enable Windows IDN */
#cmakedefine USE_WIN32_IDN 1

/* to enable Apple IDN */
#cmakedefine USE_APPLE_IDN 1

/* Define to 1 to enable websocket support. */
#cmakedefine USE_WEBSOCKETS 1

/* Define to 1 if OpenSSL has the SSL_CTX_set_srp_username function. */
#cmakedefine HAVE_OPENSSL_SRP 1

/* Define to 1 if GnuTLS has the gnutls_srp_verifier function. */
#cmakedefine HAVE_GNUTLS_SRP 1

/* Define to 1 to enable TLS-SRP support. */
#cmakedefine USE_TLS_SRP 1

/* Define to 1 to query for HTTPSRR when using DoH */
#cmakedefine USE_HTTPSRR 1

/* if ECH support is available */
#cmakedefine USE_ECH 1
