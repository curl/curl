/* lib/config.h.in.  Generated from configure.ac by autoheader.  */

/* to disable DICT */
#undef CURL_DISABLE_DICT

/* to disable FILE */
#undef CURL_DISABLE_FILE

/* to disable FTP */
#undef CURL_DISABLE_FTP

/* to disable GOPHER */
#undef CURL_DISABLE_GOPHER

/* to disable HTTP */
#undef CURL_DISABLE_HTTP

/* to disable LDAP */
#undef CURL_DISABLE_LDAP

/* to disable TELNET */
#undef CURL_DISABLE_TELNET

/* Set to explicitly specify we don't want to use thread-safe functions */
#undef DISABLED_THREADSAFE

/* your Entropy Gathering Daemon socket pathname */
#undef EGD_SOCKET

/* Define if you want to enable IPv6 support */
#undef ENABLE_IPV6

/* Define to 1 if you have the <alloca.h> header file. */
#undef HAVE_ALLOCA_H

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `closesocket' function. */
#undef HAVE_CLOSESOCKET

/* Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function. */
#undef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA

/* Define to 1 if you have the <crypto.h> header file. */
#undef HAVE_CRYPTO_H

/* Define to 1 if you have the <des.h> header file. */
#undef HAVE_DES_H

/* disabled non-blocking sockets */
#undef HAVE_DISABLED_NONBLOCKING

/* Define to 1 if you have the <dlfcn.h> header file. */
/* XXX: #undef HAVE_DLFCN_H */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `dlopen' function. */
#define HAVE_DLOPEN 1

/* Define to 1 if you have the <err.h> header file. */
#define HAVE_ERR_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* use FIONBIO for non-blocking sockets */
/* XXX: #undef HAVE_FIONBIO */
#define HAVE_FIONBIO 1

/* Define if getaddrinfo exists and works */
#undef HAVE_GETADDRINFO

/* Define to 1 if you have the `geteuid' function. */
#undef HAVE_GETEUID

/* Define to 1 if you have the `gethostbyaddr' function. */
#define HAVE_GETHOSTBYADDR 1

/* Define to 1 if you have the `gethostbyaddr_r' function. */
#undef HAVE_GETHOSTBYADDR_R

/* gethostbyaddr_r() takes 5 args */
#undef HAVE_GETHOSTBYADDR_R_5

/* gethostbyaddr_r() takes 7 args */
#undef HAVE_GETHOSTBYADDR_R_7

/* gethostbyaddr_r() takes 8 args */
#undef HAVE_GETHOSTBYADDR_R_8

/* Define to 1 if you have the `gethostbyname_r' function. */
#undef HAVE_GETHOSTBYNAME_R

/* gethostbyname_r() takes 3 args */
#undef HAVE_GETHOSTBYNAME_R_3

/* gethostbyname_r() takes 5 args */
#undef HAVE_GETHOSTBYNAME_R_5

/* gethostbyname_r() takes 6 args */
#undef HAVE_GETHOSTBYNAME_R_6

/* Define to 1 if you have the `getpass_r' function. */
#undef HAVE_GETPASS_R

/* Define to 1 if you have the `getpwuid' function. */
#undef HAVE_GETPWUID

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `gmtime_r' function. */
#undef HAVE_GMTIME_R

/* if you have the gssapi libraries */
#undef HAVE_GSSAPI

/* if you have the Heimdal gssapi libraries */
#undef HAVE_GSSHEIMDAL

/* if you have the MIT gssapi libraries */
#undef HAVE_GSSMIT

/* Define to 1 if you have the `inet_addr' function. */
#define HAVE_INET_ADDR 1

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if you have the `inet_ntoa_r' function. */
#undef HAVE_INET_NTOA_R

/* inet_ntoa_r() is declared */
#undef HAVE_INET_NTOA_R_DECL

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* use ioctlsocket() for non-blocking sockets */
#undef HAVE_IOCTLSOCKET

/* use Ioctlsocket() for non-blocking sockets */
#undef HAVE_IOCTLSOCKET_CASE

/* Define to 1 if you have the <io.h> header file. */
#undef HAVE_IO_H

/* if you have the Kerberos4 libraries (including -ldes) */
#undef HAVE_KRB4

/* Define to 1 if you have the `krb_get_our_ip_for_realm' function. */
#undef HAVE_KRB_GET_OUR_IP_FOR_REALM

/* Define to 1 if you have the <krb.h> header file. */
#undef HAVE_KRB_H

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#undef HAVE_LIBCRYPTO

/* Define to 1 if you have the `dl' library (-ldl). */
#undef HAVE_LIBDL

/* Define to 1 if you have the `nsl' library (-lnsl). */
#undef HAVE_LIBNSL

/* Define to 1 if you have the `resolv' library (-lresolv). */
#undef HAVE_LIBRESOLV

/* Define to 1 if you have the `resolve' library (-lresolve). */
#undef HAVE_LIBRESOLVE

/* Define to 1 if you have the `socket' library (-lsocket). */
#undef HAVE_LIBSOCKET

/* Define to 1 if you have the `ssl' library (-lssl). */
#undef HAVE_LIBSSL

/* If zlib is available */
#undef HAVE_LIBZ
//#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `localtime_r' function. */
#undef HAVE_LOCALTIME_R

/* if your compiler supports 'long long' */
#define HAVE_LONGLONG 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#undef HAVE_NET_IF_H

/* Define to 1 if you have the <openssl/crypto.h> header file. */
#undef HAVE_OPENSSL_CRYPTO_H

/* Define to 1 if you have the <openssl/engine.h> header file. */
#undef HAVE_OPENSSL_ENGINE_H

/* Define to 1 if you have the <openssl/err.h> header file. */
#undef HAVE_OPENSSL_ERR_H

/* Define to 1 if you have the <openssl/pem.h> header file. */
#undef HAVE_OPENSSL_PEM_H

/* Define to 1 if you have the <openssl/rsa.h> header file. */
#undef HAVE_OPENSSL_RSA_H

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#undef HAVE_OPENSSL_SSL_H

/* Define to 1 if you have the <openssl/x509.h> header file. */
#undef HAVE_OPENSSL_X509_H

/* use O_NONBLOCK for non-blocking sockets */
#undef HAVE_O_NONBLOCK

/* Define to 1 if you have the <pem.h> header file. */
#undef HAVE_PEM_H

/* Define to 1 if you have the `perror' function. */
#undef HAVE_PERROR

/* Define to 1 if you have the `poll' function. */
#undef HAVE_POLL

/* Define to 1 if you have the <pwd.h> header file. */
#undef HAVE_PWD_H

/* Define to 1 if you have the `RAND_egd' function. */
#undef HAVE_RAND_EGD

/* Define to 1 if you have the `RAND_screen' function. */
#undef HAVE_RAND_SCREEN

/* Define to 1 if you have the `RAND_status' function. */
#undef HAVE_RAND_STATUS

/* Define to 1 if you have the <rsa.h> header file. */
#undef HAVE_RSA_H

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/* Define to 1 if you have the <sgtty.h> header file. */
#undef HAVE_SGTTY_H

/* Define to 1 if you have the `sigaction' function. */
#undef HAVE_SIGACTION

/* Define to 1 if you have the `siginterrupt' function. */
#undef HAVE_SIGINTERRUPT

/* Define to 1 if you have the `signal' function. */
#define HAVE_SIGNAL 1

/* If you have sigsetjmp */
#undef HAVE_SIGSETJMP

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* use SO_NONBLOCK for non-blocking sockets */
#undef HAVE_SO_NONBLOCK

/* Define this if you have the SPNEGO library fbopenssl */
#undef HAVE_SPNEGO

/* Define to 1 if you have the <ssl.h> header file. */
#undef HAVE_SSL_H

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strcmpi' function. */
#undef HAVE_STRCMPI

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Define to 1 if you have the `stricmp' function. */
#undef HAVE_STRICMP

/* Define to 1 if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtok_r' function. */
#undef HAVE_STRTOK_R

/* Define to 1 if you have the `strtoll' function. */
#undef HAVE_STRTOLL

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/poll.h> header file. */
#undef HAVE_SYS_POLL_H

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
#define HAVE_SYS_SOCKIO_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/utime.h> header file. */
#undef HAVE_SYS_UTIME_H

/* Define to 1 if you have the `tcgetattr' function. */
#undef HAVE_TCGETATTR

/* Define to 1 if you have the `tcsetattr' function. */
#undef HAVE_TCSETATTR

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the <termio.h> header file. */
#undef HAVE_TERMIO_H

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `utime' function. */
#define HAVE_UTIME 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if you have the <winsock.h> header file. */
#undef HAVE_WINSOCK_H

/* Define this symbol if your OS supports changing the contents of argv */
#undef HAVE_WRITABLE_ARGV

/* Define to 1 if you have the <x509.h> header file. */
#undef HAVE_X509_H

/* if you have the zlib.h header file */
#define HAVE_ZLIB_H 1

/* need REENTRANT defined */
#undef NEED_REENTRANT

/* cpu-machine-OS */
#define OS "i386-pc-NetWare"

/* Name of package */
#undef PACKAGE

/* Define to the address where bug reports for this package should be sent. */
#undef PACKAGE_BUGREPORT

/* Define to the full name of this package. */
#undef PACKAGE_NAME

/* Define to the full name and version of this package. */
#undef PACKAGE_STRING

/* Define to the one symbol short name of this package. */
#undef PACKAGE_TARNAME

/* Define to the version of this package. */
#undef PACKAGE_VERSION

/* a suitable file to read random data from */
#undef RANDOM_FILE

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to the type of arg 1 for `select'. */
#undef SELECT_TYPE_ARG1

/* Define to the type of args 2, 3 and 4 for `select'. */
#undef SELECT_TYPE_ARG234

/* Define to the type of arg 5 for `select'. */
#undef SELECT_TYPE_ARG5

/* The size of a `curl_off_t', as computed by sizeof. */
#define SIZEOF_CURL_OFF_T 4

/* Define to 1 if you have the ANSI C header files. */
/* XXX: #undef STDC_HEADERS */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define if you want to enable ares support */
#undef USE_ARES

/* Version number of package */
#undef VERSION

/* Define to 1 if on AIX 3.
   System headers sometimes define this.
   We just want to avoid a redefinition error message.  */
#ifndef _ALL_SOURCE
# undef _ALL_SOURCE
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
#undef _FILE_OFFSET_BITS

/* Define for large files, on AIX-style hosts. */
#undef _LARGE_FILES

/* Define to empty if `const' does not conform to ANSI C. */
#undef const

/* type to use in place of in_addr_t if not defined */
#undef in_addr_t

/* Define to `unsigned' if <sys/types.h> does not define. */
#undef size_t

/* type to use in place of socklen_t if not defined */
#define socklen_t int

/* the signed version of size_t */
#undef ssize_t


