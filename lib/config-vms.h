/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define if on AIX 3.
   System headers sometimes define this.
   We just want to avoid a redefinition error message.  */
#ifndef _ALL_SOURCE
#undef _ALL_SOURCE
#endif

/* Define to empty if the keyword does not work.  */
#undef const

/* Define as the return type of signal handlers (int or void).  */
#undef RETSIGTYPE

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
#undef size_t

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define cpu-machine-OS */
#define OS "ALPHA-COMPAQ-VMS"

/* Define if you have the gethostbyaddr_r() function with 5 arguments */
#undef HAVE_GETHOSTBYADDR_R_5

/* Define if you have the gethostbyaddr_r() function with 7 arguments */
#undef HAVE_GETHOSTBYADDR_R_7

/* Define if you have the gethostbyaddr_r() function with 8 arguments */
#undef HAVE_GETHOSTBYADDR_R_8

/* Define if you have the gethostbyname_r() function with 3 arguments */
#undef HAVE_GETHOSTBYNAME_R_3

/* Define if you have the gethostbyname_r() function with 5 arguments */
#undef HAVE_GETHOSTBYNAME_R_5

/* Define if you have the gethostbyname_r() function with 6 arguments */
#undef HAVE_GETHOSTBYNAME_R_6

/* Define if you have the inet_ntoa_r function declared. */
#undef HAVE_INET_NTOA_R_DECL

/* Define if you need the _REENTRANT define for some functions */
#undef NEED_REENTRANT

/* Define if you have the Kerberos4 libraries (including -ldes) */
#undef HAVE_KRB4

/* Define this to 'int' if ssize_t is not an available typedefed type */
#undef ssize_t

/* Define this to 'int' if socklen_t is not an available typedefed type */
#define socklen_t size_t

/* Define this as a suitable file to read random data from */
#undef RANDOM_FILE

/* Define this to your Entropy Gathering Daemon socket pathname */
#undef EGD_SOCKET

/* The number of bytes in a long double.  */
#define SIZEOF_LONG_DOUBLE 8

/* The number of bytes in a long long.  */
#define SIZEOF_LONG_LONG 8

/* Define if you have the RAND_egd function.  */
#undef HAVE_RAND_EGD

/* Define if you have the RAND_screen function.  */
#undef HAVE_RAND_SCREEN

/* Define if you have the RAND_status function.  */
#undef HAVE_RAND_STATUS

/* Define if you have the closesocket function.  */
#undef HAVE_CLOSESOCKET

/* Define if you have the geteuid function.  */
#define HAVE_GETEUID 1

/* Define if you have the gethostbyaddr function.  */
#define HAVE_GETHOSTBYADDR 1

/* Define if you have the gethostbyaddr_r function.  */
#undef HAVE_GETHOSTBYADDR_R

/* Define if you have the gethostbyname_r function.  */
#undef HAVE_GETHOSTBYNAME_R

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getpass_r function.  */
#undef HAVE_GETPASS_R

/* Define if you have the getpwuid function.  */
#define HAVE_GETPWUID 1

/* Define if you have the getservbyname function.  */
#define HAVE_GETSERVBYNAME 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the inet_addr function.  */
#define HAVE_INET_ADDR 1

/* Define if you have the inet_ntoa function.  */
#define HAVE_INET_NTOA 1

/* Define if you have the inet_ntoa_r function.  */
#undef HAVE_INET_NTOA_R

/* Define if you have the krb_get_our_ip_for_realm function.  */
#undef HAVE_KRB_GET_OUR_IP_FOR_REALM

/* Define if you have the localtime_r function.  */
#undef HAVE_LOCALTIME_R

/* Define if you have the perror function.  */
#define HAVE_PERROR 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the setvbuf function.  */
#undef HAVE_SETVBUF

/* Define if you have the sigaction function.  */
#define HAVE_SIGACTION 1

/* Define if you have the signal function.  */
#define HAVE_SIGNAL 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strcasecmp function.  */
#define HAVE_STRCASECMP 1

/* Define if you have the strcmpi function.  */
#define HAVE_STRCMPI 1

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the strftime function.  */
#define HAVE_STRFTIME 1

/* Define if you have the stricmp function.  */
#define HAVE_STRICMP 1

/* Define if you have the strlcat function.  */
#undef HAVE_STRLCAT

/* Define if you have the strlcpy function.  */
#undef HAVE_STRLCPY

/* Define if you have the strstr function.  */
#define  HAVE_STRSTR 1

/* Define if you have the tcgetattr function.  */
#undef HAVE_TCGETATTR

/* Define if you have the tcsetattr function.  */
#undef HAVE_TCSETATTR

/* Define if you have the uname function.  */
#define HAVE_UNAME 1

/* Define if you have the <alloca.h> header file.  */
#undef HAVE_ALLOCA_H

/* Define if you have the <arpa/inet.h> header file.  */
#undef HAVE_ARPA_INET_H

/* Define if you have the <crypto.h> header file.  */
#undef HAVE_CRYPTO_H

/* Define if you have the <des.h> header file.  */
#undef HAVE_DES_H

/* Define if you have the <dlfcn.h> header file.  */
#undef HAVE_DLFCN_H

/* Define if you have the <err.h> header file.  */
#define HAVE_ERR_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
#define HAVE_GETOPT_H 1

/* Define if you have the <io.h> header file.  */
#undef HAVE_IO_H

/* Define if you have the <krb.h> header file.  */
#undef HAVE_KRB_H

/* Define if you have the <malloc.h> header file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <net/if.h> header file.  */
#define HAVE_NET_IF_H 1

/* Define if you have the <netdb.h> header file.  */
#define HAVE_NETDB_H 1

/* Define if you have the <netinet/if_ether.h> header file.  */
#define HAVE_NETINET_IF_ETHER_H 1

/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <openssl/crypto.h> header file.  */
#define HAVE_OPENSSL_CRYPTO_H 1

/* Define if you have the <openssl/err.h> header file.  */
#define HAVE_OPENSSL_ERR_H	1

/* Define if you have the <openssl/pem.h> header file.  */
#define HAVE_OPENSSL_PEM_H	1

/* Define if you have the <openssl/rsa.h> header file.  */
#define HAVE_OPENSSL_RSA_H 1

/* Define if you have the <openssl/ssl.h> header file.  */
#define HAVE_OPENSSL_SSL_H	1

/* Define if you have the <openssl/x509.h> header file.  */
#define HAVE_OPENSSL_X509_H	1

/* Define if you have the <pem.h> header file.  */
#undef HAVE_PEM_H

/* Define if you have the <pwd.h> header file.  */
#define HAVE_PWD_H 1

/* Define if you have the <rsa.h> header file.  */
#undef HAVE_RSA_H

/* Define if you have the <sgtty.h> header file.  */
#define HAVE_SGTTY_H 1

/* Define if you have the <ssl.h> header file.  */
#undef HAVE_SSL_H

/* Define if you have the <stdlib.h> header file.  */
#define HAVE_STDLIB_H 1

/* Define if you have the <sys/param.h> header file.  */
#undef HAVE_SYS_PARAM_H

/* Define if you have the <sys/select.h> header file.  */
#undef HAVE_SYS_SELECT_H

/* Define if you have the <sys/socket.h> header file.  */
#define HAVE_SYS_SOCKET_H 1

/* Define if you have the <sys/sockio.h> header file.  */
#undef HAVE_SYS_SOCKIO_H

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <termio.h> header file.  */
#undef HAVE_TERMIO_H

/* Define if you have the <termios.h> header file.  */
#define HAVE_TERMIOS_H 1

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the <winsock.h> header file.  */
#undef HAVE_WINSOCK_H

/* Define if you have the <x509.h> header file.  */
#undef HAVE_X509_H

/* Define if you have the crypto library (-lcrypto).  */
#define HAVE_LIBCRYPTO 1

/* Define if you have the dl library (-ldl).  */
#undef HAVE_LIBDL

/* Define if you have the nsl library (-lnsl).  */
#undef HAVE_LIBNSL

/* Define if you have the resolv library (-lresolv).  */
#define HAVE_LIBRESOLV 1

/* Define if you have the resolve library (-lresolve).  */
#undef HAVE_LIBRESOLVE

/* Define if you have the socket library (-lsocket).  */
#define HAVE_LIBSOCKET 1

/* Define if you have the ssl library (-lssl).  */
#define HAVE_LIBSSL	1

/* Define if you have the ucb library (-lucb).  */
#undef HAVE_LIBUCB

/* Number of bits in a file offset, on hosts where this is settable. */
#undef _FILE_OFFSET_BITS

/* Define for large files, on AIX-style hosts. */
#undef _LARGE_FILES

/* Define if getaddrinfo exists and works */
#define HAVE_GETADDRINFO 1

/* Define if you want to enable IPv6 support */
#undef ENABLE_IPV6

/* Set to explicitly specify we don't want to use thread-safe functions */
#undef DISABLED_THREADSAFE

#define	HAVE_TIMEVAL_H	1

/* Name of this package! */
#define PACKAGE "not-used"

/* Version number of this archive. */
#define VERSION "not-used"

/* Define if you have the getpass function.  */
#undef HAVE_GETPASS

/* Define if you have a working OpenSSL installation */
#define OPENSSL_ENABLED	1

/* Define if you have the `dlopen' function. */
#undef HAVE_DLOPEN

/* Define if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have the `strtok_r' function. */
#undef HAVE_STRTOK_R

/* Define if you have the `strtoll' function. */
#undef HAVE_STRTOLL

#define HAVE_MEMORY_H   1

#define HAVE_FIONBIO	1

/* Define if you have the `sigsetjmp' function. */
#define HAVE_SIGSETJMP 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/*
 * This needs to be defined for OpenSSL 0.9.7 and other versions that have the
 * ENGINE stuff supported. If an include of "openssl/engine.h" fails, then
 * undefine the define below.
*/
#define HAVE_OPENSSL_ENGINE_H 1
