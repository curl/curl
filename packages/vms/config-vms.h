/* MSK, 02/05/04, Hand edited for trail build on Alpha V7.3, DEC C 6.5-003 */
/* MSK, 03/09/04, Seems to work for all platforms I've built on so far.    */
/*      Added HAVE_SYS_IOCTL_H, IOCTL_3_ARGS and SIZEOF_CURL_OFF_T defines */
/* MSK, 06/04/04, Added HAVE_INET_NTOP                                     */
/* TES, 10/06/04, Added MAX_INITIAL_POST_SIZE, HAVE_BASENAME               */
/* MSK, 02/02/05, Changed HAVE_TERMIOS_H to an undef since the change in   */
/*                getpass.c no longer undef'd it during compile.           */
/* MSK, 02/08/05, turned two config-vms files into one by using USE_SSLEAY */

/* Define cpu-machine-OS */
#ifdef __ALPHA
#define OS "ALPHA-HP-VMS"
#else
#ifdef __VAX
#define OS "VAX-HP-VMS"
#else
#define OS "IA64-HP-VMS"
#endif
#endif

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define this to 'int' if socklen_t is not an available typedefed type */
#define socklen_t size_t

/* The number of bytes in a long double.  */
#define SIZEOF_LONG_DOUBLE 8

/* The number of bytes in a long long.  */
#define SIZEOF_LONG_LONG 8

/* Define if you have the geteuid function.  */
#define HAVE_GETEUID 1

/* Define if you have the basename function. */
#define HAVE_BASENAME 1

/* Define if you have the gethostbyaddr function.  */
#define HAVE_GETHOSTBYADDR 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

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

/* Define if you have the perror function.  */
#define HAVE_PERROR 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the setvbuf function.  */
#define HAVE_SETVBUF 1

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

/* Define if you have the strstr function.  */
#define  HAVE_STRSTR 1

/* Define if you have the ftruncate function. */
#define HAVE_FTRUNCATE 1

/* Define if you have the uname function.  */
#define HAVE_UNAME 1

/* Define if you have the <err.h> header file.  */
#define HAVE_ERR_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
#define HAVE_GETOPT_H 1

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

/* OpenSSL section starts here */

/* Define if you have a working OpenSSL installation */
#ifdef USE_SSLEAY

/* if OpenSSL is in use */
#define USE_OPENSSL 1

/* Define if you have the crypto library (-lcrypto).  */
#define HAVE_LIBCRYPTO 1

/* Define if you have the ssl library (-lssl).  */
#define HAVE_LIBSSL	1

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

/*
 * This needs to be defined for OpenSSL 0.9.7 and other versions that have the
 * ENGINE stuff supported. If an include of "openssl/engine.h" fails, then
 * undefine the define below.
*/
#define HAVE_OPENSSL_ENGINE_H 1

#endif /* USE_SSLEAY */
/* OpenSSL section ends here */

/* Define if you have the <pwd.h> header file.  */
#define HAVE_PWD_H 1

/* Define if you have the <sgtty.h> header file.  */
#define HAVE_SGTTY_H 1

/* Define if you have the <stdlib.h> header file.  */
#define HAVE_STDLIB_H 1

/* Define if you have the <sys/socket.h> header file.  */
#define HAVE_SYS_SOCKET_H 1

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <termios.h> header file.  */
#undef HAVE_TERMIOS_H 

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the resolv library (-lresolv).  */
#define HAVE_LIBRESOLV 1

/* Define if you have the socket library (-lsocket).  */
#define HAVE_LIBSOCKET 1

/* Define if getaddrinfo exists and works */
#define HAVE_GETADDRINFO 1

#define	HAVE_TIMEVAL_H	1

/* Name of this package! */
#define PACKAGE "not-used"

/* Version number of this archive. */
#define VERSION "not-used"

/* Define if you have the getpass function.  */
#undef HAVE_GETPASS

/* Define if you have the `dlopen' function. */
#define HAVE_DLOPEN 1

/* Define if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have the `strtok_r' function.       */
/* Seems VAX V7.3 with DEC C 6.4 doesn't define this */
#ifdef __VAX
#undef HAVE_STRTOK_R
#else
#define HAVE_STRTOK_R 1
#endif

/* Define if you have the `strtoll' function. */
#define HAVE_STRTOLL 1

/* Define if you have the <memory.h> header file. */
#define HAVE_MEMORY_H   1

#define HAVE_FIONBIO	1

/* Define if you have the `sigsetjmp' function. */
#define HAVE_SIGSETJMP 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* IOCTL_3_ARGS defined to match the ioctl function in stropts.h */
#define IOCTL_3_ARGS 1

/* Seems with versions of cURL after 7.11.0 you need to define */
/* SIZEOF_CURL_OFF_T to something to get it to compile.        */
#if defined( __VAX) || (__32BITS == 1)
#define SIZEOF_CURL_OFF_T 4
#else
#define SIZEOF_CURL_OFF_T 8
#endif

/* Somewhere around 7.12.0 HAVE_INET_NTOP was introduced. */
#define HAVE_INET_NTOP 1

/* to disable LDAP */
#define CURL_DISABLE_LDAP 1
