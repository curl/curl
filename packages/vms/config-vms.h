/* MSK, 02/05/04, Hand edited for trail build on Alpha V7.3, DEC C 6.5-003 */
/* MSK, 03/09/04, Seems to work for all platforms I've built on so far.    */
/*      Added HAVE_SYS_IOCTL_H define                                      */
/* TES, 10/06/04, Added MAX_INITIAL_POST_SIZE, HAVE_BASENAME               */
/* MSK, 02/02/05, Changed HAVE_TERMIOS_H to an undef since the change in   */
/*                getpass.c no longer undef'd it during compile.           */
/* MSK, 02/08/05, turned two config-vms files into one by using USE_SSLEAY */
/* MPZ, 12/28/05, changed HAVE_STRTOK_R define to use CRTL_VER             */
/* MSK, 01/27/07, needed to add HAVE_STRUCT_TIMEVAL define                 */

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

/* Type to use in place of socklen_t when system does not provide it.  */
#define socklen_t size_t

/* The number of bytes in a long double.  */
#define SIZEOF_LONG_DOUBLE 8

/* The number of bytes in a long long.  */
#define SIZEOF_LONG_LONG 8

/* Define if you have the alarm function.  */
#define HAVE_ALARM 1

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

/* Define if you have the ioctl function. */
#define HAVE_IOCTL 1

/* Define if you have a working ioctl FIONBIO function. */
#define HAVE_IOCTL_FIONBIO 1

/* Define if you have a working ioctl SIOCGIFADDR function. */
#define HAVE_IOCTL_SIOCGIFADDR 1

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

/* Define if you need the malloc.h header header file even with stdlib.h  */
/* #define NEED_MALLOC_H 1 */

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

/* Define if you have the <timeval.h> header file.  */
#define	HAVE_TIMEVAL_H	1

/* Define if you have the timeval struct.  */
#define	HAVE_STRUCT_TIMEVAL 1

/* Name of this package! */
#define PACKAGE "not-used"

/* Version number of this archive. */
#define VERSION "not-used"

/* Define if you have the getpass function.  */
#undef HAVE_GETPASS

/* Define if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have the `strtok_r' function.  */
/* Condition lifted from <string.h>             */
#if __CRTL_VER >= 70301000
#define HAVE_STRTOK_R 1
#endif

/* Define if you have the `strtoll' function. */
#define HAVE_STRTOLL 1

/* Define if you have the <memory.h> header file. */
#define HAVE_MEMORY_H   1

/* Define if you have the `sigsetjmp' function. */
#define HAVE_SIGSETJMP 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <stropts.h> header file. */
#define HAVE_STROPTS_H 1

/* to disable LDAP */
#define CURL_DISABLE_LDAP 1

/* Define if you have the getnameinfo function. */
#define HAVE_GETNAMEINFO 1

/* Define to the type qualifier of arg 1 for getnameinfo. */
#define GETNAMEINFO_QUAL_ARG1 const

/* Define to the type of arg 1 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG1 struct sockaddr *

/* Define to the type of arg 2 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG2 socklen_t

/* Define to the type of args 4 and 6 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG46 size_t

/* Define to the type of arg 7 for getnameinfo. */
#define GETNAMEINFO_TYPE_ARG7 int

/* Define if you have the recv function. */
#define HAVE_RECV 1

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 int

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 void *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 int

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 int

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV int

/* Define if you have the recvfrom function. */
#define HAVE_RECVFROM 1

/* Define to the type of arg 1 for recvfrom. */
#define RECVFROM_TYPE_ARG1 int

/* Define to the type pointed by arg 2 for recvfrom. */
#define RECVFROM_TYPE_ARG2 void

/* Define if the type pointed by arg 2 for recvfrom is void. */
#define RECVFROM_TYPE_ARG2_IS_VOID 1

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
#define SEND_TYPE_ARG1 int

/* Define to the type qualifier of arg 2 for send. */
#define SEND_QUAL_ARG2 const

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 void *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 int

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV int

/* Define to hide dollar sign from compilers in strict ansi mode. */
#define decc_translate_vms(__s) decc$translate_vms(__s)

