/* lib/curl_config.h.in.  Generated somehow by cmake.  */

/* when building libcurl itself */
#cmakedefine BUILDING_LIBCURL ${BUILDING_LIBCURL}

/* Location of default ca bundle */
#cmakedefine CURL_CA_BUNDLE ${CURL_CA_BUNDLE}

/* Location of default ca path */
#cmakedefine CURL_CA_PATH ${CURL_CA_PATH}

/* to disable cookies support */
#cmakedefine CURL_DISABLE_COOKIES ${CURL_DISABLE_COOKIES}

/* to disable cryptographic authentication */
#cmakedefine CURL_DISABLE_CRYPTO_AUTH ${CURL_DISABLE_CRYPTO_AUTH}

/* to disable DICT */
#cmakedefine CURL_DISABLE_DICT ${CURL_DISABLE_DICT}

/* to disable FILE */
#cmakedefine CURL_DISABLE_FILE ${CURL_DISABLE_FILE}

/* to disable FTP */
#cmakedefine CURL_DISABLE_FTP ${CURL_DISABLE_FTP}

/* to disable HTTP */
#cmakedefine CURL_DISABLE_HTTP ${CURL_DISABLE_HTTP}

/* to disable LDAP */
#cmakedefine CURL_DISABLE_LDAP ${CURL_DISABLE_LDAP}

/* to disable LDAPS */
#cmakedefine CURL_DISABLE_LDAPS ${CURL_DISABLE_LDAPS}

/* to disable proxies */
#cmakedefine CURL_DISABLE_PROXY ${CURL_DISABLE_PROXY}

/* to disable TELNET */
#cmakedefine CURL_DISABLE_TELNET ${CURL_DISABLE_TELNET}

/* to disable TFTP */
#cmakedefine CURL_DISABLE_TFTP ${CURL_DISABLE_TFTP}

/* to disable verbose strings */
#cmakedefine CURL_DISABLE_VERBOSE_STRINGS ${CURL_DISABLE_VERBOSE_STRINGS}

/* to make a symbol visible */
#cmakedefine CURL_EXTERN_SYMBOL ${CURL_EXTERN_SYMBOL}
/* Ensure using CURL_EXTERN_SYMBOL is possible */
#ifndef CURL_EXTERN_SYMBOL
#define CURL_EXTERN_SYMBOL
#endif

/* Use Windows LDAP implementation */
#cmakedefine CURL_LDAP_WIN ${CURL_LDAP_WIN}

/* when not building a shared library */
#cmakedefine CURL_STATICLIB ${CURL_STATICLIB}

/* Set to explicitly specify we don't want to use thread-safe functions */
#cmakedefine DISABLED_THREADSAFE ${DISABLED_THREADSAFE}

/* your Entropy Gathering Daemon socket pathname */
#cmakedefine EGD_SOCKET ${EGD_SOCKET}

/* Define if you want to enable IPv6 support */
#cmakedefine ENABLE_IPV6 ${ENABLE_IPV6}

/* Define to the type qualifier of arg 1 for getnameinfo. */
#cmakedefine GETNAMEINFO_QUAL_ARG1 ${GETNAMEINFO_QUAL_ARG1}

/* Define to the type of arg 1 for getnameinfo. */
#cmakedefine GETNAMEINFO_TYPE_ARG1 ${GETNAMEINFO_TYPE_ARG1}

/* Define to the type of arg 2 for getnameinfo. */
#cmakedefine GETNAMEINFO_TYPE_ARG2 ${GETNAMEINFO_TYPE_ARG2}

/* Define to the type of args 4 and 6 for getnameinfo. */
#cmakedefine GETNAMEINFO_TYPE_ARG46 ${GETNAMEINFO_TYPE_ARG46}

/* Define to the type of arg 7 for getnameinfo. */
#cmakedefine GETNAMEINFO_TYPE_ARG7 ${GETNAMEINFO_TYPE_ARG7}

/* Specifies the number of arguments to getservbyport_r */
#cmakedefine GETSERVBYPORT_R_ARGS ${GETSERVBYPORT_R_ARGS}

/* Specifies the size of the buffer to pass to getservbyport_r */
#cmakedefine GETSERVBYPORT_R_BUFSIZE ${GETSERVBYPORT_R_BUFSIZE}

/* Define to 1 if you have the alarm function. */
#cmakedefine HAVE_ALARM ${HAVE_ALARM}

/* Define to 1 if you have the <alloca.h> header file. */
#cmakedefine HAVE_ALLOCA_H ${HAVE_ALLOCA_H}

/* Define to 1 if you have the <arpa/inet.h> header file. */
#cmakedefine HAVE_ARPA_INET_H ${HAVE_ARPA_INET_H}

/* Define to 1 if you have the <arpa/tftp.h> header file. */
#cmakedefine HAVE_ARPA_TFTP_H ${HAVE_ARPA_TFTP_H}

/* Define to 1 if you have the <assert.h> header file. */
#cmakedefine HAVE_ASSERT_H ${HAVE_ASSERT_H}

/* Define to 1 if you have the `basename' function. */
#cmakedefine HAVE_BASENAME ${HAVE_BASENAME}

/* Define to 1 if bool is an available type. */
#cmakedefine HAVE_BOOL_T ${HAVE_BOOL_T}

/* Define to 1 if you have the clock_gettime function and monotonic timer. */
#cmakedefine HAVE_CLOCK_GETTIME_MONOTONIC ${HAVE_CLOCK_GETTIME_MONOTONIC}

/* Define to 1 if you have the `closesocket' function. */
#cmakedefine HAVE_CLOSESOCKET ${HAVE_CLOSESOCKET}

/* Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function. */
#cmakedefine HAVE_CRYPTO_CLEANUP_ALL_EX_DATA ${HAVE_CRYPTO_CLEANUP_ALL_EX_DATA}

/* Define to 1 if you have the <crypto.h> header file. */
#cmakedefine HAVE_CRYPTO_H ${HAVE_CRYPTO_H}

/* Define to 1 if you have the <des.h> header file. */
#cmakedefine HAVE_DES_H ${HAVE_DES_H}

/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine HAVE_DLFCN_H ${HAVE_DLFCN_H}

/* Define to 1 if you have the `ENGINE_load_builtin_engines' function. */
#cmakedefine HAVE_ENGINE_LOAD_BUILTIN_ENGINES ${HAVE_ENGINE_LOAD_BUILTIN_ENGINES}

/* Define to 1 if you have the <errno.h> header file. */
#cmakedefine HAVE_ERRNO_H ${HAVE_ERRNO_H}

/* Define to 1 if you have the <err.h> header file. */
#cmakedefine HAVE_ERR_H ${HAVE_ERR_H}

/* Define to 1 if you have the fcntl function. */
#cmakedefine HAVE_FCNTL ${HAVE_FCNTL}

/* Define to 1 if you have the <fcntl.h> header file. */
#cmakedefine HAVE_FCNTL_H ${HAVE_FCNTL_H}

/* Define to 1 if you have a working fcntl O_NONBLOCK function. */
#cmakedefine HAVE_FCNTL_O_NONBLOCK ${HAVE_FCNTL_O_NONBLOCK}

/* Define to 1 if you have the fdopen function. */
#cmakedefine HAVE_FDOPEN ${HAVE_FDOPEN}

/* Define to 1 if you have the `fork' function. */
#cmakedefine HAVE_FORK ${HAVE_FORK}

/* Define to 1 if you have the freeaddrinfo function. */
#cmakedefine HAVE_FREEADDRINFO ${HAVE_FREEADDRINFO}

/* Define to 1 if you have the freeifaddrs function. */
#cmakedefine HAVE_FREEIFADDRS ${HAVE_FREEIFADDRS}

/* Define to 1 if you have the ftruncate function. */
#cmakedefine HAVE_FTRUNCATE ${HAVE_FTRUNCATE}

/* Define to 1 if you have a working getaddrinfo function. */
#cmakedefine HAVE_GETADDRINFO ${HAVE_GETADDRINFO}

/* Define to 1 if you have the `geteuid' function. */
#cmakedefine HAVE_GETEUID ${HAVE_GETEUID}

/* Define to 1 if you have the gethostbyaddr function. */
#cmakedefine HAVE_GETHOSTBYADDR ${HAVE_GETHOSTBYADDR}

/* Define to 1 if you have the gethostbyaddr_r function. */
#cmakedefine HAVE_GETHOSTBYADDR_R ${HAVE_GETHOSTBYADDR_R}

/* gethostbyaddr_r() takes 5 args */
#cmakedefine HAVE_GETHOSTBYADDR_R_5 ${HAVE_GETHOSTBYADDR_R_5}

/* gethostbyaddr_r() takes 7 args */
#cmakedefine HAVE_GETHOSTBYADDR_R_7 ${HAVE_GETHOSTBYADDR_R_7}

/* gethostbyaddr_r() takes 8 args */
#cmakedefine HAVE_GETHOSTBYADDR_R_8 ${HAVE_GETHOSTBYADDR_R_8}

/* Define to 1 if you have the gethostbyname function. */
#cmakedefine HAVE_GETHOSTBYNAME ${HAVE_GETHOSTBYNAME}

/* Define to 1 if you have the gethostbyname_r function. */
#cmakedefine HAVE_GETHOSTBYNAME_R ${HAVE_GETHOSTBYNAME_R}

/* gethostbyname_r() takes 3 args */
#cmakedefine HAVE_GETHOSTBYNAME_R_3 ${HAVE_GETHOSTBYNAME_R_3}

/* gethostbyname_r() takes 5 args */
#cmakedefine HAVE_GETHOSTBYNAME_R_5 ${HAVE_GETHOSTBYNAME_R_5}

/* gethostbyname_r() takes 6 args */
#cmakedefine HAVE_GETHOSTBYNAME_R_6 ${HAVE_GETHOSTBYNAME_R_6}

/* Define to 1 if you have the gethostname function. */
#cmakedefine HAVE_GETHOSTNAME ${HAVE_GETHOSTNAME}

/* Define to 1 if you have a working getifaddrs function. */
#cmakedefine HAVE_GETIFADDRS ${HAVE_GETIFADDRS}

/* Define to 1 if you have the getnameinfo function. */
#cmakedefine HAVE_GETNAMEINFO ${HAVE_GETNAMEINFO}

/* Define to 1 if you have the `getpass_r' function. */
#cmakedefine HAVE_GETPASS_R ${HAVE_GETPASS_R}

/* Define to 1 if you have the `getppid' function. */
#cmakedefine HAVE_GETPPID ${HAVE_GETPPID}

/* Define to 1 if you have the `getprotobyname' function. */
#cmakedefine HAVE_GETPROTOBYNAME ${HAVE_GETPROTOBYNAME}

/* Define to 1 if you have the `getpwuid' function. */
#cmakedefine HAVE_GETPWUID ${HAVE_GETPWUID}

/* Define to 1 if you have the `getrlimit' function. */
#cmakedefine HAVE_GETRLIMIT ${HAVE_GETRLIMIT}

/* Define to 1 if you have the getservbyport_r function. */
#cmakedefine HAVE_GETSERVBYPORT_R ${HAVE_GETSERVBYPORT_R}

/* Define to 1 if you have the `gettimeofday' function. */
#cmakedefine HAVE_GETTIMEOFDAY ${HAVE_GETTIMEOFDAY}

/* Define to 1 if you have a working glibc-style strerror_r function. */
#cmakedefine HAVE_GLIBC_STRERROR_R ${HAVE_GLIBC_STRERROR_R}

/* Define to 1 if you have a working gmtime_r function. */
#cmakedefine HAVE_GMTIME_R ${HAVE_GMTIME_R}

/* if you have the gssapi libraries */
#cmakedefine HAVE_GSSAPI ${HAVE_GSSAPI}

/* Define to 1 if you have the <gssapi/gssapi_generic.h> header file. */
#cmakedefine HAVE_GSSAPI_GSSAPI_GENERIC_H ${HAVE_GSSAPI_GSSAPI_GENERIC_H}

/* Define to 1 if you have the <gssapi/gssapi.h> header file. */
#cmakedefine HAVE_GSSAPI_GSSAPI_H ${HAVE_GSSAPI_GSSAPI_H}

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
#cmakedefine HAVE_GSSAPI_GSSAPI_KRB5_H ${HAVE_GSSAPI_GSSAPI_KRB5_H}

/* if you have the GNU gssapi libraries */
#cmakedefine HAVE_GSSGNU ${HAVE_GSSGNU}

/* if you have the Heimdal gssapi libraries */
#cmakedefine HAVE_GSSHEIMDAL ${HAVE_GSSHEIMDAL}

/* if you have the MIT gssapi libraries */
#cmakedefine HAVE_GSSMIT ${HAVE_GSSMIT}

/* Define to 1 if you have the `idna_strerror' function. */
#cmakedefine HAVE_IDNA_STRERROR ${HAVE_IDNA_STRERROR}

/* Define to 1 if you have the `idn_free' function. */
#cmakedefine HAVE_IDN_FREE ${HAVE_IDN_FREE}

/* Define to 1 if you have the <idn-free.h> header file. */
#cmakedefine HAVE_IDN_FREE_H ${HAVE_IDN_FREE_H}

/* Define to 1 if you have the <ifaddrs.h> header file. */
#cmakedefine HAVE_IFADDRS_H ${HAVE_IFADDRS_H}

/* Define to 1 if you have the `inet_addr' function. */
#cmakedefine HAVE_INET_ADDR ${HAVE_INET_ADDR}

/* Define to 1 if you have the inet_ntoa_r function. */
#cmakedefine HAVE_INET_NTOA_R ${HAVE_INET_NTOA_R}

/* inet_ntoa_r() takes 2 args */
#cmakedefine HAVE_INET_NTOA_R_2 ${HAVE_INET_NTOA_R_2}

/* inet_ntoa_r() takes 3 args */
#cmakedefine HAVE_INET_NTOA_R_3 ${HAVE_INET_NTOA_R_3}

/* Define to 1 if you have a IPv6 capable working inet_ntop function. */
#cmakedefine HAVE_INET_NTOP ${HAVE_INET_NTOP}

/* Define to 1 if you have a IPv6 capable working inet_pton function. */
#cmakedefine HAVE_INET_PTON ${HAVE_INET_PTON}

/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine HAVE_INTTYPES_H ${HAVE_INTTYPES_H}

/* Define to 1 if you have the ioctl function. */
#cmakedefine HAVE_IOCTL ${HAVE_IOCTL}

/* Define to 1 if you have the ioctlsocket function. */
#cmakedefine HAVE_IOCTLSOCKET ${HAVE_IOCTLSOCKET}

/* Define to 1 if you have the IoctlSocket camel case function. */
#cmakedefine HAVE_IOCTLSOCKET_CAMEL ${HAVE_IOCTLSOCKET_CAMEL}

/* Define to 1 if you have a working IoctlSocket camel case FIONBIO function.
   */
#cmakedefine HAVE_IOCTLSOCKET_CAMEL_FIONBIO ${HAVE_IOCTLSOCKET_CAMEL_FIONBIO}

/* Define to 1 if you have a working ioctlsocket FIONBIO function. */
#cmakedefine HAVE_IOCTLSOCKET_FIONBIO ${HAVE_IOCTLSOCKET_FIONBIO}

/* Define to 1 if you have a working ioctl FIONBIO function. */
#cmakedefine HAVE_IOCTL_FIONBIO ${HAVE_IOCTL_FIONBIO}

/* Define to 1 if you have a working ioctl SIOCGIFADDR function. */
#cmakedefine HAVE_IOCTL_SIOCGIFADDR ${HAVE_IOCTL_SIOCGIFADDR}

/* Define to 1 if you have the <io.h> header file. */
#cmakedefine HAVE_IO_H ${HAVE_IO_H}

/* if you have the Kerberos4 libraries (including -ldes) */
#cmakedefine HAVE_KRB4 ${HAVE_KRB4}

/* Define to 1 if you have the `krb_get_our_ip_for_realm' function. */
#cmakedefine HAVE_KRB_GET_OUR_IP_FOR_REALM ${HAVE_KRB_GET_OUR_IP_FOR_REALM}

/* Define to 1 if you have the <krb.h> header file. */
#cmakedefine HAVE_KRB_H ${HAVE_KRB_H}

/* Define to 1 if you have the lber.h header file. */
#cmakedefine HAVE_LBER_H ${HAVE_LBER_H}

/* Define to 1 if you have the ldapssl.h header file. */
#cmakedefine HAVE_LDAPSSL_H ${HAVE_LDAPSSL_H}

/* Define to 1 if you have the ldap.h header file. */
#cmakedefine HAVE_LDAP_H ${HAVE_LDAP_H}

/* Use LDAPS implementation */
#cmakedefine HAVE_LDAP_SSL ${HAVE_LDAP_SSL}

/* Define to 1 if you have the ldap_ssl.h header file. */
#cmakedefine HAVE_LDAP_SSL_H ${HAVE_LDAP_SSL_H}

/* Define to 1 if you have the `ldap_url_parse' function. */
#cmakedefine HAVE_LDAP_URL_PARSE ${HAVE_LDAP_URL_PARSE}

/* Define to 1 if you have the <libgen.h> header file. */
#cmakedefine HAVE_LIBGEN_H ${HAVE_LIBGEN_H}

/* Define to 1 if you have the `idn' library (-lidn). */
#cmakedefine HAVE_LIBIDN ${HAVE_LIBIDN}

/* Define to 1 if you have the `resolv' library (-lresolv). */
#cmakedefine HAVE_LIBRESOLV ${HAVE_LIBRESOLV}

/* Define to 1 if you have the `resolve' library (-lresolve). */
#cmakedefine HAVE_LIBRESOLVE ${HAVE_LIBRESOLVE}

/* Define to 1 if you have the `socket' library (-lsocket). */
#cmakedefine HAVE_LIBSOCKET ${HAVE_LIBSOCKET}

/* Define to 1 if you have the `ssh2' library (-lssh2). */
#cmakedefine HAVE_LIBSSH2 ${HAVE_LIBSSH2}

/* Define to 1 if you have the <libssh2.h> header file. */
#cmakedefine HAVE_LIBSSH2_H ${HAVE_LIBSSH2_H}

/* Define to 1 if you have the `ssl' library (-lssl). */
#cmakedefine HAVE_LIBSSL ${HAVE_LIBSSL}

/* if zlib is available */
#cmakedefine HAVE_LIBZ ${HAVE_LIBZ}

/* Define to 1 if you have the <limits.h> header file. */
#cmakedefine HAVE_LIMITS_H ${HAVE_LIMITS_H}

/* if your compiler supports LL */
#cmakedefine HAVE_LL ${HAVE_LL}

/* Define to 1 if you have the <locale.h> header file. */
#cmakedefine HAVE_LOCALE_H ${HAVE_LOCALE_H}

/* Define to 1 if you have a working localtime_r function. */
#cmakedefine HAVE_LOCALTIME_R ${HAVE_LOCALTIME_R}

/* Define to 1 if the compiler supports the 'long long' data type. */
#cmakedefine HAVE_LONGLONG ${HAVE_LONGLONG}

/* Define to 1 if you have the malloc.h header file. */
#cmakedefine HAVE_MALLOC_H ${HAVE_MALLOC_H}

/* Define to 1 if you have the <memory.h> header file. */
#cmakedefine HAVE_MEMORY_H ${HAVE_MEMORY_H}

/* Define to 1 if you have the MSG_NOSIGNAL flag. */
#cmakedefine HAVE_MSG_NOSIGNAL ${HAVE_MSG_NOSIGNAL}

/* Define to 1 if you have the <netdb.h> header file. */
#cmakedefine HAVE_NETDB_H ${HAVE_NETDB_H}

/* Define to 1 if you have the <netinet/in.h> header file. */
#cmakedefine HAVE_NETINET_IN_H ${HAVE_NETINET_IN_H}

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#cmakedefine HAVE_NETINET_TCP_H ${HAVE_NETINET_TCP_H}

/* Define to 1 if you have the <net/if.h> header file. */
#cmakedefine HAVE_NET_IF_H ${HAVE_NET_IF_H}

/* Define to 1 if NI_WITHSCOPEID exists and works. */
#cmakedefine HAVE_NI_WITHSCOPEID ${HAVE_NI_WITHSCOPEID}

/* if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE
   */
#cmakedefine HAVE_OLD_GSSMIT ${HAVE_OLD_GSSMIT}

/* Define to 1 if you have the <openssl/crypto.h> header file. */
#cmakedefine HAVE_OPENSSL_CRYPTO_H ${HAVE_OPENSSL_CRYPTO_H}

/* Define to 1 if you have the <openssl/engine.h> header file. */
#cmakedefine HAVE_OPENSSL_ENGINE_H ${HAVE_OPENSSL_ENGINE_H}

/* Define to 1 if you have the <openssl/err.h> header file. */
#cmakedefine HAVE_OPENSSL_ERR_H ${HAVE_OPENSSL_ERR_H}

/* Define to 1 if you have the <openssl/pem.h> header file. */
#cmakedefine HAVE_OPENSSL_PEM_H ${HAVE_OPENSSL_PEM_H}

/* Define to 1 if you have the <openssl/pkcs12.h> header file. */
#cmakedefine HAVE_OPENSSL_PKCS12_H ${HAVE_OPENSSL_PKCS12_H}

/* Define to 1 if you have the <openssl/rsa.h> header file. */
#cmakedefine HAVE_OPENSSL_RSA_H ${HAVE_OPENSSL_RSA_H}

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#cmakedefine HAVE_OPENSSL_SSL_H ${HAVE_OPENSSL_SSL_H}

/* Define to 1 if you have the <openssl/x509.h> header file. */
#cmakedefine HAVE_OPENSSL_X509_H ${HAVE_OPENSSL_X509_H}

/* Define to 1 if you have the <pem.h> header file. */
#cmakedefine HAVE_PEM_H ${HAVE_PEM_H}

/* Define to 1 if you have the `perror' function. */
#cmakedefine HAVE_PERROR ${HAVE_PERROR}

/* Define to 1 if you have the `pipe' function. */
#cmakedefine HAVE_PIPE ${HAVE_PIPE}

/* Define to 1 if you have a working poll function. */
#cmakedefine HAVE_POLL ${HAVE_POLL}

/* If you have a fine poll */
#cmakedefine HAVE_POLL_FINE ${HAVE_POLL_FINE}

/* Define to 1 if you have the <poll.h> header file. */
#cmakedefine HAVE_POLL_H ${HAVE_POLL_H}

/* Define to 1 if you have a working POSIX-style strerror_r function. */
#cmakedefine HAVE_POSIX_STRERROR_R ${HAVE_POSIX_STRERROR_R}

/* Define to 1 if you have the <pwd.h> header file. */
#cmakedefine HAVE_PWD_H ${HAVE_PWD_H}

/* Define to 1 if you have the `RAND_egd' function. */
#cmakedefine HAVE_RAND_EGD ${HAVE_RAND_EGD}

/* Define to 1 if you have the `RAND_screen' function. */
#cmakedefine HAVE_RAND_SCREEN ${HAVE_RAND_SCREEN}

/* Define to 1 if you have the `RAND_status' function. */
#cmakedefine HAVE_RAND_STATUS ${HAVE_RAND_STATUS}

/* Define to 1 if you have the recv function. */
#cmakedefine HAVE_RECV ${HAVE_RECV}

/* Define to 1 if you have the recvfrom function. */
#cmakedefine HAVE_RECVFROM ${HAVE_RECVFROM}

/* Define to 1 if you have the <rsa.h> header file. */
#cmakedefine HAVE_RSA_H ${HAVE_RSA_H}

/* Define to 1 if you have the select function. */
#cmakedefine HAVE_SELECT ${HAVE_SELECT}

/* Define to 1 if you have the send function. */
#cmakedefine HAVE_SEND ${HAVE_SEND}

/* Define to 1 if you have the <setjmp.h> header file. */
#cmakedefine HAVE_SETJMP_H ${HAVE_SETJMP_H}

/* Define to 1 if you have the `setlocale' function. */
#cmakedefine HAVE_SETLOCALE ${HAVE_SETLOCALE}

/* Define to 1 if you have the `setmode' function. */
#cmakedefine HAVE_SETMODE ${HAVE_SETMODE}

/* Define to 1 if you have the `setrlimit' function. */
#cmakedefine HAVE_SETRLIMIT ${HAVE_SETRLIMIT}

/* Define to 1 if you have the setsockopt function. */
#cmakedefine HAVE_SETSOCKOPT ${HAVE_SETSOCKOPT}

/* Define to 1 if you have a working setsockopt SO_NONBLOCK function. */
#cmakedefine HAVE_SETSOCKOPT_SO_NONBLOCK ${HAVE_SETSOCKOPT_SO_NONBLOCK}

/* Define to 1 if you have the <sgtty.h> header file. */
#cmakedefine HAVE_SGTTY_H ${HAVE_SGTTY_H}

/* Define to 1 if you have the sigaction function. */
#cmakedefine HAVE_SIGACTION ${HAVE_SIGACTION}

/* Define to 1 if you have the siginterrupt function. */
#cmakedefine HAVE_SIGINTERRUPT ${HAVE_SIGINTERRUPT}

/* Define to 1 if you have the signal function. */
#cmakedefine HAVE_SIGNAL ${HAVE_SIGNAL}

/* Define to 1 if you have the <signal.h> header file. */
#cmakedefine HAVE_SIGNAL_H ${HAVE_SIGNAL_H}

/* Define to 1 if you have the sigsetjmp function or macro. */
#cmakedefine HAVE_SIGSETJMP ${HAVE_SIGSETJMP}

/* Define to 1 if sig_atomic_t is an available typedef. */
#cmakedefine HAVE_SIG_ATOMIC_T ${HAVE_SIG_ATOMIC_T}

/* Define to 1 if sig_atomic_t is already defined as volatile. */
#cmakedefine HAVE_SIG_ATOMIC_T_VOLATILE ${HAVE_SIG_ATOMIC_T_VOLATILE}

/* Define to 1 if struct sockaddr_in6 has the sin6_scope_id member */
#cmakedefine HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID ${HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID}

/* Define to 1 if you have the `socket' function. */
#cmakedefine HAVE_SOCKET ${HAVE_SOCKET}

/* Define this if you have the SPNEGO library fbopenssl */
#cmakedefine HAVE_SPNEGO ${HAVE_SPNEGO}

/* Define to 1 if you have the `SSL_get_shutdown' function. */
#cmakedefine HAVE_SSL_GET_SHUTDOWN ${HAVE_SSL_GET_SHUTDOWN}

/* Define to 1 if you have the <ssl.h> header file. */
#cmakedefine HAVE_SSL_H ${HAVE_SSL_H}

/* Define to 1 if you have the <stdbool.h> header file. */
#cmakedefine HAVE_STDBOOL_H ${HAVE_STDBOOL_H}

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H ${HAVE_STDINT_H}

/* Define to 1 if you have the <stdio.h> header file. */
#cmakedefine HAVE_STDIO_H ${HAVE_STDIO_H}

/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine HAVE_STDLIB_H ${HAVE_STDLIB_H}

/* Define to 1 if you have the strcasecmp function. */
#cmakedefine HAVE_STRCASECMP ${HAVE_STRCASECMP}

/* Define to 1 if you have the strcasestr function. */
#cmakedefine HAVE_STRCASESTR ${HAVE_STRCASESTR}

/* Define to 1 if you have the strcmpi function. */
#cmakedefine HAVE_STRCMPI ${HAVE_STRCMPI}

/* Define to 1 if you have the strdup function. */
#cmakedefine HAVE_STRDUP ${HAVE_STRDUP}

/* Define to 1 if you have the strerror_r function. */
#cmakedefine HAVE_STRERROR_R ${HAVE_STRERROR_R}

/* Define to 1 if you have the stricmp function. */
#cmakedefine HAVE_STRICMP ${HAVE_STRICMP}

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H ${HAVE_STRINGS_H}

/* Define to 1 if you have the <string.h> header file. */
#cmakedefine HAVE_STRING_H ${HAVE_STRING_H}

/* Define to 1 if you have the strlcat function. */
#cmakedefine HAVE_STRLCAT ${HAVE_STRLCAT}

/* Define to 1 if you have the `strlcpy' function. */
#cmakedefine HAVE_STRLCPY ${HAVE_STRLCPY}

/* Define to 1 if you have the strncasecmp function. */
#cmakedefine HAVE_STRNCASECMP ${HAVE_STRNCASECMP}

/* Define to 1 if you have the strncmpi function. */
#cmakedefine HAVE_STRNCMPI ${HAVE_STRNCMPI}

/* Define to 1 if you have the strnicmp function. */
#cmakedefine HAVE_STRNICMP ${HAVE_STRNICMP}

/* Define to 1 if you have the <stropts.h> header file. */
#cmakedefine HAVE_STROPTS_H ${HAVE_STROPTS_H}

/* Define to 1 if you have the strstr function. */
#cmakedefine HAVE_STRSTR ${HAVE_STRSTR}

/* Define to 1 if you have the strtok_r function. */
#cmakedefine HAVE_STRTOK_R ${HAVE_STRTOK_R}

/* Define to 1 if you have the strtoll function. */
#cmakedefine HAVE_STRTOLL ${HAVE_STRTOLL}

/* if struct sockaddr_storage is defined */
#cmakedefine HAVE_STRUCT_SOCKADDR_STORAGE ${HAVE_STRUCT_SOCKADDR_STORAGE}

/* Define to 1 if you have the timeval struct. */
#cmakedefine HAVE_STRUCT_TIMEVAL ${HAVE_STRUCT_TIMEVAL}

/* Define to 1 if you have the <sys/filio.h> header file. */
#cmakedefine HAVE_SYS_FILIO_H ${HAVE_SYS_FILIO_H}

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#cmakedefine HAVE_SYS_IOCTL_H ${HAVE_SYS_IOCTL_H}

/* Define to 1 if you have the <sys/param.h> header file. */
#cmakedefine HAVE_SYS_PARAM_H ${HAVE_SYS_PARAM_H}

/* Define to 1 if you have the <sys/poll.h> header file. */
#cmakedefine HAVE_SYS_POLL_H ${HAVE_SYS_POLL_H}

/* Define to 1 if you have the <sys/resource.h> header file. */
#cmakedefine HAVE_SYS_RESOURCE_H ${HAVE_SYS_RESOURCE_H}

/* Define to 1 if you have the <sys/select.h> header file. */
#cmakedefine HAVE_SYS_SELECT_H ${HAVE_SYS_SELECT_H}

/* Define to 1 if you have the <sys/socket.h> header file. */
#cmakedefine HAVE_SYS_SOCKET_H ${HAVE_SYS_SOCKET_H}

/* Define to 1 if you have the <sys/sockio.h> header file. */
#cmakedefine HAVE_SYS_SOCKIO_H ${HAVE_SYS_SOCKIO_H}

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H ${HAVE_SYS_STAT_H}

/* Define to 1 if you have the <sys/time.h> header file. */
#cmakedefine HAVE_SYS_TIME_H ${HAVE_SYS_TIME_H}

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H ${HAVE_SYS_TYPES_H}

/* Define to 1 if you have the <sys/uio.h> header file. */
#cmakedefine HAVE_SYS_UIO_H ${HAVE_SYS_UIO_H}

/* Define to 1 if you have the <sys/un.h> header file. */
#cmakedefine HAVE_SYS_UN_H ${HAVE_SYS_UN_H}

/* Define to 1 if you have the <sys/utime.h> header file. */
#cmakedefine HAVE_SYS_UTIME_H ${HAVE_SYS_UTIME_H}

/* Define to 1 if you have the <termios.h> header file. */
#cmakedefine HAVE_TERMIOS_H ${HAVE_TERMIOS_H}

/* Define to 1 if you have the <termio.h> header file. */
#cmakedefine HAVE_TERMIO_H ${HAVE_TERMIO_H}

/* Define to 1 if you have the <time.h> header file. */
#cmakedefine HAVE_TIME_H ${HAVE_TIME_H}

/* Define to 1 if you have the <tld.h> header file. */
#cmakedefine HAVE_TLD_H ${HAVE_TLD_H}

/* Define to 1 if you have the `tld_strerror' function. */
#cmakedefine HAVE_TLD_STRERROR ${HAVE_TLD_STRERROR}

/* Define to 1 if you have the `uname' function. */
#cmakedefine HAVE_UNAME ${HAVE_UNAME}

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H ${HAVE_UNISTD_H}

/* Define to 1 if you have the `utime' function. */
#cmakedefine HAVE_UTIME ${HAVE_UTIME}

/* Define to 1 if you have the <utime.h> header file. */
#cmakedefine HAVE_UTIME_H ${HAVE_UTIME_H}

/* Define to 1 if compiler supports C99 variadic macro style. */
#cmakedefine HAVE_VARIADIC_MACROS_C99 ${HAVE_VARIADIC_MACROS_C99}

/* Define to 1 if compiler supports old gcc variadic macro style. */
#cmakedefine HAVE_VARIADIC_MACROS_GCC ${HAVE_VARIADIC_MACROS_GCC}

/* Define to 1 if you have the winber.h header file. */
#cmakedefine HAVE_WINBER_H ${HAVE_WINBER_H}

/* Define to 1 if you have the windows.h header file. */
#cmakedefine HAVE_WINDOWS_H ${HAVE_WINDOWS_H}

/* Define to 1 if you have the winldap.h header file. */
#cmakedefine HAVE_WINLDAP_H ${HAVE_WINLDAP_H}

/* Define to 1 if you have the winsock2.h header file. */
#cmakedefine HAVE_WINSOCK2_H ${HAVE_WINSOCK2_H}

/* Define to 1 if you have the winsock.h header file. */
#cmakedefine HAVE_WINSOCK_H ${HAVE_WINSOCK_H}

/* Define this symbol if your OS supports changing the contents of argv */
#cmakedefine HAVE_WRITABLE_ARGV ${HAVE_WRITABLE_ARGV}

/* Define to 1 if you have the writev function. */
#cmakedefine HAVE_WRITEV ${HAVE_WRITEV}

/* Define to 1 if you have the ws2tcpip.h header file. */
#cmakedefine HAVE_WS2TCPIP_H ${HAVE_WS2TCPIP_H}

/* Define to 1 if you have the <x509.h> header file. */
#cmakedefine HAVE_X509_H ${HAVE_X509_H}

/* Define if you have the <process.h> header file. */
#cmakedefine HAVE_PROCESS_H ${HAVE_PROCESS_H}

/* if you have the zlib.h header file */
#cmakedefine HAVE_ZLIB_H ${HAVE_ZLIB_H}

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#cmakedefine LT_OBJDIR ${LT_OBJDIR}

/* If you lack a fine basename() prototype */
#cmakedefine NEED_BASENAME_PROTO ${NEED_BASENAME_PROTO}

/* Define to 1 if you need the lber.h header file even with ldap.h */
#cmakedefine NEED_LBER_H ${NEED_LBER_H}

/* Define to 1 if you need the malloc.h header file even with stdlib.h */
#cmakedefine NEED_MALLOC_H ${NEED_MALLOC_H}

/* Define to 1 if _REENTRANT preprocessor symbol must be defined. */
#cmakedefine NEED_REENTRANT ${NEED_REENTRANT}

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

/* a suitable file to read random data from */
#cmakedefine RANDOM_FILE "${RANDOM_FILE}"

/* Define to the type of arg 1 for recvfrom. */
#cmakedefine RECVFROM_TYPE_ARG1 ${RECVFROM_TYPE_ARG1}

/* Define to the type pointed by arg 2 for recvfrom. */
#cmakedefine RECVFROM_TYPE_ARG2 ${RECVFROM_TYPE_ARG2}

/* Define to 1 if the type pointed by arg 2 for recvfrom is void. */
#cmakedefine RECVFROM_TYPE_ARG2_IS_VOID ${RECVFROM_TYPE_ARG2_IS_VOID}

/* Define to the type of arg 3 for recvfrom. */
#cmakedefine RECVFROM_TYPE_ARG3 ${RECVFROM_TYPE_ARG3}

/* Define to the type of arg 4 for recvfrom. */
#cmakedefine RECVFROM_TYPE_ARG4 ${RECVFROM_TYPE_ARG4}

/* Define to the type pointed by arg 5 for recvfrom. */
#cmakedefine RECVFROM_TYPE_ARG5 ${RECVFROM_TYPE_ARG5}

/* Define to 1 if the type pointed by arg 5 for recvfrom is void. */
#cmakedefine RECVFROM_TYPE_ARG5_IS_VOID ${RECVFROM_TYPE_ARG5_IS_VOID}

/* Define to the type pointed by arg 6 for recvfrom. */
#cmakedefine RECVFROM_TYPE_ARG6 ${RECVFROM_TYPE_ARG6}

/* Define to 1 if the type pointed by arg 6 for recvfrom is void. */
#cmakedefine RECVFROM_TYPE_ARG6_IS_VOID ${RECVFROM_TYPE_ARG6_IS_VOID}

/* Define to the function return type for recvfrom. */
#cmakedefine RECVFROM_TYPE_RETV ${RECVFROM_TYPE_RETV}

/* Define to the type of arg 1 for recv. */
#cmakedefine RECV_TYPE_ARG1 ${RECV_TYPE_ARG1}

/* Define to the type of arg 2 for recv. */
#cmakedefine RECV_TYPE_ARG2 ${RECV_TYPE_ARG2}

/* Define to the type of arg 3 for recv. */
#cmakedefine RECV_TYPE_ARG3 ${RECV_TYPE_ARG3}

/* Define to the type of arg 4 for recv. */
#cmakedefine RECV_TYPE_ARG4 ${RECV_TYPE_ARG4}

/* Define to the function return type for recv. */
#cmakedefine RECV_TYPE_RETV ${RECV_TYPE_RETV}

/* Define as the return type of signal handlers (`int' or `void'). */
#cmakedefine RETSIGTYPE ${RETSIGTYPE}

/* Define to the type qualifier of arg 5 for select. */
#cmakedefine SELECT_QUAL_ARG5 ${SELECT_QUAL_ARG5}

/* Define to the type of arg 1 for select. */
#cmakedefine SELECT_TYPE_ARG1 ${SELECT_TYPE_ARG1}

/* Define to the type of args 2, 3 and 4 for select. */
#cmakedefine SELECT_TYPE_ARG234 ${SELECT_TYPE_ARG234}

/* Define to the type of arg 5 for select. */
#cmakedefine SELECT_TYPE_ARG5 ${SELECT_TYPE_ARG5}

/* Define to the function return type for select. */
#cmakedefine SELECT_TYPE_RETV ${SELECT_TYPE_RETV}

/* Define to the type qualifier of arg 2 for send. */
#cmakedefine SEND_QUAL_ARG2 ${SEND_QUAL_ARG2}

/* Define to the type of arg 1 for send. */
#cmakedefine SEND_TYPE_ARG1 ${SEND_TYPE_ARG1}

/* Define to the type of arg 2 for send. */
#cmakedefine SEND_TYPE_ARG2 ${SEND_TYPE_ARG2}

/* Define to the type of arg 3 for send. */
#cmakedefine SEND_TYPE_ARG3 ${SEND_TYPE_ARG3}

/* Define to the type of arg 4 for send. */
#cmakedefine SEND_TYPE_ARG4 ${SEND_TYPE_ARG4}

/* Define to the function return type for send. */
#cmakedefine SEND_TYPE_RETV ${SEND_TYPE_RETV}

/* The size of `int', as computed by sizeof. */
#cmakedefine SIZEOF_INT ${SIZEOF_INT}

/* The size of `short', as computed by sizeof. */
#cmakedefine SIZEOF_SHORT ${SIZEOF_SHORT}

/* The size of `long', as computed by sizeof. */
#cmakedefine SIZEOF_LONG ${SIZEOF_LONG}

/* The size of `off_t', as computed by sizeof. */
#cmakedefine SIZEOF_OFF_T ${SIZEOF_OFF_T}

/* The size of `size_t', as computed by sizeof. */
#cmakedefine SIZEOF_SIZE_T ${SIZEOF_SIZE_T}

/* The size of `time_t', as computed by sizeof. */
#cmakedefine SIZEOF_TIME_T ${SIZEOF_TIME_T}

/* The size of `void*', as computed by sizeof. */
#cmakedefine SIZEOF_VOIDP ${SIZEOF_VOIDP}

/* Define to 1 if you have the ANSI C header files. */
#cmakedefine STDC_HEADERS ${STDC_HEADERS}

/* Define to the type of arg 3 for strerror_r. */
#cmakedefine STRERROR_R_TYPE_ARG3 ${STRERROR_R_TYPE_ARG3}

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#cmakedefine TIME_WITH_SYS_TIME ${TIME_WITH_SYS_TIME}

/* Define if you want to enable c-ares support */
#cmakedefine USE_ARES ${USE_ARES}

/* Define to disable non-blocking sockets. */
#cmakedefine USE_BLOCKING_SOCKETS ${USE_BLOCKING_SOCKETS}

/* if GnuTLS is enabled */
#cmakedefine USE_GNUTLS ${USE_GNUTLS}

/* if PolarSSL is enabled */
#cmakedefine USE_POLARSSL ${USE_POLARSSL}

/* if libSSH2 is in use */
#cmakedefine USE_LIBSSH2 ${USE_LIBSSH2}

/* If you want to build curl with the built-in manual */
#cmakedefine USE_MANUAL ${USE_MANUAL}

/* if NSS is enabled */
#cmakedefine USE_NSS ${USE_NSS}

/* if OpenSSL is in use */
#cmakedefine USE_OPENSSL ${USE_OPENSSL}

/* if SSL is enabled */
#cmakedefine USE_SSLEAY ${USE_SSLEAY}

/* Define to 1 if you are building a Windows target without large file
   support. */
#cmakedefine USE_WIN32_LARGE_FILES ${USE_WIN32_LARGE_FILES}

/* to enable SSPI support */
#cmakedefine USE_WINDOWS_SSPI ${USE_WINDOWS_SSPI}

/* Define to 1 if using yaSSL in OpenSSL compatibility mode. */
#cmakedefine USE_YASSLEMUL ${USE_YASSLEMUL}

/* Version number of package */
#cmakedefine VERSION ${VERSION}

/* Define to avoid automatic inclusion of winsock.h */
#cmakedefine WIN32_LEAN_AND_MEAN ${WIN32_LEAN_AND_MEAN}

/* Define to 1 if OS is AIX. */
#ifndef _ALL_SOURCE
#  undef _ALL_SOURCE
#endif

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

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#undef inline
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
#cmakedefine size_t ${size_t}

/* the signed version of size_t */
#cmakedefine ssize_t ${ssize_t}
