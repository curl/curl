#define OS "mac"

#define HAVE_NETINET_IN_H       1
#define HAVE_SYS_SOCKET_H       1
#define HAVE_SYS_SELECT_H       1
#define HAVE_NETDB_H            1
#define HAVE_ARPA_INET_H        1
#define HAVE_UNISTD_H           1
#define HAVE_NET_IF_H           1
#define HAVE_SYS_TYPES_H        1
#define HAVE_GETTIMEOFDAY       1
#define HAVE_FCNTL_H            1
#define HAVE_SYS_STAT_H         1
#define HAVE_ALLOCA_H           1
#define HAVE_TIME_H             1
#define HAVE_STDLIB_H           1
#define HAVE_UTIME_H            1

#define TIME_WITH_SYS_TIME      1

#define HAVE_STRDUP             1
#define HAVE_UTIME              1
#define HAVE_INET_NTOA          1
#define HAVE_SETVBUF            1
#define HAVE_STRFTIME           1
#define HAVE_INET_ADDR          1
#define HAVE_MEMCPY             1
#define HAVE_SELECT             1
#define HAVE_SOCKET             1

//#define HAVE_STRICMP          1
#define HAVE_SIGACTION          1

#ifdef MACOS_SSL_SUPPORT
#       define USE_SSLEAY       1
#       define USE_OPENSSL      1
#endif

#define CURL_DISABLE_LDAP       1

#define HAVE_RAND_STATUS        1
#define HAVE_RAND_EGD           1

#define HAVE_FIONBIO            1

#include <extra/stricmp.h>
#include <extra/strdup.h>
