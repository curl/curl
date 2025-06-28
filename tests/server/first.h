#ifndef HEADER_SERVER_FIRST_H
#define HEADER_SERVER_FIRST_H
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

/* Test servers simply are standalone programs that do not use libcurl
 * library.  For convenience and to ease portability of these servers,
 * some source code files from the libcurl subdirectory are also used
 * to build the servers.  In order to achieve proper linkage of these
 * files on Windows targets it is necessary to build the test servers
 * with CURL_STATICLIB defined, independently of how libcurl is built.
 * For other platforms, this macro is a no-op and safe to set.
 */
#define CURL_STATICLIB

#define WITHOUT_LIBCURL
#define CURL_NO_OLDIES

#include "curl_setup.h"

typedef int (*entry_func_t)(int, char **);

struct entry_s {
  const char *name;
  entry_func_t ptr;
};

extern const struct entry_s s_entries[];

#ifndef UNDER_CE
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <curlx/curlx.h>

/* adjust for old MSVC */
#if defined(_MSC_VER) && (_MSC_VER < 1900)
#  define snprintf _snprintf
#endif

#ifdef _WIN32
#  define CURL_STRNICMP(p1, p2, n) _strnicmp(p1, p2, n)
#elif defined(HAVE_STRCASECMP)
#  ifdef HAVE_STRINGS_H
#  include <strings.h>
#  endif
#  define CURL_STRNICMP(p1, p2, n) strncasecmp(p1, p2, n)
#elif defined(HAVE_STRCMPI)
#  define CURL_STRNICMP(p1, p2, n) strncmpi(p1, p2, n)
#elif defined(HAVE_STRICMP)
#  define CURL_STRNICMP(p1, p2, n) strnicmp(p1, p2, n)
#else
#  error "missing case insensitive comparison function"
#endif

enum {
  DOCNUMBER_NOTHING    = -7,
  DOCNUMBER_QUIT       = -6,
  DOCNUMBER_BADCONNECT = -5,
  DOCNUMBER_INTERNAL   = -4,
  DOCNUMBER_CONNECT    = -3,
  DOCNUMBER_WERULEZ    = -2,
  DOCNUMBER_404        = -1
};

#include <curl/curl.h> /* for curl_socket_t */

#ifdef USE_UNIX_SOCKETS
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif
#endif /* USE_UNIX_SOCKETS */

typedef union {
  struct sockaddr      sa;
  struct sockaddr_in   sa4;
#ifdef USE_IPV6
  struct sockaddr_in6  sa6;
#endif
#ifdef USE_UNIX_SOCKETS
  struct sockaddr_un   sau;
#endif
} srvr_sockaddr_union_t;

/* getpart */
#define GPE_NO_BUFFER_SPACE -2
#define GPE_OUT_OF_MEMORY   -1
#define GPE_OK               0
#define GPE_END_OF_FILE      1

extern int getpart(char **outbuf, size_t *outlen,
                   const char *main, const char *sub, FILE *stream);

/* utility functions */
extern char *data_to_hex(char *data, size_t len);
extern void logmsg(const char *msg, ...);
extern void loghex(unsigned char *buffer, ssize_t len);
extern unsigned char byteval(char *value);
extern int win32_init(void);
extern const char *sstrerror(int err);
extern FILE *test2fopen(long testno, const char *logdir2);
extern curl_off_t our_getpid(void);
extern int write_pidfile(const char *filename);
extern int write_portfile(const char *filename, int port);
extern void set_advisor_read_lock(const char *filename);
extern void clear_advisor_read_lock(const char *filename);
static volatile int got_exit_signal = 0;
static volatile int exit_signal = 0;
#ifdef _WIN32
static HANDLE exit_event = NULL;
#endif
extern void install_signal_handlers(bool keep_sigalrm);
extern void restore_signal_handlers(bool keep_sigalrm);
#ifdef USE_UNIX_SOCKETS
extern int bind_unix_socket(curl_socket_t sock, const char *unix_socket,
                            struct sockaddr_un *sau);
#endif
extern unsigned short util_ultous(unsigned long ulnum);
extern curl_socket_t sockdaemon(curl_socket_t sock,
                                unsigned short *listenport,
                                const char *unix_socket,
                                bool bind_only);

/* global variables */
static const char *srcpath = "."; /* pointing to the test dir */
static const char *pidname = NULL;
static const char *portname = NULL; /* none by default */
static const char *serverlogfile = NULL;
static int serverlogslocked;
static const char *configfile = NULL;
static const char *logdir = "log";
static char loglockfile[256];
#ifdef USE_IPV6
static bool use_ipv6 = FALSE;
#endif
static const char *ipv_inuse = "IPv4";
static unsigned short server_port = 0;
static const char *socket_type = "IPv4";
static int socket_domain = AF_INET;

#define SERVERLOGS_LOCKDIR "lock"  /* within logdir */

#endif /* HEADER_SERVER_FIRST_H */
