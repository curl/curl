#ifndef HEADER_CURL_SERVER_UTIL_H
#define HEADER_CURL_SERVER_UTIL_H
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
#include "server_setup.h"

#ifdef USE_WINSOCK
/* errno.h values */
#undef  EINTR
#define EINTR    4
#undef  EAGAIN
#define EAGAIN  11
#undef  ENOMEM
#define ENOMEM  12
#undef  EINVAL
#define EINVAL  22
#undef  ERANGE
#define ERANGE  34
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

char *data_to_hex(char *data, size_t len);
void logmsg(const char *msg, ...) CURL_PRINTF(1, 2);

#define SERVERLOGS_LOCKDIR "lock"  /* within logdir */

/* global variable, where to find the 'data' dir */
extern const char *path;

/* global variable, log file name */
extern const char *serverlogfile;

#ifdef _WIN32
int win32_init(void);
const char *sstrerror(int err);
#else
#define sstrerror(e) strerror(e)
#endif

/* fopens the test case file */
FILE *test2fopen(long testno, const char *logdir);

int wait_ms(int timeout_ms);
curl_off_t our_getpid(void);
int write_pidfile(const char *filename);
int write_portfile(const char *filename, int port);
void set_advisor_read_lock(const char *filename);
void clear_advisor_read_lock(const char *filename);

/* global variable which if set indicates that the program should finish */
extern volatile int got_exit_signal;

/* global variable which if set indicates the first signal handled */
extern volatile int exit_signal;

#ifdef _WIN32
/* global event which if set indicates that the program should finish */
extern HANDLE exit_event;
#endif

void install_signal_handlers(bool keep_sigalrm);
void restore_signal_handlers(bool keep_sigalrm);

#ifdef USE_UNIX_SOCKETS
#include <curl/curl.h> /* for curl_socket_t */
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif
int bind_unix_socket(curl_socket_t sock, const char *unix_socket,
                     struct sockaddr_un *sau);
#endif /* USE_UNIX_SOCKETS */

unsigned short util_ultous(unsigned long ulnum);

#endif  /* HEADER_CURL_SERVER_UTIL_H */
