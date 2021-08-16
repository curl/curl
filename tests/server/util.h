#ifndef HEADER_CURL_SERVER_UTIL_H
#define HEADER_CURL_SERVER_UTIL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "server_setup.h"

char *data_to_hex(char *data, size_t len);
void logmsg(const char *msg, ...);
long timediff(struct timeval newer, struct timeval older);

#define TEST_DATA_PATH "%s/data/test%ld"
#define ALTTEST_DATA_PATH "%s/log/test%ld"

#define SERVERLOGS_LOCK "log/serverlogs.lock"

/* global variable, where to find the 'data' dir */
extern const char *path;

/* global variable, log file name */
extern const char *serverlogfile;

extern const char *cmdfile;

#if defined(WIN32) || defined(_WIN32)
#include <process.h>
#include <fcntl.h>

#define sleep(sec) Sleep ((sec)*1000)

#undef perror
#define perror(m) win32_perror(m)
void win32_perror(const char *msg);
#endif  /* WIN32 or _WIN32 */

#ifdef USE_WINSOCK
void win32_init(void);
void win32_cleanup(void);
#endif  /* USE_WINSOCK */

/* fopens the test case file */
FILE *test2fopen(long testno);

int wait_ms(int timeout_ms);
curl_off_t our_getpid(void);
int write_pidfile(const char *filename);
int write_portfile(const char *filename, int port);
void set_advisor_read_lock(const char *filename);
void clear_advisor_read_lock(const char *filename);
int strncasecompare(const char *first, const char *second, size_t max);

/* global variable which if set indicates that the program should finish */
extern volatile int got_exit_signal;

/* global variable which if set indicates the first signal handled */
extern volatile int exit_signal;

#ifdef WIN32
/* global event which if set indicates that the program should finish */
extern HANDLE exit_event;
#endif

void install_signal_handlers(bool keep_sigalrm);
void restore_signal_handlers(bool keep_sigalrm);

#endif  /* HEADER_CURL_SERVER_UTIL_H */
