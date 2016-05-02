#ifndef HEADER_CURL_SERVER_UTIL_H
#define HEADER_CURL_SERVER_UTIL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#define TEST_DATA_PATH "%s/data/test%ld"

#define SERVERLOGS_LOCK "log/serverlogs.lock"

/* global variable, where to find the 'data' dir */
extern const char *path;

/* global variable, log file name */
extern const char *serverlogfile;

#ifdef WIN32
#include <process.h>
#include <fcntl.h>

#define sleep(sec)   Sleep ((sec)*1000)

#undef perror
#define perror(m) win32_perror(m)
void win32_perror (const char *msg);
#endif  /* WIN32 */

#ifdef USE_WINSOCK
void win32_init(void);
void win32_cleanup(void);
#endif  /* USE_WINSOCK */

/* returns the path name to the test case file */
char *test2file(long testno);

int wait_ms(int timeout_ms);

int write_pidfile(const char *filename);

void set_advisor_read_lock(const char *filename);

void clear_advisor_read_lock(const char *filename);

#endif  /* HEADER_CURL_SERVER_UTIL_H */
