#ifndef HEADER_CURL_TOOL_HELP_H
#define HEADER_CURL_TOOL_HELP_H
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
#include "tool_setup.h"

void tool_help(const char *category);
void tool_list_engines(void);
void tool_version_info(void);
struct scan_ctx {
  const char *trigger;
  size_t tlen;
  const char *arg;
  size_t flen;
  const char *endarg;
  size_t elen;
  size_t olen;
  char rbuf[40];
  char obuf[160];
  unsigned char show; /* start as at 0.
                         trigger match moves it to 1
                         arg match moves it to 2
                         endarg stops the search */
};
void inithelpscan(struct scan_ctx *ctx, const char *trigger,
                  const char *arg, const char *endarg);
bool helpscan(const unsigned char *buf, size_t len, struct scan_ctx *ctx);

struct helptxt {
  const char *opt;
  const char *desc;
  unsigned int categories;
};

/*
  The bitmask output is generated with the following command:
  ------------------------------------------------------------
  make -C docs/cmdline-opts listcats
 */

#define CURLHELP_AUTH       (1 << 0)
#define CURLHELP_CONNECTION (1 << 1)
#define CURLHELP_CURL       (1 << 2)
#define CURLHELP_DEPRECATED (1 << 3)
#define CURLHELP_DNS        (1 << 4)
#define CURLHELP_FILE       (1 << 5)
#define CURLHELP_FTP        (1 << 6)
#define CURLHELP_GLOBAL     (1 << 7)
#define CURLHELP_HTTP       (1 << 8)
#define CURLHELP_IMAP       (1 << 9)
#define CURLHELP_IMPORTANT  (1 << 10)
#define CURLHELP_LDAP       (1 << 11)
#define CURLHELP_OUTPUT     (1 << 12)
#define CURLHELP_POP3       (1 << 13)
#define CURLHELP_POST       (1 << 14)
#define CURLHELP_PROXY      (1 << 15)
#define CURLHELP_SCP        (1 << 16)
#define CURLHELP_SFTP       (1 << 17)
#define CURLHELP_SMTP       (1 << 18)
#define CURLHELP_SSH        (1 << 19)
#define CURLHELP_TELNET     (1 << 20)
#define CURLHELP_TFTP       (1 << 21)
#define CURLHELP_TIMEOUT    (1 << 22)
#define CURLHELP_TLS        (1 << 23)
#define CURLHELP_UPLOAD     (1 << 24)
#define CURLHELP_VERBOSE    (1 << 25)

#define CURLHELP_ALL        0xfffffffU

extern const struct helptxt helptext[];

#endif /* HEADER_CURL_TOOL_HELP_H */
