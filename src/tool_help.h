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

void tool_help(char *category);
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
bool helpscan(unsigned char *buf, size_t len, struct scan_ctx *ctx);

struct helptxt {
  const char *opt;
  const char *desc;
  unsigned int categories;
};

/*
 * The bitmask output is generated with the following command
 ------------------------------------------------------------
  make -C docs/cmdline-opts listcats
 */

#define CURLHELP_AUTH       (1u << 0u)
#define CURLHELP_CONNECTION (1u << 1u)
#define CURLHELP_CURL       (1u << 2u)
#define CURLHELP_DEPRECATED (1u << 3u)
#define CURLHELP_DNS        (1u << 4u)
#define CURLHELP_FILE       (1u << 5u)
#define CURLHELP_FTP        (1u << 6u)
#define CURLHELP_GLOBAL     (1u << 7u)
#define CURLHELP_HTTP       (1u << 8u)
#define CURLHELP_IMAP       (1u << 9u)
#define CURLHELP_IMPORTANT  (1u << 10u)
#define CURLHELP_LDAP       (1u << 11u)
#define CURLHELP_OUTPUT     (1u << 12u)
#define CURLHELP_POP3       (1u << 13u)
#define CURLHELP_POST       (1u << 14u)
#define CURLHELP_PROXY      (1u << 15u)
#define CURLHELP_SCP        (1u << 16u)
#define CURLHELP_SFTP       (1u << 17u)
#define CURLHELP_SMTP       (1u << 18u)
#define CURLHELP_SSH        (1u << 19u)
#define CURLHELP_TELNET     (1u << 20u)
#define CURLHELP_TFTP       (1u << 21u)
#define CURLHELP_TIMEOUT    (1u << 22u)
#define CURLHELP_TLS        (1u << 23u)
#define CURLHELP_UPLOAD     (1u << 24u)
#define CURLHELP_VERBOSE    (1u << 25u)

#define CURLHELP_ALL        (0xfffffffu)

extern const struct helptxt helptext[];

#endif /* HEADER_CURL_TOOL_HELP_H */
