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

#define CURLHELP_AUTH       (1U << 0U)
#define CURLHELP_CONNECTION (1U << 1U)
#define CURLHELP_CURL       (1U << 2U)
#define CURLHELP_DEPRECATED (1U << 3U)
#define CURLHELP_DNS        (1U << 4U)
#define CURLHELP_FILE       (1U << 5U)
#define CURLHELP_FTP        (1U << 6U)
#define CURLHELP_GLOBAL     (1U << 7U)
#define CURLHELP_HTTP       (1U << 8U)
#define CURLHELP_IMAP       (1U << 9U)
#define CURLHELP_IMPORTANT  (1U << 10U)
#define CURLHELP_LDAP       (1U << 11U)
#define CURLHELP_OUTPUT     (1U << 12U)
#define CURLHELP_POP3       (1U << 13U)
#define CURLHELP_POST       (1U << 14U)
#define CURLHELP_PROXY      (1U << 15U)
#define CURLHELP_SCP        (1U << 16U)
#define CURLHELP_SFTP       (1U << 17U)
#define CURLHELP_SMTP       (1U << 18U)
#define CURLHELP_SSH        (1U << 19U)
#define CURLHELP_TELNET     (1U << 20U)
#define CURLHELP_TFTP       (1U << 21U)
#define CURLHELP_TIMEOUT    (1U << 22U)
#define CURLHELP_TLS        (1U << 23U)
#define CURLHELP_UPLOAD     (1U << 24U)
#define CURLHELP_VERBOSE    (1U << 25U)

#define CURLHELP_ALL        (0xfffffffU)

extern const struct helptxt helptext[];

#endif /* HEADER_CURL_TOOL_HELP_H */
