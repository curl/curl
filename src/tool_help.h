#ifndef HEADER_FETCH_TOOL_HELP_H
#define HEADER_FETCH_TOOL_HELP_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

void tool_help(char *category);
void tool_list_engines(void);
void tool_version_info(void);
struct scan_ctx
{
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

struct helptxt
{
  const char *opt;
  const char *desc;
  unsigned int categories;
};

/*
 * The bitmask output is generated with the following command
 ------------------------------------------------------------
  make -C docs/cmdline-opts listcats
 */

#define FETCHHELP_AUTH (1u << 0u)
#define FETCHHELP_CONNECTION (1u << 1u)
#define FETCHHELP_FETCH (1u << 2u)
#define FETCHHELP_DEPRECATED (1u << 3u)
#define FETCHHELP_DNS (1u << 4u)
#define FETCHHELP_FILE (1u << 5u)
#define FETCHHELP_FTP (1u << 6u)
#define FETCHHELP_GLOBAL (1u << 7u)
#define FETCHHELP_HTTP (1u << 8u)
#define FETCHHELP_IMAP (1u << 9u)
#define FETCHHELP_IMPORTANT (1u << 10u)
#define FETCHHELP_LDAP (1u << 11u)
#define FETCHHELP_OUTPUT (1u << 12u)
#define FETCHHELP_POP3 (1u << 13u)
#define FETCHHELP_POST (1u << 14u)
#define FETCHHELP_PROXY (1u << 15u)
#define FETCHHELP_SCP (1u << 16u)
#define FETCHHELP_SFTP (1u << 17u)
#define FETCHHELP_SMTP (1u << 18u)
#define FETCHHELP_SSH (1u << 19u)
#define FETCHHELP_TELNET (1u << 20u)
#define FETCHHELP_TFTP (1u << 21u)
#define FETCHHELP_TIMEOUT (1u << 22u)
#define FETCHHELP_TLS (1u << 23u)
#define FETCHHELP_UPLOAD (1u << 24u)
#define FETCHHELP_VERBOSE (1u << 25u)

#define FETCHHELP_ALL (0xfffffffu)

extern const struct helptxt helptext[];

#endif /* HEADER_FETCH_TOOL_HELP_H */
