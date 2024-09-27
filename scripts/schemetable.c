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
#include <stdio.h>
#include <curl/curl.h>

/*
 * Use this tool to generate an updated table for the Curl_getn_scheme_handler
 * function in url.c.
 */

struct detail {
  const char *n;
  const char *ifdef;
};

static const struct detail scheme[] = {
  {"dict", "#ifndef CURL_DISABLE_DICT" },
  {"file", "#ifndef CURL_DISABLE_FILE" },
  {"ftp", "#ifndef CURL_DISABLE_FTP" },
  {"ftps", "#if defined(USE_SSL) && !defined(CURL_DISABLE_FTP)" },
  {"gopher", "#ifndef CURL_DISABLE_GOPHER" },
  {"gophers", "#if defined(USE_SSL) && !defined(CURL_DISABLE_GOPHER)" },
  {"http", "#ifndef CURL_DISABLE_HTTP" },
  {"https", "#if defined(USE_SSL) && !defined(CURL_DISABLE_HTTP)" },
  {"imap", "#ifndef CURL_DISABLE_IMAP" },
  {"imaps", "#if defined(USE_SSL) && !defined(CURL_DISABLE_IMAP)" },
  {"ldap", "#ifndef CURL_DISABLE_LDAP" },
  {"ldaps", "#if !defined(CURL_DISABLE_LDAP) && \\\n"
   "  !defined(CURL_DISABLE_LDAPS) && \\\n"
   "  ((defined(USE_OPENLDAP) && defined(USE_SSL)) || \\\n"
   "   (!defined(USE_OPENLDAP) && defined(HAVE_LDAP_SSL)))" },
  {"mqtt", "#ifndef CURL_DISABLE_MQTT" },
  {"pop3", "#ifndef CURL_DISABLE_POP3" },
  {"pop3s", "#if defined(USE_SSL) && !defined(CURL_DISABLE_POP3)" },
  {"rtmp", "#ifdef USE_LIBRTMP" },
  {"rtmpt", "#ifdef USE_LIBRTMP" },
  {"rtmpe", "#ifdef USE_LIBRTMP" },
  {"rtmpte", "#ifdef USE_LIBRTMP" },
  {"rtmps", "#ifdef USE_LIBRTMP" },
  {"rtmpts", "#ifdef USE_LIBRTMP" },
  {"rtsp", "#ifndef CURL_DISABLE_RTSP" },
  {"scp", "#if defined(USE_SSH) && !defined(USE_WOLFSSH)" },
  {"sftp", "#if defined(USE_SSH)" },
  {"smb", "#if !defined(CURL_DISABLE_SMB) && \\\n"
   "  defined(USE_CURL_NTLM_CORE) && (SIZEOF_CURL_OFF_T > 4)" },
  {"smbs", "#if defined(USE_SSL) && !defined(CURL_DISABLE_SMB) && \\\n"
   "  defined(USE_CURL_NTLM_CORE) && (SIZEOF_CURL_OFF_T > 4)" },
  {"smtp", "#ifndef CURL_DISABLE_SMTP" },
  {"smtps", "#if defined(USE_SSL) && !defined(CURL_DISABLE_SMTP)" },
  {"telnet", "#ifndef CURL_DISABLE_TELNET" },
  {"tftp", "#ifndef CURL_DISABLE_TFTP" },
  {"ws",
   "#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)" },
  {"wss", "#if !defined(CURL_DISABLE_WEBSOCKETS) && \\\n"
   "  defined(USE_SSL) && !defined(CURL_DISABLE_HTTP)" },
  { NULL, NULL }
};

unsigned int calc(const char *s, int add, int shift)
{
  const char *so = s;
  unsigned int c = add;
  while(*s) {
    c <<= shift;
    c += *s;
    s++;
  }
  return c;
}

unsigned int num[100];
unsigned int ix[100];

static void showtable(int try, int init, int shift)
{
  int nulls = 0;
  int i;
  for(i = 0; scheme[i].n; ++i)
    num[i] = calc(scheme[i].n, init, shift);
  for(i = 0; scheme[i].n; ++i)
    ix[i] = num[i] % try;
  printf("/*\n"
         "   unsigned int c = %d\n"
         "   while(l) {\n"
         "     c <<= %d;\n"
         "     c += Curl_raw_tolower(*s);\n"
         "     s++;\n"
         "     l--;\n"
         "   }\n"
         "*/\n", init, shift);

  printf("  static const struct Curl_handler * const protocols[%d] = {", try);

  /* generate table */
  for(i = 0; i < try; i++) {
    int match = 0;
    int j;
    for(j = 0; scheme[j].n; j++) {
      if(ix[j] == i) {
        printf("\n");
        printf("%s\n", scheme[j].ifdef);
        printf("    &Curl_handler_%s,\n", scheme[j].n);
        printf("#else\n    NULL,\n");
        printf("#endif");
        match = 1;
        nulls = 0;
        break;
      }
    }
    if(!match) {
      if(!nulls || (nulls > 10)) {
        printf("\n   ");
        nulls = 0;
      }
      printf(" NULL,", nulls);
      nulls++;
    }
  }
  printf("\n  };\n");
}

int main(void)
{
  int i;
  int try;
  int besttry = 9999;
  int bestadd = 0;
  int bestshift = 0;
  int add;
  int shift;
  for(shift = 0; shift < 8; shift++) {
    for(add = 0; add < 999; add++) {
      for(i = 0; scheme[i].n; ++i) {
        unsigned int v = calc(scheme[i].n, add, shift);
        int j;
        int badcombo = 0;
        for(j = 0; j < i; j++) {

          if(num[j] == v) {
            /*
            printf("NOPE: %u is a dupe (%s and %s)\n",
                   v, scheme[i], scheme[j]);
            */
            badcombo = 1;
            break;
          }
        }
        if(badcombo)
          break;
        num[i] = v;
      }
#if 0
      for(i = 0; scheme[i].n; ++i) {
        printf("%u - %s\n", num[i], scheme[i].n);
      }
#endif
      /* try different remainders to find smallest possible table */
      for(try = 28; try < 199; try++) {
        int good = 1;
        for(i = 0; scheme[i].n; ++i) {
          ix[i] = num[i] % try;
        }
        /* check for dupes */
        for(i = 0; scheme[i].n && good; ++i) {
          int j;
          for(j = 0; j < i; j++) {
            if(ix[j] == ix[i]) {
              good = 0;
              break;
            }
          }
        }
        if(good) {
          if(try < besttry) {
            besttry = try;
            bestadd = add;
            bestshift = shift;
          }
          break;
        }
      }
    }
  }

  showtable(besttry, bestadd, bestshift);
}
