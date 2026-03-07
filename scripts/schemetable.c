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

static const char *scheme[] = {
  "dict",
  "file",
  "ftp",
  "ftps",
  "gopher",
  "gophers",
  "http",
  "https",
  "imap",
  "imaps",
  "ldap",
  "ldaps",
  "mqtt",
  "mqtts",
  "pop3",
  "pop3s",
  "rtmp",
  "rtmpt",
  "rtmpe",
  "rtmpte",
  "rtmps",
  "rtmpts",
  "rtsp",
  "scp",
  "sftp",
  "smb",
  "smbs",
  "smtp",
  "smtps",
  "telnet",
  "tftp",
  "ws",
  "wss",
  NULL,
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
  for(i = 0; scheme[i]; ++i)
    num[i] = calc(scheme[i], init, shift);
  for(i = 0; scheme[i]; ++i)
    ix[i] = num[i] % try;
  printf("/*\n"
         "   unsigned int c = %d\n"
         "   while(l) {\n"
         "     c <<= %d;\n"
         "     c += Curl_raw_tolower(*s);\n"
         "     s++;\n"
         "     l--;\n"
         "   }\n"
         "*/\n",
         init, shift);

  printf("  static const struct Curl_scheme * const all_schemes[%d] = {", try);

  /* generate table */
  for(i = 0; i < try; i++) {
    int match = 0;
    int j;
    for(j = 0; scheme[j]; j++) {
      if(ix[j] == i) {
        printf("\n    &Curl_scheme_%s,", scheme[j]);
        match = 1;
        nulls = 0;
        break;
      }
    }
    if(!match)
      printf(" NULL,");
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
      for(i = 0; scheme[i]; ++i) {
        unsigned int v = calc(scheme[i], add, shift);
        int j;
        int badcombo = 0;
        for(j = 0; j < i; j++) {

          if(num[j] == v) {
#if 0
            printf("NOPE: %u is a dupe (%s and %s)\n",
                   v, scheme[i], scheme[j]);
#endif
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
        for(i = 0; scheme[i]; ++i) {
          ix[i] = num[i] % try;
        }
        /* check for dupes */
        for(i = 0; scheme[i] && good; ++i) {
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
