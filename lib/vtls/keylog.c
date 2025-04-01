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
#include "curl_setup.h"

#if defined(USE_OPENSSL) || \
  defined(USE_GNUTLS) || \
  defined(USE_WOLFSSL) || \
  (defined(USE_NGTCP2) && defined(USE_NGHTTP3)) || \
  defined(USE_QUICHE) || \
  defined(USE_RUSTLS)

#include "keylog.h"
#include <curl/curl.h>
#include "escape.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* The fp for the open SSLKEYLOGFILE, or NULL if not open */
static FILE *keylog_file_fp;

void
Curl_tls_keylog_open(void)
{
  char *keylog_file_name;

  if(!keylog_file_fp) {
    keylog_file_name = curl_getenv("SSLKEYLOGFILE");
    if(keylog_file_name) {
      keylog_file_fp = fopen(keylog_file_name, FOPEN_APPENDTEXT);
      if(keylog_file_fp) {
#ifdef _WIN32
        if(setvbuf(keylog_file_fp, NULL, _IONBF, 0))
#else
        if(setvbuf(keylog_file_fp, NULL, _IOLBF, 4096))
#endif
        {
          fclose(keylog_file_fp);
          keylog_file_fp = NULL;
        }
      }
      Curl_safefree(keylog_file_name);
    }
  }
}

void
Curl_tls_keylog_close(void)
{
  if(keylog_file_fp) {
    fclose(keylog_file_fp);
    keylog_file_fp = NULL;
  }
}

bool
Curl_tls_keylog_enabled(void)
{
  return keylog_file_fp != NULL;
}

bool
Curl_tls_keylog_write_line(const char *line)
{
  /* The current maximum valid keylog line length LF and NUL is 195. */
  size_t linelen;
  char buf[256];

  if(!keylog_file_fp || !line) {
    return FALSE;
  }

  linelen = strlen(line);
  if(linelen == 0 || linelen > sizeof(buf) - 2) {
    /* Empty line or too big to fit in a LF and NUL. */
    return FALSE;
  }

  memcpy(buf, line, linelen);
  if(line[linelen - 1] != '\n') {
    buf[linelen++] = '\n';
  }
  buf[linelen] = '\0';

  /* Using fputs here instead of fprintf since libcurl's fprintf replacement
     may not be thread-safe. */
  fputs(buf, keylog_file_fp);
  return TRUE;
}

bool
Curl_tls_keylog_write(const char *label,
                      const unsigned char client_random[CLIENT_RANDOM_SIZE],
                      const unsigned char *secret, size_t secretlen)
{
  size_t pos, i;
  unsigned char line[KEYLOG_LABEL_MAXLEN + 1 + 2 * CLIENT_RANDOM_SIZE + 1 +
                     2 * SECRET_MAXLEN + 1 + 1];

  if(!keylog_file_fp) {
    return FALSE;
  }

  pos = strlen(label);
  if(pos > KEYLOG_LABEL_MAXLEN || !secretlen || secretlen > SECRET_MAXLEN) {
    /* Should never happen - sanity check anyway. */
    return FALSE;
  }

  memcpy(line, label, pos);
  line[pos++] = ' ';

  /* Client Random */
  for(i = 0; i < CLIENT_RANDOM_SIZE; i++) {
    Curl_hexbyte(&line[pos], client_random[i], FALSE);
    pos += 2;
  }
  line[pos++] = ' ';

  /* Secret */
  for(i = 0; i < secretlen; i++) {
    Curl_hexbyte(&line[pos], secret[i], FALSE);
    pos += 2;
  }
  line[pos++] = '\n';
  line[pos] = '\0';

  /* Using fputs here instead of fprintf since libcurl's fprintf replacement
     may not be thread-safe. */
  fputs((char *)line, keylog_file_fp);
  return TRUE;
}

#endif  /* TLS or QUIC backend */
