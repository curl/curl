/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) curl contributors.
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
#include "altsvc_save_test.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_ALTSVC)
#include "urldata.h"
#include "curl_fopen.h"
#include "curl_get_line.h"
#include "parsedate.h"
#include "curl_trc.h"
#include "curlx/inet_pton.h"
#include "curlx/strparse.h"
#include "connect.h"
#include "curlx/win32-fopen.h"
#include <stdarg.h>

/* Keep the interception and all included-source statics out of units.c. */
static struct {
  int armed;
  int active;
  int fault;
  int header_calls;
  int entry_calls;
  int close_calls;
  int open_calls;
  int acquired;
  int injected;
  int invalid;
  int real_close;
  FILE *stream;
  char tempname[4096];
  char snapshot[16384];
} save_test;

static const char header_marker[] = "# injected-header-partial\n";
static const char entry_marker[] = "# injected-entry-partial\n";
#ifdef _WIN32
static const char raw_header_marker[] = "# injected-header-partial\r\n";
static const char raw_entry_marker[] = "# injected-entry-partial\r\n";
#else
#define raw_header_marker header_marker
#define raw_entry_marker entry_marker
#endif
static const char sentinel[] = "ORIGINAL-ALT-SVC\0DO-NOT-PUBLISH\r\n";

/* Defined before the macro override: always execute the real close. */
static int save_real_close(FILE *fp)
{
  return curlx_fclose(fp);
}

static int save_fputs(const char *s, FILE *fp)
{
  if(save_test.armed) {
    save_test.header_calls++;
    if(!save_test.active || fp != save_test.stream)
      save_test.invalid++;
    if(save_test.fault == 1) {
      if(fputs(header_marker, fp) == EOF)
        save_test.invalid++;
      save_test.injected++;
      return EOF;
    }
  }
  return fputs(s, fp);
}

static int save_mfprintf(FILE *fp, const char *fmt, ...)
  CURL_PRINTF(2, 3);

static int save_mfprintf(FILE *fp, const char *fmt, ...)
{
  int rc;
  va_list ap;
  if(save_test.armed) {
    save_test.entry_calls++;
    if(!save_test.active || fp != save_test.stream)
      save_test.invalid++;
    if(save_test.fault == 2 && save_test.entry_calls == 2) {
      if(fputs(entry_marker, fp) == EOF)
        save_test.invalid++;
      save_test.injected++;
      return -1;
    }
  }
  va_start(ap, fmt);
  rc = curl_mvfprintf(fp, fmt, ap);
  va_end(ap);
  return rc;
}

static CURLcode save_fopen(struct Curl_easy *data, const char *name,
                           FILE **fp, char **tempname)
{
  CURLcode rc = Curl_fopen(data, name, fp, tempname);
  if(save_test.armed) {
    save_test.open_calls++;
    if(!rc) {
      size_t len = *tempname ? strlen(*tempname) : 0;
      save_test.acquired++;
      save_test.active = 1;
      save_test.stream = *fp;
      if(!*tempname || len >= sizeof(save_test.tempname))
        save_test.invalid++;
      else
        memcpy(save_test.tempname, *tempname, len + 1);
    }
  }
  return rc;
}

static int save_fclose(FILE *fp)
{
  int rc;
  FILE *reader;
  size_t nread;
  if(!save_test.armed)
    return save_real_close(fp);
  save_test.close_calls++;
  if(!save_test.active || fp != save_test.stream) {
    save_test.invalid++;
    return EOF; /* Never close an already closed stream again. */
  }
  save_test.active = 0;
  rc = save_real_close(fp);
  save_test.real_close = rc;
  reader = curlx_fopen(save_test.tempname, "rb");
  if(!reader)
    save_test.invalid++;
  else {
    nread = fread(save_test.snapshot, 1,
                  sizeof(save_test.snapshot) - 1, reader);
    save_test.snapshot[nread] = 0;
    if(ferror(reader) || !feof(reader))
      save_test.invalid++;
    if(save_real_close(reader))
      save_test.invalid++;
  }
  if(save_test.fault == 3 && !rc) {
    save_test.injected++;
    return EOF;
  }
  return rc;
}

/* altsvc.c includes canonical altsvc.h declarations under these aliases. */

#define Curl_alpnid2str save_Curl_alpnid2str
#define Curl_altsvc_init save_Curl_altsvc_init
#define Curl_altsvc_load save_Curl_altsvc_load
#define Curl_altsvc_save save_Curl_altsvc_save
#define Curl_altsvc_ctrl save_Curl_altsvc_ctrl
#define Curl_altsvc_cleanup save_Curl_altsvc_cleanup
#define Curl_altsvc_parse save_Curl_altsvc_parse
#define Curl_altsvc_lookup save_Curl_altsvc_lookup
#define fputs save_fputs
#define curl_mfprintf save_mfprintf
#undef curlx_fclose
#define curlx_fclose save_fclose
#define Curl_fopen save_fopen
#include "../../lib/altsvc.c"
#undef Curl_fopen
#undef curlx_fclose
#undef curl_mfprintf
#undef fputs
#undef Curl_alpnid2str
#undef Curl_altsvc_init
#undef Curl_altsvc_load
#undef Curl_altsvc_save
#undef Curl_altsvc_ctrl
#undef Curl_altsvc_cleanup
#undef Curl_altsvc_parse
#undef Curl_altsvc_lookup
#undef MAX_ALTSVC_LINE
#undef MAX_ALTSVC_DATELEN
#undef MAX_ALTSVC_HOSTLEN
#undef MAX_ALTSVC_ALPNLEN
#undef H3VERSION
#undef altsvc_free
#undef ALTSVC_MA
#undef ALTSVC_PERSIST
#ifdef CURL_MEMDEBUG
#define curlx_fclose(file) curl_dbg_fclose(file, __LINE__, __FILE__)
#else
#define curlx_fclose fclose
#endif

static int save_fault_case(struct Curl_easy *data, struct altsvcinfo *asi,
                           const char *filename, int fault)
{
  CURLcode result;
  FILE *fp;
  size_t nread;
  char bytes[sizeof(sentinel)];
  curlx_struct_stat st;
  int failures = 0;
  int expected_calls = fault == 1 ? 0 :
    (fault == 2 ? 2 : (int)Curl_llist_count(&asi->list));

  memset(&save_test, 0, sizeof(save_test));
  save_test.fault = fault;
  fp = curlx_fopen(filename, "wb");
  if(!fp)
    return 1;
  if(fwrite(sentinel, 1, sizeof(sentinel) - 1, fp) != sizeof(sentinel) - 1)
    failures++;
  if(save_real_close(fp))
    failures++;
  if(failures) {
    unlink(filename);
    return failures;
  }

  save_test.armed = 1;
  result = save_Curl_altsvc_save(data, asi, filename);
  save_test.armed = 0;
  if(result != CURLE_WRITE_ERROR)
    failures++;
  if(save_test.open_calls != 1 || save_test.acquired != 1 ||
     save_test.header_calls != 1 || save_test.entry_calls != expected_calls ||
     save_test.close_calls != 1 || save_test.active || save_test.real_close ||
     save_test.injected != 1 || save_test.invalid)
    failures++;
  if(fault == 1 && strcmp(save_test.snapshot, raw_header_marker))
    failures++;
  if(fault == 2 && !strstr(save_test.snapshot, raw_entry_marker))
    failures++;
  if(fault == 3 && strncmp(save_test.snapshot, "# Your alt-svc cache.", 21))
    failures++;

  /* Observe actual cleanup; neither rename nor unlink is intercepted. */
  if(!save_test.tempname[0])
    failures++;
  else if(!curlx_stat(save_test.tempname, &st) || errno != ENOENT)
    failures++;

  fp = curlx_fopen(filename, "rb");
  if(!fp)
    failures++;
  else {
    nread = fread(bytes, 1, sizeof(bytes), fp);
    if(ferror(fp) || !feof(fp))
      failures++;
#ifdef _WIN32
    if(nread != sizeof(sentinel) - 1 ||
       memcmp(bytes, sentinel, sizeof(sentinel) - 1))
      failures++;
#else
    /* Curl_fopen pretruncates regular destinations on POSIX. */
    if(nread)
      failures++;
#endif
    if(save_real_close(fp))
      failures++;
  }
  unlink(filename);
  if(save_test.tempname[0])
    unlink(save_test.tempname);
  return failures;
}

int altsvc_save_test(struct Curl_easy *data, struct altsvcinfo *asi,
                     const char *arg)
{
  struct altsvcinfo *empty;
  char *filename;
  int failures;
  if(Curl_llist_count(&asi->list) < 3)
    return 1;
  filename = curl_maprintf("%s-save-errors", arg);
  if(!filename)
    return 1;
  empty = save_Curl_altsvc_init();
  if(!empty) {
    curlx_free(filename);
    return 1;
  }
  failures = save_fault_case(data, asi, filename, 1);
  failures += save_fault_case(data, empty, filename, 1);
  failures += save_fault_case(data, asi, filename, 2);
  failures += save_fault_case(data, asi, filename, 3);
  save_Curl_altsvc_cleanup(&empty);
  curlx_free(filename);
  return failures;
}
#else
int altsvc_save_test(struct Curl_easy *data, struct altsvcinfo *asi,
                     const char *arg)
{
  (void)data;
  (void)asi;
  (void)arg;
  return 0;
}
#endif
