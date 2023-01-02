/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Mandy Wu, <mandy.wu@intel.com>
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
#include "server_setup.h"

/*
 * This is a fake ntlm_auth, which is used for testing NTLM single-sign-on.
 * When DEBUGBUILD is defined, libcurl invoke this tool instead of real winbind
 * daemon helper /usr/bin/ntlm_auth. This tool will accept commands and
 * responses with a pre-written string saved in test case test2005.
 */

#define ENABLE_CURLX_PRINTF
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"

/* include memdebug.h last */
#include "memdebug.h"

#define LOGFILE "log/fake_ntlm%ld.log"

const char *serverlogfile;

/*
 * Returns an allocated buffer with printable representation of input
 * buffer contents or returns NULL on out of memory condition.
 */
static char *printable(char *inbuf, size_t inlength)
{
  char *outbuf;
  char *newbuf;
  size_t newsize;
  size_t outsize;
  size_t outincr = 0;
  size_t i, o = 0;

#define HEX_FMT_STR  "[0x%02X]"
#define HEX_STR_LEN  6
#define NOTHING_STR  "[NOTHING]"
#define NOTHING_LEN  9

  if(!inlength)
    inlength = strlen(inbuf);

  if(inlength) {
    outincr = ((inlength/2) < (HEX_STR_LEN + 1)) ?
      HEX_STR_LEN + 1 : inlength/2;
    outsize = inlength + outincr;
  }
  else
    outsize = NOTHING_LEN + 1;

  outbuf = malloc(outsize);
  if(!outbuf)
    return NULL;

  if(!inlength) {
    msnprintf(&outbuf[0], outsize, "%s", NOTHING_STR);
    return outbuf;
  }

  for(i = 0; i<inlength; i++) {

    if(o > outsize - (HEX_STR_LEN + 1)) {
      newsize = outsize + outincr;
      newbuf = realloc(outbuf, newsize);
      if(!newbuf) {
        free(outbuf);
        return NULL;
      }
      outbuf = newbuf;
      outsize = newsize;
    }

    if((inbuf[i] > 0x20) && (inbuf[i] < 0x7F)) {
      outbuf[o] = inbuf[i];
      o++;
    }
    else {
      msnprintf(&outbuf[o], outsize - o, HEX_FMT_STR, inbuf[i]);
      o += HEX_STR_LEN;
    }

  }
  outbuf[o] = '\0';

  return outbuf;
}

int main(int argc, char *argv[])
{
  char buf[1024];
  char logfilename[256];
  FILE *stream;
  int error;
  char *type1_input = NULL, *type3_input = NULL;
  char *type1_output = NULL, *type3_output = NULL;
  size_t size = 0;
  long testnum;
  const char *env;
  int arg = 1;
  const char *helper_user = "unknown";
  const char *helper_proto = "unknown";
  const char *helper_domain = "unknown";
  bool use_cached_creds = FALSE;
  char *msgbuf;

  buf[0] = '\0';

  while(argc > arg) {
    if(!strcmp("--use-cached-creds", argv[arg])) {
      use_cached_creds = TRUE;
      arg++;
    }
    else if(!strcmp("--helper-protocol", argv[arg])) {
      arg++;
      if(argc > arg)
        helper_proto = argv[arg++];
    }
    else if(!strcmp("--username", argv[arg])) {
      arg++;
      if(argc > arg)
        helper_user = argv[arg++];
    }
    else if(!strcmp("--domain", argv[arg])) {
      arg++;
      if(argc > arg)
        helper_domain = argv[arg++];
    }
    else {
      puts("Usage: fake_ntlm [option]\n"
           " --use-cached-creds\n"
           " --helper-protocol [protocol]\n"
           " --username [username]\n"
           " --domain [domain]");
      exit(1);
    }
  }

  env = getenv("CURL_NTLM_AUTH_TESTNUM");
  if(env) {
    char *endptr;
    long lnum = strtol(env, &endptr, 10);
    if((endptr != env + strlen(env)) || (lnum < 1L)) {
      fprintf(stderr, "Test number not valid in CURL_NTLM_AUTH_TESTNUM");
      exit(1);
    }
    testnum = lnum;
  }
  else {
    fprintf(stderr, "Test number not specified in CURL_NTLM_AUTH_TESTNUM");
    exit(1);
  }

  /* logmsg cannot be used until this file name is set */
  msnprintf(logfilename, sizeof(logfilename), LOGFILE, testnum);
  serverlogfile = logfilename;

  logmsg("fake_ntlm (user: %s) (proto: %s) (domain: %s) (cached creds: %s)",
         helper_user, helper_proto, helper_domain,
         (use_cached_creds) ? "yes" : "no");

  env = getenv("CURL_NTLM_AUTH_SRCDIR");
  if(env) {
    path = env;
  }

  stream = test2fopen(testnum);
  if(!stream) {
    error = errno;
    logmsg("fopen() failed with error: %d %s", error, strerror(error));
    logmsg("Couldn't open test file %ld", testnum);
    exit(1);
  }
  else {
    /* get the ntlm_auth input/output */
    error = getpart(&type1_input, &size, "ntlm_auth_type1", "input", stream);
    fclose(stream);
    if(error || size == 0) {
      logmsg("getpart() type 1 input failed with error: %d", error);
      exit(1);
    }
  }

  stream = test2fopen(testnum);
  if(!stream) {
    error = errno;
    logmsg("fopen() failed with error: %d %s", error, strerror(error));
    logmsg("Couldn't open test file %ld", testnum);
  }
  else {
    size = 0;
    error = getpart(&type3_input, &size, "ntlm_auth_type3", "input", stream);
    fclose(stream);
    if(error || size == 0) {
      logmsg("getpart() type 3 input failed with error: %d", error);
      exit(1);
    }
  }

  while(fgets(buf, sizeof(buf), stdin)) {
    if(strcmp(buf, type1_input) == 0) {
      stream = test2fopen(testnum);
      if(!stream) {
        error = errno;
        logmsg("fopen() failed with error: %d %s", error, strerror(error));
        logmsg("Couldn't open test file %ld", testnum);
        exit(1);
      }
      else {
        size = 0;
        error = getpart(&type1_output, &size, "ntlm_auth_type1", "output",
                        stream);
        fclose(stream);
        if(error || size == 0) {
          logmsg("getpart() type 1 output failed with error: %d", error);
          exit(1);
        }
      }
      printf("%s", type1_output);
      fflush(stdout);
    }
    else if(strncmp(buf, type3_input, strlen(type3_input)) == 0) {
      stream = test2fopen(testnum);
      if(!stream) {
        error = errno;
        logmsg("fopen() failed with error: %d %s", error, strerror(error));
        logmsg("Couldn't open test file %ld", testnum);
        exit(1);
      }
      else {
        size = 0;
        error = getpart(&type3_output, &size, "ntlm_auth_type3", "output",
                        stream);
        fclose(stream);
        if(error || size == 0) {
          logmsg("getpart() type 3 output failed with error: %d", error);
          exit(1);
        }
      }
      printf("%s", type3_output);
      fflush(stdout);
    }
    else {
      printf("Unknown request\n");
      msgbuf = printable(buf, 0);
      if(msgbuf) {
        logmsg("invalid input: '%s'\n", msgbuf);
        free(msgbuf);
      }
      else
        logmsg("OOM formatting invalid input: '%s'\n", buf);
      exit(1);
    }
  }
  logmsg("Exit");
  return 1;
}
