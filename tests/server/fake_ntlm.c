/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Mandy Wu, <mandy.wu@intel.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * This is a fake ntlm_auth, which is used for testing NTLM single-sign-on.
 * When DEBUGBUILD is defined, libcurl invoke this tool instead of real winbind
 * daemon helper /usr/bin/ntlm_auth. This tool will accept commands and
 * responses with a pre-written string saved in test case test2005.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/fake_ntlm.log"
#endif

const char *serverlogfile = DEFAULT_LOGFILE;

int main(void)
{
  char buf[1024];
  FILE *stream;
  char *filename;
  int error;
  char *type1_input = NULL, *type3_input = NULL;
  char *type1_output = NULL, *type3_output = NULL;
  size_t size = 0;

  filename = test2file(2005);
  stream=fopen(filename, "rb");
  if(!stream) {
    error = ERRNO;
    logmsg("fopen() failed with error: %d %s", error, strerror(error));
    logmsg("Error opening file: %s", filename);
    logmsg("Couldn't open test file %ld", 2005);
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

  stream=fopen(filename, "rb");
  if(!stream) {
    error = ERRNO;
    logmsg("fopen() failed with error: %d %s", error, strerror(error));
    logmsg("Error opening file: %s", filename);
    logmsg("Couldn't open test file %ld", 2005);
    exit(1);
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

  while(fgets(buf, 1024, stdin)) {
    if(strcmp(buf, type1_input) == 0) {
      stream=fopen(filename, "rb");
      if(!stream) {
        error = ERRNO;
        logmsg("fopen() failed with error: %d %s", error, strerror(error));
        logmsg("Error opening file: %s", filename);
        logmsg("Couldn't open test file %ld", 2005);
        exit(1);
      }
      else {
        size = 0;
        error = getpart(&type1_output, &size, "ntlm_auth_type1", "output", stream);
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
      stream=fopen(filename, "rb");
      if(!stream) {
        error = ERRNO;
        logmsg("fopen() failed with error: %d %s", error, strerror(error));
        logmsg("Error opening file: %s", filename);
        logmsg("Couldn't open test file %ld", 2005);
        exit(1);
      }
      else {
        size = 0;
        error = getpart(&type3_output, &size, "ntlm_auth_type3", "output", stream);
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
      logmsg("invalid input: %s\n", buf);
      exit(1);
    }
  }
  return 1;
}
