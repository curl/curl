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
 * are also available at https://fetch.se/docs/copyright.html.
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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

/* The maximum string length limit (FETCH_MAX_INPUT_LENGTH) is an internal
   define not publicly exposed so we set our own */
#define MAX_INPUT_LENGTH 8000000

static char testbuf[MAX_INPUT_LENGTH + 2];

FETCHcode test(char *URL)
{
  const struct fetch_easyoption *o;
  FETCH *easy;
  int error = 0;
  (void)URL;

  fetch_global_init(FETCH_GLOBAL_ALL);
  easy = fetch_easy_init();
  if (!easy)
  {
    fetch_global_cleanup();
    return (FETCHcode)1;
  }

  /* make it a null-terminated C string with just As */
  memset(testbuf, 'A', MAX_INPUT_LENGTH + 1);
  testbuf[MAX_INPUT_LENGTH + 1] = 0;

  printf("string length: %d\n", (int)strlen(testbuf));

  for (o = fetch_easy_option_next(NULL);
       o;
       o = fetch_easy_option_next(o))
  {
    if (o->type == FETCHOT_STRING)
    {
      FETCHcode result;
      /*
       * Whitelist string options that are safe for abuse
       */
      FETCH_IGNORE_DEPRECATION(
          switch (o->id) {
            case FETCHOPT_PROXY_TLSAUTH_TYPE:
            case FETCHOPT_TLSAUTH_TYPE:
            case FETCHOPT_RANDOM_FILE:
            case FETCHOPT_EGDSOCKET:
              continue;
            default:
              /* check this */
              break;
          })

      /* This is a string. Make sure that passing in a string longer
         FETCH_MAX_INPUT_LENGTH returns an error */
      result = fetch_easy_setopt(easy, o->id, testbuf);
      switch (result)
      {
      case FETCHE_BAD_FUNCTION_ARGUMENT: /* the most normal */
      case FETCHE_UNKNOWN_OPTION:        /* left out from the build */
      case FETCHE_NOT_BUILT_IN:          /* not supported */
      case FETCHE_UNSUPPORTED_PROTOCOL:  /* detected by protocol2num() */
        break;
      default:
        /* all other return codes are unexpected */
        fprintf(stderr, "fetch_easy_setopt(%s...) returned %d\n",
                o->name, result);
        error++;
        break;
      }
    }
  }
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();
  return error == 0 ? FETCHE_OK : TEST_ERR_FAILURE;
}
