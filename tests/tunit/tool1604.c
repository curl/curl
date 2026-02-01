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
#include "unitcheck.h"

#if defined(_WIN32) || defined(MSDOS)

#include "tool_cfgable.h"
#include "tool_doswin.h"

static void getflagstr(char *buf, size_t len, int flags)
{
  curl_msnprintf(buf, len, "%s,%s",
                 ((flags & SANITIZE_ALLOW_PATH) ?
                  "SANITIZE_ALLOW_PATH" : ""),
                 ((flags & SANITIZE_ALLOW_RESERVED) ?
                  "SANITIZE_ALLOW_RESERVED" : ""));
}

static void getcurlcodestr(char *buf, size_t len, int cc)
{
  curl_msnprintf(buf, len, "%s (%d)",
             (cc == SANITIZE_ERR_OK ? "SANITIZE_ERR_OK" :
              cc == SANITIZE_ERR_BAD_ARGUMENT ? "SANITIZE_ERR_BAD_ARGUMENT" :
              cc == SANITIZE_ERR_INVALID_PATH ? "SANITIZE_ERR_INVALID_PATH" :
              cc == SANITIZE_ERR_OUT_OF_MEMORY ? "SANITIZE_ERR_OUT_OF_MEMORY" :
              "unexpected error code - add name"), cc);
}
#endif

static CURLcode test_tool1604(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(_WIN32) || defined(MSDOS)
  struct data {
    const char *input;
    int flags;
    const char *expected_output;
    SANITIZEcode expected_result;
  };

  /* START sanitize_file_name */
  struct data data[] = {
    { "", 0,
      "", SANITIZE_ERR_OK
    },
    { "normal filename", 0,
      "normal filename", SANITIZE_ERR_OK
    },
    { "control\tchar", 0,
      "control_char", SANITIZE_ERR_OK
    },
    { "banned*char", 0,
      "banned_char", SANITIZE_ERR_OK
    },
    { "f:foo", 0,
      "f_foo", SANITIZE_ERR_OK
    },
    { "f:foo", SANITIZE_ALLOW_PATH,
      "f:foo", SANITIZE_ERR_OK
    },
    { "f:\\foo", 0,
      "f__foo", SANITIZE_ERR_OK
    },
    { "f:\\foo", SANITIZE_ALLOW_PATH,
      "f:\\foo", SANITIZE_ERR_OK
    },
    { "f:/foo", 0,
      "f__foo", SANITIZE_ERR_OK
    },
    { "f:/foo", SANITIZE_ALLOW_PATH,
      "f:/foo", SANITIZE_ERR_OK
    },
#ifndef MSDOS
    { "\\\\?\\C:\\foo", SANITIZE_ALLOW_PATH,
      "\\\\?\\C:\\foo", SANITIZE_ERR_OK
    },
    { "\\\\?\\C:\\foo", 0,
      "____C__foo", SANITIZE_ERR_OK
    },
#endif
    { "foo:bar", 0,
      "foo_bar", SANITIZE_ERR_OK
    },
    { "foo|<>/bar\\\":?*baz", 0,
      "foo____bar_____baz", SANITIZE_ERR_OK
    },
    { "f:foo::$DATA", 0,
      "f_foo__$DATA", SANITIZE_ERR_OK
    },
    { "con . air", 0,
      "con _ air", SANITIZE_ERR_OK
    },
    { "con.air", 0,
      "con_air", SANITIZE_ERR_OK
    },
    { "con:/x", 0,
      "con__x", SANITIZE_ERR_OK
    },
    { "file . . . .  ..  .", 0,
      "file", SANITIZE_ERR_OK
    },
    { "foo . . ? . . ", 0,
      "foo . . _", SANITIZE_ERR_OK
    },
    { "com1", 0,
      "_com1", SANITIZE_ERR_OK
    },
    { "com1", SANITIZE_ALLOW_RESERVED,
      "com1", SANITIZE_ERR_OK
    },
    { "f:\\com1", 0,
      "f__com1", SANITIZE_ERR_OK
    },
    { "f:\\com1", SANITIZE_ALLOW_PATH,
      "f:\\_com1", SANITIZE_ERR_OK
    },
    { "f:\\com1", SANITIZE_ALLOW_RESERVED,
      "f__com1", SANITIZE_ERR_OK
    },
    { "f:\\com1", SANITIZE_ALLOW_RESERVED | SANITIZE_ALLOW_PATH,
      "f:\\com1", SANITIZE_ERR_OK
    },
    { "com1:\\com1", SANITIZE_ALLOW_PATH,
      "_com1:\\_com1", SANITIZE_ERR_OK
    },
    { "com1:\\com1", SANITIZE_ALLOW_RESERVED | SANITIZE_ALLOW_PATH,
      "com1:\\com1", SANITIZE_ERR_OK
    },
    { "com1:\\com1", SANITIZE_ALLOW_RESERVED,
      "com1__com1", SANITIZE_ERR_OK
    },
#ifndef MSDOS
    { "\\com1", SANITIZE_ALLOW_PATH,
      "\\_com1", SANITIZE_ERR_OK
    },
    { "\\\\com1", SANITIZE_ALLOW_PATH,
      "\\\\com1", SANITIZE_ERR_OK
    },
    { "\\\\?\\C:\\com1", SANITIZE_ALLOW_PATH,
      "\\\\?\\C:\\com1", SANITIZE_ERR_OK
    },
#endif
    { "CoM1", 0,
      "_CoM1", SANITIZE_ERR_OK
    },
    { "CoM1", SANITIZE_ALLOW_RESERVED,
      "CoM1", SANITIZE_ERR_OK
    },
    { "COM56", 0,
      "COM56", SANITIZE_ERR_OK
    },
    { NULL, 0,
      NULL, SANITIZE_ERR_BAD_ARGUMENT
    },
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(data); ++i) {
    char *output = NULL;
    char flagstr[256];
    char receivedstr[256];
    char expectedstr[256];
    const char *flg = flagstr;
    const char *rec = receivedstr;
    const char *exp = expectedstr;
    SANITIZEcode res;

    res = sanitize_file_name(&output, data[i].input, data[i].flags);

    if(res == data[i].expected_result &&
       ((!output && !data[i].expected_output) ||
        (output && data[i].expected_output &&
         !strcmp(output, data[i].expected_output)))) { /* OK */
      curlx_free(output);
      continue;
    }

    getflagstr(flagstr, sizeof(flagstr), data[i].flags);
    abort_unless(flg, "out of memory");
    getcurlcodestr(receivedstr, sizeof(receivedstr), res);
    abort_unless(rec, "out of memory");
    getcurlcodestr(expectedstr, sizeof(expectedstr), data[i].expected_result);
    abort_unless(exp, "out of memory");

    unitfail++;
    curl_mfprintf(stderr, "\n"
                  "%s:%d sanitize_file_name failed.\n"
                  "input: %s\n"
                  "flags: %s\n"
                  "output: %s\n"
                  "result: %s\n"
                  "expected output: %s\n"
                  "expected result: %s\n",
                  __FILE__, __LINE__,
                  data[i].input,
                  flagstr,
                  output ? output : "(null)",
                  receivedstr,
                  data[i].expected_output ? data[i].expected_output : "(null)",
                  expectedstr);

    curlx_free(output);
  }
  /* END sanitize_file_name */
#else
  curl_mfprintf(stderr, "Skipped test not for this platform\n");
#endif /* _WIN32 || MSDOS */

  UNITTEST_END_SIMPLE
}
