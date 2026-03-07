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

#include "tool_getparam.h"

static CURLcode test_tool1394(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct cert {
    const char *param;
    const char *cert;
    const char *passwd;
  };

  static const struct cert values[] = {
    /* -E parameter */        /* exp. cert name */  /* exp. passphrase */
    {"foo:bar:baz",            "foo",                "bar:baz"},
    {"foo\\:bar:baz",          "foo:bar",            "baz"},
    {"foo\\\\:bar:baz",        "foo\\",              "bar:baz"},
    {"foo:bar\\:baz",          "foo",                "bar\\:baz"},
    {"foo:bar\\\\:baz",        "foo",                "bar\\\\:baz"},
    {"foo\\bar\\baz",          "foo\\bar\\baz",      NULL},
    {"foo\\\\bar\\\\baz",      "foo\\bar\\baz",      NULL},
    {"foo\\",                  "foo\\",              NULL},
    {"foo\\\\",                "foo\\",              NULL},
    {"foo:bar\\",              "foo",                "bar\\"},
    {"foo:bar\\\\",            "foo",                "bar\\\\"},
    {"foo:bar:",               "foo",                "bar:"},
    {"foo\\::bar\\:",          "foo:",               "bar\\:"},
    {"pkcs11:foobar",          "pkcs11:foobar",      NULL},
    {"PKCS11:foobar",          "PKCS11:foobar",      NULL},
    {"PkCs11:foobar",          "PkCs11:foobar",      NULL},
#ifdef _WIN32
    {"c:\\foo:bar:baz",        "c:\\foo",            "bar:baz"},
    {"c:\\foo\\:bar:baz",      "c:\\foo:bar",        "baz"},
    {"c:\\foo\\\\:bar:baz",    "c:\\foo\\",          "bar:baz"},
    {"c:\\foo:bar\\:baz",      "c:\\foo",            "bar\\:baz"},
    {"c:\\foo:bar\\\\:baz",    "c:\\foo",            "bar\\\\:baz"},
    {"c:\\foo\\bar\\baz",      "c:\\foo\\bar\\baz",  NULL},
    {"c:\\foo\\\\bar\\\\baz",  "c:\\foo\\bar\\baz",  NULL},
    {"c:\\foo\\",              "c:\\foo\\",          NULL},
    {"c:\\foo\\\\",            "c:\\foo\\",          NULL},
    {"c:\\foo:bar\\",          "c:\\foo",            "bar\\"},
    {"c:\\foo:bar\\\\",        "c:\\foo",            "bar\\\\"},
    {"c:\\foo:bar:",           "c:\\foo",            "bar:"},
    {"c:\\foo\\::bar\\:",      "c:\\foo:",           "bar\\:"},
#endif
    {NULL, NULL, NULL}
  };
  const struct cert *p;
  char *certname, *passphrase;
  ParameterError err;
  for(p = &values[0]; p->param; p++) {
    err = parse_cert_parameter(p->param, &certname, &passphrase);
    if(!err) {
      if(certname) {
        if(strcmp(p->cert, certname)) {
          curl_mprintf("expected certname '%s' but got '%s' "
                       "for -E param '%s'\n", p->cert, certname, p->param);
          fail("assertion failure");
        }
      }
      else {
        curl_mprintf("expected certname '%s' but got NULL "
                     "for -E param '%s'\n", p->cert, p->param);
        fail("assertion failure");
      }
    }
    else {
      if(certname) {
        curl_mprintf("expected certname NULL but got '%s' "
                     "for -E param '%s'\n", certname, p->param);
        fail("assertion failure");
      }
    }
    if(p->passwd) {
      if(passphrase) {
        if(strcmp(p->passwd, passphrase)) {
          curl_mprintf("expected passphrase '%s' but got '%s'"
                       "for -E param '%s'\n", p->passwd, passphrase, p->param);
          fail("assertion failure");
        }
      }
      else {
        curl_mprintf("expected passphrase '%s' but got NULL "
                     "for -E param '%s'\n", p->passwd, p->param);
        fail("assertion failure");
      }
    }
    else {
      if(passphrase) {
        curl_mprintf("expected passphrase NULL but got '%s' "
                     "for -E param '%s'\n", passphrase, p->param);
        fail("assertion failure");
      }
    }
    if(certname)
      curlx_free(certname);
    if(passphrase)
      curlx_free(passphrase);
  }

  UNITTEST_END_SIMPLE
}
