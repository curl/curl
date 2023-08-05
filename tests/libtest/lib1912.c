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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define print_err(name, exp) \
  fprintf(stderr, "Type mismatch for CURLOPT_%s (expected %s)\n", name, exp);

int test(char *URL)
{
/* Only test if GCC typechecking is available */
  int error = 0;
#ifdef CURLINC_TYPECHECK_GCC_H
  const struct curl_easyoption *o;
  for(o = curl_easy_option_next(NULL);
      o;
      o = curl_easy_option_next(o)) {
    CURL_IGNORE_DEPRECATION(
      /* Test for mismatch OR missing typecheck macros */
      if(curlcheck_long_option(o->id) !=
          (o->type == CURLOT_LONG || o->type == CURLOT_VALUES)) {
        print_err(o->name, "CURLOT_LONG or CURLOT_VALUES");
        error++;
      }
      if(curlcheck_off_t_option(o->id) != (o->type == CURLOT_OFF_T)) {
        print_err(o->name, "CURLOT_OFF_T");
        error++;
      }
      if(curlcheck_string_option(o->id) != (o->type == CURLOT_STRING)) {
        print_err(o->name, "CURLOT_STRING");
        error++;
      }
      if(curlcheck_slist_option(o->id) != (o->type == CURLOT_SLIST)) {
        print_err(o->name, "CURLOT_SLIST");
        error++;
      }
      if(curlcheck_cb_data_option(o->id) != (o->type == CURLOT_CBPTR)) {
        print_err(o->name, "CURLOT_CBPTR");
        error++;
      }
      /* From here: only test that the type matches if macro is known */
      if(curlcheck_write_cb_option(o->id) && (o->type != CURLOT_FUNCTION)) {
        print_err(o->name, "CURLOT_FUNCTION");
        error++;
      }
      if(curlcheck_conv_cb_option(o->id) && (o->type != CURLOT_FUNCTION)) {
        print_err(o->name, "CURLOT_FUNCTION");
        error++;
      }
      if(curlcheck_postfields_option(o->id) && (o->type != CURLOT_OBJECT)) {
        print_err(o->name, "CURLOT_OBJECT");
        error++;
      }
      /* Todo: no gcc typecheck for CURLOPTTYPE_BLOB types? */
    )
  }
#endif
  (void)URL;
  return error;
}
