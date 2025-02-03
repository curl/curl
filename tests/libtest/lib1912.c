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

#define print_err(name, exp) \
  fprintf(stderr, "Type mismatch for FETCHOPT_%s (expected %s)\n", name, exp);

FETCHcode test(char *URL)
{
  /* Only test if GCC typechecking is available */
  int error = 0;
#ifdef FETCHINC_TYPECHECK_GCC_H
  const struct fetch_easyoption *o;
  for (o = fetch_easy_option_next(NULL);
       o;
       o = fetch_easy_option_next(o))
  {
    FETCH_IGNORE_DEPRECATION(
        /* Test for mismatch OR missing typecheck macros */
        if (fetchcheck_long_option(o->id) !=
            (o->type == FETCHOT_LONG || o->type == FETCHOT_VALUES)) {
          print_err(o->name, "FETCHOT_LONG or FETCHOT_VALUES");
          error++;
        } if (fetchcheck_off_t_option(o->id) != (o->type == FETCHOT_OFF_T)) {
          print_err(o->name, "FETCHOT_OFF_T");
          error++;
        } if (fetchcheck_string_option(o->id) != (o->type == FETCHOT_STRING)) {
          print_err(o->name, "FETCHOT_STRING");
          error++;
        } if (fetchcheck_slist_option(o->id) != (o->type == FETCHOT_SLIST)) {
          print_err(o->name, "FETCHOT_SLIST");
          error++;
        } if (fetchcheck_cb_data_option(o->id) != (o->type == FETCHOT_CBPTR)) {
          print_err(o->name, "FETCHOT_CBPTR");
          error++;
        }
        /* From here: only test that the type matches if macro is known */
        if (fetchcheck_write_cb_option(o->id) && (o->type != FETCHOT_FUNCTION)) {
          print_err(o->name, "FETCHOT_FUNCTION");
          error++;
        } if (fetchcheck_conv_cb_option(o->id) && (o->type != FETCHOT_FUNCTION)) {
          print_err(o->name, "FETCHOT_FUNCTION");
          error++;
        } if (fetchcheck_postfields_option(o->id) && (o->type != FETCHOT_OBJECT)) {
          print_err(o->name, "FETCHOT_OBJECT");
          error++;
        }
        /* Todo: no gcc typecheck for FETCHOPTTYPE_BLOB types? */
    )
  }
#endif
  (void)URL;
  return error == 0 ? FETCHE_OK : TEST_ERR_FAILURE;
}
