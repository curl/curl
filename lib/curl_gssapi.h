#ifndef HEADER_CURL_GSSAPI_H
#define HEADER_CURL_GSSAPI_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"
#include "urldata.h"

#ifdef HAVE_GSSAPI

#ifdef HAVE_GSSGNU
#  include <gss.h>
#elif defined HAVE_GSSMIT
   /* MIT style */
#  include <gssapi/gssapi.h>
#  include <gssapi/gssapi_generic.h>
#  include <gssapi/gssapi_krb5.h>
#else
   /* Heimdal-style */
#  include <gssapi.h>
#endif


/* Common method for using gss api */

OM_uint32 Curl_gss_init_sec_context(
    struct SessionHandle *data,
    OM_uint32 * minor_status,
    gss_ctx_id_t * context,
    gss_name_t target_name,
    gss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    gss_buffer_t output_token,
    OM_uint32 * ret_flags);

#endif /* HAVE_GSSAPI */

#endif /* HEADER_CURL_GSSAPI_H */
