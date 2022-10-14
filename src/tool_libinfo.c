/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#include "strcase.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_libinfo.h"

#include "memdebug.h" /* keep this as LAST include */

/* global variable definitions, for libcurl run-time info */

static const char *no_protos = NULL;

curl_version_info_data *curlinfo = NULL;
const char * const *built_in_protos = &no_protos;

size_t proto_count = 0;

const char *proto_file = NULL;
const char *proto_ftp = NULL;
const char *proto_ftps = NULL;
const char *proto_http = NULL;
const char *proto_https = NULL;
const char *proto_rtsp = NULL;
const char *proto_scp = NULL;
const char *proto_sftp = NULL;
const char *proto_tftp = NULL;

static struct proto_name_tokenp {
  const char   *proto_name;
  const char  **proto_tokenp;
} const possibly_built_in[] = {
  { "file",     &proto_file  },
  { "ftp",      &proto_ftp   },
  { "ftps",     &proto_ftps  },
  { "http",     &proto_http  },
  { "https",    &proto_https },
  { "rtsp",     &proto_rtsp  },
  { "scp",      &proto_scp   },
  { "sftp",     &proto_sftp  },
  { "tftp",     &proto_tftp  },
  {  NULL,      NULL         }
};

/*
 * libcurl_info_init: retrieves run-time information about libcurl,
 * setting a global pointer 'curlinfo' to libcurl's run-time info
 * struct, count protocols and flag those we are interested in.
 */

CURLcode get_libcurl_info(void)
{
  CURLcode result = CURLE_OK;

  /* Pointer to libcurl's run-time version information */
  curlinfo = curl_version_info(CURLVERSION_NOW);
  if(!curlinfo)
    return CURLE_FAILED_INIT;

  if(curlinfo->protocols) {
    const char *const *builtin;
    const struct proto_name_tokenp *p;

    built_in_protos = curlinfo->protocols;

    for(builtin = built_in_protos; !result && *builtin; builtin++) {
      /* Identify protocols we are interested in. */
      for(p = possibly_built_in; p->proto_name; p++)
        if(curl_strequal(p->proto_name, *builtin)) {
          *p->proto_tokenp = *builtin;
          break;
        }
    }
    proto_count = builtin - built_in_protos;
  }

  return CURLE_OK;
}

/* Tokenize a protocol name.
 * Return the address of the protocol name listed by the library, or NULL if
 * not found.
 * Although this may seem useless, this always returns the same address for
 * a given protocol and thus allows comparing pointers rather than strings.
 * In addition, the returned pointer is not deallocated until the program ends.
 */

const char *proto_token(const char *proto)
{
  const char * const *builtin;

  if(!proto)
    return NULL;
  for(builtin = built_in_protos; *builtin; builtin++)
    if(curl_strequal(*builtin, proto))
      break;
  return *builtin;
}
