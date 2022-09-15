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

#define MAX_PROTOS      64      /* Maximum number of supported protocols. */

curl_version_info_data *curlinfo = NULL;

proto_t proto_last = 0;

proto_t proto_ftp = PROTO_NONE;
proto_t proto_ftps = PROTO_NONE;
proto_t proto_http = PROTO_NONE;
proto_t proto_https = PROTO_NONE;
proto_t proto_file = PROTO_NONE;
proto_t proto_rtsp = PROTO_NONE;
proto_t proto_scp = PROTO_NONE;
proto_t proto_sftp = PROTO_NONE;
proto_t proto_tftp = PROTO_NONE;

static struct proto_name_nump {
  const char    *proto_name;
  proto_t       *proto_nump;
} const possibly_built_in[] = {
  /* Keep entries in CURLPROTO_* order for sorting purpose. */
  { "http",     &proto_http  },
  { "https",    &proto_https },
  { "ftp",      &proto_ftp   },
  { "ftps",     &proto_ftps  },
  { "scp",      &proto_scp   },
  { "sftp",     &proto_sftp  },
  { "telnet",   NULL         },
  { "ldap",     NULL         },
  { "ldaps",    NULL         },
  { "dict",     NULL         },
  { "file",     &proto_file  },
  { "tftp",     &proto_tftp  },
  { "imap",     NULL         },
  { "imaps",    NULL         },
  { "pop3",     NULL         },
  { "pop3s",    NULL         },
  { "smtp",     NULL         },
  { "smtps",    NULL         },
  { "rtsp",     &proto_rtsp  },
  { "rtmp",     NULL         },
  { "rtmpt",    NULL         },
  { "rtmpe",    NULL         },
  { "rtmpte",   NULL         },
  { "rtmps",    NULL         },
  { "rtmpts",   NULL         },
  { "gopher",   NULL         },
  { "smb",      NULL         },
  { "smbs",     NULL         },
  { "mqtt",     NULL         },
  { "gophers",  NULL         },
  { "ws",       NULL         },
  { "wss",      NULL         },
  {  NULL,      NULL         }
};

static const char *built_in_protos[MAX_PROTOS + 1] = {NULL};

/*
 * scheme2protocol() returns the protocol number for the specified URL scheme
 */
proto_t scheme2protocol(const char *scheme)
{
  proto_t p;

  for(p = 0; built_in_protos[p]; p++)
    if(curl_strequal(scheme, built_in_protos[p]))
      return p;
  return PROTO_NONE;
}

/*
 * protocol2scheme() returns the name of the specified protocol.
 */
const char *protocol2scheme(proto_t proto)
{
  return proto < proto_last? built_in_protos[proto]: NULL;
}

/* Enter a protoype in the built-in prototype table. */
static CURLcode enter_proto(const char *proto)
{
  if(scheme2protocol(proto) == PROTO_NONE) {
    if(proto_last >= MAX_PROTOS)
      return CURLE_OUT_OF_MEMORY;
    built_in_protos[proto_last] = proto;
    built_in_protos[++proto_last] = NULL;
  }

  return CURLE_OK;
}

/* qsort helper functions for prototype array. */
static int sortkey(const void *arg)
{
  const char *proto = *(const char **) arg;
  const struct proto_name_nump *p;

  for(p = possibly_built_in; p->proto_name; p++)
    if(curl_strequal(p->proto_name, proto))
      break;

  return (int) (p - possibly_built_in);
}

static int protocmp(const void *p1, const void *p2)
{
  return sortkey(p1) - sortkey(p2);
}

/*
 * libcurl_info_init: retrieves run-time information about libcurl,
 * setting a global pointer 'curlinfo' to libcurl's run-time info
 * struct, Assigning numbers to specific protocols and identifying protocols
 * we are interested in.
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
    const struct proto_name_nump *p;

    /* Copy protocols to local table. */
    for(builtin = curlinfo->protocols; !result && *builtin; builtin++)
      result = enter_proto(*builtin);

    /* Special case: if RTMP is present, also include RTMPE, RTMPS, RTMPT,
       RTMPTE and RTMPTS. */
    if(scheme2protocol("rtmp") != PROTO_NONE) {
      if(!result)
        result = enter_proto("rtmpe");
      if(!result)
        result = enter_proto("rtmps");
      if(!result)
        result = enter_proto("rtmpt");
      if(!result)
        result = enter_proto("rtmpte");
      if(!result)
        result = enter_proto("rtmpts");
    }

    if(result)
      return result;

    /* Sort the protocols to be sure the primary ones are always accessible and
     * to retain their list order for testing purposes. */
    qsort(built_in_protos, proto_last, sizeof(built_in_protos[0]), protocmp);

    /* Identify protocols we are interested in. */
    for(p = possibly_built_in; p->proto_name; p++)
      if(p->proto_nump)
        *p->proto_nump = scheme2protocol(p->proto_name);
  }

  return CURLE_OK;
}
