/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <curl/curl.h>

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_libinfo.h"

#include "memdebug.h" /* keep this as LAST include */

/* global variable definitions, for libcurl run-time info */

curl_version_info_data *curlinfo = NULL;
long built_in_protos = 0;

/*
 * libcurl_info_init: retrieves run-time information about libcurl,
 * setting a global pointer 'curlinfo' to libcurl's run-time info
 * struct, and a global bit pattern 'built_in_protos' composed of
 * CURLPROTO_* bits indicating which protocols are actually built
 * into library being used.
 */

CURLcode get_libcurl_info(void)
{
  static struct proto_name_pattern {
    const char *proto_name;
    long        proto_pattern;
  } const possibly_built_in[] = {
    { "dict",   CURLPROTO_DICT   },
    { "file",   CURLPROTO_FILE   },
    { "ftp",    CURLPROTO_FTP    },
    { "ftps",   CURLPROTO_FTPS   },
    { "gopher", CURLPROTO_GOPHER },
    { "http",   CURLPROTO_HTTP   },
    { "https",  CURLPROTO_HTTPS  },
    { "imap",   CURLPROTO_IMAP   },
    { "imaps",  CURLPROTO_IMAPS  },
    { "ldap",   CURLPROTO_LDAP   },
    { "ldaps",  CURLPROTO_LDAPS  },
    { "pop3",   CURLPROTO_POP3   },
    { "pop3s",  CURLPROTO_POP3S  },
    { "rtmp",   CURLPROTO_RTMP   },
    { "rtsp",   CURLPROTO_RTSP   },
    { "scp",    CURLPROTO_SCP    },
    { "sftp",   CURLPROTO_SFTP   },
    { "smtp",   CURLPROTO_SMTP   },
    { "smtps",  CURLPROTO_SMTPS  },
    { "telnet", CURLPROTO_TELNET },
    { "tftp",   CURLPROTO_TFTP   },
    {  NULL,    0                }
  };

  struct proto_name_pattern const *p;
  const char *const *proto;

  /* Pointer to libcurl's run-time version information */
  curlinfo = curl_version_info(CURLVERSION_NOW);
  if(!curlinfo)
    return CURLE_FAILED_INIT;

  /* Build CURLPROTO_* bit pattern with libcurl's built-in protocols */
  built_in_protos = 0;
  if(curlinfo->protocols) {
    for(proto = curlinfo->protocols; *proto; proto++) {
      for(p = possibly_built_in; p->proto_name; p++) {
        if(curlx_raw_equal(*proto, p->proto_name)) {
          built_in_protos |= p->proto_pattern;
          break;
        }
      }
    }
  }

  return CURLE_OK;
}

