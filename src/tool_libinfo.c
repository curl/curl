/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

#include "strcase.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_libinfo.h"

#include "memdebug.h" /* keep this as LAST include */

/* global variable definitions, for libcurl run-time info */

curl_version_info_data *curlinfo = NULL;
long built_in_protos = 0;
curl_sslbackend ssl_backend = CURLSSLBACKEND_NONE;

#ifdef WIN32
bool ssl_paths_use_utf8 = false;
#endif

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
    { "gophers",CURLPROTO_GOPHERS},
    { "http",   CURLPROTO_HTTP   },
    { "https",  CURLPROTO_HTTPS  },
    { "imap",   CURLPROTO_IMAP   },
    { "imaps",  CURLPROTO_IMAPS  },
    { "ldap",   CURLPROTO_LDAP   },
    { "ldaps",  CURLPROTO_LDAPS  },
    { "mqtt",   CURLPROTO_MQTT   },
    { "pop3",   CURLPROTO_POP3   },
    { "pop3s",  CURLPROTO_POP3S  },
    { "rtmp",   CURLPROTO_RTMP   },
    { "rtmps",  CURLPROTO_RTMPS  },
    { "rtsp",   CURLPROTO_RTSP   },
    { "scp",    CURLPROTO_SCP    },
    { "sftp",   CURLPROTO_SFTP   },
    { "smb",    CURLPROTO_SMB    },
    { "smbs",   CURLPROTO_SMBS   },
    { "smtp",   CURLPROTO_SMTP   },
    { "smtps",  CURLPROTO_SMTPS  },
    { "telnet", CURLPROTO_TELNET },
    { "tftp",   CURLPROTO_TFTP   },
    {  NULL,    0                }
  };

  const char *const *proto;

  /* Pointer to libcurl's run-time version information */
  curlinfo = curl_version_info(CURLVERSION_NOW);
  if(!curlinfo)
    return CURLE_FAILED_INIT;

  /* Build CURLPROTO_* bit pattern with libcurl's built-in protocols */
  built_in_protos = 0;
  if(curlinfo->protocols) {
    for(proto = curlinfo->protocols; *proto; proto++) {
      struct proto_name_pattern const *p;
      for(p = possibly_built_in; p->proto_name; p++) {
        if(curl_strequal(*proto, p->proto_name)) {
          built_in_protos |= p->proto_pattern;
          break;
        }
      }
    }
  }

  if((curlinfo->features & CURL_VERSION_SSL)) {
    CURL *curl = curl_easy_init();
    struct curl_tlssessioninfo *tlsinfo = NULL;
    CURLcode result;

    if(!curl)
      return CURLE_FAILED_INIT;

    result = curl_easy_getinfo(curl, CURLINFO_TLS_SSL_PTR, &tlsinfo);
    if(result)
      return result;

    ssl_backend = tlsinfo->backend;
  }

#if defined(WIN32)
  /*
   * Paths that are ultimately passed to SSL libraries are expected in current
   * locale encoding. In Windows, two exceptions to this are Schannel in
   * Unicode build and OpenSSL 1.0.0a+, which expect UTF-8 but if invalid will
   * fall back to the current locale. Forks of OpenSSL (BoringSSL, LibreSSL) do
   * not expect UTF-8. So, for just those two exceptions we signal to use UTF-8
   * paths since that is more correct.
   */
  if(ssl_backend == CURLSSLBACKEND_OPENSSL) {
    char c = 0;
    unsigned int x, y, z;
    const char *p = curlinfo->ssl_version;

    /* Skip inactive backend versions in MultiSSL version strings.
       Example: "(foo) (bar (baz)) OpenSSL/1.0.1 (qux)" */
    if((curlinfo->features & CURL_VERSION_MULTI_SSL)) {
      size_t open = 0;
      for(; *p; ++p) {
        if(*p == '(')
          ++open;
        else if(open && *p == ')')
          --open;
        else if(!open && *p != ' ')
          break;
      }
    }

    /* SSL paths use UTF-8 if OpenSSL/1.0.0a or later */
    if(3 <= sscanf(p, "OpenSSL/%u.%u.%u%c", &x, &y, &z, &c) &&
       (x > 1 || (x == 1 && (y || z || (c >= 'a' && c <= 'z')))))
      ssl_paths_use_utf8 = true;
  }
#ifdef _UNICODE
  else if(ssl_backend == CURLSSLBACKEND_SCHANNEL)
    ssl_paths_use_utf8 = true;
#endif

#endif /* WIN32 */

  return CURLE_OK;
}
