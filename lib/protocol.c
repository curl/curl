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
#include "curl_setup.h"

#include "protocol.h"
#include "strcase.h"

#include "dict.h"
#include "file.h"
#include "ftp.h"
#include "gopher.h"
#include "http.h"
#include "imap.h"
#include "curl_ldap.h"
#include "mqtt.h"
#include "pop3.h"
#include "rtsp.h"
#include "smb.h"
#include "smtp.h"
#include "telnet.h"
#include "tftp.h"
#include "ws.h"
#include "vssh/ssh.h"


/* All URI schemes known to libcurl, but not necessarily implemented
 * by protocol handlers. */
const struct Curl_scheme Curl_scheme_dict = {
  "dict",                               /* scheme */
#ifdef CURL_DISABLE_DICT
  ZERO_NULL,
#else
  &Curl_protocol_dict,
#endif
  CURLPROTO_DICT,                       /* protocol */
  CURLPROTO_DICT,                       /* family */
  PROTOPT_NONE | PROTOPT_NOURLQUERY,    /* flags */
  PORT_DICT,                            /* defport */
};

const struct Curl_scheme Curl_scheme_file = {
  "file",                               /* scheme */
#ifdef CURL_DISABLE_FILE
  ZERO_NULL,
#else
  &Curl_protocol_file,
#endif
  CURLPROTO_FILE,                       /* protocol */
  CURLPROTO_FILE,                       /* family */
  PROTOPT_NONETWORK | PROTOPT_NOURLQUERY, /* flags */
  0                                     /* defport */
};

const struct Curl_scheme Curl_scheme_ftp = {
  "ftp",                           /* scheme */
#ifdef CURL_DISABLE_FTP
  ZERO_NULL,
#else
  &Curl_protocol_ftp,
#endif
  CURLPROTO_FTP,                   /* protocol */
  CURLPROTO_FTP,                   /* family */
  PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD |
  PROTOPT_NOURLQUERY | PROTOPT_PROXY_AS_HTTP |
  PROTOPT_WILDCARD | PROTOPT_SSL_REUSE |
  PROTOPT_CONN_REUSE, /* flags */
  PORT_FTP,                        /* defport */
};

const struct Curl_scheme Curl_scheme_ftps = {
  "ftps",                          /* scheme */
#if defined(CURL_DISABLE_FTP) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_ftp,
#endif
  CURLPROTO_FTPS,                  /* protocol */
  CURLPROTO_FTP,                   /* family */
  PROTOPT_SSL | PROTOPT_DUAL | PROTOPT_CLOSEACTION |
  PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY | PROTOPT_WILDCARD |
  PROTOPT_CONN_REUSE, /* flags */
  PORT_FTPS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_gopher = {
  "gopher",                             /* scheme */
#ifdef CURL_DISABLE_GOPHER
  ZERO_NULL,
#else
  &Curl_protocol_gopher,
#endif
  CURLPROTO_GOPHER,                     /* protocol */
  CURLPROTO_GOPHER,                     /* family */
  PROTOPT_NONE,                         /* flags */
  PORT_GOPHER,                          /* defport */
};

const struct Curl_scheme Curl_scheme_gophers = {
  "gophers",                            /* scheme */
#if defined(CURL_DISABLE_GOPHER) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_gophers,
#endif
  CURLPROTO_GOPHERS,                    /* protocol */
  CURLPROTO_GOPHER,                     /* family */
  PROTOPT_SSL,                          /* flags */
  PORT_GOPHER,                          /* defport */
};

const struct Curl_scheme Curl_scheme_http = {
  "http",                               /* scheme */
#ifdef CURL_DISABLE_HTTP
  ZERO_NULL,
#else
  &Curl_protocol_http,
#endif
  CURLPROTO_HTTP,                       /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE,
  PORT_HTTP,                            /* defport */
};

const struct Curl_scheme Curl_scheme_https = {
  "https",                              /* scheme */
#if defined(CURL_DISABLE_HTTP) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_http,
#endif
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN | /* flags */
  PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE,
  PORT_HTTPS,                           /* defport */
};

const struct Curl_scheme Curl_scheme_imap = {
  "imap",                           /* scheme */
#ifdef CURL_DISABLE_IMAP
  ZERO_NULL,
#else
  &Curl_protocol_imap,
#endif
  CURLPROTO_IMAP,                   /* protocol */
  CURLPROTO_IMAP,                   /* family */
  PROTOPT_CLOSEACTION |             /* flags */
  PROTOPT_URLOPTIONS | PROTOPT_SSL_REUSE |
  PROTOPT_CONN_REUSE,
  PORT_IMAP,                        /* defport */
};

const struct Curl_scheme Curl_scheme_imaps = {
  "imaps",                          /* scheme */
#if defined(CURL_DISABLE_IMAP) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_imap,
#endif
  CURLPROTO_IMAPS,                  /* protocol */
  CURLPROTO_IMAP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL | /* flags */
  PROTOPT_URLOPTIONS | PROTOPT_CONN_REUSE,
  PORT_IMAPS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_ldap = {
  "ldap",                               /* scheme */
#ifdef CURL_DISABLE_LDAP
  ZERO_NULL,
#else
  &Curl_protocol_ldap,
#endif
  CURLPROTO_LDAP,                       /* protocol */
  CURLPROTO_LDAP,                       /* family */
  PROTOPT_SSL_REUSE,                    /* flags */
  PORT_LDAP,                            /* defport */
};

const struct Curl_scheme Curl_scheme_ldaps = {
  "ldaps",                              /* scheme */
#if defined(CURL_DISABLE_LDAP) || !defined(HAVE_LDAP_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_ldap,
#endif
  CURLPROTO_LDAPS,                      /* protocol */
  CURLPROTO_LDAP,                       /* family */
  PROTOPT_SSL,                          /* flags */
  PORT_LDAPS,                           /* defport */
};

const struct Curl_scheme Curl_scheme_mqtt = {
  "mqtt",                             /* scheme */
#ifdef CURL_DISABLE_MQTT
  ZERO_NULL,
#else
  &Curl_protocol_mqtt,
#endif
  CURLPROTO_MQTT,                     /* protocol */
  CURLPROTO_MQTT,                     /* family */
  PROTOPT_NONE,                       /* flags */
  PORT_MQTT,                          /* defport */
};

const struct Curl_scheme Curl_scheme_mqtts = {
  "mqtts",                            /* scheme */
#if defined(CURL_DISABLE_MQTT) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_mqtts,
#endif
  CURLPROTO_MQTTS,                    /* protocol */
  CURLPROTO_MQTT,                     /* family */
  PROTOPT_SSL,                        /* flags */
  PORT_MQTTS,                         /* defport */
};

const struct Curl_scheme Curl_scheme_pop3 = {
  "pop3",                           /* scheme */
#ifdef CURL_DISABLE_POP3
  ZERO_NULL,
#else
  &Curl_protocol_pop3,
#endif
  CURLPROTO_POP3,                   /* protocol */
  CURLPROTO_POP3,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | /* flags */
  PROTOPT_URLOPTIONS | PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE,
  PORT_POP3,                        /* defport */
};

const struct Curl_scheme Curl_scheme_pop3s = {
  "pop3s",                          /* scheme */
#if defined(CURL_DISABLE_POP3) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_pop3,
#endif
  CURLPROTO_POP3S,                  /* protocol */
  CURLPROTO_POP3,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL | /* flags */
  PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS | PROTOPT_CONN_REUSE,
  PORT_POP3S,                       /* defport */
};

const struct Curl_scheme Curl_scheme_rtsp = {
  "rtsp",                               /* scheme */
#ifdef CURL_DISABLE_RTSP
  ZERO_NULL,
#else
  &Curl_protocol_rtsp,
#endif
  CURLPROTO_RTSP,                       /* protocol */
  CURLPROTO_RTSP,                       /* family */
  PROTOPT_CONN_REUSE,                   /* flags */
  PORT_RTSP,                            /* defport */
};

const struct Curl_scheme Curl_scheme_sftp = {
  "sftp",                               /* scheme */
#ifndef USE_SSH
  NULL,
#else
  &Curl_protocol_sftp,
#endif
  CURLPROTO_SFTP,                       /* protocol */
  CURLPROTO_SFTP,                       /* family */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | /* flags */
  PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE,
  PORT_SSH                              /* defport */
};

const struct Curl_scheme Curl_scheme_scp = {
  "scp",                                /* scheme */
#ifndef USE_SSH
  NULL,
#else
  &Curl_protocol_scp,
#endif
  CURLPROTO_SCP,                        /* protocol */
  CURLPROTO_SCP,                        /* family */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | /* flags */
  PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE,
  PORT_SSH,                             /* defport */
};

const struct Curl_scheme Curl_scheme_smb = {
  "smb",                                /* scheme */
#if defined(CURL_ENABLE_SMB) && defined(USE_CURL_NTLM_CORE)
  &Curl_protocol_smb,
#else
  ZERO_NULL,
#endif
  CURLPROTO_SMB,                        /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_CONN_REUSE,                   /* flags */
  PORT_SMB,                             /* defport */
};

const struct Curl_scheme Curl_scheme_smbs = {
  "smbs",                               /* scheme */
#if defined(CURL_ENABLE_SMB) && defined(USE_CURL_NTLM_CORE) &&  \
  defined(USE_SSL)
  &Curl_protocol_smb,
#else
  ZERO_NULL,
#endif
  CURLPROTO_SMBS,                       /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_SSL | PROTOPT_CONN_REUSE,     /* flags */
  PORT_SMBS,                            /* defport */
};

const struct Curl_scheme Curl_scheme_smtp = {
  "smtp",                           /* scheme */
#ifdef CURL_DISABLE_SMTP
  ZERO_NULL,
#else
  &Curl_protocol_smtp,
#endif
  CURLPROTO_SMTP,                   /* protocol */
  CURLPROTO_SMTP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | /* flags */
  PROTOPT_URLOPTIONS | PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE,
  PORT_SMTP,                        /* defport */
};

const struct Curl_scheme Curl_scheme_smtps = {
  "smtps",                          /* scheme */
#if defined(CURL_DISABLE_SMTP) || !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_smtp,
#endif
  CURLPROTO_SMTPS,                  /* protocol */
  CURLPROTO_SMTP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL | /* flags */
  PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS | PROTOPT_CONN_REUSE,
  PORT_SMTPS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_telnet = {
  "telnet",                             /* scheme */
#ifdef CURL_DISABLE_TELNET
  ZERO_NULL,
#else
  &Curl_protocol_telnet,
#endif
  CURLPROTO_TELNET,                     /* protocol */
  CURLPROTO_TELNET,                     /* family */
  PROTOPT_NONE | PROTOPT_NOURLQUERY,    /* flags */
  PORT_TELNET,                          /* defport */
};

const struct Curl_scheme Curl_scheme_tftp = {
  "tftp",                               /* scheme */
#ifdef CURL_DISABLE_TFTP
  ZERO_NULL,
#else
  &Curl_protocol_tftp,
#endif
  CURLPROTO_TFTP,                       /* protocol */
  CURLPROTO_TFTP,                       /* family */
  PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY, /* flags */
  PORT_TFTP,                            /* defport */
};

const struct Curl_scheme Curl_scheme_ws = {
  "ws",                                 /* scheme */
#if defined(CURL_DISABLE_WEBSOCKETS) || defined(CURL_DISABLE_HTTP)
  ZERO_NULL,
#else
  &Curl_protocol_ws,
#endif
  CURLPROTO_WS,                         /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL,
  PORT_HTTP                             /* defport */
};

const struct Curl_scheme Curl_scheme_wss = {
  "wss",                                /* scheme */
#if defined(CURL_DISABLE_WEBSOCKETS) || defined(CURL_DISABLE_HTTP) || \
    !defined(USE_SSL)
  ZERO_NULL,
#else
  &Curl_protocol_ws,
#endif
  CURLPROTO_WSS,                        /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | /* flags */
  PROTOPT_USERPWDCTRL,
  PORT_HTTPS                            /* defport */
};

/* Returns a struct scheme pointer if the name is a known scheme. Check the
   ->run struct field for non-NULL to figure out if an implementation is
   present. */
const struct Curl_scheme *Curl_getn_scheme(const char *scheme, size_t len)
{
  /* table generated by schemetable.c:
     1. gcc schemetable.c && ./a.out
     2. check how small the table gets
     3. tweak the hash algorithm, then rerun from 1
     4. when the table is good enough
     5. copy the table into this source code
     6. make sure this function uses the same hash function that worked for
     schemetable.c
     */
  static const struct Curl_scheme * const all_schemes[47] = {
    &Curl_scheme_mqtt,
    &Curl_scheme_smtp,
    &Curl_scheme_tftp,
    &Curl_scheme_imap, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    &Curl_scheme_ldaps,
    &Curl_scheme_dict, NULL,
    &Curl_scheme_file, NULL,
    &Curl_scheme_pop3s,
    &Curl_scheme_ftp,
    &Curl_scheme_scp,
    &Curl_scheme_mqtts,
    &Curl_scheme_imaps,
    &Curl_scheme_ldap,
    &Curl_scheme_http,
    &Curl_scheme_smb, NULL, NULL,
    &Curl_scheme_telnet,
    &Curl_scheme_https,
    &Curl_scheme_gopher,
    &Curl_scheme_rtsp, NULL, NULL,
    &Curl_scheme_wss, NULL,
    &Curl_scheme_gophers,
    &Curl_scheme_smtps,
    &Curl_scheme_pop3,
    &Curl_scheme_ws, NULL, NULL,
    &Curl_scheme_sftp,
    &Curl_scheme_ftps, NULL,
    &Curl_scheme_smbs, NULL,
  };

  if(len && (len <= 7)) {
    const char *s = scheme;
    size_t l = len;
    const struct Curl_scheme *h;
    unsigned int c = 792;
    while(l) {
      c <<= 4;
      c += (unsigned int)Curl_raw_tolower(*s);
      s++;
      l--;
    }

    h = all_schemes[c % 47];
    if(h && curl_strnequal(scheme, h->name, len) && !h->name[len])
      return h;
  }
  return NULL;
}

const struct Curl_scheme *Curl_get_scheme(const char *scheme)
{
  return Curl_getn_scheme(scheme, strlen(scheme));
}
