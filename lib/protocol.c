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
  PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE |
  PROTOPT_HTTP_PROXY_TUNNEL,
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
  PROTOPT_NONE,                         /* flags */
  PORT_SMB,                             /* defport */
};

const struct Curl_scheme Curl_scheme_smbs = {
  "smbs",                               /* scheme */
#if defined(CURL_ENABLE_SMB) && defined(USE_CURL_NTLM_CORE) && defined(USE_SSL)
  &Curl_protocol_smb,
#else
  ZERO_NULL,
#endif
  CURLPROTO_SMBS,                       /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_SSL,                          /* flags */
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

const struct Curl_scheme Curl_scheme_socks = {
  "socks",                          /* scheme */
  ZERO_NULL,
  CURLPROTO_SOCKS,                  /* protocol */
  CURLPROTO_SOCKS,                  /* family */
  PROTOPT_NO_TRANSFER,              /* flags */
  PORT_SOCKS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_socks4 = {
  "socks4",                         /* scheme */
  ZERO_NULL,
  CURLPROTO_SOCKS,                  /* protocol */
  CURLPROTO_SOCKS,                  /* family */
  PROTOPT_NO_TRANSFER,              /* flags */
  PORT_SOCKS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_socks4a = {
  "socks4a",                        /* scheme */
  ZERO_NULL,
  CURLPROTO_SOCKS,                  /* protocol */
  CURLPROTO_SOCKS,                  /* family */
  PROTOPT_NO_TRANSFER,              /* flags */
  PORT_SOCKS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_socks5 = {
  "socks5",                         /* scheme */
  ZERO_NULL,
  CURLPROTO_SOCKS,                  /* protocol */
  CURLPROTO_SOCKS,                  /* family */
  PROTOPT_NO_TRANSFER,              /* flags */
  PORT_SOCKS,                       /* defport */
};

const struct Curl_scheme Curl_scheme_socks5h = {
  "socks5h",                         /* scheme */
  ZERO_NULL,
  CURLPROTO_SOCKS,                  /* protocol */
  CURLPROTO_SOCKS,                  /* family */
  PROTOPT_NO_TRANSFER,              /* flags */
  PORT_SOCKS,                       /* defport */
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
  PROTOPT_USERPWDCTRL | PROTOPT_HTTP_PROXY_TUNNEL,
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
  PROTOPT_USERPWDCTRL | PROTOPT_HTTP_PROXY_TUNNEL,
  PORT_HTTPS                            /* defport */
};

static const struct Curl_scheme *two_letter_scheme(const char *scheme)
{
  if((Curl_raw_tolower(scheme[0]) == 'w') &&
     (Curl_raw_tolower(scheme[1]) == 's'))
    return &Curl_scheme_ws;
  return NULL;
}

static const struct Curl_scheme *three_letter_scheme(const char *scheme)
{
  char s0 = Curl_raw_tolower(scheme[0]);
  char s1 = Curl_raw_tolower(scheme[1]);
  char s2 = Curl_raw_tolower(scheme[2]);
  if(s0 == 'f') {
    if(s1 == 't' && s2 == 'p')
      return &Curl_scheme_ftp;
  }
  else if(s0 == 'w') {
    if(s1 == 's' && s2 == 's')
      return &Curl_scheme_wss;
  }
  else if(s0 == 's') {
    if(s1 == 'c' && s2 == 'p')
      return &Curl_scheme_scp;
    if(s1 == 'm' && s2 == 'b')
      return &Curl_scheme_smb;
  }
  return NULL;
}

static const struct Curl_scheme *four_letter_scheme(const char *scheme)
{
  char s0 = Curl_raw_tolower(scheme[0]);
  char s1 = Curl_raw_tolower(scheme[1]);
  char s2 = Curl_raw_tolower(scheme[2]);
  char s3 = Curl_raw_tolower(scheme[3]);
  if(s3 == 'p') {
    if(s0 == 'h') {
      if(s1 == 't' && s2 == 't')
        return &Curl_scheme_http;
    }
    else if(s0 == 'i') {
      if(s1 == 'm' && s2 == 'a')
        return &Curl_scheme_imap;
    }
    else if(s0 == 'l') {
      if(s1 == 'd' && s2 == 'a')
        return &Curl_scheme_ldap;
    }
    else if(s0 == 'r') {
      if(s1 == 't' && s2 == 's')
        return &Curl_scheme_rtsp;
    }
    else if(s0 == 't') {
      if(s1 == 'f' && s2 == 't')
        return &Curl_scheme_tftp;
    }
    else if(s0 == 's') {
      if(s1 == 'f' && s2 == 't')
        return &Curl_scheme_sftp;
      if(s1 == 'm' && s2 == 't')
        return &Curl_scheme_smtp;
    }
  }
  else if(s0 == 'f') {
    if(s1 == 't' && s2 == 'p' && s3 == 's')
      return &Curl_scheme_ftps;
    if(s1 == 'i' && s2 == 'l' && s3 == 'e')
      return &Curl_scheme_file;
  }
  else if(s0 == 'm') {
    if(s1 == 'q' && s2 == 't' && s3 == 't')
      return &Curl_scheme_mqtt;
  }
  else if(s0 == 'p') {
    if(s1 == 'o' && s2 == 'p' && s3 == '3')
      return &Curl_scheme_pop3;
  }
  else if(s0 == 'd') {
    if(s1 == 'i' && s2 == 'c' && s3 == 't')
      return &Curl_scheme_dict;
  }
  else if(s0 == 's') {
    if(s1 == 'm' && s2 == 'b' && s3 == 's')
      return &Curl_scheme_smbs;
  }
  return NULL;
}

static const struct Curl_scheme *five_letter_scheme(const char *scheme)
{
  char s4 = Curl_raw_tolower(scheme[4]);
  if(s4 == 's') {
    char s0 = Curl_raw_tolower(scheme[0]);
    char s1 = Curl_raw_tolower(scheme[1]);
    char s2 = Curl_raw_tolower(scheme[2]);
    char s3 = Curl_raw_tolower(scheme[3]);
    if(s3 == 'p') {
      switch(s0) {
      case 'h':
        if(s1 == 't' && s2 == 't')
          return &Curl_scheme_https;
        break;
      case 'l':
        if(s1 == 'd' && s2 == 'a')
          return &Curl_scheme_ldaps;
        break;
      case 'i':
        if(s1 == 'm' && s2 == 'a')
          return &Curl_scheme_imaps;
        break;
      case 's':
        if(s1 == 'm' && s2 == 't')
          return &Curl_scheme_smtps;
        break;
      default:
        break;
      }
    }
    else if(s0 == 'p') {
      if(s1 == 'o' && s2 == 'p' && s3 == '3')
        return &Curl_scheme_pop3s;
    }
    else if(s0 == 'm') {
      if(s1 == 'q' && s2 == 't' && s3 == 't')
        return &Curl_scheme_mqtts;
    }
    else if(s0 == 's') {
      if(s1 == 'o' && s2 == 'c' && s3 == 'k')
        return &Curl_scheme_socks;
    }
  }
  return NULL;
}

static const struct Curl_scheme *six_letter_scheme(const char *scheme)
{
  char s0 = Curl_raw_tolower(scheme[0]);
  switch(s0) {
  case 's':
    if(curl_strnequal("ocks4", &scheme[1], 5))
      return &Curl_scheme_socks4;
    if(curl_strnequal("ocks5", &scheme[1], 5))
      return &Curl_scheme_socks5;
    break;
  case 'g':
    if(curl_strnequal("opher", &scheme[1], 5))
      return &Curl_scheme_gopher;
    break;
  case 't':
    if(curl_strnequal("elnet", &scheme[1], 5))
      return &Curl_scheme_telnet;
    break;
  }
  return NULL;
}

static const struct Curl_scheme *seven_letter_scheme(const char *scheme)
{
  char s0 = Curl_raw_tolower(scheme[0]);
  if(s0 == 's') {
    if(curl_strnequal("ocks4a", &scheme[1], 6))
      return &Curl_scheme_socks4a;
    if(curl_strnequal("ocks5h", &scheme[1], 6))
      return &Curl_scheme_socks5h;
  }
  else if(s0 == 'g') {
    if(curl_strnequal("ophers", &scheme[1], 6))
      return &Curl_scheme_gophers;
  }
  return NULL;
}

/* Returns a struct scheme pointer if the name is a known scheme. Check the
   ->run struct field for non-NULL to figure out if an implementation is
   present. */
const struct Curl_scheme *Curl_getn_scheme(const char *scheme, size_t len)
{
  typedef const struct Curl_scheme *(*letterfunc)(const char *ptr);
  static const letterfunc parse[] = {
    two_letter_scheme,
    three_letter_scheme,
    four_letter_scheme,
    five_letter_scheme,
    six_letter_scheme,
    seven_letter_scheme
  };

  if(len < 2 || len > 7)
    return NULL;

  return parse[len - 2](scheme);
}

const struct Curl_scheme *Curl_get_scheme(const char *scheme)
{
  return Curl_getn_scheme(scheme, strlen(scheme));
}
