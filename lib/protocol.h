#ifndef HEADER_CURL_PROTOCOL_H
#define HEADER_CURL_PROTOCOL_H
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
/* This file is for lib internal stuff */
#include "curl_setup.h"

struct Curl_easy;
struct connectdata;
struct easy_pollset;

/* Known protocol default port numbers */
#define PORT_FTP    21
#define PORT_FTPS   990
#define PORT_TELNET 23
#define PORT_HTTP   80
#define PORT_HTTPS  443
#define PORT_DICT   2628
#define PORT_LDAP   389
#define PORT_LDAPS  636
#define PORT_TFTP   69
#define PORT_SSH    22
#define PORT_IMAP   143
#define PORT_IMAPS  993
#define PORT_POP3   110
#define PORT_POP3S  995
#define PORT_SMB    445
#define PORT_SMBS   445
#define PORT_SMTP   25
#define PORT_SMTPS  465 /* sometimes called SSMTP */
#define PORT_RTSP   554
#define PORT_GOPHER 70
#define PORT_MQTT   1883
#define PORT_MQTTS  8883

/* CURLPROTO_GOPHERS (29) is the highest publicly used protocol bit number,
 * the rest are internal information. If we use higher bits we only do this on
 * platforms that have a >= 64-bit type and then we use such a type for the
 * protocol fields in the scheme definition.
 */
#define CURLPROTO_WS     (1L << 30)
#define CURLPROTO_WSS    ((curl_prot_t)1 << 31)
#define CURLPROTO_MQTTS  (1LL << 32)

#define CURLPROTO_64ALL ((uint64_t)0xffffffffffffffff)

/* the default protocols accepting a redirect to */
#define CURLPROTO_REDIR (CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_FTP | \
                         CURLPROTO_FTPS)

typedef curl_off_t curl_prot_t;

/* This mask is for all the old protocols that are provided and defined in the
   public header and shall exclude protocols added since which are not exposed
   in the API */
#define CURLPROTO_MASK   0x3fffffff

/* Convenience defines for checking protocols or their SSL based version. Each
   protocol scheme should only ever have a single CURLPROTO_ in its protocol
   field. */
#define PROTO_FAMILY_HTTP (CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_WS | \
                           CURLPROTO_WSS)
#define PROTO_FAMILY_FTP  (CURLPROTO_FTP | CURLPROTO_FTPS)
#define PROTO_FAMILY_POP3 (CURLPROTO_POP3 | CURLPROTO_POP3S)
#define PROTO_FAMILY_SMB  (CURLPROTO_SMB | CURLPROTO_SMBS)
#define PROTO_FAMILY_SMTP (CURLPROTO_SMTP | CURLPROTO_SMTPS)
#define PROTO_FAMILY_SSH  (CURLPROTO_SCP | CURLPROTO_SFTP)

#if !defined(CURL_DISABLE_FTP) || defined(USE_SSH) || \
  !defined(CURL_DISABLE_POP3)
/* these protocols support CURLOPT_DIRLISTONLY */
#define CURL_LIST_ONLY_PROTOCOL 1
#endif

/* When redirecting transfers. */
typedef enum {
  FOLLOW_NONE,  /* not used within the function, a placeholder to allow
                   initing to this */
  FOLLOW_FAKE,  /* only records stuff, not actually following */
  FOLLOW_RETRY, /* set if this is a request retry as opposed to a real
                   redirect following */
  FOLLOW_REDIR /* a full true redirect */
} followtype;

/*
 * Specific protocol handler, an implementation of one or more URI schemes.
 */
struct Curl_protocol {
  /* Complement to setup_connection_internals(). This is done before the
     transfer "owns" the connection. */
  CURLcode (*setup_connection)(struct Curl_easy *data,
                               struct connectdata *conn);

  /* These two functions MUST be set to be protocol dependent */
  CURLcode (*do_it)(struct Curl_easy *data, bool *done);
  CURLcode (*done)(struct Curl_easy *, CURLcode, bool);

  /* If the curl_do() function is better made in two halves, this
   * curl_do_more() function will be called afterwards, if set. For example
   * for doing the FTP stuff after the PASV/PORT command.
   */
  CURLcode (*do_more)(struct Curl_easy *, int *);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * after the connect() and everything is done, as a step in the connection.
   * The 'done' pointer points to a bool that should be set to TRUE if the
   * function completes before return. If it does not complete, the caller
   * should call the ->connecting() function until it is.
   */
  CURLcode (*connect_it)(struct Curl_easy *data, bool *done);

  /* See above. */
  CURLcode (*connecting)(struct Curl_easy *data, bool *done);
  CURLcode (*doing)(struct Curl_easy *data, bool *done);

  /* Called from the multi interface during the PROTOCONNECT phase, and it
     should then return a proper fd set */
  CURLcode (*proto_pollset)(struct Curl_easy *data,
                            struct easy_pollset *ps);

  /* Called from the multi interface during the DOING phase, and it should
     then return a proper fd set */
  CURLcode (*doing_pollset)(struct Curl_easy *data,
                            struct easy_pollset *ps);

  /* Called from the multi interface during the DO_MORE phase, and it should
     then return a proper fd set */
  CURLcode (*domore_pollset)(struct Curl_easy *data,
                            struct easy_pollset *ps);

  /* Called from the multi interface during the DO_DONE, PERFORM and
     WAITPERFORM phases, and it should then return a proper fd set. Not setting
     this will make libcurl use the generic default one. */
  CURLcode (*perform_pollset)(struct Curl_easy *data,
                              struct easy_pollset *ps);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * by the curl_disconnect(), as a step in the disconnection. If the handler
   * is called because the connection has been considered dead,
   * dead_connection is set to TRUE. The connection is (again) associated with
   * the transfer here.
   */
  CURLcode (*disconnect)(struct Curl_easy *, struct connectdata *,
                         bool dead_connection);

  /* If used, this function gets called from transfer.c to
     allow the protocol to do extra handling in writing response to
     the client. */
  CURLcode (*write_resp)(struct Curl_easy *data, const char *buf, size_t blen,
                         bool is_eos);

  /* If used, this function gets called from transfer.c to
     allow the protocol to do extra handling in writing a single response
     header line to the client. */
  CURLcode (*write_resp_hd)(struct Curl_easy *data,
                            const char *hd, size_t hdlen, bool is_eos);

  /* If used, this function checks for a connection managed by this
    protocol and currently not in use, if it should be considered dead. */
  bool (*connection_is_dead)(struct Curl_easy *data,
                             struct connectdata *conn);

  /* attach() attaches this transfer to this connection */
  void (*attach)(struct Curl_easy *data, struct connectdata *conn);

  /* return CURLE_OK if a redirect to `newurl` should be followed,
     CURLE_TOO_MANY_REDIRECTS otherwise. May alter `data` to change
     the way the follow request is performed. */
  CURLcode (*follow)(struct Curl_easy *data, const char *newurl,
                     followtype type);
};

#define PROTOPT_NONE 0             /* nothing extra */
#define PROTOPT_SSL (1 << 0)       /* uses SSL */
#define PROTOPT_DUAL (1 << 1)      /* this protocol uses two connections */
#define PROTOPT_CLOSEACTION (1 << 2) /* need action before socket close */
/* some protocols will have to call the underlying functions without regard to
   what exact state the socket signals. IE even if the socket says "readable",
   the send function might need to be called while uploading, or vice versa.
*/
#define PROTOPT_DIRLOCK (1 << 3)
#define PROTOPT_NONETWORK (1 << 4) /* protocol does not use the network! */
#define PROTOPT_NEEDSPWD (1 << 5)  /* needs a password, and if none is set it
                                      gets a default */
#define PROTOPT_NOURLQUERY (1 << 6)  /* protocol cannot handle
                                        URL query strings (?foo=bar) ! */
#define PROTOPT_CREDSPERREQUEST (1 << 7) /* requires login credentials per
                                            request instead of per
                                            connection */
#define PROTOPT_ALPN (1 << 8) /* set ALPN for this */
/* (1 << 9) was PROTOPT_STREAM, now free */
#define PROTOPT_URLOPTIONS (1 << 10) /* allow options part in the userinfo
                                        field of the URL */
#define PROTOPT_PROXY_AS_HTTP (1 << 11) /* allow this non-HTTP scheme over a
                                           HTTP proxy as HTTP proxies may know
                                           this protocol and act as
                                           a gateway */
#define PROTOPT_WILDCARD (1 << 12)  /* protocol supports wildcard matching */
#define PROTOPT_USERPWDCTRL (1 << 13) /* Allow "control bytes" (< 32 ASCII) in
                                         username and password */
#define PROTOPT_NOTCPPROXY (1 << 14)  /* this protocol cannot proxy over TCP */
#define PROTOPT_SSL_REUSE (1 << 15)   /* this protocol may reuse an existing
                                         SSL connection in the same family
                                         without having PROTOPT_SSL. */
#define PROTOPT_CONN_REUSE (1 << 16)  /* this protocol can reuse connections */

/* Everything about a URI scheme. */
struct Curl_scheme {
  const char *name;       /* URL scheme name in lowercase */
  const struct Curl_protocol *run; /* implementation, optional */
  curl_prot_t protocol;   /* See CURLPROTO_* - this needs to be the single
                             specific protocol bit */
  curl_prot_t family;     /* single bit for protocol family; the non-TLS name
                             of the protocol this is */
  uint32_t flags;         /* Extra particular characteristics, see PROTOPT_* */
  uint16_t defport;       /* Default port. */
};

/* Get scheme definition for a URI scheme name
 * @param scheme URI scheme name, case-insensitive
 * @return NULL if scheme is not known
 */
const struct Curl_scheme *Curl_get_scheme(const char *scheme);
const struct Curl_scheme *Curl_getn_scheme(const char *scheme, size_t len);

/* For direct access to a URI scheme */
extern const struct Curl_scheme Curl_scheme_dict;
extern const struct Curl_scheme Curl_scheme_file;
extern const struct Curl_scheme Curl_scheme_ftp;
extern const struct Curl_scheme Curl_scheme_ftps;
extern const struct Curl_scheme Curl_scheme_gopher;
extern const struct Curl_scheme Curl_scheme_gophers;
extern const struct Curl_scheme Curl_scheme_http;
extern const struct Curl_scheme Curl_scheme_https;
extern const struct Curl_scheme Curl_scheme_imap;
extern const struct Curl_scheme Curl_scheme_imaps;
extern const struct Curl_scheme Curl_scheme_ldap;
extern const struct Curl_scheme Curl_scheme_ldaps;
extern const struct Curl_scheme Curl_scheme_mqtt;
extern const struct Curl_scheme Curl_scheme_mqtts;
extern const struct Curl_scheme Curl_scheme_pop3;
extern const struct Curl_scheme Curl_scheme_pop3s;
extern const struct Curl_scheme Curl_scheme_rtsp;
extern const struct Curl_scheme Curl_scheme_scp;
extern const struct Curl_scheme Curl_scheme_sftp;
extern const struct Curl_scheme Curl_scheme_smb;
extern const struct Curl_scheme Curl_scheme_smbs;
extern const struct Curl_scheme Curl_scheme_smtp;
extern const struct Curl_scheme Curl_scheme_smtps;
extern const struct Curl_scheme Curl_scheme_telnet;
extern const struct Curl_scheme Curl_scheme_tftp;
extern const struct Curl_scheme Curl_scheme_ws;
extern const struct Curl_scheme Curl_scheme_wss;

#endif /* HEADER_CURL_PROTOCOL_H */
