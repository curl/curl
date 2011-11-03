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
 * RFC2821 SMTP protocol
 * RFC3207 SMTP over TLS
 * RFC4954 SMTP Authentication
 * RFC2195 CRAM-MD5 authentication
 * RFC4616 PLAIN authentication
 *
 ***************************************************************************/

#include "setup.h"

#ifndef CURL_DISABLE_SMTP

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "socks.h"
#include "smtp.h"

#include "strtoofft.h"
#include "strequal.h"
#include "sslgen.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "rawstr.h"
#include "strtoofft.h"
#include "curl_base64.h"
#include "curl_md5.h"
#include "curl_hmac.h"
#include "curl_gethostname.h"
#include "curl_ntlm_msgs.h"
#include "warnless.h"
#include "http_proxy.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Local API functions */
static CURLcode smtp_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode smtp_do(struct connectdata *conn, bool *done);
static CURLcode smtp_done(struct connectdata *conn,
                          CURLcode, bool premature);
static CURLcode smtp_connect(struct connectdata *conn, bool *done);
static CURLcode smtp_disconnect(struct connectdata *conn, bool dead);
static CURLcode smtp_multi_statemach(struct connectdata *conn, bool *done);
static int smtp_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks);
static CURLcode smtp_doing(struct connectdata *conn,
                           bool *dophase_done);
static CURLcode smtp_setup_connection(struct connectdata * conn);
static CURLcode smtp_state_upgrade_tls(struct connectdata *conn);

/*
 * SMTP protocol handler.
 */

const struct Curl_handler Curl_handler_smtp = {
  "SMTP",                           /* scheme */
  smtp_setup_connection,            /* setup_connection */
  smtp_do,                          /* do_it */
  smtp_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  smtp_connect,                     /* connect_it */
  smtp_multi_statemach,             /* connecting */
  smtp_doing,                       /* doing */
  smtp_getsock,                     /* proto_getsock */
  smtp_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  smtp_disconnect,                  /* disconnect */
  ZERO_NULL,                        /* readwrite */
  PORT_SMTP,                        /* defport */
  CURLPROTO_SMTP,                   /* protocol */
  PROTOPT_CLOSEACTION               /* flags */
};

#ifdef USE_SSL
/*
 * SMTPS protocol handler.
 */

const struct Curl_handler Curl_handler_smtps = {
  "SMTPS",                          /* scheme */
  smtp_setup_connection,            /* setup_connection */
  smtp_do,                          /* do_it */
  smtp_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  smtp_connect,                     /* connect_it */
  smtp_multi_statemach,             /* connecting */
  smtp_doing,                       /* doing */
  smtp_getsock,                     /* proto_getsock */
  smtp_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  smtp_disconnect,                  /* disconnect */
  ZERO_NULL,                        /* readwrite */
  PORT_SMTPS,                       /* defport */
  CURLPROTO_SMTP | CURLPROTO_SMTPS, /* protocol */
  PROTOPT_CLOSEACTION | PROTOPT_SSL /* flags */
};
#endif

#ifndef CURL_DISABLE_HTTP
/*
 * HTTP-proxyed SMTP protocol handler.
 */

static const struct Curl_handler Curl_handler_smtp_proxy = {
  "SMTP",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_SMTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};

#ifdef USE_SSL
/*
 * HTTP-proxyed SMTPS protocol handler.
 */

static const struct Curl_handler Curl_handler_smtps_proxy = {
  "SMTPS",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_SMTPS,                           /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};
#endif
#endif

/* Function that checks for an ending smtp status code at the start of the
   given string.
   As a side effect, it also flags allowed authentication mechanisms according
   to EHLO AUTH response. */
static int smtp_endofresp(struct pingpong *pp, int *resp)
{
  char *line = pp->linestart_resp;
  size_t len = pp->nread_resp;
  struct connectdata *conn = pp->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  int result;
  size_t wordlen;

  if(len < 4 || !ISDIGIT(line[0]) || !ISDIGIT(line[1]) || !ISDIGIT(line[2]))
    return FALSE;       /* Nothing for us. */

  if((result = (line[3] == ' ')) != 0)
    *resp = curlx_sltosi(strtol(line, NULL, 10));

  line += 4;
  len -= 4;

  if(smtpc->state == SMTP_EHLO && len >= 5 && !memcmp(line, "AUTH ", 5)) {
    line += 5;
    len -= 5;

    for(;;) {
      while(len &&
            (*line == ' ' || *line == '\t' ||
             *line == '\r' || *line == '\n')) {
        line++;
        len--;
      }

      if(!len)
        break;

      for(wordlen = 0; wordlen < len && line[wordlen] != ' ' &&
            line[wordlen] != '\t' && line[wordlen] != '\r' &&
            line[wordlen] != '\n';)
        wordlen++;

      if(wordlen == 5 && !memcmp(line, "LOGIN", 5))
        smtpc->authmechs |= SMTP_AUTH_LOGIN;
      else if(wordlen == 5 && !memcmp(line, "PLAIN", 5))
        smtpc->authmechs |= SMTP_AUTH_PLAIN;
      else if(wordlen == 8 && !memcmp(line, "CRAM-MD5", 8))
        smtpc->authmechs |= SMTP_AUTH_CRAM_MD5;
      else if(wordlen == 10 && !memcmp(line, "DIGEST-MD5", 10))
        smtpc->authmechs |= SMTP_AUTH_DIGEST_MD5;
      else if(wordlen == 6 && !memcmp(line, "GSSAPI", 6))
        smtpc->authmechs |= SMTP_AUTH_GSSAPI;
      else if(wordlen == 8 && !memcmp(line, "EXTERNAL", 8))
        smtpc->authmechs |= SMTP_AUTH_EXTERNAL;
      else if(wordlen == 4 && !memcmp(line, "NTLM", 4))
        smtpc->authmechs |= SMTP_AUTH_NTLM;

      line += wordlen;
      len -= wordlen;
    }
  }

  return result;
}

/* This is the ONLY way to change SMTP state! */
static void state(struct connectdata *conn,
                  smtpstate newstate)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[] = {
    "STOP",
    "SERVERGREET",
    "EHLO",
    "HELO",
    "STARTTLS",
    "UPGRADETLS",
    "AUTHPLAIN",
    "AUTHLOGIN",
    "AUTHPASSWD",
    "AUTHCRAM",
    "AUTHNTLM",
    "AUTHNTLM_TYPE2MSG",
    "AUTH",
    "MAIL",
    "RCPT",
    "DATA",
    "POSTDATA",
    "QUIT",
    /* LAST */
  };
  if(smtpc->state != newstate)
    infof(conn->data, "SMTP %p state change from %s to %s\n",
          smtpc, names[smtpc->state], names[newstate]);
#endif
  smtpc->state = newstate;
}

static CURLcode smtp_state_ehlo(struct connectdata *conn)
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->authmechs = 0;         /* No known authentication mechanisms yet. */
  smtpc->authused = 0;          /* Clear the authentication mechanism used
                                   for esmtp connections */

  /* send EHLO */
  result = Curl_pp_sendf(&smtpc->pp, "EHLO %s", smtpc->domain);

  if(result)
    return result;

  state(conn, SMTP_EHLO);
  return CURLE_OK;
}

static CURLcode smtp_state_helo(struct connectdata *conn)
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->authused = 0;          /* No authentication mechanism used in smtp
                                   connections */

  /* send HELO */
  result = Curl_pp_sendf(&smtpc->pp, "HELO %s", smtpc->domain);

  if(result)
    return result;

  state(conn, SMTP_HELO);
  return CURLE_OK;
}

static CURLcode smtp_auth_plain_data(struct connectdata *conn,
                                     char **outptr, size_t *outlen)
{
  char plainauth[2 * MAX_CURL_USER_LENGTH + MAX_CURL_PASSWORD_LENGTH];
  size_t ulen;
  size_t plen;

  ulen = strlen(conn->user);
  plen = strlen(conn->passwd);

  if(2 * ulen + plen + 2 > sizeof plainauth) {
    *outlen = 0;
    *outptr = NULL;
    return CURLE_OUT_OF_MEMORY; /* plainauth too small */
  }

  memcpy(plainauth, conn->user, ulen);
  plainauth[ulen] = '\0';
  memcpy(plainauth + ulen + 1, conn->user, ulen);
  plainauth[2 * ulen + 1] = '\0';
  memcpy(plainauth + 2 * ulen + 2, conn->passwd, plen);
  return Curl_base64_encode(conn->data, plainauth, 2 * ulen + plen + 2,
                            outptr, outlen);
}

static CURLcode smtp_auth_login_user(struct connectdata *conn,
                                     char **outptr, size_t *outlen)
{
  size_t ulen = strlen(conn->user);

  if(!ulen) {
    *outptr = strdup("=");
    if(*outptr) {
      *outlen = (size_t) 1;
      return CURLE_OK;
    }
    *outlen = 0;
    return CURLE_OUT_OF_MEMORY;
  }

  return Curl_base64_encode(conn->data, conn->user, ulen, outptr, outlen);
}

#ifdef USE_NTLM
static CURLcode smtp_auth_ntlm_type1_message(struct connectdata *conn,
                                             char **outptr, size_t *outlen)
{
  return Curl_ntlm_create_type1_message(conn->user, conn->passwd,
                                        &conn->ntlm, outptr, outlen);
}
#endif

static CURLcode smtp_authenticate(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  char *initresp = NULL;
  const char *mech = NULL;
  size_t len = 0;
  smtpstate state1 = SMTP_STOP;
  smtpstate state2 = SMTP_STOP;

  /* Check we have a username and password to authenticate with and end the
     connect phase if we don't. */
  if(!conn->bits.user_passwd) {
    state(conn, SMTP_STOP);

    return result;
  }

  /* Check supported authentication mechanisms by decreasing order of
     security. */
#ifndef CURL_DISABLE_CRYPTO_AUTH
  if(smtpc->authmechs & SMTP_AUTH_CRAM_MD5) {
    mech = "CRAM-MD5";
    state1 = SMTP_AUTHCRAM;
    smtpc->authused = SMTP_AUTH_CRAM_MD5;
  }
  else
#endif
#ifdef USE_NTLM
  if(smtpc->authmechs & SMTP_AUTH_NTLM) {
    mech = "NTLM";
    state1 = SMTP_AUTHNTLM;
    state2 = SMTP_AUTHNTLM_TYPE2MSG;
    smtpc->authused = SMTP_AUTH_NTLM;
    result = smtp_auth_ntlm_type1_message(conn, &initresp, &len);
  }
  else
#endif
  if(smtpc->authmechs & SMTP_AUTH_LOGIN) {
    mech = "LOGIN";
    state1 = SMTP_AUTHLOGIN;
    state2 = SMTP_AUTHPASSWD;
    smtpc->authused = SMTP_AUTH_LOGIN;
    result = smtp_auth_login_user(conn, &initresp, &len);
  }
  else if(smtpc->authmechs & SMTP_AUTH_PLAIN) {
    mech = "PLAIN";
    state1 = SMTP_AUTHPLAIN;
    state2 = SMTP_AUTH;
    smtpc->authused = SMTP_AUTH_PLAIN;
    result = smtp_auth_plain_data(conn, &initresp, &len);
  }
  else {
    infof(conn->data, "No known auth mechanisms supported!\n");
    result = CURLE_LOGIN_DENIED;      /* Other mechanisms not supported. */
  }

  if(!result) {
    if(initresp &&
       strlen(mech) + len <= 512 - 8) { /* AUTH <mech> ...<crlf> */
       result = Curl_pp_sendf(&smtpc->pp, "AUTH %s %s", mech, initresp);

      if(!result)
        state(conn, state2);
    }
    else {
      result = Curl_pp_sendf(&smtpc->pp, "AUTH %s", mech);

      if(!result)
        state(conn, state1);
    }
    Curl_safefree(initresp);
  }

  return result;
}

/* For the SMTP "protocol connect" and "doing" phases only */
static int smtp_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks)
{
  return Curl_pp_getsock(&conn->proto.smtpc.pp, socks, numsocks);
}

#ifdef USE_SSL
static void smtp_to_smtps(struct connectdata *conn)
{
  conn->handler = &Curl_handler_smtps;
}
#else
#define smtp_to_smtps(x) Curl_nop_stmt
#endif

/* for STARTTLS responses */
static CURLcode smtp_state_starttls_resp(struct connectdata *conn,
                                         int smtpcode,
                                         smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; /* no use for this yet */

  if(smtpcode != 220) {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied. %c", smtpcode);
      result = CURLE_LOGIN_DENIED;
    }
    else
      result = smtp_authenticate(conn);
  }
  else {
    if(data->state.used_interface == Curl_if_multi) {
      state(conn, SMTP_UPGRADETLS);
      return smtp_state_upgrade_tls(conn);
    }
    else {
      result = Curl_ssl_connect(conn, FIRSTSOCKET);
      if(CURLE_OK == result) {
        smtp_to_smtps(conn);
        result = smtp_state_ehlo(conn);
      }
    }
  }

  return result;
}

static CURLcode smtp_state_upgrade_tls(struct connectdata *conn)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  CURLcode result;

  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &smtpc->ssldone);

  if(smtpc->ssldone) {
    smtp_to_smtps(conn);
    result = smtp_state_ehlo(conn);
  }

  return result;
}

/* for EHLO responses */
static CURLcode smtp_state_ehlo_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    if((data->set.use_ssl <= CURLUSESSL_TRY || conn->ssl[FIRSTSOCKET].use) &&
     !conn->bits.user_passwd)
      result = smtp_state_helo(conn);
    else {
      failf(data, "Access denied: %d", smtpcode);
      result = CURLE_LOGIN_DENIED;
    }
  }
  else if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
    /* We don't have a SSL/TLS connection yet, but SSL is requested. Switch
       to TLS connection now */
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "STARTTLS");
    state(conn, SMTP_STARTTLS);
  }
  else
    result = smtp_authenticate(conn);

  return result;
}

/* for HELO responses */
static CURLcode smtp_state_helo_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* end the connect phase */
    state(conn, SMTP_STOP);
  }

  return result;
}

/* for AUTH PLAIN (without initial response) responses */
static CURLcode smtp_state_authplain_resp(struct connectdata *conn,
                                          int smtpcode,
                                          smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *plainauth = NULL;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = smtp_auth_plain_data(conn, &plainauth, &len);

    if(!result) {
      if(plainauth) {
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", plainauth);

        if(!result)
          state(conn, SMTP_AUTH);
      }
      Curl_safefree(plainauth);
    }
  }

  return result;
}

/* for AUTH LOGIN (without initial response) responses */
static CURLcode smtp_state_authlogin_resp(struct connectdata *conn,
                                          int smtpcode,
                                          smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *authuser = NULL;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = smtp_auth_login_user(conn, &authuser, &len);

    if(!result) {
      if(authuser) {
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", authuser);

        if(!result)
          state(conn, SMTP_AUTHPASSWD);
      }
      Curl_safefree(authuser);
    }
  }

  return result;
}

/* for responses to user entry of AUTH LOGIN. */
static CURLcode smtp_state_authpasswd_resp(struct connectdata *conn,
                                           int smtpcode,
                                           smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t plen;
  size_t len = 0;
  char *authpasswd = NULL;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    plen = strlen(conn->passwd);

    if(!plen)
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "=");
    else {
      result = Curl_base64_encode(data, conn->passwd, plen, &authpasswd, &len);

      if(!result) {
        if(authpasswd) {
          result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", authpasswd);

          if(!result)
            state(conn, SMTP_AUTH);
        }
        Curl_safefree(authpasswd);
      }
    }
  }

  return result;
}

#ifndef CURL_DISABLE_CRYPTO_AUTH

/* for AUTH CRAM-MD5 responses. */
static CURLcode smtp_state_authcram_resp(struct connectdata *conn,
                                         int smtpcode,
                                         smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char * chlg64 = data->state.buffer;
  unsigned char * chlg;
  size_t chlglen;
  size_t len = 0;
  char *rplyb64 = NULL;
  HMAC_context *ctxt;
  unsigned char digest[16];
  char reply[MAX_CURL_USER_LENGTH + 32 /* 2 * size of MD5 digest */ + 1];

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    return CURLE_LOGIN_DENIED;
  }

  /* Get the challenge. */
  for(chlg64 += 4; *chlg64 == ' ' || *chlg64 == '\t'; chlg64++)
    ;

  chlg = (unsigned char *) NULL;
  chlglen = 0;

  if(*chlg64 != '=') {
    for(len = strlen(chlg64); len--;)
      if(chlg64[len] != '\r' && chlg64[len] != '\n' && chlg64[len] != ' ' &&
         chlg64[len] != '\t')
        break;

    if(++len) {
      chlg64[len] = '\0';

      result = Curl_base64_decode(chlg64, &chlg, &chlglen);
      if(result)
        return result;
    }
  }

  /* Compute digest. */
  ctxt = Curl_HMAC_init(Curl_HMAC_MD5,
                        (const unsigned char *) conn->passwd,
                        (unsigned int)(strlen(conn->passwd)));

  if(!ctxt) {
    Curl_safefree(chlg);
    return CURLE_OUT_OF_MEMORY;
  }

  if(chlglen > 0)
    Curl_HMAC_update(ctxt, chlg, (unsigned int)(chlglen));

  Curl_safefree(chlg);

  Curl_HMAC_final(ctxt, digest);

  /* Prepare the reply. */
  snprintf(reply, sizeof reply,
   "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           conn->user, digest[0], digest[1], digest[2], digest[3], digest[4],
           digest[5],
           digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
           digest[12], digest[13], digest[14], digest[15]);

  /* Encode it to base64 and send it. */
  result = Curl_base64_encode(data, reply, 0, &rplyb64, &len);

  if(!result) {
    if(rplyb64) {
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", rplyb64);

      if(!result)
        state(conn, SMTP_AUTH);
    }
    Curl_safefree(rplyb64);
  }

  return result;
}

#endif

#ifdef USE_NTLM
/* for the AUTH NTLM (without initial response) response. */
static CURLcode smtp_state_auth_ntlm_resp(struct connectdata *conn,
                                          int smtpcode,
                                          smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *type1msg = NULL;
  size_t len = 0;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = smtp_auth_ntlm_type1_message(conn, &type1msg, &len);

    if(!result) {
      if(type1msg) {
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", type1msg);

        if(!result)
          state(conn, SMTP_AUTHNTLM_TYPE2MSG);
      }
      Curl_safefree(type1msg);
    }
  }

  return result;
}

/* for the NTLM type-2 response (sent in reponse to our type-1 message). */
static CURLcode smtp_state_auth_ntlm_type2msg_resp(struct connectdata *conn,
                                                   int smtpcode,
                                                   smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *type3msg = NULL;
  size_t len = 0;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    result = Curl_ntlm_decode_type2_message(data, data->state.buffer + 4,
                                            &conn->ntlm);
    if(!result) {
      result = Curl_ntlm_create_type3_message(conn->data, conn->user,
                                              conn->passwd, &conn->ntlm,
                                              &type3msg, &len);
      if(!result) {
        if(type3msg) {
          result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", type3msg);

          if(!result)
            state(conn, SMTP_AUTH);
        }
        Curl_safefree(type3msg);
      }
    }
  }

  return result;
}
#endif

/* for final responses to AUTH sequences. */
static CURLcode smtp_state_auth_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode != 235) {
    failf(data, "Authentication failed: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else
    state(conn, SMTP_STOP);             /* End of connect phase. */

  return result;
}

/* start the DO phase */
static CURLcode smtp_mail(struct connectdata *conn)
{
  char *from = NULL;
  char *size = NULL;
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  /* calculate the FROM parameter */
  if(!data->set.str[STRING_MAIL_FROM])
    /* null reverse-path, RFC-2821, sect. 3.7 */
    from = strdup("<>");
  else if(data->set.str[STRING_MAIL_FROM][0] == '<')
    from = aprintf("%s", data->set.str[STRING_MAIL_FROM]);
  else
    from = aprintf("<%s>", data->set.str[STRING_MAIL_FROM]);

  if(!from)
    return CURLE_OUT_OF_MEMORY;

  /* calculate the optional SIZE parameter */
  if(conn->data->set.infilesize > 0) {
    size = aprintf("%" FORMAT_OFF_T, data->set.infilesize);

    if(!size) {
      Curl_safefree(from);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* send MAIL FROM */
  if(!size)
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "MAIL FROM:%s", from);
  else
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "MAIL FROM:%s SIZE=%s",
                           from, size);

  Curl_safefree(size);
  Curl_safefree(from);

  if(result)
    return result;

  state(conn, SMTP_MAIL);

  return result;
}

static CURLcode smtp_rcpt_to(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  /* send RCPT TO */
  if(smtpc->rcpt) {
    if(smtpc->rcpt->data[0] == '<')
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "RCPT TO:%s",
                             smtpc->rcpt->data);
    else
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "RCPT TO:<%s>",
                             smtpc->rcpt->data);
    if(!result)
      state(conn, SMTP_RCPT);
  }

  return result;
}

/* for MAIL responses */
static CURLcode smtp_state_mail_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
    state(conn, SMTP_STOP);
  }
  else {
    struct smtp_conn *smtpc = &conn->proto.smtpc;
    smtpc->rcpt = data->set.mail_rcpt;

    result = smtp_rcpt_to(conn);
  }

  return result;
}

/* for RCPT responses */
static CURLcode smtp_state_rcpt_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
    state(conn, SMTP_STOP);
  }
  else {
    struct smtp_conn *smtpc = &conn->proto.smtpc;

    if(smtpc->rcpt) {
      smtpc->rcpt = smtpc->rcpt->next;
      result = smtp_rcpt_to(conn);

      /* if we failed or still is in RCPT sending, return */
      if(result || smtpc->rcpt)
        return result;
    }

    /* send DATA */
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "DATA");
    if(result)
      return result;

    state(conn, SMTP_DATA);
  }

  return result;
}

/* for the DATA response */
static CURLcode smtp_state_data_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  struct SessionHandle *data = conn->data;
  struct FTP *smtp = data->state.proto.smtp;

  (void)instate; /* no use for this yet */

  if(smtpcode != 354) {
    state(conn, SMTP_STOP);
    return CURLE_RECV_ERROR;
  }

  /* SMTP upload */
  Curl_setup_transfer(conn, -1, -1, FALSE, NULL, /* no download */
                      FIRSTSOCKET, smtp->bytecountp);

  state(conn, SMTP_STOP);
  return CURLE_OK;
}

/* for the POSTDATA response, which is received after the entire DATA
   part has been sent off to the server */
static CURLcode smtp_state_postdata_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;

  (void)instate; /* no use for this yet */

  if(smtpcode != 250)
    result = CURLE_RECV_ERROR;

  state(conn, SMTP_STOP);

  return result;
}

static CURLcode smtp_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data = conn->data;
  int smtpcode;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  size_t nread = 0;

  if(smtpc->state == SMTP_UPGRADETLS)
    return smtp_state_upgrade_tls(conn);

  if(pp->sendleft)
    /* we have a piece of a command still left to send */
    return Curl_pp_flushsend(pp);

  /* we read a piece of response */
  result = Curl_pp_readresp(sock, pp, &smtpcode, &nread);
  if(result)
    return result;

  if(smtpcode) {
    /* we have now received a full SMTP server response */
    switch(smtpc->state) {
    case SMTP_SERVERGREET:
      if(smtpcode/100 != 2) {
        failf(data, "Got unexpected smtp-server response: %d", smtpcode);
        return CURLE_FTP_WEIRD_SERVER_REPLY;
      }

      result = smtp_state_ehlo(conn);
      if(result)
        return result;
      break;

    case SMTP_EHLO:
      result = smtp_state_ehlo_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_HELO:
      result = smtp_state_helo_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_STARTTLS:
      result = smtp_state_starttls_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHPLAIN:
      result = smtp_state_authplain_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHLOGIN:
      result = smtp_state_authlogin_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHPASSWD:
      result = smtp_state_authpasswd_resp(conn, smtpcode, smtpc->state);
      break;

#ifndef CURL_DISABLE_CRYPTO_AUTH
    case SMTP_AUTHCRAM:
      result = smtp_state_authcram_resp(conn, smtpcode, smtpc->state);
      break;
#endif

#ifdef USE_NTLM
    case SMTP_AUTHNTLM:
      result = smtp_state_auth_ntlm_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTHNTLM_TYPE2MSG:
      result = smtp_state_auth_ntlm_type2msg_resp(conn, smtpcode,
                                                  smtpc->state);
      break;
#endif

    case SMTP_AUTH:
      result = smtp_state_auth_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_MAIL:
      result = smtp_state_mail_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_RCPT:
      result = smtp_state_rcpt_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_DATA:
      result = smtp_state_data_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_POSTDATA:
      result = smtp_state_postdata_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_QUIT:
      /* fallthrough, just stop! */
    default:
      /* internal error */
      state(conn, SMTP_STOP);
      break;
    }
  }

  return result;
}

/* called repeatedly until done from multi.c */
static CURLcode smtp_multi_statemach(struct connectdata *conn,
                                     bool *done)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  CURLcode result;

  if((conn->handler->flags & PROTOPT_SSL) && !smtpc->ssldone)
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &smtpc->ssldone);
  else
    result = Curl_pp_multi_statemach(&smtpc->pp);

  *done = (smtpc->state == SMTP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode smtp_easy_statemach(struct connectdata *conn)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  CURLcode result = CURLE_OK;

  while(smtpc->state != SMTP_STOP) {
    result = Curl_pp_easy_statemach(pp);
    if(result)
      break;
  }

  return result;
}

/*
 * Allocate and initialize the struct SMTP for the current SessionHandle.  If
 * need be.
 */
static CURLcode smtp_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct FTP *smtp = data->state.proto.smtp;
  if(!smtp) {
    smtp = data->state.proto.smtp = calloc(sizeof(struct FTP), 1);
    if(!smtp)
      return CURLE_OUT_OF_MEMORY;
  }

  /* get some initial data into the smtp struct */
  smtp->bytecountp = &data->req.bytecount;

  /* No need to duplicate user+password, the connectdata struct won't change
     during a session, but we re-init them here since on subsequent inits
     since the conn struct may have changed or been replaced.
  */
  smtp->user = conn->user;
  smtp->passwd = conn->passwd;

  return CURLE_OK;
}

/*
 * smtp_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable pointed to by 'done' will be TRUE if the protocol-layer
 * connect phase is done when this function returns, or FALSE if not. When
 * called as a part of the easy interface, it will always be TRUE.
 */
static CURLcode smtp_connect(struct connectdata *conn,
                             bool *done) /* see description above */
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct SessionHandle *data = conn->data;
  struct pingpong *pp = &smtpc->pp;
  const char *path = conn->data->state.path;
  int len;
  char localhost[HOSTNAME_MAX + 1];

  *done = FALSE; /* default to not done yet */

  /* If there already is a protocol-specific struct allocated for this
     sessionhandle, deal with it */
  Curl_reset_reqproto(conn);

  result = smtp_init(conn);
  if(CURLE_OK != result)
    return result;

  /* We always support persistent connections on smtp */
  conn->bits.close = FALSE;

  pp->response_time = RESP_TIMEOUT; /* set default response time-out */
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
    /* for SMTP over HTTP proxy */
    struct HTTP http_proxy;
    struct FTP *smtp_save;

    /* BLOCKING */
    /* We want "seamless" SMTP operations through HTTP proxy tunnel */

    /* Curl_proxyCONNECT is based on a pointer to a struct HTTP at the member
     * conn->proto.http; we want SMTP through HTTP and we have to change the
     * member temporarily for connecting to the HTTP proxy. After
     * Curl_proxyCONNECT we have to set back the member to the original struct
     * SMTP pointer
     */
    smtp_save = data->state.proto.smtp;
    memset(&http_proxy, 0, sizeof(http_proxy));
    data->state.proto.http = &http_proxy;

    result = Curl_proxyCONNECT(conn, FIRSTSOCKET,
                               conn->host.name, conn->remote_port);

    data->state.proto.smtp = smtp_save;

    if(CURLE_OK != result)
      return result;
  }

  if((conn->handler->protocol & CURLPROTO_SMTPS) &&
      data->state.used_interface != Curl_if_multi) {
    /* SMTPS is simply smtp with SSL for the control channel */
    /* now, perform the SSL initialization for this socket */
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  Curl_pp_init(pp); /* init the response reader stuff */

  pp->response_time = RESP_TIMEOUT; /* set default response time-out */
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

  if(!*path) {
    if(!Curl_gethostname(localhost, sizeof localhost))
      path = localhost;
    else
      path = "localhost";
  }

  /* url decode the path and use it as domain with EHLO */
  smtpc->domain = curl_easy_unescape(conn->data, path, 0, &len);
  if(!smtpc->domain)
    return CURLE_OUT_OF_MEMORY;

  /* When we connect, we start in the state where we await the server greeting
   */
  state(conn, SMTP_SERVERGREET);

  if(data->state.used_interface == Curl_if_multi)
    result = smtp_multi_statemach(conn, done);
  else {
    result = smtp_easy_statemach(conn);
    if(!result)
      *done = TRUE;
  }

  return result;
}

/***********************************************************************
 *
 * smtp_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
static CURLcode smtp_done(struct connectdata *conn, CURLcode status,
                          bool premature)
{
  struct SessionHandle *data = conn->data;
  struct FTP *smtp = data->state.proto.smtp;
  CURLcode result = CURLE_OK;
  ssize_t bytes_written;
  (void)premature;

  if(!smtp)
    /* When the easy handle is removed from the multi while libcurl is still
     * trying to resolve the host name, it seems that the smtp struct is not
     * yet initialized, but the removal action calls Curl_done() which calls
     * this function. So we simply return success if no smtp pointer is set.
     */
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; /* marked for closure */
    result = status;      /* use the already set error code */
  }
  else
    /* TODO: make this work even when the socket is EWOULDBLOCK in this
       call! */

    /* write to socket (send away data) */
    result = Curl_write(conn,
                        conn->writesockfd,  /* socket to send to */
                        SMTP_EOB,           /* buffer pointer */
                        SMTP_EOB_LEN,       /* buffer size */
                        &bytes_written);    /* actually sent away */


  if(status == CURLE_OK) {
    struct smtp_conn *smtpc = &conn->proto.smtpc;
    struct pingpong *pp = &smtpc->pp;
    pp->response = Curl_tvnow(); /* timeout relative now */

    state(conn, SMTP_POSTDATA);
    /* run the state-machine

       TODO: when the multi interface is used, this _really_ should be using
       the smtp_multi_statemach function but we have no general support for
       non-blocking DONE operations, not in the multi state machine and with
       Curl_done() invokes on several places in the code!
    */
    result = smtp_easy_statemach(conn);
  }

  /* clear these for next connection */
  smtp->transfer = FTPTRANSFER_BODY;

  return result;
}

/***********************************************************************
 *
 * smtp_perform()
 *
 * This is the actual DO function for SMTP. Get a file/directory according to
 * the options previously setup.
 */

static
CURLcode smtp_perform(struct connectdata *conn,
                     bool *connected,  /* connect status after PASV / PORT */
                     bool *dophase_done)
{
  /* this is SMTP and no proxy */
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    /* requested no body means no transfer... */
    struct FTP *smtp = conn->data->state.proto.smtp;
    smtp->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  /* start the first command in the DO phase */
  result = smtp_mail(conn);
  if(result)
    return result;

  /* run the state-machine */
  if(conn->data->state.used_interface == Curl_if_multi)
    result = smtp_multi_statemach(conn, dophase_done);
  else {
    result = smtp_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}

/***********************************************************************
 *
 * smtp_do()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (smtp_perform).
 *
 * The input argument is already checked for validity.
 */
static CURLcode smtp_do(struct connectdata *conn, bool *done)
{
  CURLcode retcode = CURLE_OK;

  *done = FALSE; /* default to false */

  /*
    Since connections can be re-used between SessionHandles, this might be a
    connection already existing but on a fresh SessionHandle struct so we must
    make sure we have a good 'struct SMTP' to play with. For new connections,
    the struct SMTP is allocated and setup in the smtp_connect() function.
  */
  Curl_reset_reqproto(conn);
  retcode = smtp_init(conn);
  if(retcode)
    return retcode;

  retcode = smtp_regular_transfer(conn, done);

  return retcode;
}

/***********************************************************************
 *
 * smtp_quit()
 *
 * This should be called before calling sclose().  We should then wait for the
 * response from the server before returning. The calling code should then try
 * to close the connection.
 *
 */
static CURLcode smtp_quit(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  result = Curl_pp_sendf(&conn->proto.smtpc.pp, "QUIT");
  if(result)
    return result;
  state(conn, SMTP_QUIT);

  result = smtp_easy_statemach(conn);

  return result;
}

/***********************************************************************
 *
 * smtp_disconnect()
 *
 * Disconnect from an SMTP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode smtp_disconnect(struct connectdata *conn,
                                bool dead_connection)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to.
  */

  /* The SMTP session may or may not have been allocated/setup at this
     point! */
  if(!dead_connection && smtpc->pp.conn)
    (void)smtp_quit(conn); /* ignore errors on the LOGOUT */

  Curl_pp_disconnect(&smtpc->pp);

#ifdef USE_NTLM
  /* Cleanup the ntlm structure */
  if(smtpc->authused == SMTP_AUTH_NTLM) {
    Curl_ntlm_sspi_cleanup(&conn->ntlm);
  }
#endif

  /* This won't already be freed in some error cases */
  Curl_safefree(smtpc->domain);
  smtpc->domain = NULL;

  return CURLE_OK;
}

/* call this when the DO phase has completed */
static CURLcode smtp_dophase_done(struct connectdata *conn,
                                  bool connected)
{
  struct FTP *smtp = conn->data->state.proto.smtp;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  (void)connected;

  if(smtp->transfer != FTPTRANSFER_BODY)
    /* no data to transfer */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  free(smtpc->domain);
  smtpc->domain = NULL;

  return CURLE_OK;
}

/* called from multi.c while DOing */
static CURLcode smtp_doing(struct connectdata *conn,
                           bool *dophase_done)
{
  CURLcode result;
  result = smtp_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    result = smtp_dophase_done(conn, FALSE /* not connected */);

    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

/***********************************************************************
 *
 * smtp_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 */
static
CURLcode smtp_regular_transfer(struct connectdata *conn,
                               bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  struct SessionHandle *data = conn->data;
  data->req.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  result = smtp_perform(conn,
                        &connected, /* have we connected after PASV/PORT */
                        dophase_done); /* all commands in the DO-phase done? */

  if(CURLE_OK == result) {

    if(!*dophase_done)
      /* the DO phase has not completed yet */
      return CURLE_OK;

    result = smtp_dophase_done(conn, connected);
    if(result)
      return result;
  }

  return result;
}

static CURLcode smtp_setup_connection(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    /* Unless we have asked to tunnel smtp operations through the proxy, we
       switch and use HTTP operations only */
#ifndef CURL_DISABLE_HTTP
    if(conn->handler == &Curl_handler_smtp)
      conn->handler = &Curl_handler_smtp_proxy;
    else {
#ifdef USE_SSL
      conn->handler = &Curl_handler_smtps_proxy;
#else
      failf(data, "SMTPS not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif
    }
    /*
     * We explicitly mark this connection as persistent here as we're doing
     * SMTP over HTTP and thus we accidentally avoid setting this value
     * otherwise.
     */
    conn->bits.close = FALSE;
#else
    failf(data, "SMTP over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }

  data->state.path++;   /* don't include the initial slash */

  return CURLE_OK;
}

CURLcode Curl_smtp_escape_eob(struct connectdata *conn, ssize_t nread)
{
  /* When sending SMTP payload, we must detect CRLF.CRLF sequences in
   * the data and make sure it is sent as CRLF..CRLF instead, as
   * otherwise it will wrongly be detected as end of data by the server.
   */
  ssize_t i;
  ssize_t si;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct SessionHandle *data = conn->data;

  if(data->state.scratch == NULL)
    data->state.scratch = malloc(2 * BUFSIZE);
  if(data->state.scratch == NULL) {
    failf (data, "Failed to alloc scratch buffer!");
    return CURLE_OUT_OF_MEMORY;
  }
  /* This loop can be improved by some kind of Boyer-Moore style of
     approach but that is saved for later... */
  for(i = 0, si = 0; i < nread; i++) {

    if(SMTP_EOB[smtpc->eob] == data->req.upload_fromhere[i])
      smtpc->eob++;
    else if(smtpc->eob) {
      /* previously a substring matched, output that first */
      memcpy(&data->state.scratch[si], SMTP_EOB, smtpc->eob);
      si += smtpc->eob;

      /* then compare the first byte */
      if(SMTP_EOB[0] == data->req.upload_fromhere[i])
        smtpc->eob = 1;
      else
        smtpc->eob = 0;
    }

    if(SMTP_EOB_LEN == smtpc->eob) {
      /* It matched, copy the replacement data to the target buffer
         instead. Note that the replacement does not contain the
         trailing CRLF but we instead continue to match on that one
         to deal with repeated sequences. Like CRLF.CRLF.CRLF etc
      */
      memcpy(&data->state.scratch[si], SMTP_EOB_REPL,
             SMTP_EOB_REPL_LEN);
      si += SMTP_EOB_REPL_LEN;
      smtpc->eob = 2; /* start over at two bytes */
    }
    else if(!smtpc->eob)
      data->state.scratch[si++] = data->req.upload_fromhere[i];

  } /* for() */

  if(si != nread) {
    /* only use the new buffer if we replaced something */
    nread = si;

    /* upload from the new (replaced) buffer instead */
    data->req.upload_fromhere = data->state.scratch;

    /* set the new amount too */
    data->req.upload_present = nread;
  }

  return CURLE_OK;
}

#endif /* CURL_DISABLE_SMTP */
