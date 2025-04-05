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
 * RFC1734 POP3 Authentication
 * RFC1939 POP3 protocol
 * RFC2195 CRAM-MD5 authentication
 * RFC2384 POP URL Scheme
 * RFC2449 POP3 Extension Mechanism
 * RFC2595 Using TLS with IMAP, POP3 and ACAP
 * RFC2831 DIGEST-MD5 authentication
 * RFC4422 Simple Authentication and Security Layer (SASL)
 * RFC4616 PLAIN authentication
 * RFC4752 The Kerberos V5 ("GSSAPI") SASL Mechanism
 * RFC5034 POP3 SASL Authentication Mechanism
 * RFC6749 OAuth 2.0 Authorization Framework
 * RFC8314 Use of TLS for Email Submission and Access
 * Draft   LOGIN SASL Mechanism <draft-murchison-sasl-login-00.txt>
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_POP3

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "socks.h"
#include "pop3.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "cfilters.h"
#include "connect.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "bufref.h"
#include "curl_sasl.h"
#include "curl_md5.h"
#include "warnless.h"
#include "strdup.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* Local API functions */
static CURLcode pop3_regular_transfer(struct Curl_easy *data, bool *done);
static CURLcode pop3_do(struct Curl_easy *data, bool *done);
static CURLcode pop3_done(struct Curl_easy *data, CURLcode status,
                          bool premature);
static CURLcode pop3_connect(struct Curl_easy *data, bool *done);
static CURLcode pop3_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead);
static CURLcode pop3_multi_statemach(struct Curl_easy *data, bool *done);
static int pop3_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks);
static CURLcode pop3_doing(struct Curl_easy *data, bool *dophase_done);
static CURLcode pop3_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn);
static CURLcode pop3_parse_url_options(struct connectdata *conn);
static CURLcode pop3_parse_url_path(struct Curl_easy *data);
static CURLcode pop3_parse_custom_request(struct Curl_easy *data);
static CURLcode pop3_perform_auth(struct Curl_easy *data, const char *mech,
                                  const struct bufref *initresp);
static CURLcode pop3_continue_auth(struct Curl_easy *data, const char *mech,
                                   const struct bufref *resp);
static CURLcode pop3_cancel_auth(struct Curl_easy *data, const char *mech);
static CURLcode pop3_get_message(struct Curl_easy *data, struct bufref *out);

/* This function scans the body after the end-of-body and writes everything
 * until the end is found */
static CURLcode pop3_write(struct Curl_easy *data,
                           const char *str, size_t nread, bool is_eos);

/*
 * POP3 protocol handler.
 */

const struct Curl_handler Curl_handler_pop3 = {
  "pop3",                           /* scheme */
  pop3_setup_connection,            /* setup_connection */
  pop3_do,                          /* do_it */
  pop3_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  pop3_connect,                     /* connect_it */
  pop3_multi_statemach,             /* connecting */
  pop3_doing,                       /* doing */
  pop3_getsock,                     /* proto_getsock */
  pop3_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  pop3_disconnect,                  /* disconnect */
  pop3_write,                       /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  ZERO_NULL,                        /* follow */
  PORT_POP3,                        /* defport */
  CURLPROTO_POP3,                   /* protocol */
  CURLPROTO_POP3,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | /* flags */
  PROTOPT_URLOPTIONS
};

#ifdef USE_SSL
/*
 * POP3S protocol handler.
 */

const struct Curl_handler Curl_handler_pop3s = {
  "pop3s",                          /* scheme */
  pop3_setup_connection,            /* setup_connection */
  pop3_do,                          /* do_it */
  pop3_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  pop3_connect,                     /* connect_it */
  pop3_multi_statemach,             /* connecting */
  pop3_doing,                       /* doing */
  pop3_getsock,                     /* proto_getsock */
  pop3_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  pop3_disconnect,                  /* disconnect */
  pop3_write,                       /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  ZERO_NULL,                        /* follow */
  PORT_POP3S,                       /* defport */
  CURLPROTO_POP3S,                  /* protocol */
  CURLPROTO_POP3,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL
  | PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS /* flags */
};
#endif

/* SASL parameters for the pop3 protocol */
static const struct SASLproto saslpop3 = {
  "pop",                /* The service name */
  pop3_perform_auth,    /* Send authentication command */
  pop3_continue_auth,   /* Send authentication continuation */
  pop3_cancel_auth,     /* Send authentication cancellation */
  pop3_get_message,     /* Get SASL response message */
  255 - 8,              /* Max line len - strlen("AUTH ") - 1 space - crlf */
  '*',                  /* Code received when continuation is expected */
  '+',                  /* Code to receive upon authentication success */
  SASL_AUTH_DEFAULT,    /* Default mechanisms */
  SASL_FLAG_BASE64      /* Configuration flags */
};

struct pop3_cmd {
  const char *name;
  unsigned short nlen;
  BIT(multiline); /* response is multi-line with last '.' line */
  BIT(multiline_with_args); /* is multi-line when command has args */
};

static const struct pop3_cmd pop3cmds[] = {
  { "APOP", 4, FALSE, FALSE },
  { "AUTH", 4, FALSE, FALSE },
  { "CAPA", 4, TRUE, TRUE },
  { "DELE", 4, FALSE, FALSE },
  { "LIST", 4, TRUE, FALSE },
  { "MSG",  3, TRUE, TRUE },
  { "NOOP", 4, FALSE, FALSE },
  { "PASS", 4, FALSE, FALSE },
  { "QUIT", 4, FALSE, FALSE },
  { "RETR", 4, TRUE, TRUE },
  { "RSET", 4, FALSE, FALSE },
  { "STAT", 4, FALSE, FALSE },
  { "STLS", 4, FALSE, FALSE },
  { "TOP",  3, TRUE, TRUE },
  { "UIDL", 4, TRUE, FALSE },
  { "USER", 4, FALSE, FALSE },
  { "UTF8", 4, FALSE, FALSE },
  { "XTND", 4, TRUE, TRUE },
};

/* Return iff a command is defined as "multi-line" (RFC 1939),
 * has a response terminated by a last line with a '.'.
 */
static bool pop3_is_multiline(const char *cmdline)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(pop3cmds); ++i) {
    if(strncasecompare(pop3cmds[i].name, cmdline, pop3cmds[i].nlen)) {
      if(!cmdline[pop3cmds[i].nlen])
        return pop3cmds[i].multiline;
      else if(cmdline[pop3cmds[i].nlen] == ' ')
        return pop3cmds[i].multiline_with_args;
    }
  }
  /* Unknown command, assume multi-line for backward compatibility with
   * earlier curl versions that only could do multi-line responses. */
  return TRUE;
}

/***********************************************************************
 *
 * pop3_endofresp()
 *
 * Checks for an ending POP3 status code at the start of the given string, but
 * also detects the APOP timestamp from the server greeting and various
 * capabilities from the CAPA response including the supported authentication
 * types and allowed SASL mechanisms.
 */
static bool pop3_endofresp(struct Curl_easy *data, struct connectdata *conn,
                           const char *line, size_t len, int *resp)
{
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  (void)data;

  /* Do we have an error response? */
  if(len >= 4 && !memcmp("-ERR", line, 4)) {
    *resp = '-';

    return TRUE;
  }

  /* Are we processing CAPA command responses? */
  if(pop3c->state == POP3_CAPA) {
    /* Do we have the terminating line? */
    if(len >= 1 && line[0] == '.')
      /* Treat the response as a success */
      *resp = '+';
    else
      /* Treat the response as an untagged continuation */
      *resp = '*';

    return TRUE;
  }

  /* Do we have a success response? */
  if(len >= 3 && !memcmp("+OK", line, 3)) {
    *resp = '+';

    return TRUE;
  }

  /* Do we have a continuation response? */
  if(len >= 1 && line[0] == '+') {
    *resp = '*';

    return TRUE;
  }

  return FALSE; /* Nothing for us */
}

/***********************************************************************
 *
 * pop3_get_message()
 *
 * Gets the authentication message from the response buffer.
 */
static CURLcode pop3_get_message(struct Curl_easy *data, struct bufref *out)
{
  char *message = Curl_dyn_ptr(&data->conn->proto.pop3c.pp.recvbuf);
  size_t len = data->conn->proto.pop3c.pp.nfinal;

  if(len > 2) {
    /* Find the start of the message */
    len -= 2;
    for(message += 2; *message == ' ' || *message == '\t'; message++, len--)
      ;

    /* Find the end of the message */
    while(len--)
      if(message[len] != '\r' && message[len] != '\n' && message[len] != ' ' &&
         message[len] != '\t')
        break;

    /* Terminate the message */
    message[++len] = '\0';
    Curl_bufref_set(out, message, len, NULL);
  }
  else
    /* junk input => zero length output */
    Curl_bufref_set(out, "", 0, NULL);

  return CURLE_OK;
}

/***********************************************************************
 *
 * pop3_state()
 *
 * This is the ONLY way to change POP3 state!
 */
static void pop3_state(struct Curl_easy *data, pop3state newstate)
{
  struct pop3_conn *pop3c = &data->conn->proto.pop3c;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[] = {
    "STOP",
    "SERVERGREET",
    "CAPA",
    "STARTTLS",
    "UPGRADETLS",
    "AUTH",
    "APOP",
    "USER",
    "PASS",
    "COMMAND",
    "QUIT",
    /* LAST */
  };

  if(pop3c->state != newstate)
    infof(data, "POP3 %p state change from %s to %s",
          (void *)pop3c, names[pop3c->state], names[newstate]);
#endif

  pop3c->state = newstate;
}

/***********************************************************************
 *
 * pop3_perform_capa()
 *
 * Sends the CAPA command in order to obtain a list of server side supported
 * capabilities.
 */
static CURLcode pop3_perform_capa(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;

  pop3c->sasl.authmechs = SASL_AUTH_NONE; /* No known auth. mechanisms yet */
  pop3c->sasl.authused = SASL_AUTH_NONE;  /* Clear the auth. mechanism used */
  pop3c->tls_supported = FALSE;           /* Clear the TLS capability */

  /* Send the CAPA command */
  result = Curl_pp_sendf(data, &pop3c->pp, "%s", "CAPA");

  if(!result)
    pop3_state(data, POP3_CAPA);

  return result;
}

/***********************************************************************
 *
 * pop3_perform_starttls()
 *
 * Sends the STLS command to start the upgrade to TLS.
 */
static CURLcode pop3_perform_starttls(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  /* Send the STLS command */
  CURLcode result = Curl_pp_sendf(data, &conn->proto.pop3c.pp, "%s", "STLS");

  if(!result)
    pop3_state(data, POP3_STARTTLS);

  return result;
}

/***********************************************************************
 *
 * pop3_perform_upgrade_tls()
 *
 * Performs the upgrade to TLS.
 */
static CURLcode pop3_perform_upgrade_tls(struct Curl_easy *data,
                                         struct connectdata *conn)
{
#ifdef USE_SSL
  /* Start the SSL connection */
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  CURLcode result;
  bool ssldone = FALSE;

  if(!Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
    result = Curl_ssl_cfilter_add(data, conn, FIRSTSOCKET);
    if(result)
      goto out;
    /* Change the connection handler */
    conn->handler = &Curl_handler_pop3s;
  }

  DEBUGASSERT(!pop3c->ssldone);
  result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &ssldone);
  DEBUGF(infof(data, "pop3_perform_upgrade_tls, connect -> %d, %d",
         result, ssldone));
  if(!result && ssldone) {
    pop3c->ssldone = ssldone;
     /* perform CAPA now, changes pop3c->state out of POP3_UPGRADETLS */
    result = pop3_perform_capa(data, conn);
  }
out:
  return result;
#else
  (void)data;
  (void)conn;
  return CURLE_NOT_BUILT_IN;
#endif
}

/***********************************************************************
 *
 * pop3_perform_user()
 *
 * Sends a clear text USER command to authenticate with.
 */
static CURLcode pop3_perform_user(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* Check we have a username and password to authenticate with and end the
     connect phase if we do not */
  if(!data->state.aptr.user) {
    pop3_state(data, POP3_STOP);

    return result;
  }

  /* Send the USER command */
  result = Curl_pp_sendf(data, &conn->proto.pop3c.pp, "USER %s",
                         conn->user ? conn->user : "");
  if(!result)
    pop3_state(data, POP3_USER);

  return result;
}

#ifndef CURL_DISABLE_DIGEST_AUTH
/***********************************************************************
 *
 * pop3_perform_apop()
 *
 * Sends an APOP command to authenticate with.
 */
static CURLcode pop3_perform_apop(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  size_t i;
  struct MD5_context *ctxt;
  unsigned char digest[MD5_DIGEST_LEN];
  char secret[2 * MD5_DIGEST_LEN + 1];

  /* Check we have a username and password to authenticate with and end the
     connect phase if we do not */
  if(!data->state.aptr.user) {
    pop3_state(data, POP3_STOP);

    return result;
  }

  /* Create the digest */
  ctxt = Curl_MD5_init(&Curl_DIGEST_MD5);
  if(!ctxt)
    return CURLE_OUT_OF_MEMORY;

  Curl_MD5_update(ctxt, (const unsigned char *) pop3c->apoptimestamp,
                  curlx_uztoui(strlen(pop3c->apoptimestamp)));

  Curl_MD5_update(ctxt, (const unsigned char *) conn->passwd,
                  curlx_uztoui(strlen(conn->passwd)));

  /* Finalise the digest */
  Curl_MD5_final(ctxt, digest);

  /* Convert the calculated 16 octet digest into a 32 byte hex string */
  for(i = 0; i < MD5_DIGEST_LEN; i++)
    msnprintf(&secret[2 * i], 3, "%02x", digest[i]);

  result = Curl_pp_sendf(data, &pop3c->pp, "APOP %s %s", conn->user, secret);

  if(!result)
    pop3_state(data, POP3_APOP);

  return result;
}
#endif

/***********************************************************************
 *
 * pop3_perform_auth()
 *
 * Sends an AUTH command allowing the client to login with the given SASL
 * authentication mechanism.
 */
static CURLcode pop3_perform_auth(struct Curl_easy *data,
                                  const char *mech,
                                  const struct bufref *initresp)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &data->conn->proto.pop3c;
  const char *ir = (const char *) Curl_bufref_ptr(initresp);

  if(ir) {                                  /* AUTH <mech> ...<crlf> */
    /* Send the AUTH command with the initial response */
    result = Curl_pp_sendf(data, &pop3c->pp, "AUTH %s %s", mech, ir);
  }
  else {
    /* Send the AUTH command */
    result = Curl_pp_sendf(data, &pop3c->pp, "AUTH %s", mech);
  }

  return result;
}

/***********************************************************************
 *
 * pop3_continue_auth()
 *
 * Sends SASL continuation data.
 */
static CURLcode pop3_continue_auth(struct Curl_easy *data,
                                   const char *mech,
                                   const struct bufref *resp)
{
  struct pop3_conn *pop3c = &data->conn->proto.pop3c;

  (void)mech;

  return Curl_pp_sendf(data, &pop3c->pp,
                       "%s", (const char *) Curl_bufref_ptr(resp));
}

/***********************************************************************
 *
 * pop3_cancel_auth()
 *
 * Sends SASL cancellation.
 */
static CURLcode pop3_cancel_auth(struct Curl_easy *data, const char *mech)
{
  struct pop3_conn *pop3c = &data->conn->proto.pop3c;

  (void)mech;

  return Curl_pp_sendf(data, &pop3c->pp, "*");
}

/***********************************************************************
 *
 * pop3_perform_authentication()
 *
 * Initiates the authentication sequence, with the appropriate SASL
 * authentication mechanism, falling back to APOP and clear text should a
 * common mechanism not be available between the client and server.
 */
static CURLcode pop3_perform_authentication(struct Curl_easy *data,
                                            struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  saslprogress progress = SASL_IDLE;

  /* Check we have enough data to authenticate with and end the
     connect phase if we do not */
  if(!Curl_sasl_can_authenticate(&pop3c->sasl, data)) {
    pop3_state(data, POP3_STOP);
    return result;
  }

  if(pop3c->authtypes & pop3c->preftype & POP3_TYPE_SASL) {
    /* Calculate the SASL login details */
    result = Curl_sasl_start(&pop3c->sasl, data, FALSE, &progress);

    if(!result)
      if(progress == SASL_INPROGRESS)
        pop3_state(data, POP3_AUTH);
  }

  if(!result && progress == SASL_IDLE) {
#ifndef CURL_DISABLE_DIGEST_AUTH
    if(pop3c->authtypes & pop3c->preftype & POP3_TYPE_APOP)
      /* Perform APOP authentication */
      result = pop3_perform_apop(data, conn);
    else
#endif
    if(pop3c->authtypes & pop3c->preftype & POP3_TYPE_CLEARTEXT)
      /* Perform clear text authentication */
      result = pop3_perform_user(data, conn);
    else {
      /* Other mechanisms not supported */
      infof(data, "No known authentication mechanisms supported");
      result = CURLE_LOGIN_DENIED;
    }
  }

  return result;
}

/***********************************************************************
 *
 * pop3_perform_command()
 *
 * Sends a POP3 based command.
 */
static CURLcode pop3_perform_command(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct POP3 *pop3 = data->req.p.pop3;
  const char *command = NULL;

  /* Calculate the default command */
  if(pop3->id[0] == '\0' || data->set.list_only) {
    command = "LIST";

    if(pop3->id[0] != '\0')
      /* Message specific LIST so skip the BODY transfer */
      pop3->transfer = PPTRANSFER_INFO;
  }
  else
    command = "RETR";

  if(pop3->custom && pop3->custom[0] != '\0')
    command = pop3->custom;

  /* Send the command */
  if(pop3->id[0] != '\0')
    result = Curl_pp_sendf(data, &conn->proto.pop3c.pp, "%s %s",
                           command, pop3->id);
  else
    result = Curl_pp_sendf(data, &conn->proto.pop3c.pp, "%s", command);

  if(!result) {
    pop3_state(data, POP3_COMMAND);
    data->req.no_body = !pop3_is_multiline(command);
  }

  return result;
}

/***********************************************************************
 *
 * pop3_perform_quit()
 *
 * Performs the quit action prior to sclose() be called.
 */
static CURLcode pop3_perform_quit(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  /* Send the QUIT command */
  CURLcode result = Curl_pp_sendf(data, &conn->proto.pop3c.pp, "%s", "QUIT");

  if(!result)
    pop3_state(data, POP3_QUIT);

  return result;
}

/* For the initial server greeting */
static CURLcode pop3_state_servergreet_resp(struct Curl_easy *data,
                                            int pop3code,
                                            pop3state instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  const char *line = Curl_dyn_ptr(&data->conn->proto.pop3c.pp.recvbuf);
  size_t len = data->conn->proto.pop3c.pp.nfinal;

  (void)instate; /* no use for this yet */

  if(pop3code != '+') {
    failf(data, "Got unexpected pop3-server response");
    result = CURLE_WEIRD_SERVER_REPLY;
  }
  else if(len > 3) {
    /* Does the server support APOP authentication? */
    char *lt;
    char *gt = NULL;

    /* Look for the APOP timestamp */
    lt = memchr(line, '<', len);
    if(lt)
      /* search the remainder for '>' */
      gt = memchr(lt, '>', len - (lt - line));
    if(gt) {
      /* the length of the timestamp, including the brackets */
      size_t timestamplen = gt - lt + 1;
      char *at = memchr(lt, '@', timestamplen);
      /* If the timestamp does not contain '@' it is not (as required by
         RFC-1939) conformant to the RFC-822 message id syntax, and we
         therefore do not use APOP authentication. */
      if(at) {
        /* dupe the timestamp */
        pop3c->apoptimestamp = Curl_memdup0(lt, timestamplen);
        if(!pop3c->apoptimestamp)
          return CURLE_OUT_OF_MEMORY;
        /* Store the APOP capability */
        pop3c->authtypes |= POP3_TYPE_APOP;
      }
    }

    if(!result)
      result = pop3_perform_capa(data, conn);
  }

  return result;
}

/* For CAPA responses */
static CURLcode pop3_state_capa_resp(struct Curl_easy *data, int pop3code,
                                     pop3state instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  const char *line = Curl_dyn_ptr(&data->conn->proto.pop3c.pp.recvbuf);
  size_t len = data->conn->proto.pop3c.pp.nfinal;

  (void)instate; /* no use for this yet */

  /* Do we have a untagged continuation response? */
  if(pop3code == '*') {
    /* Does the server support the STLS capability? */
    if(len >= 4 && !memcmp(line, "STLS", 4))
      pop3c->tls_supported = TRUE;

    /* Does the server support clear text authentication? */
    else if(len >= 4 && !memcmp(line, "USER", 4))
      pop3c->authtypes |= POP3_TYPE_CLEARTEXT;

    /* Does the server support SASL based authentication? */
    else if(len >= 5 && !memcmp(line, "SASL ", 5)) {
      pop3c->authtypes |= POP3_TYPE_SASL;

      /* Advance past the SASL keyword */
      line += 5;
      len -= 5;

      /* Loop through the data line */
      for(;;) {
        size_t llen;
        size_t wordlen;
        unsigned short mechbit;

        while(len &&
              (*line == ' ' || *line == '\t' ||
               *line == '\r' || *line == '\n')) {

          line++;
          len--;
        }

        if(!len)
          break;

        /* Extract the word */
        for(wordlen = 0; wordlen < len && line[wordlen] != ' ' &&
              line[wordlen] != '\t' && line[wordlen] != '\r' &&
              line[wordlen] != '\n';)
          wordlen++;

        /* Test the word for a matching authentication mechanism */
        mechbit = Curl_sasl_decode_mech(line, wordlen, &llen);
        if(mechbit && llen == wordlen)
          pop3c->sasl.authmechs |= mechbit;

        line += wordlen;
        len -= wordlen;
      }
    }
  }
  else {
    /* Clear text is supported when CAPA is not recognised */
    if(pop3code != '+')
      pop3c->authtypes |= POP3_TYPE_CLEARTEXT;

    if(!data->set.use_ssl || Curl_conn_is_ssl(conn, FIRSTSOCKET))
      result = pop3_perform_authentication(data, conn);
    else if(pop3code == '+' && pop3c->tls_supported)
      /* Switch to TLS connection now */
      result = pop3_perform_starttls(data, conn);
    else if(data->set.use_ssl <= CURLUSESSL_TRY)
      /* Fallback and carry on with authentication */
      result = pop3_perform_authentication(data, conn);
    else {
      failf(data, "STLS not supported.");
      result = CURLE_USE_SSL_FAILED;
    }
  }

  return result;
}

/* For STARTTLS responses */
static CURLcode pop3_state_starttls_resp(struct Curl_easy *data,
                                         struct connectdata *conn,
                                         int pop3code,
                                         pop3state instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  /* Pipelining in response is forbidden. */
  if(data->conn->proto.pop3c.pp.overflow)
    return CURLE_WEIRD_SERVER_REPLY;

  if(pop3code != '+') {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied");
      result = CURLE_USE_SSL_FAILED;
    }
    else
      result = pop3_perform_authentication(data, conn);
  }
  else
    pop3_state(data, POP3_UPGRADETLS);

  return result;
}

/* For SASL authentication responses */
static CURLcode pop3_state_auth_resp(struct Curl_easy *data,
                                     int pop3code,
                                     pop3state instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  saslprogress progress;

  (void)instate; /* no use for this yet */

  result = Curl_sasl_continue(&pop3c->sasl, data, pop3code, &progress);
  if(!result)
    switch(progress) {
    case SASL_DONE:
      pop3_state(data, POP3_STOP);  /* Authenticated */
      break;
    case SASL_IDLE:            /* No mechanism left after cancellation */
#ifndef CURL_DISABLE_DIGEST_AUTH
      if(pop3c->authtypes & pop3c->preftype & POP3_TYPE_APOP)
        /* Perform APOP authentication */
        result = pop3_perform_apop(data, conn);
      else
#endif
      if(pop3c->authtypes & pop3c->preftype & POP3_TYPE_CLEARTEXT)
        /* Perform clear text authentication */
        result = pop3_perform_user(data, conn);
      else {
        failf(data, "Authentication cancelled");
        result = CURLE_LOGIN_DENIED;
      }
      break;
    default:
      break;
    }

  return result;
}

#ifndef CURL_DISABLE_DIGEST_AUTH
/* For APOP responses */
static CURLcode pop3_state_apop_resp(struct Curl_easy *data, int pop3code,
                                     pop3state instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  if(pop3code != '+') {
    failf(data, "Authentication failed: %d", pop3code);
    result = CURLE_LOGIN_DENIED;
  }
  else
    /* End of connect phase */
    pop3_state(data, POP3_STOP);

  return result;
}
#endif

/* For USER responses */
static CURLcode pop3_state_user_resp(struct Curl_easy *data, int pop3code,
                                     pop3state instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  (void)instate; /* no use for this yet */

  if(pop3code != '+') {
    failf(data, "Access denied. %c", pop3code);
    result = CURLE_LOGIN_DENIED;
  }
  else
    /* Send the PASS command */
    result = Curl_pp_sendf(data, &conn->proto.pop3c.pp, "PASS %s",
                           conn->passwd ? conn->passwd : "");
  if(!result)
    pop3_state(data, POP3_PASS);

  return result;
}

/* For PASS responses */
static CURLcode pop3_state_pass_resp(struct Curl_easy *data, int pop3code,
                                     pop3state instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  if(pop3code != '+') {
    failf(data, "Access denied. %c", pop3code);
    result = CURLE_LOGIN_DENIED;
  }
  else
    /* End of connect phase */
    pop3_state(data, POP3_STOP);

  return result;
}

/* For command responses */
static CURLcode pop3_state_command_resp(struct Curl_easy *data,
                                        int pop3code,
                                        pop3state instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct POP3 *pop3 = data->req.p.pop3;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;

  (void)instate; /* no use for this yet */

  if(pop3code != '+') {
    pop3_state(data, POP3_STOP);
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* This 'OK' line ends with a CR LF pair which is the two first bytes of the
     EOB string so count this is two matching bytes. This is necessary to make
     the code detect the EOB if the only data than comes now is %2e CR LF like
     when there is no body to return. */
  pop3c->eob = 2;

  /* But since this initial CR LF pair is not part of the actual body, we set
     the strip counter here so that these bytes will not be delivered. */
  pop3c->strip = 2;

  if(pop3->transfer == PPTRANSFER_BODY) {
    /* POP3 download */
    Curl_xfer_setup1(data, CURL_XFER_RECV, -1, FALSE);

    if(pp->overflow) {
      /* The recv buffer contains data that is actually body content so send
         it as such. Note that there may even be additional "headers" after
         the body */

      /* keep only the overflow */
      Curl_dyn_tail(&pp->recvbuf, pp->overflow);
      pp->nfinal = 0; /* done */

      if(!data->req.no_body) {
        result = pop3_write(data, Curl_dyn_ptr(&pp->recvbuf),
                            Curl_dyn_len(&pp->recvbuf), FALSE);
        if(result)
          return result;
      }

      /* reset the buffer */
      Curl_dyn_reset(&pp->recvbuf);
      pp->overflow = 0;
    }
  }
  else
    pp->overflow = 0;

  /* End of DO phase */
  pop3_state(data, POP3_STOP);

  return result;
}

static CURLcode pop3_statemachine(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  int pop3code;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;
  size_t nread = 0;
  (void)data;

  /* Busy upgrading the connection; right now all I/O is SSL/TLS, not POP3 */
upgrade_tls:
  if(pop3c->state == POP3_UPGRADETLS) {
    result = pop3_perform_upgrade_tls(data, conn);
    if(result || (pop3c->state == POP3_UPGRADETLS))
      return result;
  }

  /* Flush any data that needs to be sent */
  if(pp->sendleft)
    return Curl_pp_flushsend(data, pp);

 do {
    /* Read the response from the server */
   result = Curl_pp_readresp(data, FIRSTSOCKET, pp, &pop3code, &nread);
   if(result)
     return result;

    if(!pop3code)
      break;

    /* We have now received a full POP3 server response */
    switch(pop3c->state) {
    case POP3_SERVERGREET:
      result = pop3_state_servergreet_resp(data, pop3code, pop3c->state);
      break;

    case POP3_CAPA:
      result = pop3_state_capa_resp(data, pop3code, pop3c->state);
      break;

    case POP3_STARTTLS:
      result = pop3_state_starttls_resp(data, conn, pop3code, pop3c->state);
      /* During UPGRADETLS, leave the read loop as we need to connect
       * (e.g. TLS handshake) before we continue sending/receiving. */
      if(!result && (pop3c->state == POP3_UPGRADETLS))
        goto upgrade_tls;
      break;

    case POP3_AUTH:
      result = pop3_state_auth_resp(data, pop3code, pop3c->state);
      break;

#ifndef CURL_DISABLE_DIGEST_AUTH
    case POP3_APOP:
      result = pop3_state_apop_resp(data, pop3code, pop3c->state);
      break;
#endif

    case POP3_USER:
      result = pop3_state_user_resp(data, pop3code, pop3c->state);
      break;

    case POP3_PASS:
      result = pop3_state_pass_resp(data, pop3code, pop3c->state);
      break;

    case POP3_COMMAND:
      result = pop3_state_command_resp(data, pop3code, pop3c->state);
      break;

    case POP3_QUIT:
      pop3_state(data, POP3_STOP);
      break;

    default:
      /* internal error */
      pop3_state(data, POP3_STOP);
      break;
    }
  } while(!result && pop3c->state != POP3_STOP && Curl_pp_moredata(pp));

  return result;
}

/* Called repeatedly until done from multi.c */
static CURLcode pop3_multi_statemach(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct pop3_conn *pop3c = &conn->proto.pop3c;

  result = Curl_pp_statemach(data, &pop3c->pp, FALSE, FALSE);
  *done = (pop3c->state == POP3_STOP);

  return result;
}

static CURLcode pop3_block_statemach(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     bool disconnecting)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;

  while(pop3c->state != POP3_STOP && !result)
    result = Curl_pp_statemach(data, &pop3c->pp, TRUE, disconnecting);

  return result;
}

/* Allocate and initialize the POP3 struct for the current Curl_easy if
   required */
static CURLcode pop3_init(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct POP3 *pop3;

  pop3 = data->req.p.pop3 = CALLOC(1, sizeof(struct POP3));
  if(!pop3)
    result = CURLE_OUT_OF_MEMORY;

  return result;
}

/* For the POP3 "protocol connect" and "doing" phases only */
static int pop3_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks)
{
  return Curl_pp_getsock(data, &conn->proto.pop3c.pp, socks);
}

/***********************************************************************
 *
 * pop3_connect()
 *
 * This function should do everything that is to be considered a part of the
 * connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE if not.
 */
static CURLcode pop3_connect(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct pingpong *pp = &pop3c->pp;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections in POP3 */
  connkeep(conn, "POP3 default");

  PINGPONG_SETUP(pp, pop3_statemachine, pop3_endofresp);

  /* Set the default preferred authentication type and mechanism */
  pop3c->preftype = POP3_TYPE_ANY;
  Curl_sasl_init(&pop3c->sasl, data, &saslpop3);

  /* Initialise the pingpong layer */
  Curl_pp_init(pp);

  /* Parse the URL options */
  result = pop3_parse_url_options(conn);
  if(result)
    return result;

  /* Start off waiting for the server greeting response */
  pop3_state(data, POP3_SERVERGREET);

  result = pop3_multi_statemach(data, done);

  return result;
}

/***********************************************************************
 *
 * pop3_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
static CURLcode pop3_done(struct Curl_easy *data, CURLcode status,
                          bool premature)
{
  CURLcode result = CURLE_OK;
  struct POP3 *pop3 = data->req.p.pop3;

  (void)premature;

  if(!pop3)
    return CURLE_OK;

  if(status) {
    connclose(data->conn, "POP3 done with bad status");
    result = status;         /* use the already set error code */
  }

  /* Cleanup our per-request based variables */
  Curl_safefree(pop3->id);
  Curl_safefree(pop3->custom);

  /* Clear the transfer mode for the next request */
  pop3->transfer = PPTRANSFER_BODY;

  return result;
}

/***********************************************************************
 *
 * pop3_perform()
 *
 * This is the actual DO function for POP3. Get a message/listing according to
 * the options previously setup.
 */
static CURLcode pop3_perform(struct Curl_easy *data, bool *connected,
                             bool *dophase_done)
{
  /* This is POP3 and no proxy */
  CURLcode result = CURLE_OK;
  struct POP3 *pop3 = data->req.p.pop3;

  DEBUGF(infof(data, "DO phase starts"));

  if(data->req.no_body) {
    /* Requested no body means no transfer */
    pop3->transfer = PPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  /* Start the first command in the DO phase */
  result = pop3_perform_command(data);
  if(result)
    return result;

  /* Run the state-machine */
  result = pop3_multi_statemach(data, dophase_done);
  *connected = Curl_conn_is_connected(data->conn, FIRSTSOCKET);

  if(*dophase_done)
    DEBUGF(infof(data, "DO phase is complete"));

  return result;
}

/***********************************************************************
 *
 * pop3_do()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (pop3_perform).
 *
 * The input argument is already checked for validity.
 */
static CURLcode pop3_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  *done = FALSE; /* default to false */

  /* Parse the URL path */
  result = pop3_parse_url_path(data);
  if(result)
    return result;

  /* Parse the custom request */
  result = pop3_parse_custom_request(data);
  if(result)
    return result;

  result = pop3_regular_transfer(data, done);

  return result;
}

/***********************************************************************
 *
 * pop3_disconnect()
 *
 * Disconnect from an POP3 server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode pop3_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead_connection)
{
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  (void)data;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to. */

  if(!dead_connection && conn->bits.protoconnstart) {
    if(!pop3_perform_quit(data, conn))
      (void)pop3_block_statemach(data, conn, TRUE); /* ignore errors on QUIT */
  }

  /* Disconnect from the server */
  Curl_pp_disconnect(&pop3c->pp);

  /* Cleanup the SASL module */
  Curl_sasl_cleanup(conn, pop3c->sasl.authused);

  /* Cleanup our connection based variables */
  Curl_safefree(pop3c->apoptimestamp);

  return CURLE_OK;
}

/* Call this when the DO phase has completed */
static CURLcode pop3_dophase_done(struct Curl_easy *data, bool connected)
{
  (void)data;
  (void)connected;

  return CURLE_OK;
}

/* Called from multi.c while DOing */
static CURLcode pop3_doing(struct Curl_easy *data, bool *dophase_done)
{
  CURLcode result = pop3_multi_statemach(data, dophase_done);

  if(result)
    DEBUGF(infof(data, "DO phase failed"));
  else if(*dophase_done) {
    result = pop3_dophase_done(data, FALSE /* not connected */);

    DEBUGF(infof(data, "DO phase is complete"));
  }

  return result;
}

/***********************************************************************
 *
 * pop3_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 */
static CURLcode pop3_regular_transfer(struct Curl_easy *data,
                                      bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;

  /* Make sure size is unknown at this point */
  data->req.size = -1;

  /* Set the progress data */
  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  /* Carry out the perform */
  result = pop3_perform(data, &connected, dophase_done);

  /* Perform post DO phase operations if necessary */
  if(!result && *dophase_done)
    result = pop3_dophase_done(data, connected);

  return result;
}

static CURLcode pop3_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  /* Initialise the POP3 layer */
  (void)conn;
  return pop3_init(data);
}

/***********************************************************************
 *
 * pop3_parse_url_options()
 *
 * Parse the URL login options.
 */
static CURLcode pop3_parse_url_options(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  const char *ptr = conn->options;

  while(!result && ptr && *ptr) {
    const char *key = ptr;
    const char *value;

    while(*ptr && *ptr != '=')
      ptr++;

    value = ptr + 1;

    while(*ptr && *ptr != ';')
      ptr++;

    if(strncasecompare(key, "AUTH=", 5)) {
      result = Curl_sasl_parse_url_auth_option(&pop3c->sasl,
                                               value, ptr - value);

      if(result && strncasecompare(value, "+APOP", ptr - value)) {
        pop3c->preftype = POP3_TYPE_APOP;
        pop3c->sasl.prefmech = SASL_AUTH_NONE;
        result = CURLE_OK;
      }
    }
    else
      result = CURLE_URL_MALFORMAT;

    if(*ptr == ';')
      ptr++;
  }

  if(pop3c->preftype != POP3_TYPE_APOP)
    switch(pop3c->sasl.prefmech) {
    case SASL_AUTH_NONE:
      pop3c->preftype = POP3_TYPE_NONE;
      break;
    case SASL_AUTH_DEFAULT:
      pop3c->preftype = POP3_TYPE_ANY;
      break;
    default:
      pop3c->preftype = POP3_TYPE_SASL;
      break;
    }

  return result;
}

/***********************************************************************
 *
 * pop3_parse_url_path()
 *
 * Parse the URL path into separate path components.
 */
static CURLcode pop3_parse_url_path(struct Curl_easy *data)
{
  /* The POP3 struct is already initialised in pop3_connect() */
  struct POP3 *pop3 = data->req.p.pop3;
  const char *path = &data->state.up.path[1]; /* skip leading path */

  /* URL decode the path for the message ID */
  return Curl_urldecode(path, 0, &pop3->id, NULL, REJECT_CTRL);
}

/***********************************************************************
 *
 * pop3_parse_custom_request()
 *
 * Parse the custom request.
 */
static CURLcode pop3_parse_custom_request(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct POP3 *pop3 = data->req.p.pop3;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  /* URL decode the custom request */
  if(custom)
    result = Curl_urldecode(custom, 0, &pop3->custom, NULL, REJECT_CTRL);

  return result;
}

/***********************************************************************
 *
 * pop3_write()
 *
 * This function scans the body after the end-of-body and writes everything
 * until the end is found.
 */
static CURLcode pop3_write(struct Curl_easy *data, const char *str,
                           size_t nread, bool is_eos)
{
  /* This code could be made into a special function in the handler struct */
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  struct connectdata *conn = data->conn;
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  bool strip_dot = FALSE;
  size_t last = 0;
  size_t i;
  (void)is_eos;

  /* Search through the buffer looking for the end-of-body marker which is
     5 bytes (0d 0a 2e 0d 0a). Note that a line starting with a dot matches
     the eob so the server will have prefixed it with an extra dot which we
     need to strip out. Additionally the marker could of course be spread out
     over 5 different data chunks. */
  for(i = 0; i < nread; i++) {
    size_t prev = pop3c->eob;

    switch(str[i]) {
    case 0x0d:
      if(pop3c->eob == 0) {
        pop3c->eob++;

        if(i) {
          /* Write out the body part that did not match */
          result = Curl_client_write(data, CLIENTWRITE_BODY, &str[last],
                                     i - last);

          if(result)
            return result;

          last = i;
        }
      }
      else if(pop3c->eob == 3)
        pop3c->eob++;
      else
        /* If the character match was not at position 0 or 3 then restart the
           pattern matching */
        pop3c->eob = 1;
      break;

    case 0x0a:
      if(pop3c->eob == 1 || pop3c->eob == 4)
        pop3c->eob++;
      else
        /* If the character match was not at position 1 or 4 then start the
           search again */
        pop3c->eob = 0;
      break;

    case 0x2e:
      if(pop3c->eob == 2)
        pop3c->eob++;
      else if(pop3c->eob == 3) {
        /* We have an extra dot after the CRLF which we need to strip off */
        strip_dot = TRUE;
        pop3c->eob = 0;
      }
      else
        /* If the character match was not at position 2 then start the search
           again */
        pop3c->eob = 0;
      break;

    default:
      pop3c->eob = 0;
      break;
    }

    /* Did we have a partial match which has subsequently failed? */
    if(prev && prev >= pop3c->eob) {
      /* Strip can only be non-zero for the very first mismatch after CRLF
         and then both prev and strip are equal and nothing will be output
         below */
      while(prev && pop3c->strip) {
        prev--;
        pop3c->strip--;
      }

      if(prev) {
        /* If the partial match was the CRLF and dot then only write the CRLF
           as the server would have inserted the dot */
        if(strip_dot && prev - 1 > 0) {
          result = Curl_client_write(data, CLIENTWRITE_BODY, POP3_EOB,
                                     prev - 1);
        }
        else if(!strip_dot) {
          result = Curl_client_write(data, CLIENTWRITE_BODY, POP3_EOB,
                                     prev);
        }
        else {
          result = CURLE_OK;
        }

        if(result)
          return result;

        last = i;
        strip_dot = FALSE;
      }
    }
  }

  if(pop3c->eob == POP3_EOB_LEN) {
    /* We have a full match so the transfer is done, however we must transfer
    the CRLF at the start of the EOB as this is considered to be part of the
    message as per RFC-1939, sect. 3 */
    result = Curl_client_write(data, CLIENTWRITE_BODY, POP3_EOB, 2);

    k->keepon &= ~KEEP_RECV;
    pop3c->eob = 0;

    return result;
  }

  if(pop3c->eob)
    /* While EOB is matching nothing should be output */
    return CURLE_OK;

  if(nread - last) {
    result = Curl_client_write(data, CLIENTWRITE_BODY, &str[last],
                               nread - last);
  }

  return result;
}

#endif /* CURL_DISABLE_POP3 */
