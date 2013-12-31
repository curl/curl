/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * RFC1870 SMTP Service Extension for Message Size
 * RFC2195 CRAM-MD5 authentication
 * RFC2831 DIGEST-MD5 authentication
 * RFC3207 SMTP over TLS
 * RFC4422 Simple Authentication and Security Layer (SASL)
 * RFC4616 PLAIN authentication
 * RFC4954 SMTP Authentication
 * RFC5321 SMTP protocol
 * RFC6749 OAuth 2.0 Authorization Framework
 * Draft   SMTP URL Interface   <draft-earhart-url-smtp-00.txt>
 * Draft   LOGIN SASL Mechanism <draft-murchison-sasl-login-00.txt>
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_SMTP

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
#include "vtls/vtls.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "rawstr.h"
#include "curl_gethostname.h"
#include "curl_sasl.h"
#include "warnless.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Local API functions */
static CURLcode smtp_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode smtp_do(struct connectdata *conn, bool *done);
static CURLcode smtp_done(struct connectdata *conn, CURLcode status,
                          bool premature);
static CURLcode smtp_connect(struct connectdata *conn, bool *done);
static CURLcode smtp_disconnect(struct connectdata *conn, bool dead);
static CURLcode smtp_multi_statemach(struct connectdata *conn, bool *done);
static int smtp_getsock(struct connectdata *conn, curl_socket_t *socks,
                        int numsocks);
static CURLcode smtp_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode smtp_setup_connection(struct connectdata *conn);
static CURLcode smtp_parse_url_options(struct connectdata *conn);
static CURLcode smtp_parse_url_path(struct connectdata *conn);
static CURLcode smtp_parse_custom_request(struct connectdata *conn);
static CURLcode smtp_calc_sasl_details(struct connectdata *conn,
                                       const char **mech,
                                       char **initresp, size_t *len,
                                       smtpstate *state1, smtpstate *state2);

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
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY /* flags */
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
  PROTOPT_CLOSEACTION | PROTOPT_SSL
  | PROTOPT_NOURLQUERY              /* flags */
};
#endif

#ifndef CURL_DISABLE_HTTP
/*
 * HTTP-proxyed SMTP protocol handler.
 */

static const struct Curl_handler Curl_handler_smtp_proxy = {
  "SMTP",                               /* scheme */
  Curl_http_setup_conn,                 /* setup_connection */
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
  Curl_http_setup_conn,                 /* setup_connection */
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

#ifdef USE_SSL
static void smtp_to_smtps(struct connectdata *conn)
{
  conn->handler = &Curl_handler_smtps;
}
#else
#define smtp_to_smtps(x) Curl_nop_stmt
#endif

/***********************************************************************
 *
 * smtp_endofresp()
 *
 * Checks for an ending SMTP status code at the start of the given string, but
 * also detects various capabilities from the EHLO response including the
 * supported authentication mechanisms.
 */
static bool smtp_endofresp(struct connectdata *conn, char *line, size_t len,
                           int *resp)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  bool result = FALSE;

  /* Nothing for us */
  if(len < 4 || !ISDIGIT(line[0]) || !ISDIGIT(line[1]) || !ISDIGIT(line[2]))
    return FALSE;

  /* Do we have a command response? This should be the response code followed
     by a space and optionally some text as per RFC-5321 and as outlined in
     Section 4. Examples of RFC-4954 but some e-mail servers ignore this and
     only send the response code instead as per Section 4.2. */
  if(line[3] == ' ' || len == 5) {
    result = TRUE;
    *resp = curlx_sltosi(strtol(line, NULL, 10));

    /* Make sure real server never sends internal value */
    if(*resp == 1)
      *resp = 0;
  }
  /* Do we have a multiline (continuation) response? */
  else if(line[3] == '-' &&
          (smtpc->state == SMTP_EHLO || smtpc->state == SMTP_COMMAND)) {
    result = TRUE;
    *resp = 1;  /* Internal response code */
  }

  return result;
}

/***********************************************************************
 *
 * smtp_get_message()
 *
 * Gets the authentication message from the response buffer.
 */
static void smtp_get_message(char *buffer, char** outptr)
{
  size_t len = 0;
  char* message = NULL;

  /* Find the start of the message */
  for(message = buffer + 4; *message == ' ' || *message == '\t'; message++)
    ;

  /* Find the end of the message */
  for(len = strlen(message); len--;)
    if(message[len] != '\r' && message[len] != '\n' && message[len] != ' ' &&
        message[len] != '\t')
      break;

  /* Terminate the message */
  if(++len) {
    message[len] = '\0';
  }

  *outptr = message;
}

/***********************************************************************
 *
 * state()
 *
 * This is the ONLY way to change SMTP state!
 */
static void state(struct connectdata *conn, smtpstate newstate)
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
    "AUTH_PLAIN",
    "AUTH_LOGIN",
    "AUTH_LOGIN_PASSWD",
    "AUTH_CRAMMD5",
    "AUTH_DIGESTMD5",
    "AUTH_DIGESTMD5_RESP",
    "AUTH_NTLM",
    "AUTH_NTLM_TYPE2MSG",
    "AUTH_XOAUTH2",
    "AUTH_CANCEL",
    "AUTH_FINAL",
    "COMMAND",
    "MAIL",
    "RCPT",
    "DATA",
    "POSTDATA",
    "QUIT",
    /* LAST */
  };

  if(smtpc->state != newstate)
    infof(conn->data, "SMTP %p state change from %s to %s\n",
          (void *)smtpc, names[smtpc->state], names[newstate]);
#endif

  smtpc->state = newstate;
}

/***********************************************************************
 *
 * smtp_perform_ehlo()
 *
 * Sends the EHLO command to not only initialise communication with the ESMTP
 * server but to also obtain a list of server side supported capabilities.
 */
static CURLcode smtp_perform_ehlo(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->authmechs = 0;         /* No known authentication mechanisms yet */
  smtpc->authused = 0;          /* Clear the authentication mechanism used
                                   for esmtp connections */
  smtpc->tls_supported = FALSE; /* Clear the TLS capability */

  /* Send the EHLO command */
  result = Curl_pp_sendf(&smtpc->pp, "EHLO %s", smtpc->domain);

  if(!result)
    state(conn, SMTP_EHLO);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_helo()
 *
 * Sends the HELO command to initialise communication with the SMTP server.
 */
static CURLcode smtp_perform_helo(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->authused = 0;          /* No authentication mechanism used in smtp
                                   connections */

  /* Send the HELO command */
  result = Curl_pp_sendf(&smtpc->pp, "HELO %s", smtpc->domain);

  if(!result)
    state(conn, SMTP_HELO);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_starttls()
 *
 * Sends the STLS command to start the upgrade to TLS.
 */
static CURLcode smtp_perform_starttls(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* Send the STARTTLS command */
  result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "STARTTLS");

  if(!result)
    state(conn, SMTP_STARTTLS);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_upgrade_tls()
 *
 * Performs the upgrade to TLS.
 */
static CURLcode smtp_perform_upgrade_tls(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  /* Start the SSL connection */
  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &smtpc->ssldone);

  if(!result) {
    if(smtpc->state != SMTP_UPGRADETLS)
      state(conn, SMTP_UPGRADETLS);

    if(smtpc->ssldone) {
      smtp_to_smtps(conn);
      result = smtp_perform_ehlo(conn);
    }
  }

  return result;
}

/***********************************************************************
 *
 * smtp_perform_auth()
 *
 * Sends an AUTH command allowing the client to login with the given SASL
 * authentication mechanism.
 */
static CURLcode smtp_perform_auth(struct connectdata *conn,
                                  const char *mech,
                                  const char *initresp, size_t len,
                                  smtpstate state1, smtpstate state2)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  if(initresp && 8 + strlen(mech) + len <= 512) { /* AUTH <mech> ...<crlf> */
    /* Send the AUTH command with the initial response */
    result = Curl_pp_sendf(&smtpc->pp, "AUTH %s %s", mech, initresp);

    if(!result)
      state(conn, state2);
  }
  else {
    /* Send the AUTH command */
    result = Curl_pp_sendf(&smtpc->pp, "AUTH %s", mech);

    if(!result)
      state(conn, state1);
  }

  return result;
}

/***********************************************************************
 *
 * smtp_perform_authentication()
 *
 * Initiates the authentication sequence, with the appropriate SASL
 * authentication mechanism.
 */
static CURLcode smtp_perform_authentication(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *mech = NULL;
  char *initresp = NULL;
  size_t len = 0;
  smtpstate state1 = SMTP_STOP;
  smtpstate state2 = SMTP_STOP;

  /* Check we have a username and password to authenticate with and end the
     connect phase if we don't */
  if(!conn->bits.user_passwd) {
    state(conn, SMTP_STOP);

    return result;
  }

  /* Calculate the SASL login details */
  result = smtp_calc_sasl_details(conn, &mech, &initresp, &len, &state1,
                                  &state2);

  if(!result) {
    if(mech) {
      /* Perform SASL based authentication */
      result = smtp_perform_auth(conn, mech, initresp, len, state1, state2);

      Curl_safefree(initresp);
    }
    else {
      /* Other mechanisms not supported */
      infof(conn->data, "No known authentication mechanisms supported!\n");
      result = CURLE_LOGIN_DENIED;
    }
  }

  return result;
}

/***********************************************************************
 *
 * smtp_perform_command()
 *
 * Sends a SMTP based command.
 */
static CURLcode smtp_perform_command(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;

  /* Send the command */
  if(smtp->rcpt)
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s %s",
                            smtp->custom && smtp->custom[0] != '\0' ?
                            smtp->custom : "VRFY",
                            smtp->rcpt->data);
  else
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s",
                           smtp->custom && smtp->custom[0] != '\0' ?
                           smtp->custom : "HELP");

  if(!result)
    state(conn, SMTP_COMMAND);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_mail()
 *
 * Sends an MAIL command to initiate the upload of a message.
 */
static CURLcode smtp_perform_mail(struct connectdata *conn)
{
  char *from = NULL;
  char *auth = NULL;
  char *size = NULL;
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  /* Calculate the FROM parameter */
  if(!data->set.str[STRING_MAIL_FROM])
    /* Null reverse-path, RFC-5321, sect. 3.6.3 */
    from = strdup("<>");
  else if(data->set.str[STRING_MAIL_FROM][0] == '<')
    from = aprintf("%s", data->set.str[STRING_MAIL_FROM]);
  else
    from = aprintf("<%s>", data->set.str[STRING_MAIL_FROM]);

  if(!from)
    return CURLE_OUT_OF_MEMORY;

  /* Calculate the optional AUTH parameter */
  if(data->set.str[STRING_MAIL_AUTH] && conn->proto.smtpc.authused) {
    if(data->set.str[STRING_MAIL_AUTH][0] != '\0')
      auth = aprintf("%s", data->set.str[STRING_MAIL_AUTH]);
    else
      /* Empty AUTH, RFC-2554, sect. 5 */
      auth = strdup("<>");

    if(!auth) {
      Curl_safefree(from);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* Calculate the optional SIZE parameter */
  if(conn->proto.smtpc.size_supported && conn->data->set.infilesize > 0) {
    size = aprintf("%" CURL_FORMAT_CURL_OFF_T, data->set.infilesize);

    if(!size) {
      Curl_safefree(from);
      Curl_safefree(auth);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* Send the MAIL command */
  if(!auth && !size)
    result = Curl_pp_sendf(&conn->proto.smtpc.pp,
                           "MAIL FROM:%s", from);
  else if(auth && !size)
    result = Curl_pp_sendf(&conn->proto.smtpc.pp,
                           "MAIL FROM:%s AUTH=%s", from, auth);
  else if(auth && size)
    result = Curl_pp_sendf(&conn->proto.smtpc.pp,
                           "MAIL FROM:%s AUTH=%s SIZE=%s", from, auth, size);
  else
    result = Curl_pp_sendf(&conn->proto.smtpc.pp,
                           "MAIL FROM:%s SIZE=%s", from, size);

  Curl_safefree(from);
  Curl_safefree(auth);
  Curl_safefree(size);

  if(!result)
    state(conn, SMTP_MAIL);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_rcpt_to()
 *
 * Sends a RCPT TO command for a given recipient as part of the message upload
 * process.
 */
static CURLcode smtp_perform_rcpt_to(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;

  /* Send the RCPT TO command */
  if(smtp->rcpt->data[0] == '<')
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "RCPT TO:%s",
                            smtp->rcpt->data);
  else
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "RCPT TO:<%s>",
                            smtp->rcpt->data);
  if(!result)
    state(conn, SMTP_RCPT);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_quit()
 *
 * Performs the quit action prior to sclose() being called.
 */
static CURLcode smtp_perform_quit(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* Send the QUIT command */
  result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "QUIT");

  if(!result)
    state(conn, SMTP_QUIT);

  return result;
}

/* For the initial server greeting */
static CURLcode smtp_state_servergreet_resp(struct connectdata *conn,
                                            int smtpcode,
                                            smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Got unexpected smtp-server response: %d", smtpcode);
    result = CURLE_FTP_WEIRD_SERVER_REPLY;
  }
  else
    result = smtp_perform_ehlo(conn);

  return result;
}

/* For STARTTLS responses */
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
      result = CURLE_USE_SSL_FAILED;
    }
    else
      result = smtp_perform_authentication(conn);
  }
  else
    result = smtp_perform_upgrade_tls(conn);

  return result;
}

/* For EHLO responses */
static CURLcode smtp_state_ehlo_resp(struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *line = data->state.buffer;
  size_t len = strlen(line);
  size_t wordlen;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2 && smtpcode != 1) {
    if((data->set.use_ssl <= CURLUSESSL_TRY || conn->ssl[FIRSTSOCKET].use) &&
     !conn->bits.user_passwd)
      result = smtp_perform_helo(conn);
    else {
      failf(data, "Remote access denied: %d", smtpcode);
      result = CURLE_REMOTE_ACCESS_DENIED;
    }
  }
  else {
    line += 4;
    len -= 4;

    /* Does the server support the STARTTLS capability? */
    if(len >= 8 && !memcmp(line, "STARTTLS", 8))
      smtpc->tls_supported = TRUE;

    /* Does the server support the SIZE capability? */
    else if(len >= 4 && !memcmp(line, "SIZE", 4))
      smtpc->size_supported = TRUE;

    /* Do we have the authentication mechanism list? */
    else if(len >= 5 && !memcmp(line, "AUTH ", 5)) {
      line += 5;
      len -= 5;

      /* Loop through the data line */
      for(;;) {
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
        if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_LOGIN))
          smtpc->authmechs |= SASL_MECH_LOGIN;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_PLAIN))
          smtpc->authmechs |= SASL_MECH_PLAIN;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_CRAM_MD5))
          smtpc->authmechs |= SASL_MECH_CRAM_MD5;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_DIGEST_MD5))
          smtpc->authmechs |= SASL_MECH_DIGEST_MD5;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_GSSAPI))
          smtpc->authmechs |= SASL_MECH_GSSAPI;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_EXTERNAL))
          smtpc->authmechs |= SASL_MECH_EXTERNAL;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_NTLM))
          smtpc->authmechs |= SASL_MECH_NTLM;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_XOAUTH2))
          smtpc->authmechs |= SASL_MECH_XOAUTH2;

        line += wordlen;
        len -= wordlen;
      }
    }

    if(smtpcode != 1) {
      if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
        /* We don't have a SSL/TLS connection yet, but SSL is requested */
        if(smtpc->tls_supported)
          /* Switch to TLS connection now */
          result = smtp_perform_starttls(conn);
        else if(data->set.use_ssl == CURLUSESSL_TRY)
          /* Fallback and carry on with authentication */
          result = smtp_perform_authentication(conn);
        else {
          failf(data, "STARTTLS not supported.");
          result = CURLE_USE_SSL_FAILED;
        }
      }
      else
        result = smtp_perform_authentication(conn);
    }
  }

  return result;
}

/* For HELO responses */
static CURLcode smtp_state_helo_resp(struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Remote access denied: %d", smtpcode);
    result = CURLE_REMOTE_ACCESS_DENIED;
  }
  else
    /* End of connect phase */
    state(conn, SMTP_STOP);

  return result;
}

/* For AUTH PLAIN (without initial response) responses */
static CURLcode smtp_state_auth_plain_resp(struct connectdata *conn,
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
    /* Create the authorisation message */
    result = Curl_sasl_create_plain_message(conn->data, conn->user,
                                            conn->passwd, &plainauth, &len);
    if(!result && plainauth) {
      /* Send the message */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", plainauth);

      if(!result)
        state(conn, SMTP_AUTH_FINAL);
    }
  }

  Curl_safefree(plainauth);

  return result;
}

/* For AUTH LOGIN (without initial response) responses */
static CURLcode smtp_state_auth_login_resp(struct connectdata *conn,
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
    /* Create the user message */
    result = Curl_sasl_create_login_message(conn->data, conn->user,
                                            &authuser, &len);
    if(!result && authuser) {
      /* Send the user */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", authuser);

      if(!result)
        state(conn, SMTP_AUTH_LOGIN_PASSWD);
    }
  }

  Curl_safefree(authuser);

  return result;
}

/* For AUTH LOGIN user entry responses */
static CURLcode smtp_state_auth_login_password_resp(struct connectdata *conn,
                                                    int smtpcode,
                                                    smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *authpasswd = NULL;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the password message */
    result = Curl_sasl_create_login_message(conn->data, conn->passwd,
                                            &authpasswd, &len);
    if(!result && authpasswd) {
      /* Send the password */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", authpasswd);

      if(!result)
        state(conn, SMTP_AUTH_FINAL);
    }
  }

  Curl_safefree(authpasswd);

  return result;
}

#ifndef CURL_DISABLE_CRYPTO_AUTH
/* For AUTH CRAM-MD5 responses */
static CURLcode smtp_state_auth_cram_resp(struct connectdata *conn,
                                          int smtpcode,
                                          smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *chlg = NULL;
  char *chlg64 = NULL;
  char *rplyb64 = NULL;
  size_t len = 0;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    return CURLE_LOGIN_DENIED;
  }

  /* Get the challenge message */
  smtp_get_message(data->state.buffer, &chlg64);

  /* Decode the challenge message */
  result = Curl_sasl_decode_cram_md5_message(chlg64, &chlg, &len);
  if(result) {
    /* Send the cancellation */
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "*");

    if(!result)
      state(conn, SMTP_AUTH_CANCEL);
  }
  else {
    /* Create the response message */
    result = Curl_sasl_create_cram_md5_message(data, chlg, conn->user,
                                               conn->passwd, &rplyb64, &len);
    if(!result && rplyb64) {
      /* Send the response */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", rplyb64);

      if(!result)
        state(conn, SMTP_AUTH_FINAL);
    }
  }

  Curl_safefree(chlg);
  Curl_safefree(rplyb64);

  return result;
}

/* For AUTH DIGEST-MD5 challenge responses */
static CURLcode smtp_state_auth_digest_resp(struct connectdata *conn,
                                            int smtpcode,
                                            smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *chlg64 = NULL;
  char *rplyb64 = NULL;
  size_t len = 0;

  char nonce[64];
  char realm[128];
  char algorithm[64];

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    return CURLE_LOGIN_DENIED;
  }

  /* Get the challenge message */
  smtp_get_message(data->state.buffer, &chlg64);

  /* Decode the challange message */
  result = Curl_sasl_decode_digest_md5_message(chlg64, nonce, sizeof(nonce),
                                               realm, sizeof(realm),
                                               algorithm, sizeof(algorithm));
  if(result || strcmp(algorithm, "md5-sess") != 0) {
    /* Send the cancellation */
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "*");

    if(!result)
      state(conn, SMTP_AUTH_CANCEL);
  }
  else {
    /* Create the response message */
    result = Curl_sasl_create_digest_md5_message(data, nonce, realm,
                                                 conn->user, conn->passwd,
                                                 "smtp", &rplyb64, &len);
    if(!result && rplyb64) {
      /* Send the response */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", rplyb64);

      if(!result)
        state(conn, SMTP_AUTH_DIGESTMD5_RESP);
    }
  }

  Curl_safefree(rplyb64);

  return result;
}

/* For AUTH DIGEST-MD5 challenge-response responses */
static CURLcode smtp_state_auth_digest_resp_resp(struct connectdata *conn,
                                                 int smtpcode,
                                                 smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Authentication failed: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Send an empty response */
    result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "");

    if(!result)
      state(conn, SMTP_AUTH_FINAL);
  }

  return result;
}

#endif

#ifdef USE_NTLM
/* For AUTH NTLM (without initial response) responses */
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
    /* Create the type-1 message */
    result = Curl_sasl_create_ntlm_type1_message(conn->user, conn->passwd,
                                                 &conn->ntlm,
                                                 &type1msg, &len);
    if(!result && type1msg) {
      /* Send the message */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", type1msg);

      if(!result)
        state(conn, SMTP_AUTH_NTLM_TYPE2MSG);
    }
  }

  Curl_safefree(type1msg);

  return result;
}

/* For NTLM type-2 responses (sent in reponse to our type-1 message) */
static CURLcode smtp_state_auth_ntlm_type2msg_resp(struct connectdata *conn,
                                                   int smtpcode,
                                                   smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *type2msg = NULL;
  char *type3msg = NULL;
  size_t len = 0;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Get the type-2 message */
    smtp_get_message(data->state.buffer, &type2msg);

    /* Decode the type-2 message */
    result = Curl_sasl_decode_ntlm_type2_message(data, type2msg, &conn->ntlm);
    if(result) {
      /* Send the cancellation */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "*");

      if(!result)
        state(conn, SMTP_AUTH_CANCEL);
    }
    else {
      /* Create the type-3 message */
      result = Curl_sasl_create_ntlm_type3_message(data, conn->user,
                                                   conn->passwd, &conn->ntlm,
                                                   &type3msg, &len);
      if(!result && type3msg) {
        /* Send the message */
        result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", type3msg);

        if(!result)
          state(conn, SMTP_AUTH_FINAL);
      }
    }
  }

  Curl_safefree(type3msg);

  return result;
}
#endif

/* For AUTH XOAUTH2 (without initial response) responses */
static CURLcode smtp_state_auth_xoauth2_resp(struct connectdata *conn,
                                             int smtpcode, smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *xoauth = NULL;

  (void)instate; /* no use for this yet */

  if(smtpcode != 334) {
    failf(data, "Access denied: %d", smtpcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the authorisation message */
    result = Curl_sasl_create_xoauth2_message(conn->data, conn->user,
                                              conn->xoauth2_bearer,
                                              &xoauth, &len);
    if(!result && xoauth) {
      /* Send the message */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", xoauth);

      if(!result)
        state(conn, SMTP_AUTH_FINAL);
    }
  }

  Curl_safefree(xoauth);

  return result;
}

/* For AUTH cancellation responses */
static CURLcode smtp_state_auth_cancel_resp(struct connectdata *conn,
                                            int smtpcode,
                                            smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *mech = NULL;
  char *initresp = NULL;
  size_t len = 0;
  smtpstate state1 = SMTP_STOP;
  smtpstate state2 = SMTP_STOP;

  (void)smtpcode;
  (void)instate; /* no use for this yet */

  /* Remove the offending mechanism from the supported list */
  smtpc->authmechs ^= smtpc->authused;

  /* Calculate alternative SASL login details */
  result = smtp_calc_sasl_details(conn, &mech, &initresp, &len, &state1,
                                  &state2);

  if(!result) {
    /* Do we have any mechanisms left? */
    if(mech) {
      /* Retry SASL based authentication */
      result = smtp_perform_auth(conn, mech, initresp, len, state1, state2);

      Curl_safefree(initresp);
    }
    else {
      failf(data, "Authentication cancelled");

      result = CURLE_LOGIN_DENIED;
    }
  }

  return result;
}

/* For final responses in the AUTH sequence */
static CURLcode smtp_state_auth_final_resp(struct connectdata *conn,
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
    /* End of connect phase */
    state(conn, SMTP_STOP);

  return result;
}

/* For command responses */
static CURLcode smtp_state_command_resp(struct connectdata *conn, int smtpcode,
                                        smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;
  char *line = data->state.buffer;
  size_t len = strlen(line);

  (void)instate; /* no use for this yet */

  if((smtp->rcpt && smtpcode/100 != 2 && smtpcode != 553 && smtpcode != 1) ||
     (!smtp->rcpt && smtpcode/100 != 2 && smtpcode != 1)) {
    failf(data, "Command failed: %d", smtpcode);
    result = CURLE_RECV_ERROR;
  }
  else {
    /* Temporarily add the LF character back and send as body to the client */
    if(!data->set.opt_no_body) {
      line[len] = '\n';
      result = Curl_client_write(conn, CLIENTWRITE_BODY, line, len + 1);
      line[len] = '\0';
    }

    if(smtpcode != 1) {
      if(smtp->rcpt) {
        smtp->rcpt = smtp->rcpt->next;

        if(smtp->rcpt) {
          /* Send the next command */
          result = smtp_perform_command(conn);
        }
        else
          /* End of DO phase */
          state(conn, SMTP_STOP);
      }
      else
        /* End of DO phase */
        state(conn, SMTP_STOP);
    }
  }

  return result;
}

/* For MAIL responses */
static CURLcode smtp_state_mail_resp(struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "MAIL failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else
    /* Start the RCPT TO command */
    result = smtp_perform_rcpt_to(conn);

  return result;
}

/* For RCPT responses */
static CURLcode smtp_state_rcpt_resp(struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "RCPT failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else {
    smtp->rcpt = smtp->rcpt->next;

    if(smtp->rcpt)
      /* Send the next RCPT TO command */
      result = smtp_perform_rcpt_to(conn);
    else {
      /* Send the DATA command */
      result = Curl_pp_sendf(&conn->proto.smtpc.pp, "%s", "DATA");

      if(!result)
        state(conn, SMTP_DATA);
    }
  }

  return result;
}

/* For DATA response */
static CURLcode smtp_state_data_resp(struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode != 354) {
    failf(data, "DATA failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else {
    /* Set the progress upload size */
    Curl_pgrsSetUploadSize(data, data->set.infilesize);

    /* SMTP upload */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, FIRSTSOCKET, NULL);

    /* End of DO phase */
    state(conn, SMTP_STOP);
  }

  return result;
}

/* For POSTDATA responses, which are received after the entire DATA
   part has been sent to the server */
static CURLcode smtp_state_postdata_resp(struct connectdata *conn,
                                         int smtpcode,
                                         smtpstate instate)
{
  CURLcode result = CURLE_OK;

  (void)instate; /* no use for this yet */

  if(smtpcode != 250)
    result = CURLE_RECV_ERROR;

  /* End of DONE phase */
  state(conn, SMTP_STOP);

  return result;
}

static CURLcode smtp_statemach_act(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data = conn->data;
  int smtpcode;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  size_t nread = 0;

  /* Busy upgrading the connection; right now all I/O is SSL/TLS, not SMTP */
  if(smtpc->state == SMTP_UPGRADETLS)
    return smtp_perform_upgrade_tls(conn);

  /* Flush any data that needs to be sent */
  if(pp->sendleft)
    return Curl_pp_flushsend(pp);

  do {
    /* Read the response from the server */
    result = Curl_pp_readresp(sock, pp, &smtpcode, &nread);
    if(result)
      return result;

    /* Store the latest response for later retrieval if necessary */
    if(smtpc->state != SMTP_QUIT && smtpcode != 1)
      data->info.httpcode = smtpcode;

    if(!smtpcode)
      break;

    /* We have now received a full SMTP server response */
    switch(smtpc->state) {
    case SMTP_SERVERGREET:
      result = smtp_state_servergreet_resp(conn, smtpcode, smtpc->state);
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

    case SMTP_AUTH_PLAIN:
      result = smtp_state_auth_plain_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_LOGIN:
      result = smtp_state_auth_login_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_LOGIN_PASSWD:
      result = smtp_state_auth_login_password_resp(conn, smtpcode,
                                                   smtpc->state);
      break;

#ifndef CURL_DISABLE_CRYPTO_AUTH
    case SMTP_AUTH_CRAMMD5:
      result = smtp_state_auth_cram_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_DIGESTMD5:
      result = smtp_state_auth_digest_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_DIGESTMD5_RESP:
      result = smtp_state_auth_digest_resp_resp(conn, smtpcode, smtpc->state);
      break;
#endif

#ifdef USE_NTLM
    case SMTP_AUTH_NTLM:
      result = smtp_state_auth_ntlm_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_NTLM_TYPE2MSG:
      result = smtp_state_auth_ntlm_type2msg_resp(conn, smtpcode,
                                                  smtpc->state);
      break;
#endif

    case SMTP_AUTH_XOAUTH2:
      result = smtp_state_auth_xoauth2_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_CANCEL:
      result = smtp_state_auth_cancel_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_AUTH_FINAL:
      result = smtp_state_auth_final_resp(conn, smtpcode, smtpc->state);
      break;

    case SMTP_COMMAND:
      result = smtp_state_command_resp(conn, smtpcode, smtpc->state);
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
  } while(!result && smtpc->state != SMTP_STOP && Curl_pp_moredata(pp));

  return result;
}

/* Called repeatedly until done from multi.c */
static CURLcode smtp_multi_statemach(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  if((conn->handler->flags & PROTOPT_SSL) && !smtpc->ssldone) {
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &smtpc->ssldone);
    if(result || !smtpc->ssldone)
      return result;
  }

  result = Curl_pp_statemach(&smtpc->pp, FALSE);
  *done = (smtpc->state == SMTP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode smtp_block_statemach(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  while(smtpc->state != SMTP_STOP && !result)
    result = Curl_pp_statemach(&smtpc->pp, TRUE);

  return result;
}

/* Allocate and initialize the SMTP struct for the current SessionHandle if
   required */
static CURLcode smtp_init(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp;

  smtp = data->req.protop = calloc(sizeof(struct SMTP), 1);
  if(!smtp)
    result = CURLE_OUT_OF_MEMORY;

  return result;
}

/* For the SMTP "protocol connect" and "doing" phases only */
static int smtp_getsock(struct connectdata *conn, curl_socket_t *socks,
                        int numsocks)
{
  return Curl_pp_getsock(&conn->proto.smtpc.pp, socks, numsocks);
}

/***********************************************************************
 *
 * smtp_connect()
 *
 * This function should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable pointed to by 'done' will be TRUE if the protocol-layer
 * connect phase is done when this function returns, or FALSE if not.
 */
static CURLcode smtp_connect(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections in SMTP */
  conn->bits.close = FALSE;

  /* Set the default response time-out */
  pp->response_time = RESP_TIMEOUT;
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

  /* Set the default preferred authentication mechanism */
  smtpc->prefmech = SASL_AUTH_ANY;

  /* Initialise the pingpong layer */
  Curl_pp_init(pp);

  /* Parse the URL options */
  result = smtp_parse_url_options(conn);
  if(result)
    return result;

  /* Parse the URL path */
  result = smtp_parse_url_path(conn);
  if(result)
    return result;

  /* Start off waiting for the server greeting response */
  state(conn, SMTP_SERVERGREET);

  result = smtp_multi_statemach(conn, done);

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
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;
  struct pingpong *pp = &conn->proto.smtpc.pp;
  const char *eob;
  ssize_t len;
  ssize_t bytes_written;

  (void)premature;

  if(!smtp)
    /* When the easy handle is removed from the multi interface while libcurl
       is still trying to resolve the host name, the SMTP struct is not yet
       initialized. However, the removal action calls Curl_done() which in
       turn calls this function, so we simply return success. */
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; /* marked for closure */
    result = status;         /* use the already set error code */
  }
  else if(!data->set.connect_only && data->set.upload && data->set.mail_rcpt) {
    /* Calculate the EOB taking into account any terminating CRLF from the
       previous line of the email or the CRLF of the DATA command when there
       is "no mail data". RFC-5321, sect. 4.1.1.4. */
    eob = SMTP_EOB;
    len = SMTP_EOB_LEN;
    if(smtp->trailing_crlf || !conn->data->set.infilesize) {
      eob += 2;
      len -= 2;
    }

    /* Send the end of block data */
    result = Curl_write(conn, conn->writesockfd, eob, len, &bytes_written);
    if(result)
      return result;

    if(bytes_written != len) {
      /* The whole chunk was not sent so keep it around and adjust the
         pingpong structure accordingly */
      pp->sendthis = strdup(eob);
      pp->sendsize = len;
      pp->sendleft = len - bytes_written;
    }
    else
      /* Successfully sent so adjust the response timeout relative to now */
      pp->response = Curl_tvnow();

    state(conn, SMTP_POSTDATA);

    /* Run the state-machine

       TODO: when the multi interface is used, this _really_ should be using
       the smtp_multi_statemach function but we have no general support for
       non-blocking DONE operations, not in the multi state machine and with
       Curl_done() invokes on several places in the code!
    */
    result = smtp_block_statemach(conn);
  }

  /* Cleanup our per-request based variables */
  Curl_safefree(smtp->custom);

  /* Clear the transfer mode for the next request */
  smtp->transfer = FTPTRANSFER_BODY;

  return result;
}

/***********************************************************************
 *
 * smtp_perform()
 *
 * This is the actual DO function for SMTP. Transfer a mail, send a command
 * or get some data according to the options previously setup.
 */
static CURLcode smtp_perform(struct connectdata *conn, bool *connected,
                             bool *dophase_done)
{
  /* This is SMTP and no proxy */
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(data->set.opt_no_body) {
    /* Requested no body means no transfer */
    smtp->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  /* Store the first recipient (or NULL if not specified) */
  smtp->rcpt = data->set.mail_rcpt;

  /* Start the first command in the DO phase */
  if(data->set.upload && data->set.mail_rcpt)
    /* MAIL transfer */
    result = smtp_perform_mail(conn);
  else
    /* SMTP based command (VRFY, EXPN, NOOP, RSET or HELP) */
    result = smtp_perform_command(conn);

  if(result)
    return result;

  /* Run the state-machine */
  result = smtp_multi_statemach(conn, dophase_done);

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
  CURLcode result = CURLE_OK;

  *done = FALSE; /* default to false */

  /* Parse the custom request */
  result = smtp_parse_custom_request(conn);
  if(result)
    return result;

  result = smtp_regular_transfer(conn, done);

  return result;
}

/***********************************************************************
 *
 * smtp_disconnect()
 *
 * Disconnect from an SMTP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode smtp_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to. */

  /* The SMTP session may or may not have been allocated/setup at this
     point! */
  if(!dead_connection && smtpc->pp.conn && smtpc->pp.conn->bits.protoconnstart)
    if(!smtp_perform_quit(conn))
      (void)smtp_block_statemach(conn); /* ignore errors on QUIT */

  /* Disconnect from the server */
  Curl_pp_disconnect(&smtpc->pp);

  /* Cleanup the SASL module */
  Curl_sasl_cleanup(conn, smtpc->authused);

  /* Cleanup our connection based variables */
  Curl_safefree(smtpc->domain);

  return CURLE_OK;
}

/* Call this when the DO phase has completed */
static CURLcode smtp_dophase_done(struct connectdata *conn, bool connected)
{
  struct SMTP *smtp = conn->data->req.protop;

  (void)connected;

  if(smtp->transfer != FTPTRANSFER_BODY)
    /* no data to transfer */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return CURLE_OK;
}

/* Called from multi.c while DOing */
static CURLcode smtp_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result = smtp_multi_statemach(conn, dophase_done);

  if(result)
    DEBUGF(infof(conn->data, "DO phase failed\n"));
  else if(*dophase_done) {
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
static CURLcode smtp_regular_transfer(struct connectdata *conn,
                                      bool *dophase_done)
{
  CURLcode result = CURLE_OK;
  bool connected = FALSE;
  struct SessionHandle *data = conn->data;

  /* Make sure size is unknown at this point */
  data->req.size = -1;

  /* Set the progress data */
  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  /* Carry out the perform */
  result = smtp_perform(conn, &connected, dophase_done);

  /* Perform post DO phase operations if necessary */
  if(!result && *dophase_done)
    result = smtp_dophase_done(conn, connected);

  return result;
}

static CURLcode smtp_setup_connection(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  CURLcode result;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    /* Unless we have asked to tunnel SMTP operations through the proxy, we
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
    /* set it up as a HTTP connection instead */
    return conn->handler->setup_connection(conn);

#else
    failf(data, "SMTP over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }

  /* Initialise the SMTP layer */
  result = smtp_init(conn);
  if(result)
    return result;

  data->state.path++;   /* don't include the initial slash */

  return CURLE_OK;
}

/***********************************************************************
 *
 * smtp_parse_url_options()
 *
 * Parse the URL login options.
 */
static CURLcode smtp_parse_url_options(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *options = conn->options;
  const char *ptr = options;
  bool reset = TRUE;

  while(ptr && *ptr) {
    const char *key = ptr;

    while(*ptr && *ptr != '=')
        ptr++;

    if(strnequal(key, "AUTH", 4)) {
      size_t len = 0;
      const char *value = ++ptr;

      if(reset) {
        reset = FALSE;
        smtpc->prefmech = SASL_AUTH_NONE;
      }

      while(*ptr && *ptr != ';') {
        ptr++;
        len++;
      }

      if(strnequal(value, "*", len))
        smtpc->prefmech = SASL_AUTH_ANY;
      else if(strnequal(value, SASL_MECH_STRING_LOGIN, len))
        smtpc->prefmech |= SASL_MECH_LOGIN;
      else if(strnequal(value, SASL_MECH_STRING_PLAIN, len))
        smtpc->prefmech |= SASL_MECH_PLAIN;
      else if(strnequal(value, SASL_MECH_STRING_CRAM_MD5, len))
        smtpc->prefmech |= SASL_MECH_CRAM_MD5;
      else if(strnequal(value, SASL_MECH_STRING_DIGEST_MD5, len))
        smtpc->prefmech |= SASL_MECH_DIGEST_MD5;
      else if(strnequal(value, SASL_MECH_STRING_GSSAPI, len))
        smtpc->prefmech |= SASL_MECH_GSSAPI;
      else if(strnequal(value, SASL_MECH_STRING_NTLM, len))
        smtpc->prefmech |= SASL_MECH_NTLM;
      else if(strnequal(value, SASL_MECH_STRING_XOAUTH2, len))
        smtpc->prefmech |= SASL_MECH_XOAUTH2;

      if(*ptr == ';')
        ptr++;
    }
    else
      result = CURLE_URL_MALFORMAT;
  }

  return result;
}

/***********************************************************************
 *
 * smtp_parse_url_path()
 *
 * Parse the URL path into separate path components.
 */
static CURLcode smtp_parse_url_path(struct connectdata *conn)
{
  /* The SMTP struct is already initialised in smtp_connect() */
  struct SessionHandle *data = conn->data;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *path = data->state.path;
  char localhost[HOSTNAME_MAX + 1];

  /* Calculate the path if necessary */
  if(!*path) {
    if(!Curl_gethostname(localhost, sizeof(localhost)))
      path = localhost;
    else
      path = "localhost";
  }

  /* URL decode the path and use it as the domain in our EHLO */
  return Curl_urldecode(conn->data, path, 0, &smtpc->domain, NULL, TRUE);
}

/***********************************************************************
 *
 * smtp_parse_custom_request()
 *
 * Parse the custom request.
 */
static CURLcode smtp_parse_custom_request(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  /* URL decode the custom request */
  if(custom)
    result = Curl_urldecode(data, custom, 0, &smtp->custom, NULL, TRUE);

  return result;
}

/***********************************************************************
 *
 * smtp_calc_sasl_details()
 *
 * Calculate the required login details for SASL authentication.
 */
static CURLcode smtp_calc_sasl_details(struct connectdata *conn,
                                       const char **mech,
                                       char **initresp, size_t *len,
                                       smtpstate *state1, smtpstate *state2)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  /* Calculate the supported authentication mechanism, by decreasing order of
     security, as well as the initial response where appropriate */
#ifndef CURL_DISABLE_CRYPTO_AUTH
  if((smtpc->authmechs & SASL_MECH_DIGEST_MD5) &&
     (smtpc->prefmech & SASL_MECH_DIGEST_MD5)) {
    *mech = SASL_MECH_STRING_DIGEST_MD5;
    *state1 = SMTP_AUTH_DIGESTMD5;
    smtpc->authused = SASL_MECH_DIGEST_MD5;
  }
  else if((smtpc->authmechs & SASL_MECH_CRAM_MD5) &&
          (smtpc->prefmech & SASL_MECH_CRAM_MD5)) {
    *mech = SASL_MECH_STRING_CRAM_MD5;
    *state1 = SMTP_AUTH_CRAMMD5;
    smtpc->authused = SASL_MECH_CRAM_MD5;
  }
  else
#endif
#ifdef USE_NTLM
  if((smtpc->authmechs & SASL_MECH_NTLM) &&
     (smtpc->prefmech & SASL_MECH_NTLM)) {
    *mech = SASL_MECH_STRING_NTLM;
    *state1 = SMTP_AUTH_NTLM;
    *state2 = SMTP_AUTH_NTLM_TYPE2MSG;
    smtpc->authused = SASL_MECH_NTLM;

    if(data->set.sasl_ir)
      result = Curl_sasl_create_ntlm_type1_message(conn->user, conn->passwd,
                                                   &conn->ntlm,
                                                   initresp, len);
    }
  else
#endif
  if(((smtpc->authmechs & SASL_MECH_XOAUTH2) &&
      (smtpc->prefmech & SASL_MECH_XOAUTH2) &&
      (smtpc->prefmech != SASL_AUTH_ANY)) || conn->xoauth2_bearer) {
    *mech = SASL_MECH_STRING_XOAUTH2;
    *state1 = SMTP_AUTH_XOAUTH2;
    *state2 = SMTP_AUTH_FINAL;
    smtpc->authused = SASL_MECH_XOAUTH2;

    if(data->set.sasl_ir)
      result = Curl_sasl_create_xoauth2_message(data, conn->user,
                                                conn->xoauth2_bearer,
                                                initresp, len);
  }
  else if((smtpc->authmechs & SASL_MECH_LOGIN) &&
          (smtpc->prefmech & SASL_MECH_LOGIN)) {
    *mech = SASL_MECH_STRING_LOGIN;
    *state1 = SMTP_AUTH_LOGIN;
    *state2 = SMTP_AUTH_LOGIN_PASSWD;
    smtpc->authused = SASL_MECH_LOGIN;

    if(data->set.sasl_ir)
      result = Curl_sasl_create_login_message(data, conn->user, initresp, len);
  }
  else if((smtpc->authmechs & SASL_MECH_PLAIN) &&
          (smtpc->prefmech & SASL_MECH_PLAIN)) {
    *mech = SASL_MECH_STRING_PLAIN;
    *state1 = SMTP_AUTH_PLAIN;
    *state2 = SMTP_AUTH_FINAL;
    smtpc->authused = SASL_MECH_PLAIN;

    if(data->set.sasl_ir)
      result = Curl_sasl_create_plain_message(data, conn->user, conn->passwd,
                                              initresp, len);
  }

  return result;
}

CURLcode Curl_smtp_escape_eob(struct connectdata *conn, ssize_t nread)
{
  /* When sending a SMTP payload we must detect CRLF. sequences making sure
     they are sent as CRLF.. instead, as a . on the beginning of a line will
     be deleted by the server when not part of an EOB terminator and a
     genuine CRLF.CRLF which isn't escaped will wrongly be detected as end of
     data by the server
  */
  ssize_t i;
  ssize_t si;
  struct SessionHandle *data = conn->data;
  struct SMTP *smtp = data->req.protop;

  /* Do we need to allocate the scatch buffer? */
  if(!data->state.scratch) {
    data->state.scratch = malloc(2 * BUFSIZE);

    if(!data->state.scratch) {
      failf (data, "Failed to alloc scratch buffer!");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* This loop can be improved by some kind of Boyer-Moore style of
     approach but that is saved for later... */
  for(i = 0, si = 0; i < nread; i++) {
    if(SMTP_EOB[smtp->eob] == data->req.upload_fromhere[i]) {
      smtp->eob++;

      /* Is the EOB potentially the terminating CRLF? */
      if(2 == smtp->eob || SMTP_EOB_LEN == smtp->eob)
        smtp->trailing_crlf = TRUE;
      else
        smtp->trailing_crlf = FALSE;
    }
    else if(smtp->eob) {
      /* A previous substring matched so output that first */
      memcpy(&data->state.scratch[si], SMTP_EOB, smtp->eob);
      si += smtp->eob;

      /* Then compare the first byte */
      if(SMTP_EOB[0] == data->req.upload_fromhere[i])
        smtp->eob = 1;
      else
        smtp->eob = 0;

      /* Reset the trailing CRLF flag as there was more data */
      smtp->trailing_crlf = FALSE;
    }

    /* Do we have a match for CRLF. as per RFC-5321, sect. 4.5.2 */
    if(SMTP_EOB_FIND_LEN == smtp->eob) {
      /* Copy the replacement data to the target buffer */
      memcpy(&data->state.scratch[si], SMTP_EOB_REPL, SMTP_EOB_REPL_LEN);
      si += SMTP_EOB_REPL_LEN;
      smtp->eob = 0;
    }
    else if(!smtp->eob)
      data->state.scratch[si++] = data->req.upload_fromhere[i];
  }

  if(smtp->eob) {
    /* A substring matched before processing ended so output that now */
    memcpy(&data->state.scratch[si], SMTP_EOB, smtp->eob);
    si += smtp->eob;
    smtp->eob = 0;
  }

  if(si != nread) {
    /* Only use the new buffer if we replaced something */
    nread = si;

    /* Upload from the new (replaced) buffer instead */
    data->req.upload_fromhere = data->state.scratch;

    /* Set the new amount too */
    data->req.upload_present = nread;
  }

  return CURLE_OK;
}

#endif /* CURL_DISABLE_SMTP */
