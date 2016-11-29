/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
 * RFC4752 The Kerberos V5 ("GSSAPI") SASL Mechanism
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
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "socks.h"
#include "smtp.h"
#include "strtoofft.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "curl_gethostname.h"
#include "curl_sasl.h"
#include "warnless.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
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
static CURLcode smtp_perform_auth(struct connectdata *conn, const char *mech,
                                  const char *initresp);
static CURLcode smtp_continue_auth(struct connectdata *conn, const char *resp);
static void smtp_get_message(char *buffer, char **outptr);

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
  CURLPROTO_SMTPS,                  /* protocol */
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

/* SASL parameters for the smtp protocol */
static const struct SASLproto saslsmtp = {
  "smtp",                     /* The service name */
  334,                        /* Code received when continuation is expected */
  235,                        /* Code to receive upon authentication success */
  512 - 8,                    /* Maximum initial response length (no max) */
  smtp_perform_auth,          /* Send authentication command */
  smtp_continue_auth,         /* Send authentication continuation */
  smtp_get_message            /* Get SASL response message */
};

#ifdef USE_SSL
static void smtp_to_smtps(struct connectdata *conn)
{
  /* Change the connection handler */
  conn->handler = &Curl_handler_smtps;

  /* Set the connection's upgraded to TLS flag */
  conn->tls_upgraded = TRUE;
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
static void smtp_get_message(char *buffer, char **outptr)
{
  size_t len = 0;
  char *message = NULL;

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
    "AUTH",
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

  smtpc->sasl.authmechs = SASL_AUTH_NONE; /* No known auth. mechanism yet */
  smtpc->sasl.authused = SASL_AUTH_NONE;  /* Clear the authentication mechanism
                                             used for esmtp connections */
  smtpc->tls_supported = FALSE;           /* Clear the TLS capability */
  smtpc->auth_supported = FALSE;          /* Clear the AUTH capability */

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

  smtpc->sasl.authused = SASL_AUTH_NONE; /* No authentication mechanism used
                                            in smtp connections */

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
                                  const char *initresp)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  if(initresp) {                                  /* AUTH <mech> ...<crlf> */
    /* Send the AUTH command with the initial response */
    result = Curl_pp_sendf(&smtpc->pp, "AUTH %s %s", mech, initresp);
  }
  else {
    /* Send the AUTH command */
    result = Curl_pp_sendf(&smtpc->pp, "AUTH %s", mech);
  }

  return result;
}

/***********************************************************************
 *
 * smtp_continue_auth()
 *
 * Sends SASL continuation data or cancellation.
 */
static CURLcode smtp_continue_auth(struct connectdata *conn, const char *resp)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  return Curl_pp_sendf(&smtpc->pp, "%s", resp);
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
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  saslprogress progress;

  /* Check we have enough data to authenticate with, and the
     server supports authentiation, and end the connect phase if not */
  if(!smtpc->auth_supported ||
     !Curl_sasl_can_authenticate(&smtpc->sasl, conn)) {
    state(conn, SMTP_STOP);
    return result;
  }

  /* Calculate the SASL login details */
  result = Curl_sasl_start(&smtpc->sasl, conn, FALSE, &progress);

  if(!result) {
    if(progress == SASL_INPROGRESS)
      state(conn, SMTP_AUTH);
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
  struct Curl_easy *data = conn->data;
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
  struct Curl_easy *data = conn->data;

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
  if(data->set.str[STRING_MAIL_AUTH] && conn->proto.smtpc.sasl.authused) {
    if(data->set.str[STRING_MAIL_AUTH][0] != '\0')
      auth = aprintf("%s", data->set.str[STRING_MAIL_AUTH]);
    else
      /* Empty AUTH, RFC-2554, sect. 5 */
      auth = strdup("<>");

    if(!auth) {
      free(from);

      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* Calculate the optional SIZE parameter */
  if(conn->proto.smtpc.size_supported && conn->data->state.infilesize > 0) {
    size = aprintf("%" CURL_FORMAT_CURL_OFF_T, data->state.infilesize);

    if(!size) {
      free(from);
      free(auth);

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

  free(from);
  free(auth);
  free(size);

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
  struct Curl_easy *data = conn->data;
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
  struct Curl_easy *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Got unexpected smtp-server response: %d", smtpcode);
    result = CURLE_WEIRD_SERVER_REPLY;
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
  struct Curl_easy *data = conn->data;

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
  struct Curl_easy *data = conn->data;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *line = data->state.buffer;
  size_t len = strlen(line);
  size_t wordlen;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2 && smtpcode != 1) {
    if(data->set.use_ssl <= CURLUSESSL_TRY || conn->ssl[FIRSTSOCKET].use)
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

    /* Does the server support authentication? */
    else if(len >= 5 && !memcmp(line, "AUTH ", 5)) {
      smtpc->auth_supported = TRUE;

      /* Advance past the AUTH keyword */
      line += 5;
      len -= 5;

      /* Loop through the data line */
      for(;;) {
        size_t llen;
        unsigned int mechbit;

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
          smtpc->sasl.authmechs |= mechbit;

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
  struct Curl_easy *data = conn->data;

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

/* For SASL authentication responses */
static CURLcode smtp_state_auth_resp(struct connectdata *conn,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  saslprogress progress;

  (void)instate; /* no use for this yet */

  result = Curl_sasl_continue(&smtpc->sasl, conn, smtpcode, &progress);
  if(!result)
    switch(progress) {
    case SASL_DONE:
      state(conn, SMTP_STOP);  /* Authenticated */
      break;
    case SASL_IDLE:            /* No mechanism left after cancellation */
      failf(data, "Authentication cancelled");
      result = CURLE_LOGIN_DENIED;
      break;
    default:
      break;
    }

  return result;
}

/* For command responses */
static CURLcode smtp_state_command_resp(struct connectdata *conn, int smtpcode,
                                        smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
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
  struct Curl_easy *data = conn->data;

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
  struct Curl_easy *data = conn->data;
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
  struct Curl_easy *data = conn->data;

  (void)instate; /* no use for this yet */

  if(smtpcode != 354) {
    failf(data, "DATA failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else {
    /* Set the progress upload size */
    Curl_pgrsSetUploadSize(data, data->state.infilesize);

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
  struct Curl_easy *data = conn->data;
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

    case SMTP_AUTH:
      result = smtp_state_auth_resp(conn, smtpcode, smtpc->state);
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

/* Allocate and initialize the SMTP struct for the current Curl_easy if
   required */
static CURLcode smtp_init(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
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
  connkeep(conn, "SMTP default");

  /* Set the default response time-out */
  pp->response_time = RESP_TIMEOUT;
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

  /* Initialize the SASL storage */
  Curl_sasl_init(&smtpc->sasl, &saslsmtp);

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
  struct Curl_easy *data = conn->data;
  struct SMTP *smtp = data->req.protop;
  struct pingpong *pp = &conn->proto.smtpc.pp;
  char *eob;
  ssize_t len;
  ssize_t bytes_written;

  (void)premature;

  if(!smtp || !pp->conn)
    return CURLE_OK;

  if(status) {
    connclose(conn, "SMTP done with bad status"); /* marked for closure */
    result = status;         /* use the already set error code */
  }
  else if(!data->set.connect_only && data->set.upload && data->set.mail_rcpt) {
    /* Calculate the EOB taking into account any terminating CRLF from the
       previous line of the email or the CRLF of the DATA command when there
       is "no mail data". RFC-5321, sect. 4.1.1.4.

       Note: As some SSL backends, such as OpenSSL, will cause Curl_write() to
       fail when using a different pointer following a previous write, that
       returned CURLE_AGAIN, we duplicate the EOB now rather than when the
       bytes written doesn't equal len. */
    if(smtp->trailing_crlf || !conn->data->state.infilesize) {
      eob = strdup(SMTP_EOB + 2);
      len = SMTP_EOB_LEN - 2;
    }
    else {
      eob = strdup(SMTP_EOB);
      len = SMTP_EOB_LEN;
    }

    if(!eob)
      return CURLE_OUT_OF_MEMORY;

    /* Send the end of block data */
    result = Curl_write(conn, conn->writesockfd, eob, len, &bytes_written);
    if(result) {
      free(eob);
      return result;
    }

    if(bytes_written != len) {
      /* The whole chunk was not sent so keep it around and adjust the
         pingpong structure accordingly */
      pp->sendthis = eob;
      pp->sendsize = len;
      pp->sendleft = len - bytes_written;
    }
    else {
      /* Successfully sent so adjust the response timeout relative to now */
      pp->response = Curl_tvnow();

      free(eob);
    }

    state(conn, SMTP_POSTDATA);

    /* Run the state-machine

       TODO: when the multi interface is used, this _really_ should be using
       the smtp_multi_statemach function but we have no general support for
       non-blocking DONE operations!
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
  struct Curl_easy *data = conn->data;
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
  Curl_sasl_cleanup(conn, smtpc->sasl.authused);

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
  struct Curl_easy *data = conn->data;

  /* Make sure size is unknown at this point */
  data->req.size = -1;

  /* Set the progress data */
  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  /* Carry out the perform */
  result = smtp_perform(conn, &connected, dophase_done);

  /* Perform post DO phase operations if necessary */
  if(!result && *dophase_done)
    result = smtp_dophase_done(conn, connected);

  return result;
}

static CURLcode smtp_setup_connection(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  CURLcode result;

  /* Clear the TLS upgraded flag */
  conn->tls_upgraded = FALSE;

  /* Set up the proxy if necessary */
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
  const char *ptr = conn->options;

  smtpc->sasl.resetprefs = TRUE;

  while(!result && ptr && *ptr) {
    const char *key = ptr;
    const char *value;

    while(*ptr && *ptr != '=')
      ptr++;

    value = ptr + 1;

    while(*ptr && *ptr != ';')
      ptr++;

    if(strncasecompare(key, "AUTH=", 5))
      result = Curl_sasl_parse_url_auth_option(&smtpc->sasl,
                                               value, ptr - value);
    else
      result = CURLE_URL_MALFORMAT;

    if(*ptr == ';')
      ptr++;
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
  struct Curl_easy *data = conn->data;
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
  struct Curl_easy *data = conn->data;
  struct SMTP *smtp = data->req.protop;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  /* URL decode the custom request */
  if(custom)
    result = Curl_urldecode(data, custom, 0, &smtp->custom, NULL, TRUE);

  return result;
}

CURLcode Curl_smtp_escape_eob(struct connectdata *conn, const ssize_t nread)
{
  /* When sending a SMTP payload we must detect CRLF. sequences making sure
     they are sent as CRLF.. instead, as a . on the beginning of a line will
     be deleted by the server when not part of an EOB terminator and a
     genuine CRLF.CRLF which isn't escaped will wrongly be detected as end of
     data by the server
  */
  ssize_t i;
  ssize_t si;
  struct Curl_easy *data = conn->data;
  struct SMTP *smtp = data->req.protop;
  char *scratch = data->state.scratch;
  char *newscratch = NULL;
  char *oldscratch = NULL;
  size_t eob_sent;

  /* Do we need to allocate a scratch buffer? */
  if(!scratch || data->set.crlf) {
    oldscratch = scratch;

    scratch = newscratch = malloc(2 * BUFSIZE);
    if(!newscratch) {
      failf(data, "Failed to alloc scratch buffer!");

      return CURLE_OUT_OF_MEMORY;
    }
  }

  /* Have we already sent part of the EOB? */
  eob_sent = smtp->eob;

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
      memcpy(&scratch[si], &SMTP_EOB[eob_sent], smtp->eob - eob_sent);
      si += smtp->eob - eob_sent;

      /* Then compare the first byte */
      if(SMTP_EOB[0] == data->req.upload_fromhere[i])
        smtp->eob = 1;
      else
        smtp->eob = 0;

      eob_sent = 0;

      /* Reset the trailing CRLF flag as there was more data */
      smtp->trailing_crlf = FALSE;
    }

    /* Do we have a match for CRLF. as per RFC-5321, sect. 4.5.2 */
    if(SMTP_EOB_FIND_LEN == smtp->eob) {
      /* Copy the replacement data to the target buffer */
      memcpy(&scratch[si], &SMTP_EOB_REPL[eob_sent],
             SMTP_EOB_REPL_LEN - eob_sent);
      si += SMTP_EOB_REPL_LEN - eob_sent;
      smtp->eob = 0;
      eob_sent = 0;
    }
    else if(!smtp->eob)
      scratch[si++] = data->req.upload_fromhere[i];
  }

  if(smtp->eob - eob_sent) {
    /* A substring matched before processing ended so output that now */
    memcpy(&scratch[si], &SMTP_EOB[eob_sent], smtp->eob - eob_sent);
    si += smtp->eob - eob_sent;
  }

  /* Only use the new buffer if we replaced something */
  if(si != nread) {
    /* Upload from the new (replaced) buffer instead */
    data->req.upload_fromhere = scratch;

    /* Save the buffer so it can be freed later */
    data->state.scratch = scratch;

    /* Free the old scratch buffer */
    free(oldscratch);

    /* Set the new amount too */
    data->req.upload_present = si;
  }
  else
    free(newscratch);

  return CURLE_OK;
}

#endif /* CURL_DISABLE_SMTP */
