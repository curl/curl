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
 * RFC1870 SMTP Service Extension for Message Size
 * RFC2195 CRAM-MD5 authentication
 * RFC2831 DIGEST-MD5 authentication
 * RFC3207 SMTP over TLS
 * RFC4422 Simple Authentication and Security Layer (SASL)
 * RFC4616 PLAIN authentication
 * RFC4752 The Kerberos V5 ("GSSAPI") SASL Mechanism
 * RFC4954 SMTP Authentication
 * RFC5321 SMTP protocol
 * RFC5890 Internationalized Domain Names for Applications (IDNA)
 * RFC6531 SMTP Extension for Internationalized Email
 * RFC6532 Internationalized Email Headers
 * RFC6749 OAuth 2.0 Authorization Framework
 * RFC8314 Use of TLS for Email Submission and Access
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
#include "mime.h"
#include "socks.h"
#include "smtp.h"
#include "strtoofft.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "cfilters.h"
#include "connect.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "curl_gethostname.h"
#include "bufref.h"
#include "curl_sasl.h"
#include "warnless.h"
#include "idn.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* Local API functions */
static CURLcode smtp_regular_transfer(struct Curl_easy *data, bool *done);
static CURLcode smtp_do(struct Curl_easy *data, bool *done);
static CURLcode smtp_done(struct Curl_easy *data, CURLcode status,
                          bool premature);
static CURLcode smtp_connect(struct Curl_easy *data, bool *done);
static CURLcode smtp_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead);
static CURLcode smtp_multi_statemach(struct Curl_easy *data, bool *done);
static int smtp_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks);
static CURLcode smtp_doing(struct Curl_easy *data, bool *dophase_done);
static CURLcode smtp_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn);
static CURLcode smtp_parse_url_options(struct connectdata *conn);
static CURLcode smtp_parse_url_path(struct Curl_easy *data);
static CURLcode smtp_parse_custom_request(struct Curl_easy *data);
static CURLcode smtp_parse_address(const char *fqma,
                                   char **address, struct hostname *host);
static CURLcode smtp_perform_auth(struct Curl_easy *data, const char *mech,
                                  const struct bufref *initresp);
static CURLcode smtp_continue_auth(struct Curl_easy *data, const char *mech,
                                   const struct bufref *resp);
static CURLcode smtp_cancel_auth(struct Curl_easy *data, const char *mech);
static CURLcode smtp_get_message(struct Curl_easy *data, struct bufref *out);
static CURLcode cr_eob_add(struct Curl_easy *data);

/*
 * SMTP protocol handler.
 */

const struct Curl_handler Curl_handler_smtp = {
  "smtp",                           /* scheme */
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
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_SMTP,                        /* defport */
  CURLPROTO_SMTP,                   /* protocol */
  CURLPROTO_SMTP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | /* flags */
  PROTOPT_URLOPTIONS
};

#ifdef USE_SSL
/*
 * SMTPS protocol handler.
 */

const struct Curl_handler Curl_handler_smtps = {
  "smtps",                          /* scheme */
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
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach connection */
  PORT_SMTPS,                       /* defport */
  CURLPROTO_SMTPS,                  /* protocol */
  CURLPROTO_SMTP,                   /* family */
  PROTOPT_CLOSEACTION | PROTOPT_SSL
  | PROTOPT_NOURLQUERY | PROTOPT_URLOPTIONS /* flags */
};
#endif

/* SASL parameters for the smtp protocol */
static const struct SASLproto saslsmtp = {
  "smtp",               /* The service name */
  smtp_perform_auth,    /* Send authentication command */
  smtp_continue_auth,   /* Send authentication continuation */
  smtp_cancel_auth,     /* Cancel authentication */
  smtp_get_message,     /* Get SASL response message */
  512 - 8,              /* Max line len - strlen("AUTH ") - 1 space - crlf */
  334,                  /* Code received when continuation is expected */
  235,                  /* Code to receive upon authentication success */
  SASL_AUTH_DEFAULT,    /* Default mechanisms */
  SASL_FLAG_BASE64      /* Configuration flags */
};

#ifdef USE_SSL
static void smtp_to_smtps(struct connectdata *conn)
{
  /* Change the connection handler */
  conn->handler = &Curl_handler_smtps;

  /* Set the connection's upgraded to TLS flag */
  conn->bits.tls_upgraded = TRUE;
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
static bool smtp_endofresp(struct Curl_easy *data, struct connectdata *conn,
                           char *line, size_t len, int *resp)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  bool result = FALSE;
  (void)data;

  /* Nothing for us */
  if(len < 4 || !ISDIGIT(line[0]) || !ISDIGIT(line[1]) || !ISDIGIT(line[2]))
    return FALSE;

  /* Do we have a command response? This should be the response code followed
     by a space and optionally some text as per RFC-5321 and as outlined in
     Section 4. Examples of RFC-4954 but some email servers ignore this and
     only send the response code instead as per Section 4.2. */
  if(line[3] == ' ' || len == 5) {
    char tmpline[6];

    result = TRUE;
    memset(tmpline, '\0', sizeof(tmpline));
    memcpy(tmpline, line, (len == 5 ? 5 : 3));
    *resp = curlx_sltosi(strtol(tmpline, NULL, 10));

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
static CURLcode smtp_get_message(struct Curl_easy *data, struct bufref *out)
{
  char *message = Curl_dyn_ptr(&data->conn->proto.smtpc.pp.recvbuf);
  size_t len = data->conn->proto.smtpc.pp.nfinal;

  if(len > 4) {
    /* Find the start of the message */
    len -= 4;
    for(message += 4; *message == ' ' || *message == '\t'; message++, len--)
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
 * smtp_state()
 *
 * This is the ONLY way to change SMTP state!
 */
static void smtp_state(struct Curl_easy *data, smtpstate newstate)
{
  struct smtp_conn *smtpc = &data->conn->proto.smtpc;
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
    infof(data, "SMTP %p state change from %s to %s",
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
static CURLcode smtp_perform_ehlo(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->sasl.authmechs = SASL_AUTH_NONE; /* No known auth. mechanism yet */
  smtpc->sasl.authused = SASL_AUTH_NONE;  /* Clear the authentication mechanism
                                             used for esmtp connections */
  smtpc->tls_supported = FALSE;           /* Clear the TLS capability */
  smtpc->auth_supported = FALSE;          /* Clear the AUTH capability */

  /* Send the EHLO command */
  result = Curl_pp_sendf(data, &smtpc->pp, "EHLO %s", smtpc->domain);

  if(!result)
    smtp_state(data, SMTP_EHLO);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_helo()
 *
 * Sends the HELO command to initialise communication with the SMTP server.
 */
static CURLcode smtp_perform_helo(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  smtpc->sasl.authused = SASL_AUTH_NONE; /* No authentication mechanism used
                                            in smtp connections */

  /* Send the HELO command */
  result = Curl_pp_sendf(data, &smtpc->pp, "HELO %s", smtpc->domain);

  if(!result)
    smtp_state(data, SMTP_HELO);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_starttls()
 *
 * Sends the STLS command to start the upgrade to TLS.
 */
static CURLcode smtp_perform_starttls(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  /* Send the STARTTLS command */
  CURLcode result = Curl_pp_sendf(data, &conn->proto.smtpc.pp,
                                  "%s", "STARTTLS");

  if(!result)
    smtp_state(data, SMTP_STARTTLS);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_upgrade_tls()
 *
 * Performs the upgrade to TLS.
 */
static CURLcode smtp_perform_upgrade_tls(struct Curl_easy *data)
{
  /* Start the SSL connection */
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  CURLcode result;
  bool ssldone = FALSE;

  if(!Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
    result = Curl_ssl_cfilter_add(data, conn, FIRSTSOCKET);
    if(result)
      goto out;
  }

  result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &ssldone);
  if(!result) {
    smtpc->ssldone = ssldone;
    if(smtpc->state != SMTP_UPGRADETLS)
      smtp_state(data, SMTP_UPGRADETLS);

    if(smtpc->ssldone) {
      smtp_to_smtps(conn);
      result = smtp_perform_ehlo(data);
    }
  }
out:
  return result;
}

/***********************************************************************
 *
 * smtp_perform_auth()
 *
 * Sends an AUTH command allowing the client to login with the given SASL
 * authentication mechanism.
 */
static CURLcode smtp_perform_auth(struct Curl_easy *data,
                                  const char *mech,
                                  const struct bufref *initresp)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &data->conn->proto.smtpc;
  const char *ir = (const char *) Curl_bufref_ptr(initresp);

  if(ir) {                                  /* AUTH <mech> ...<crlf> */
    /* Send the AUTH command with the initial response */
    result = Curl_pp_sendf(data, &smtpc->pp, "AUTH %s %s", mech, ir);
  }
  else {
    /* Send the AUTH command */
    result = Curl_pp_sendf(data, &smtpc->pp, "AUTH %s", mech);
  }

  return result;
}

/***********************************************************************
 *
 * smtp_continue_auth()
 *
 * Sends SASL continuation data.
 */
static CURLcode smtp_continue_auth(struct Curl_easy *data,
                                   const char *mech,
                                   const struct bufref *resp)
{
  struct smtp_conn *smtpc = &data->conn->proto.smtpc;

  (void)mech;

  return Curl_pp_sendf(data, &smtpc->pp,
                       "%s", (const char *) Curl_bufref_ptr(resp));
}

/***********************************************************************
 *
 * smtp_cancel_auth()
 *
 * Sends SASL cancellation.
 */
static CURLcode smtp_cancel_auth(struct Curl_easy *data, const char *mech)
{
  struct smtp_conn *smtpc = &data->conn->proto.smtpc;

  (void)mech;

  return Curl_pp_sendf(data, &smtpc->pp, "*");
}

/***********************************************************************
 *
 * smtp_perform_authentication()
 *
 * Initiates the authentication sequence, with the appropriate SASL
 * authentication mechanism.
 */
static CURLcode smtp_perform_authentication(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  saslprogress progress;

  /* Check we have enough data to authenticate with, and the
     server supports authentication, and end the connect phase if not */
  if(!smtpc->auth_supported ||
     !Curl_sasl_can_authenticate(&smtpc->sasl, data)) {
    smtp_state(data, SMTP_STOP);
    return result;
  }

  /* Calculate the SASL login details */
  result = Curl_sasl_start(&smtpc->sasl, data, FALSE, &progress);

  if(!result) {
    if(progress == SASL_INPROGRESS)
      smtp_state(data, SMTP_AUTH);
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
 * smtp_perform_command()
 *
 * Sends a SMTP based command.
 */
static CURLcode smtp_perform_command(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;

  if(smtp->rcpt) {
    /* We notify the server we are sending UTF-8 data if a) it supports the
       SMTPUTF8 extension and b) The mailbox contains UTF-8 characters, in
       either the local address or hostname parts. This is regardless of
       whether the hostname is encoded using IDN ACE */
    bool utf8 = FALSE;

    if((!smtp->custom) || (!smtp->custom[0])) {
      char *address = NULL;
      struct hostname host = { NULL, NULL, NULL, NULL };

      /* Parse the mailbox to verify into the local address and hostname
         parts, converting the hostname to an IDN A-label if necessary */
      result = smtp_parse_address(smtp->rcpt->data,
                                  &address, &host);
      if(result)
        return result;

      /* Establish whether we should report SMTPUTF8 to the server for this
         mailbox as per RFC-6531 sect. 3.1 point 6 */
      utf8 = (conn->proto.smtpc.utf8_supported) &&
             ((host.encalloc) || (!Curl_is_ASCII_name(address)) ||
              (!Curl_is_ASCII_name(host.name)));

      /* Send the VRFY command (Note: The hostname part may be absent when the
         host is a local system) */
      result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "VRFY %s%s%s%s",
                             address,
                             host.name ? "@" : "",
                             host.name ? host.name : "",
                             utf8 ? " SMTPUTF8" : "");

      Curl_free_idnconverted_hostname(&host);
      free(address);
    }
    else {
      /* Establish whether we should report that we support SMTPUTF8 for EXPN
         commands to the server as per RFC-6531 sect. 3.1 point 6 */
      utf8 = (conn->proto.smtpc.utf8_supported) &&
             (!strcmp(smtp->custom, "EXPN"));

      /* Send the custom recipient based command such as the EXPN command */
      result = Curl_pp_sendf(data, &conn->proto.smtpc.pp,
                             "%s %s%s", smtp->custom,
                             smtp->rcpt->data,
                             utf8 ? " SMTPUTF8" : "");
    }
  }
  else
    /* Send the non-recipient based command such as HELP */
    result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s",
                           smtp->custom && smtp->custom[0] != '\0' ?
                           smtp->custom : "HELP");

  if(!result)
    smtp_state(data, SMTP_COMMAND);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_mail()
 *
 * Sends an MAIL command to initiate the upload of a message.
 */
static CURLcode smtp_perform_mail(struct Curl_easy *data)
{
  char *from = NULL;
  char *auth = NULL;
  char *size = NULL;
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  /* We notify the server we are sending UTF-8 data if a) it supports the
     SMTPUTF8 extension and b) The mailbox contains UTF-8 characters, in
     either the local address or hostname parts. This is regardless of
     whether the hostname is encoded using IDN ACE */
  bool utf8 = FALSE;

  /* Calculate the FROM parameter */
  if(data->set.str[STRING_MAIL_FROM]) {
    char *address = NULL;
    struct hostname host = { NULL, NULL, NULL, NULL };

    /* Parse the FROM mailbox into the local address and hostname parts,
       converting the hostname to an IDN A-label if necessary */
    result = smtp_parse_address(data->set.str[STRING_MAIL_FROM],
                                &address, &host);
    if(result)
      goto out;

    /* Establish whether we should report SMTPUTF8 to the server for this
       mailbox as per RFC-6531 sect. 3.1 point 4 and sect. 3.4 */
    utf8 = (conn->proto.smtpc.utf8_supported) &&
           ((host.encalloc) || (!Curl_is_ASCII_name(address)) ||
            (!Curl_is_ASCII_name(host.name)));

    if(host.name) {
      from = aprintf("<%s@%s>", address, host.name);

      Curl_free_idnconverted_hostname(&host);
    }
    else
      /* An invalid mailbox was provided but we will simply let the server
         worry about that and reply with a 501 error */
      from = aprintf("<%s>", address);

    free(address);
  }
  else
    /* Null reverse-path, RFC-5321, sect. 3.6.3 */
    from = strdup("<>");

  if(!from) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  /* Calculate the optional AUTH parameter */
  if(data->set.str[STRING_MAIL_AUTH] && conn->proto.smtpc.sasl.authused) {
    if(data->set.str[STRING_MAIL_AUTH][0] != '\0') {
      char *address = NULL;
      struct hostname host = { NULL, NULL, NULL, NULL };

      /* Parse the AUTH mailbox into the local address and hostname parts,
         converting the hostname to an IDN A-label if necessary */
      result = smtp_parse_address(data->set.str[STRING_MAIL_AUTH],
                                  &address, &host);
      if(result)
        goto out;

      /* Establish whether we should report SMTPUTF8 to the server for this
         mailbox as per RFC-6531 sect. 3.1 point 4 and sect. 3.4 */
      if((!utf8) && (conn->proto.smtpc.utf8_supported) &&
         ((host.encalloc) || (!Curl_is_ASCII_name(address)) ||
          (!Curl_is_ASCII_name(host.name))))
        utf8 = TRUE;

      if(host.name) {
        auth = aprintf("<%s@%s>", address, host.name);

        Curl_free_idnconverted_hostname(&host);
      }
      else
        /* An invalid mailbox was provided but we will simply let the server
           worry about it */
        auth = aprintf("<%s>", address);
      free(address);
    }
    else
      /* Empty AUTH, RFC-2554, sect. 5 */
      auth = strdup("<>");

    if(!auth) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

#ifndef CURL_DISABLE_MIME
  /* Prepare the mime data if some. */
  if(data->set.mimepost.kind != MIMEKIND_NONE) {
    /* Use the whole structure as data. */
    data->set.mimepost.flags &= ~(unsigned int)MIME_BODY_ONLY;

    /* Add external headers and mime version. */
    curl_mime_headers(&data->set.mimepost, data->set.headers, 0);
    result = Curl_mime_prepare_headers(data, &data->set.mimepost, NULL,
                                       NULL, MIMESTRATEGY_MAIL);

    if(!result)
      if(!Curl_checkheaders(data, STRCONST("Mime-Version")))
        result = Curl_mime_add_header(&data->set.mimepost.curlheaders,
                                      "Mime-Version: 1.0");

    if(!result)
      result = Curl_creader_set_mime(data, &data->set.mimepost);
    if(result)
      goto out;
    data->state.infilesize = Curl_creader_total_length(data);
  }
  else
#endif
  {
    result = Curl_creader_set_fread(data, data->state.infilesize);
    if(result)
      goto out;
  }

  /* Calculate the optional SIZE parameter */
  if(conn->proto.smtpc.size_supported && data->state.infilesize > 0) {
    size = aprintf("%" CURL_FORMAT_CURL_OFF_T, data->state.infilesize);

    if(!size) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  /* If the mailboxes in the FROM and AUTH parameters do not include a UTF-8
     based address then quickly scan through the recipient list and check if
     any there do, as we need to correctly identify our support for SMTPUTF8
     in the envelope, as per RFC-6531 sect. 3.4 */
  if(conn->proto.smtpc.utf8_supported && !utf8) {
    struct SMTP *smtp = data->req.p.smtp;
    struct curl_slist *rcpt = smtp->rcpt;

    while(rcpt && !utf8) {
      /* Does the hostname contain non-ASCII characters? */
      if(!Curl_is_ASCII_name(rcpt->data))
        utf8 = TRUE;

      rcpt = rcpt->next;
    }
  }

  /* Add the client reader doing STMP EOB escaping */
  result = cr_eob_add(data);
  if(result)
    goto out;

  /* Send the MAIL command */
  result = Curl_pp_sendf(data, &conn->proto.smtpc.pp,
                         "MAIL FROM:%s%s%s%s%s%s",
                         from,                 /* Mandatory                 */
                         auth ? " AUTH=" : "", /* Optional on AUTH support  */
                         auth ? auth : "",     /*                           */
                         size ? " SIZE=" : "", /* Optional on SIZE support  */
                         size ? size : "",     /*                           */
                         utf8 ? " SMTPUTF8"    /* Internationalised mailbox */
                               : "");          /* included in our envelope  */

out:
  free(from);
  free(auth);
  free(size);

  if(!result)
    smtp_state(data, SMTP_MAIL);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_rcpt_to()
 *
 * Sends a RCPT TO command for a given recipient as part of the message upload
 * process.
 */
static CURLcode smtp_perform_rcpt_to(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;
  char *address = NULL;
  struct hostname host = { NULL, NULL, NULL, NULL };

  /* Parse the recipient mailbox into the local address and hostname parts,
     converting the hostname to an IDN A-label if necessary */
  result = smtp_parse_address(smtp->rcpt->data,
                              &address, &host);
  if(result)
    return result;

  /* Send the RCPT TO command */
  if(host.name)
    result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "RCPT TO:<%s@%s>",
                           address, host.name);
  else
    /* An invalid mailbox was provided but we will simply let the server worry
       about that and reply with a 501 error */
    result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "RCPT TO:<%s>",
                           address);

  Curl_free_idnconverted_hostname(&host);
  free(address);

  if(!result)
    smtp_state(data, SMTP_RCPT);

  return result;
}

/***********************************************************************
 *
 * smtp_perform_quit()
 *
 * Performs the quit action prior to sclose() being called.
 */
static CURLcode smtp_perform_quit(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  /* Send the QUIT command */
  CURLcode result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s", "QUIT");

  if(!result)
    smtp_state(data, SMTP_QUIT);

  return result;
}

/* For the initial server greeting */
static CURLcode smtp_state_servergreet_resp(struct Curl_easy *data,
                                            int smtpcode,
                                            smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Got unexpected smtp-server response: %d", smtpcode);
    result = CURLE_WEIRD_SERVER_REPLY;
  }
  else
    result = smtp_perform_ehlo(data);

  return result;
}

/* For STARTTLS responses */
static CURLcode smtp_state_starttls_resp(struct Curl_easy *data,
                                         int smtpcode,
                                         smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  /* Pipelining in response is forbidden. */
  if(data->conn->proto.smtpc.pp.overflow)
    return CURLE_WEIRD_SERVER_REPLY;

  if(smtpcode != 220) {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied, code %d", smtpcode);
      result = CURLE_USE_SSL_FAILED;
    }
    else
      result = smtp_perform_authentication(data);
  }
  else
    result = smtp_perform_upgrade_tls(data);

  return result;
}

/* For EHLO responses */
static CURLcode smtp_state_ehlo_resp(struct Curl_easy *data,
                                     struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *line = Curl_dyn_ptr(&smtpc->pp.recvbuf);
  size_t len = smtpc->pp.nfinal;

  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2 && smtpcode != 1) {
    if(data->set.use_ssl <= CURLUSESSL_TRY
       || Curl_conn_is_ssl(conn, FIRSTSOCKET))
      result = smtp_perform_helo(data, conn);
    else {
      failf(data, "Remote access denied: %d", smtpcode);
      result = CURLE_REMOTE_ACCESS_DENIED;
    }
  }
  else if(len >= 4) {
    line += 4;
    len -= 4;

    /* Does the server support the STARTTLS capability? */
    if(len >= 8 && !memcmp(line, "STARTTLS", 8))
      smtpc->tls_supported = TRUE;

    /* Does the server support the SIZE capability? */
    else if(len >= 4 && !memcmp(line, "SIZE", 4))
      smtpc->size_supported = TRUE;

    /* Does the server support the UTF-8 capability? */
    else if(len >= 8 && !memcmp(line, "SMTPUTF8", 8))
      smtpc->utf8_supported = TRUE;

    /* Does the server support authentication? */
    else if(len >= 5 && !memcmp(line, "AUTH ", 5)) {
      smtpc->auth_supported = TRUE;

      /* Advance past the AUTH keyword */
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
          smtpc->sasl.authmechs |= mechbit;

        line += wordlen;
        len -= wordlen;
      }
    }

    if(smtpcode != 1) {
      if(data->set.use_ssl && !Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
        /* We do not have a SSL/TLS connection yet, but SSL is requested */
        if(smtpc->tls_supported)
          /* Switch to TLS connection now */
          result = smtp_perform_starttls(data, conn);
        else if(data->set.use_ssl == CURLUSESSL_TRY)
          /* Fallback and carry on with authentication */
          result = smtp_perform_authentication(data);
        else {
          failf(data, "STARTTLS not supported.");
          result = CURLE_USE_SSL_FAILED;
        }
      }
      else
        result = smtp_perform_authentication(data);
    }
  }
  else {
    failf(data, "Unexpectedly short EHLO response");
    result = CURLE_WEIRD_SERVER_REPLY;
  }

  return result;
}

/* For HELO responses */
static CURLcode smtp_state_helo_resp(struct Curl_easy *data, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "Remote access denied: %d", smtpcode);
    result = CURLE_REMOTE_ACCESS_DENIED;
  }
  else
    /* End of connect phase */
    smtp_state(data, SMTP_STOP);

  return result;
}

/* For SASL authentication responses */
static CURLcode smtp_state_auth_resp(struct Curl_easy *data,
                                     int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  saslprogress progress;

  (void)instate; /* no use for this yet */

  result = Curl_sasl_continue(&smtpc->sasl, data, smtpcode, &progress);
  if(!result)
    switch(progress) {
    case SASL_DONE:
      smtp_state(data, SMTP_STOP);  /* Authenticated */
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
static CURLcode smtp_state_command_resp(struct Curl_easy *data, int smtpcode,
                                        smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;
  char *line = Curl_dyn_ptr(&data->conn->proto.smtpc.pp.recvbuf);
  size_t len = data->conn->proto.smtpc.pp.nfinal;

  (void)instate; /* no use for this yet */

  if((smtp->rcpt && smtpcode/100 != 2 && smtpcode != 553 && smtpcode != 1) ||
     (!smtp->rcpt && smtpcode/100 != 2 && smtpcode != 1)) {
    failf(data, "Command failed: %d", smtpcode);
    result = CURLE_WEIRD_SERVER_REPLY;
  }
  else {
    if(!data->req.no_body)
      result = Curl_client_write(data, CLIENTWRITE_BODY, line, len);

    if(smtpcode != 1) {
      if(smtp->rcpt) {
        smtp->rcpt = smtp->rcpt->next;

        if(smtp->rcpt) {
          /* Send the next command */
          result = smtp_perform_command(data);
        }
        else
          /* End of DO phase */
          smtp_state(data, SMTP_STOP);
      }
      else
        /* End of DO phase */
        smtp_state(data, SMTP_STOP);
    }
  }

  return result;
}

/* For MAIL responses */
static CURLcode smtp_state_mail_resp(struct Curl_easy *data, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  if(smtpcode/100 != 2) {
    failf(data, "MAIL failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else
    /* Start the RCPT TO command */
    result = smtp_perform_rcpt_to(data);

  return result;
}

/* For RCPT responses */
static CURLcode smtp_state_rcpt_resp(struct Curl_easy *data,
                                     struct connectdata *conn, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;
  bool is_smtp_err = FALSE;
  bool is_smtp_blocking_err = FALSE;

  (void)instate; /* no use for this yet */

  is_smtp_err = (smtpcode/100 != 2) ? TRUE : FALSE;

  /* If there is multiple RCPT TO to be issued, it is possible to ignore errors
     and proceed with only the valid addresses. */
  is_smtp_blocking_err =
    (is_smtp_err && !data->set.mail_rcpt_allowfails) ? TRUE : FALSE;

  if(is_smtp_err) {
    /* Remembering the last failure which we can report if all "RCPT TO" have
       failed and we cannot proceed. */
    smtp->rcpt_last_error = smtpcode;

    if(is_smtp_blocking_err) {
      failf(data, "RCPT failed: %d", smtpcode);
      result = CURLE_SEND_ERROR;
    }
  }
  else {
    /* Some RCPT TO commands have succeeded. */
    smtp->rcpt_had_ok = TRUE;
  }

  if(!is_smtp_blocking_err) {
    smtp->rcpt = smtp->rcpt->next;

    if(smtp->rcpt)
      /* Send the next RCPT TO command */
      result = smtp_perform_rcpt_to(data);
    else {
      /* We were not able to issue a successful RCPT TO command while going
         over recipients (potentially multiple). Sending back last error. */
      if(!smtp->rcpt_had_ok) {
        failf(data, "RCPT failed: %d (last error)", smtp->rcpt_last_error);
        result = CURLE_SEND_ERROR;
      }
      else {
        /* Send the DATA command */
        result = Curl_pp_sendf(data, &conn->proto.smtpc.pp, "%s", "DATA");

        if(!result)
          smtp_state(data, SMTP_DATA);
      }
    }
  }

  return result;
}

/* For DATA response */
static CURLcode smtp_state_data_resp(struct Curl_easy *data, int smtpcode,
                                     smtpstate instate)
{
  CURLcode result = CURLE_OK;
  (void)instate; /* no use for this yet */

  if(smtpcode != 354) {
    failf(data, "DATA failed: %d", smtpcode);
    result = CURLE_SEND_ERROR;
  }
  else {
    /* Set the progress upload size */
    Curl_pgrsSetUploadSize(data, data->state.infilesize);

    /* SMTP upload */
    Curl_xfer_setup1(data, CURL_XFER_SEND, -1, FALSE);

    /* End of DO phase */
    smtp_state(data, SMTP_STOP);
  }

  return result;
}

/* For POSTDATA responses, which are received after the entire DATA
   part has been sent to the server */
static CURLcode smtp_state_postdata_resp(struct Curl_easy *data,
                                         int smtpcode,
                                         smtpstate instate)
{
  CURLcode result = CURLE_OK;

  (void)instate; /* no use for this yet */

  if(smtpcode != 250)
    result = CURLE_WEIRD_SERVER_REPLY;

  /* End of DONE phase */
  smtp_state(data, SMTP_STOP);

  return result;
}

static CURLcode smtp_statemachine(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  int smtpcode;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;
  size_t nread = 0;

  /* Busy upgrading the connection; right now all I/O is SSL/TLS, not SMTP */
upgrade_tls:
  if(smtpc->state == SMTP_UPGRADETLS)
    return smtp_perform_upgrade_tls(data);

  /* Flush any data that needs to be sent */
  if(pp->sendleft)
    return Curl_pp_flushsend(data, pp);

  do {
    /* Read the response from the server */
    result = Curl_pp_readresp(data, FIRSTSOCKET, pp, &smtpcode, &nread);
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
      result = smtp_state_servergreet_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_EHLO:
      result = smtp_state_ehlo_resp(data, conn, smtpcode, smtpc->state);
      break;

    case SMTP_HELO:
      result = smtp_state_helo_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_STARTTLS:
      result = smtp_state_starttls_resp(data, smtpcode, smtpc->state);
      /* During UPGRADETLS, leave the read loop as we need to connect
       * (e.g. TLS handshake) before we continue sending/receiving. */
      if(!result && (smtpc->state == SMTP_UPGRADETLS))
        goto upgrade_tls;
      break;

    case SMTP_AUTH:
      result = smtp_state_auth_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_COMMAND:
      result = smtp_state_command_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_MAIL:
      result = smtp_state_mail_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_RCPT:
      result = smtp_state_rcpt_resp(data, conn, smtpcode, smtpc->state);
      break;

    case SMTP_DATA:
      result = smtp_state_data_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_POSTDATA:
      result = smtp_state_postdata_resp(data, smtpcode, smtpc->state);
      break;

    case SMTP_QUIT:
    default:
      /* internal error */
      smtp_state(data, SMTP_STOP);
      break;
    }
  } while(!result && smtpc->state != SMTP_STOP && Curl_pp_moredata(pp));

  return result;
}

/* Called repeatedly until done from multi.c */
static CURLcode smtp_multi_statemach(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  if((conn->handler->flags & PROTOPT_SSL) && !smtpc->ssldone) {
    bool ssldone = FALSE;
    result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &ssldone);
    smtpc->ssldone = ssldone;
    if(result || !smtpc->ssldone)
      return result;
  }

  result = Curl_pp_statemach(data, &smtpc->pp, FALSE, FALSE);
  *done = (smtpc->state == SMTP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode smtp_block_statemach(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     bool disconnecting)
{
  CURLcode result = CURLE_OK;
  struct smtp_conn *smtpc = &conn->proto.smtpc;

  while(smtpc->state != SMTP_STOP && !result)
    result = Curl_pp_statemach(data, &smtpc->pp, TRUE, disconnecting);

  return result;
}

/* Allocate and initialize the SMTP struct for the current Curl_easy if
   required */
static CURLcode smtp_init(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp;

  smtp = data->req.p.smtp = calloc(1, sizeof(struct SMTP));
  if(!smtp)
    result = CURLE_OUT_OF_MEMORY;

  return result;
}

/* For the SMTP "protocol connect" and "doing" phases only */
static int smtp_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks)
{
  return Curl_pp_getsock(data, &conn->proto.smtpc.pp, socks);
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
static CURLcode smtp_connect(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct pingpong *pp = &smtpc->pp;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections in SMTP */
  connkeep(conn, "SMTP default");

  PINGPONG_SETUP(pp, smtp_statemachine, smtp_endofresp);

  /* Initialize the SASL storage */
  Curl_sasl_init(&smtpc->sasl, data, &saslsmtp);

  /* Initialise the pingpong layer */
  Curl_pp_init(pp);

  /* Parse the URL options */
  result = smtp_parse_url_options(conn);
  if(result)
    return result;

  /* Parse the URL path */
  result = smtp_parse_url_path(data);
  if(result)
    return result;

  /* Start off waiting for the server greeting response */
  smtp_state(data, SMTP_SERVERGREET);

  result = smtp_multi_statemach(data, done);

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
static CURLcode smtp_done(struct Curl_easy *data, CURLcode status,
                          bool premature)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct SMTP *smtp = data->req.p.smtp;

  (void)premature;

  if(!smtp)
    return CURLE_OK;

  /* Cleanup our per-request based variables */
  Curl_safefree(smtp->custom);

  if(status) {
    connclose(conn, "SMTP done with bad status"); /* marked for closure */
    result = status;         /* use the already set error code */
  }
  else if(!data->set.connect_only && data->set.mail_rcpt &&
          (data->state.upload || IS_MIME_POST(data))) {

    smtp_state(data, SMTP_POSTDATA);

    /* Run the state-machine */
    result = smtp_block_statemach(data, conn, FALSE);
  }

  /* Clear the transfer mode for the next request */
  smtp->transfer = PPTRANSFER_BODY;

  return result;
}

/***********************************************************************
 *
 * smtp_perform()
 *
 * This is the actual DO function for SMTP. Transfer a mail, send a command
 * or get some data according to the options previously setup.
 */
static CURLcode smtp_perform(struct Curl_easy *data, bool *connected,
                             bool *dophase_done)
{
  /* This is SMTP and no proxy */
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;

  DEBUGF(infof(data, "DO phase starts"));

  if(data->req.no_body) {
    /* Requested no body means no transfer */
    smtp->transfer = PPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  /* Store the first recipient (or NULL if not specified) */
  smtp->rcpt = data->set.mail_rcpt;

  /* Track of whether we have successfully sent at least one RCPT TO command */
  smtp->rcpt_had_ok = FALSE;

  /* Track of the last error we have received by sending RCPT TO command */
  smtp->rcpt_last_error = 0;

  /* Initial data character is the first character in line: it is implicitly
     preceded by a virtual CRLF. */
  smtp->trailing_crlf = TRUE;
  smtp->eob = 2;

  /* Start the first command in the DO phase */
  if((data->state.upload || IS_MIME_POST(data)) && data->set.mail_rcpt)
    /* MAIL transfer */
    result = smtp_perform_mail(data);
  else
    /* SMTP based command (VRFY, EXPN, NOOP, RSET or HELP) */
    result = smtp_perform_command(data);

  if(result)
    return result;

  /* Run the state-machine */
  result = smtp_multi_statemach(data, dophase_done);

  *connected = Curl_conn_is_connected(data->conn, FIRSTSOCKET);

  if(*dophase_done)
    DEBUGF(infof(data, "DO phase is complete"));

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
static CURLcode smtp_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  *done = FALSE; /* default to false */

  /* Parse the custom request */
  result = smtp_parse_custom_request(data);
  if(result)
    return result;

  result = smtp_regular_transfer(data, done);

  return result;
}

/***********************************************************************
 *
 * smtp_disconnect()
 *
 * Disconnect from an SMTP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode smtp_disconnect(struct Curl_easy *data,
                                struct connectdata *conn,
                                bool dead_connection)
{
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  (void)data;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to. */

  if(!dead_connection && conn->bits.protoconnstart) {
    if(!smtp_perform_quit(data, conn))
      (void)smtp_block_statemach(data, conn, TRUE); /* ignore errors on QUIT */
  }

  /* Disconnect from the server */
  Curl_pp_disconnect(&smtpc->pp);

  /* Cleanup the SASL module */
  Curl_sasl_cleanup(conn, smtpc->sasl.authused);

  /* Cleanup our connection based variables */
  Curl_safefree(smtpc->domain);

  return CURLE_OK;
}

/* Call this when the DO phase has completed */
static CURLcode smtp_dophase_done(struct Curl_easy *data, bool connected)
{
  struct SMTP *smtp = data->req.p.smtp;

  (void)connected;

  if(smtp->transfer != PPTRANSFER_BODY)
    /* no data to transfer */
    Curl_xfer_setup_nop(data);

  return CURLE_OK;
}

/* Called from multi.c while DOing */
static CURLcode smtp_doing(struct Curl_easy *data, bool *dophase_done)
{
  CURLcode result = smtp_multi_statemach(data, dophase_done);

  if(result)
    DEBUGF(infof(data, "DO phase failed"));
  else if(*dophase_done) {
    result = smtp_dophase_done(data, FALSE /* not connected */);

    DEBUGF(infof(data, "DO phase is complete"));
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
static CURLcode smtp_regular_transfer(struct Curl_easy *data,
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
  result = smtp_perform(data, &connected, dophase_done);

  /* Perform post DO phase operations if necessary */
  if(!result && *dophase_done)
    result = smtp_dophase_done(data, connected);

  return result;
}

static CURLcode smtp_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  CURLcode result;

  /* Clear the TLS upgraded flag */
  conn->bits.tls_upgraded = FALSE;

  /* Initialise the SMTP layer */
  result = smtp_init(data);
  if(result)
    return result;

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
static CURLcode smtp_parse_url_path(struct Curl_easy *data)
{
  /* The SMTP struct is already initialised in smtp_connect() */
  struct connectdata *conn = data->conn;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  const char *path = &data->state.up.path[1]; /* skip leading path */
  char localhost[HOSTNAME_MAX + 1];

  /* Calculate the path if necessary */
  if(!*path) {
    if(!Curl_gethostname(localhost, sizeof(localhost)))
      path = localhost;
    else
      path = "localhost";
  }

  /* URL decode the path and use it as the domain in our EHLO */
  return Curl_urldecode(path, 0, &smtpc->domain, NULL, REJECT_CTRL);
}

/***********************************************************************
 *
 * smtp_parse_custom_request()
 *
 * Parse the custom request.
 */
static CURLcode smtp_parse_custom_request(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct SMTP *smtp = data->req.p.smtp;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  /* URL decode the custom request */
  if(custom)
    result = Curl_urldecode(custom, 0, &smtp->custom, NULL, REJECT_CTRL);

  return result;
}

/***********************************************************************
 *
 * smtp_parse_address()
 *
 * Parse the fully qualified mailbox address into a local address part and the
 * hostname, converting the hostname to an IDN A-label, as per RFC-5890, if
 * necessary.
 *
 * Parameters:
 *
 * conn  [in]              - The connection handle.
 * fqma  [in]              - The fully qualified mailbox address (which may or
 *                           may not contain UTF-8 characters).
 * address        [in/out] - A new allocated buffer which holds the local
 *                           address part of the mailbox. This buffer must be
 *                           free'ed by the caller.
 * host           [in/out] - The hostname structure that holds the original,
 *                           and optionally encoded, hostname.
 *                           Curl_free_idnconverted_hostname() must be called
 *                           once the caller has finished with the structure.
 *
 * Returns CURLE_OK on success.
 *
 * Notes:
 *
 * Should a UTF-8 hostname require conversion to IDN ACE and we cannot honor
 * that conversion then we shall return success. This allow the caller to send
 * the data to the server as a U-label (as per RFC-6531 sect. 3.2).
 *
 * If an mailbox '@' separator cannot be located then the mailbox is considered
 * to be either a local mailbox or an invalid mailbox (depending on what the
 * calling function deems it to be) then the input will simply be returned in
 * the address part with the hostname being NULL.
 */
static CURLcode smtp_parse_address(const char *fqma, char **address,
                                   struct hostname *host)
{
  CURLcode result = CURLE_OK;
  size_t length;

  /* Duplicate the fully qualified email address so we can manipulate it,
     ensuring it does not contain the delimiters if specified */
  char *dup = strdup(fqma[0] == '<' ? fqma + 1  : fqma);
  if(!dup)
    return CURLE_OUT_OF_MEMORY;

  length = strlen(dup);
  if(length) {
    if(dup[length - 1] == '>')
      dup[length - 1] = '\0';
  }

  /* Extract the hostname from the address (if we can) */
  host->name = strpbrk(dup, "@");
  if(host->name) {
    *host->name = '\0';
    host->name = host->name + 1;

    /* Attempt to convert the hostname to IDN ACE */
    (void) Curl_idnconvert_hostname(host);

    /* If Curl_idnconvert_hostname() fails then we shall attempt to continue
       and send the hostname using UTF-8 rather than as 7-bit ACE (which is
       our preference) */
  }

  /* Extract the local address from the mailbox */
  *address = dup;

  return result;
}

struct cr_eob_ctx {
  struct Curl_creader super;
  struct bufq buf;
  size_t n_eob; /* how many EOB bytes we matched so far */
  size_t eob;       /* Number of bytes of the EOB (End Of Body) that
                       have been received so far */
  BIT(read_eos);  /* we read an EOS from the next reader */
  BIT(eos);       /* we have returned an EOS */
};

static CURLcode cr_eob_init(struct Curl_easy *data,
                            struct Curl_creader *reader)
{
  struct cr_eob_ctx *ctx = reader->ctx;
  (void)data;
  /* The first char we read is the first on a line, as if we had
   * read CRLF just before */
  ctx->n_eob = 2;
  Curl_bufq_init2(&ctx->buf, (16 * 1024), 1, BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

static void cr_eob_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_eob_ctx *ctx = reader->ctx;
  (void)data;
  Curl_bufq_free(&ctx->buf);
}

/* this is the 5-bytes End-Of-Body marker for SMTP */
#define SMTP_EOB "\r\n.\r\n"
#define SMTP_EOB_FIND_LEN 3

/* client reader doing SMTP End-Of-Body escaping. */
static CURLcode cr_eob_read(struct Curl_easy *data,
                            struct Curl_creader *reader,
                            char *buf, size_t blen,
                            size_t *pnread, bool *peos)
{
  struct cr_eob_ctx *ctx = reader->ctx;
  CURLcode result = CURLE_OK;
  size_t nread, i, start, n;
  bool eos;

  if(!ctx->read_eos && Curl_bufq_is_empty(&ctx->buf)) {
    /* Get more and convert it when needed */
    result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
    if(result)
      return result;

    ctx->read_eos = eos;
    if(nread) {
      if(!ctx->n_eob && !memchr(buf, SMTP_EOB[0], nread)) {
        /* not in the middle of a match, no EOB start found, just pass */
        *pnread = nread;
        *peos = FALSE;
        return CURLE_OK;
      }
      /* scan for EOB (continuation) and convert */
      for(i = start = 0; i < nread; ++i) {
        if(ctx->n_eob >= SMTP_EOB_FIND_LEN) {
          /* matched the EOB prefix and seeing additional char, add '.' */
          result = Curl_bufq_cwrite(&ctx->buf, buf + start, i - start, &n);
          if(result)
            return result;
          result = Curl_bufq_cwrite(&ctx->buf, ".", 1, &n);
          if(result)
            return result;
          ctx->n_eob = 0;
          start = i;
          if(data->state.infilesize > 0)
            data->state.infilesize++;
        }

        if(buf[i] != SMTP_EOB[ctx->n_eob])
          ctx->n_eob = 0;

        if(buf[i] == SMTP_EOB[ctx->n_eob]) {
          /* matching another char of the EOB */
          ++ctx->n_eob;
        }
      }

      /* add any remainder to buf */
      if(start < nread) {
        result = Curl_bufq_cwrite(&ctx->buf, buf + start, nread - start, &n);
        if(result)
          return result;
      }
    }

    if(ctx->read_eos) {
      /* if we last matched a CRLF or if the data was empty, add ".\r\n"
       * to end the body. If we sent something and it did not end with "\r\n",
       * add "\r\n.\r\n" to end the body */
      const char *eob = SMTP_EOB;
      switch(ctx->n_eob) {
        case 2:
          /* seen a CRLF at the end, just add the remainder */
          eob = &SMTP_EOB[2];
          break;
        case 3:
          /* ended with '\r\n.', we should escpe the last '.' */
          eob = "." SMTP_EOB;
          break;
        default:
          break;
      }
      result = Curl_bufq_cwrite(&ctx->buf, eob, strlen(eob), &n);
      if(result)
        return result;
    }
  }

  *peos = FALSE;
  if(!Curl_bufq_is_empty(&ctx->buf)) {
    result = Curl_bufq_cread(&ctx->buf, buf, blen, pnread);
  }
  else
    *pnread = 0;

  if(ctx->read_eos && Curl_bufq_is_empty(&ctx->buf)) {
    /* no more data, read all, done. */
    ctx->eos = TRUE;
  }
  *peos = ctx->eos;
  DEBUGF(infof(data, "cr_eob_read(%zu) -> %d, %zd, %d",
         blen, result, *pnread, *peos));
  return result;
}

static curl_off_t cr_eob_total_length(struct Curl_easy *data,
                                      struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return -1;
}

static const struct Curl_crtype cr_eob = {
  "cr-smtp-eob",
  cr_eob_init,
  cr_eob_read,
  cr_eob_close,
  Curl_creader_def_needs_rewind,
  cr_eob_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_rewind,
  Curl_creader_def_unpause,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_eob_ctx)
};

static CURLcode cr_eob_add(struct Curl_easy *data)
{
  struct Curl_creader *reader = NULL;
  CURLcode result;

  result = Curl_creader_create(&reader, data, &cr_eob,
                               CURL_CR_CONTENT_ENCODE);
  if(!result)
    result = Curl_creader_add(data, reader);

  if(result && reader)
    Curl_creader_free(data, reader);
  return result;
}

#endif /* CURL_DISABLE_SMTP */
