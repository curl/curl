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
 * RFC2195 CRAM-MD5 authentication
 * RFC2595 Using TLS with IMAP, POP3 and ACAP
 * RFC2831 DIGEST-MD5 authentication
 * RFC3501 IMAPv4 protocol
 * RFC4422 Simple Authentication and Security Layer (SASL)
 * RFC4616 PLAIN authentication
 * RFC4959 IMAP Extension for SASL Initial Client Response
 * RFC5092 IMAP URL Scheme
 * RFC6749 OAuth 2.0 Authorization Framework
 * Draft   LOGIN SASL Mechanism <draft-murchison-sasl-login-00.txt>
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_IMAP

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
#include "imap.h"

#include "strtoofft.h"
#include "strequal.h"
#include "vtls/vtls.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "rawstr.h"
#include "curl_sasl.h"
#include "warnless.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Local API functions */
static CURLcode imap_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode imap_do(struct connectdata *conn, bool *done);
static CURLcode imap_done(struct connectdata *conn, CURLcode status,
                          bool premature);
static CURLcode imap_connect(struct connectdata *conn, bool *done);
static CURLcode imap_disconnect(struct connectdata *conn, bool dead);
static CURLcode imap_multi_statemach(struct connectdata *conn, bool *done);
static int imap_getsock(struct connectdata *conn, curl_socket_t *socks,
                        int numsocks);
static CURLcode imap_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode imap_setup_connection(struct connectdata *conn);
static char *imap_atom(const char *str);
static CURLcode imap_sendf(struct connectdata *conn, const char *fmt, ...);
static CURLcode imap_parse_url_options(struct connectdata *conn);
static CURLcode imap_parse_url_path(struct connectdata *conn);
static CURLcode imap_parse_custom_request(struct connectdata *conn);
static CURLcode imap_calc_sasl_details(struct connectdata *conn,
                                       const char **mech,
                                       char **initresp, size_t *len,
                                       imapstate *state1, imapstate *state2);

/*
 * IMAP protocol handler.
 */

const struct Curl_handler Curl_handler_imap = {
  "IMAP",                           /* scheme */
  imap_setup_connection,            /* setup_connection */
  imap_do,                          /* do_it */
  imap_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  imap_connect,                     /* connect_it */
  imap_multi_statemach,             /* connecting */
  imap_doing,                       /* doing */
  imap_getsock,                     /* proto_getsock */
  imap_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  imap_disconnect,                  /* disconnect */
  ZERO_NULL,                        /* readwrite */
  PORT_IMAP,                        /* defport */
  CURLPROTO_IMAP,                   /* protocol */
  PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD
  | PROTOPT_NOURLQUERY              /* flags */
};

#ifdef USE_SSL
/*
 * IMAPS protocol handler.
 */

const struct Curl_handler Curl_handler_imaps = {
  "IMAPS",                          /* scheme */
  imap_setup_connection,            /* setup_connection */
  imap_do,                          /* do_it */
  imap_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  imap_connect,                     /* connect_it */
  imap_multi_statemach,             /* connecting */
  imap_doing,                       /* doing */
  imap_getsock,                     /* proto_getsock */
  imap_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  imap_disconnect,                  /* disconnect */
  ZERO_NULL,                        /* readwrite */
  PORT_IMAPS,                       /* defport */
  CURLPROTO_IMAP | CURLPROTO_IMAPS, /* protocol */
  PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_NEEDSPWD
  | PROTOPT_NOURLQUERY              /* flags */
};
#endif

#ifndef CURL_DISABLE_HTTP
/*
 * HTTP-proxyed IMAP protocol handler.
 */

static const struct Curl_handler Curl_handler_imap_proxy = {
  "IMAP",                               /* scheme */
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
  PORT_IMAP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};

#ifdef USE_SSL
/*
 * HTTP-proxyed IMAPS protocol handler.
 */

static const struct Curl_handler Curl_handler_imaps_proxy = {
  "IMAPS",                              /* scheme */
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
  PORT_IMAPS,                           /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};
#endif
#endif

#ifdef USE_SSL
static void imap_to_imaps(struct connectdata *conn)
{
  conn->handler = &Curl_handler_imaps;
}
#else
#define imap_to_imaps(x) Curl_nop_stmt
#endif

/***********************************************************************
 *
 * imap_matchresp()
 *
 * Determines whether the untagged response is related to the specified
 * command by checking if it is in format "* <command-name> ..." or
 * "* <number> <command-name> ...".
 *
 * The "* " marker is assumed to have already been checked by the caller.
 */
static bool imap_matchresp(const char *line, size_t len, const char *cmd)
{
  const char *end = line + len;
  size_t cmd_len = strlen(cmd);

  /* Skip the untagged response marker */
  line += 2;

  /* Do we have a number after the marker? */
  if(line < end && ISDIGIT(*line)) {
    /* Skip the number */
    do
      line++;
    while(line < end && ISDIGIT(*line));

    /* Do we have the space character? */
    if(line == end || *line != ' ')
      return FALSE;

    line++;
  }

  /* Does the command name match and is it followed by a space character or at
     the end of line? */
  if(line + cmd_len <= end && Curl_raw_nequal(line, cmd, cmd_len) &&
     (line[cmd_len] == ' ' || line + cmd_len == end))
    return TRUE;

  return FALSE;
}

/***********************************************************************
 *
 * imap_endofresp()
 *
 * Checks whether the given string is a valid tagged, untagged or continuation
 * response which can be processed by the response handler.
 */
static bool imap_endofresp(struct connectdata *conn, char *line, size_t len,
                           int *resp)
{
  struct IMAP *imap = conn->data->req.protop;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *id = imapc->resptag;
  size_t id_len = strlen(id);

  /* Do we have a tagged command response? */
  if(len >= id_len + 1 && !memcmp(id, line, id_len) && line[id_len] == ' ') {
    line += id_len + 1;
    len -= id_len + 1;

    if(len >= 2 && !memcmp(line, "OK", 2))
      *resp = 'O';
    else if(len >= 2 && !memcmp(line, "NO", 2))
      *resp = 'N';
    else if(len >= 3 && !memcmp(line, "BAD", 3))
      *resp = 'B';
    else {
      failf(conn->data, "Bad tagged response");
      *resp = -1;
    }

    return TRUE;
  }

  /* Do we have an untagged command response? */
  if(len >= 2 && !memcmp("* ", line, 2)) {
    switch(imapc->state) {
      /* States which are interested in untagged responses */
      case IMAP_CAPABILITY:
        if(!imap_matchresp(line, len, "CAPABILITY"))
          return FALSE;
        break;

      case IMAP_LIST:
        if((!imap->custom && !imap_matchresp(line, len, "LIST")) ||
          (imap->custom && !imap_matchresp(line, len, imap->custom) &&
           (strcmp(imap->custom, "STORE") ||
            !imap_matchresp(line, len, "FETCH")) &&
           strcmp(imap->custom, "SELECT") &&
           strcmp(imap->custom, "EXAMINE") &&
           strcmp(imap->custom, "SEARCH") &&
           strcmp(imap->custom, "EXPUNGE") &&
           strcmp(imap->custom, "LSUB") &&
           strcmp(imap->custom, "UID") &&
           strcmp(imap->custom, "NOOP")))
          return FALSE;
        break;

      case IMAP_SELECT:
        /* SELECT is special in that its untagged responses do not have a
           common prefix so accept anything! */
        break;

      case IMAP_FETCH:
        if(!imap_matchresp(line, len, "FETCH"))
          return FALSE;
        break;

      /* Ignore other untagged responses */
      default:
        return FALSE;
    }

    *resp = '*';
    return TRUE;
  }

  /* Do we have a continuation response? This should be a + symbol followed by
     a space and optionally some text as per RFC-3501 for the AUTHENTICATE and
     APPEND commands and as outlined in Section 4. Examples of RFC-4959 but
     some e-mail servers ignore this and only send a single + instead. */
  if((len == 3 && !memcmp("+", line, 1)) ||
     (len >= 2 && !memcmp("+ ", line, 2))) {
    switch(imapc->state) {
      /* States which are interested in continuation responses */
      case IMAP_AUTHENTICATE_PLAIN:
      case IMAP_AUTHENTICATE_LOGIN:
      case IMAP_AUTHENTICATE_LOGIN_PASSWD:
      case IMAP_AUTHENTICATE_CRAMMD5:
      case IMAP_AUTHENTICATE_DIGESTMD5:
      case IMAP_AUTHENTICATE_DIGESTMD5_RESP:
      case IMAP_AUTHENTICATE_NTLM:
      case IMAP_AUTHENTICATE_NTLM_TYPE2MSG:
      case IMAP_AUTHENTICATE_XOAUTH2:
      case IMAP_AUTHENTICATE_FINAL:
      case IMAP_APPEND:
        *resp = '+';
        break;

      default:
        failf(conn->data, "Unexpected continuation response");
        *resp = -1;
        break;
    }

    return TRUE;
  }

  return FALSE; /* Nothing for us */
}

/***********************************************************************
 *
 * imap_get_message()
 *
 * Gets the authentication message from the response buffer.
 */
static void imap_get_message(char *buffer, char** outptr)
{
  size_t len = 0;
  char* message = NULL;

  /* Find the start of the message */
  for(message = buffer + 2; *message == ' ' || *message == '\t'; message++)
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
 * This is the ONLY way to change IMAP state!
 */
static void state(struct connectdata *conn, imapstate newstate)
{
  struct imap_conn *imapc = &conn->proto.imapc;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[]={
    "STOP",
    "SERVERGREET",
    "CAPABILITY",
    "STARTTLS",
    "UPGRADETLS",
    "AUTHENTICATE_PLAIN",
    "AUTHENTICATE_LOGIN",
    "AUTHENTICATE_LOGIN_PASSWD",
    "AUTHENTICATE_CRAMMD5",
    "AUTHENTICATE_DIGESTMD5",
    "AUTHENTICATE_DIGESTMD5_RESP",
    "AUTHENTICATE_NTLM",
    "AUTHENTICATE_NTLM_TYPE2MSG",
    "AUTHENTICATE_XOAUTH2",
    "AUTHENTICATE_CANCEL",
    "AUTHENTICATE_FINAL",
    "LOGIN",
    "LIST",
    "SELECT",
    "FETCH",
    "FETCH_FINAL",
    "APPEND",
    "APPEND_FINAL",
    "LOGOUT",
    /* LAST */
  };

  if(imapc->state != newstate)
    infof(conn->data, "IMAP %p state change from %s to %s\n",
          (void *)imapc, names[imapc->state], names[newstate]);
#endif

  imapc->state = newstate;
}

/***********************************************************************
 *
 * imap_perform_capability()
 *
 * Sends the CAPABILITY command in order to obtain a list of server side
 * supported capabilities.
 */
static CURLcode imap_perform_capability(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;

  imapc->authmechs = 0;         /* No known authentication mechanisms yet */
  imapc->authused = 0;          /* Clear the authentication mechanism used */
  imapc->tls_supported = FALSE; /* Clear the TLS capability */

  /* Send the CAPABILITY command */
  result = imap_sendf(conn, "CAPABILITY");

  if(!result)
    state(conn, IMAP_CAPABILITY);

  return result;
}

/***********************************************************************
 *
 * imap_perform_starttls()
 *
 * Sends the STARTTLS command to start the upgrade to TLS.
 */
static CURLcode imap_perform_starttls(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* Send the STARTTLS command */
  result = imap_sendf(conn, "STARTTLS");

  if(!result)
    state(conn, IMAP_STARTTLS);

  return result;
}

/***********************************************************************
 *
 * imap_perform_upgrade_tls()
 *
 * Performs the upgrade to TLS.
 */
static CURLcode imap_perform_upgrade_tls(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;

  /* Start the SSL connection */
  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &imapc->ssldone);

  if(!result) {
    if(imapc->state != IMAP_UPGRADETLS)
      state(conn, IMAP_UPGRADETLS);

    if(imapc->ssldone) {
      imap_to_imaps(conn);
      result = imap_perform_capability(conn);
    }
  }

  return result;
}

/***********************************************************************
 *
 * imap_perform_login()
 *
 * Sends a clear text LOGIN command to authenticate with.
 */
static CURLcode imap_perform_login(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  char *user;
  char *passwd;

  /* Check we have a username and password to authenticate with and end the
     connect phase if we don't */
  if(!conn->bits.user_passwd) {
    state(conn, IMAP_STOP);

    return result;
  }

  /* Make sure the username and password are in the correct atom format */
  user = imap_atom(conn->user);
  passwd = imap_atom(conn->passwd);

  /* Send the LOGIN command */
  result = imap_sendf(conn, "LOGIN %s %s", user ? user : "",
                      passwd ? passwd : "");

  Curl_safefree(user);
  Curl_safefree(passwd);

  if(!result)
    state(conn, IMAP_LOGIN);

  return result;
}

/***********************************************************************
 *
 * imap_perform_authenticate()
 *
 * Sends an AUTHENTICATE command allowing the client to login with the given
 * SASL authentication mechanism.
 */
static CURLcode imap_perform_authenticate(struct connectdata *conn,
                                          const char *mech,
                                          const char *initresp,
                                          imapstate state1, imapstate state2)
{
  CURLcode result = CURLE_OK;

  if(initresp) {
    /* Send the AUTHENTICATE command with the initial response */
    result = imap_sendf(conn, "AUTHENTICATE %s %s", mech, initresp);

    if(!result)
      state(conn, state2);
  }
  else {
    /* Send the AUTHENTICATE command */
    result = imap_sendf(conn, "AUTHENTICATE %s", mech);

    if(!result)
      state(conn, state1);
  }

  return result;
}

/***********************************************************************
 *
 * imap_perform_authentication()
 *
 * Initiates the authentication sequence, with the appropriate SASL
 * authentication mechanism, falling back to clear text should a common
 * mechanism not be available between the client and server.
 */
static CURLcode imap_perform_authentication(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *mech = NULL;
  char *initresp = NULL;
  size_t len = 0;
  imapstate state1 = IMAP_STOP;
  imapstate state2 = IMAP_STOP;

  /* Check we have a username and password to authenticate with and end the
     connect phase if we don't */
  if(!conn->bits.user_passwd) {
    state(conn, IMAP_STOP);

    return result;
  }

  /* Calculate the SASL login details */
  result = imap_calc_sasl_details(conn, &mech, &initresp, &len, &state1,
                                  &state2);

  if(!result) {
    if(mech && (imapc->preftype & IMAP_TYPE_SASL)) {
      /* Perform SASL based authentication */
      result = imap_perform_authenticate(conn, mech, initresp, state1, state2);

      Curl_safefree(initresp);
    }
    else if((!imapc->login_disabled) &&
            (imapc->preftype & IMAP_TYPE_CLEARTEXT))
      /* Perform clear text authentication */
      result = imap_perform_login(conn);
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
 * imap_perform_list()
 *
 * Sends a LIST command or an alternative custom request.
 */
static CURLcode imap_perform_list(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = data->req.protop;
  char *mailbox;

  if(imap->custom)
    /* Send the custom request */
    result = imap_sendf(conn, "%s%s", imap->custom,
                        imap->custom_params ? imap->custom_params : "");
  else {
    /* Make sure the mailbox is in the correct atom format */
    mailbox = imap_atom(imap->mailbox ? imap->mailbox : "");
    if(!mailbox)
      return CURLE_OUT_OF_MEMORY;

    /* Send the LIST command */
    result = imap_sendf(conn, "LIST \"%s\" *", mailbox);

    Curl_safefree(mailbox);
  }

  if(!result)
    state(conn, IMAP_LIST);

  return result;
}

/***********************************************************************
 *
 * imap_perform_select()
 *
 * Sends a SELECT command to ask the server to change the selected mailbox.
 */
static CURLcode imap_perform_select(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = data->req.protop;
  struct imap_conn *imapc = &conn->proto.imapc;
  char *mailbox;

  /* Invalidate old information as we are switching mailboxes */
  Curl_safefree(imapc->mailbox);
  Curl_safefree(imapc->mailbox_uidvalidity);

  /* Check we have a mailbox */
  if(!imap->mailbox) {
    failf(conn->data, "Cannot SELECT without a mailbox.");
    return CURLE_URL_MALFORMAT;
  }

  /* Make sure the mailbox is in the correct atom format */
  mailbox = imap_atom(imap->mailbox);
  if(!mailbox)
    return CURLE_OUT_OF_MEMORY;

  /* Send the SELECT command */
  result = imap_sendf(conn, "SELECT %s", mailbox);

  Curl_safefree(mailbox);

  if(!result)
    state(conn, IMAP_SELECT);

  return result;
}

/***********************************************************************
 *
 * imap_perform_fetch()
 *
 * Sends a FETCH command to initiate the download of a message.
 */
static CURLcode imap_perform_fetch(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct IMAP *imap = conn->data->req.protop;

  /* Check we have a UID */
  if(!imap->uid) {
    failf(conn->data, "Cannot FETCH without a UID.");
    return CURLE_URL_MALFORMAT;
  }

  /* Send the FETCH command */
  result = imap_sendf(conn, "FETCH %s BODY[%s]",
                      imap->uid,
                      imap->section ? imap->section : "");

  if(!result)
    state(conn, IMAP_FETCH);

  return result;
}

/***********************************************************************
 *
 * imap_perform_append()
 *
 * Sends an APPEND command to initiate the upload of a message.
 */
static CURLcode imap_perform_append(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct IMAP *imap = conn->data->req.protop;
  char *mailbox;

  /* Check we have a mailbox */
  if(!imap->mailbox) {
    failf(conn->data, "Cannot APPEND without a mailbox.");
    return CURLE_URL_MALFORMAT;
  }

  /* Check we know the size of the upload */
  if(conn->data->set.infilesize < 0) {
    failf(conn->data, "Cannot APPEND with unknown input file size\n");
    return CURLE_UPLOAD_FAILED;
  }

  /* Make sure the mailbox is in the correct atom format */
  mailbox = imap_atom(imap->mailbox);
  if(!mailbox)
    return CURLE_OUT_OF_MEMORY;

  /* Send the APPEND command */
  result = imap_sendf(conn, "APPEND %s (\\Seen) {%" CURL_FORMAT_CURL_OFF_T "}",
                      mailbox, conn->data->set.infilesize);

  Curl_safefree(mailbox);

  if(!result)
    state(conn, IMAP_APPEND);

  return result;
}

/***********************************************************************
 *
 * imap_perform_logout()
 *
 * Performs the logout action prior to sclose() being called.
 */
static CURLcode imap_perform_logout(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  /* Send the LOGOUT command */
  result = imap_sendf(conn, "LOGOUT");

  if(!result)
    state(conn, IMAP_LOGOUT);

  return result;
}

/* For the initial server greeting */
static CURLcode imap_state_servergreet_resp(struct connectdata *conn,
                                            int imapcode,
                                            imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    failf(data, "Got unexpected imap-server response");
    result = CURLE_FTP_WEIRD_SERVER_REPLY; /* TODO: fix this code */
  }
  else
    result = imap_perform_capability(conn);

  return result;
}

/* For CAPABILITY responses */
static CURLcode imap_state_capability_resp(struct connectdata *conn,
                                           int imapcode,
                                           imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *line = data->state.buffer;
  size_t wordlen;

  (void)instate; /* no use for this yet */

  /* Do we have a untagged response? */
  if(imapcode == '*') {
    line += 2;

    /* Loop through the data line */
    for(;;) {
      while(*line &&
            (*line == ' ' || *line == '\t' ||
              *line == '\r' || *line == '\n')) {

        line++;
      }

      if(!*line)
        break;

      /* Extract the word */
      for(wordlen = 0; line[wordlen] && line[wordlen] != ' ' &&
            line[wordlen] != '\t' && line[wordlen] != '\r' &&
            line[wordlen] != '\n';)
        wordlen++;

      /* Does the server support the STARTTLS capability? */
      if(wordlen == 8 && !memcmp(line, "STARTTLS", 8))
        imapc->tls_supported = TRUE;

      /* Has the server explicitly disabled clear text authentication? */
      else if(wordlen == 13 && !memcmp(line, "LOGINDISABLED", 13))
        imapc->login_disabled = TRUE;

      /* Does the server support the SASL-IR capability? */
      else if(wordlen == 7 && !memcmp(line, "SASL-IR", 7))
        imapc->ir_supported = TRUE;

      /* Do we have a SASL based authentication mechanism? */
      else if(wordlen > 5 && !memcmp(line, "AUTH=", 5)) {
        line += 5;
        wordlen -= 5;

        /* Test the word for a matching authentication mechanism */
        if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_LOGIN))
          imapc->authmechs |= SASL_MECH_LOGIN;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_PLAIN))
          imapc->authmechs |= SASL_MECH_PLAIN;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_CRAM_MD5))
          imapc->authmechs |= SASL_MECH_CRAM_MD5;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_DIGEST_MD5))
          imapc->authmechs |= SASL_MECH_DIGEST_MD5;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_GSSAPI))
          imapc->authmechs |= SASL_MECH_GSSAPI;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_EXTERNAL))
          imapc->authmechs |= SASL_MECH_EXTERNAL;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_NTLM))
          imapc->authmechs |= SASL_MECH_NTLM;
        else if(sasl_mech_equal(line, wordlen, SASL_MECH_STRING_XOAUTH2))
          imapc->authmechs |= SASL_MECH_XOAUTH2;
      }

      line += wordlen;
    }
  }
  else if(imapcode == 'O') {
    if(data->set.use_ssl && !conn->ssl[FIRSTSOCKET].use) {
      /* We don't have a SSL/TLS connection yet, but SSL is requested */
      if(imapc->tls_supported)
        /* Switch to TLS connection now */
        result = imap_perform_starttls(conn);
      else if(data->set.use_ssl == CURLUSESSL_TRY)
        /* Fallback and carry on with authentication */
        result = imap_perform_authentication(conn);
      else {
        failf(data, "STARTTLS not supported.");
        result = CURLE_USE_SSL_FAILED;
      }
    }
    else
      result = imap_perform_authentication(conn);
  }
  else
    result = imap_perform_authentication(conn);

  return result;
}

/* For STARTTLS responses */
static CURLcode imap_state_starttls_resp(struct connectdata *conn,
                                         int imapcode,
                                         imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    if(data->set.use_ssl != CURLUSESSL_TRY) {
      failf(data, "STARTTLS denied. %c", imapcode);
      result = CURLE_USE_SSL_FAILED;
    }
    else
      result = imap_perform_authentication(conn);
  }
  else
    result = imap_perform_upgrade_tls(conn);

  return result;
}

/* For AUTHENTICATE PLAIN (without initial response) responses */
static CURLcode imap_state_auth_plain_resp(struct connectdata *conn,
                                           int imapcode,
                                           imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *plainauth = NULL;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied. %c", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the authorisation message */
    result = Curl_sasl_create_plain_message(data, conn->user, conn->passwd,
                                            &plainauth, &len);
    if(!result && plainauth) {
      /* Send the message */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", plainauth);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_FINAL);
    }
  }

  Curl_safefree(plainauth);

  return result;
}

/* For AUTHENTICATE LOGIN (without initial response) responses */
static CURLcode imap_state_auth_login_resp(struct connectdata *conn,
                                           int imapcode,
                                           imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *authuser = NULL;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the user message */
    result = Curl_sasl_create_login_message(data, conn->user,
                                            &authuser, &len);
    if(!result && authuser) {
      /* Send the user */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", authuser);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_LOGIN_PASSWD);
    }
  }

  Curl_safefree(authuser);

  return result;
}

/* For AUTHENTICATE LOGIN user entry responses */
static CURLcode imap_state_auth_login_password_resp(struct connectdata *conn,
                                                    int imapcode,
                                                    imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *authpasswd = NULL;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the password message */
    result = Curl_sasl_create_login_message(data, conn->passwd,
                                            &authpasswd, &len);
    if(!result && authpasswd) {
      /* Send the password */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", authpasswd);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_FINAL);
    }
  }

  Curl_safefree(authpasswd);

  return result;
}

#ifndef CURL_DISABLE_CRYPTO_AUTH
/* For AUTHENTICATE CRAM-MD5 responses */
static CURLcode imap_state_auth_cram_resp(struct connectdata *conn,
                                          int imapcode,
                                          imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *chlg = NULL;
  char *chlg64 = NULL;
  char *rplyb64 = NULL;
  size_t len = 0;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    return CURLE_LOGIN_DENIED;
  }

  /* Get the challenge message */
  imap_get_message(data->state.buffer, &chlg64);

  /* Decode the challenge message */
  result = Curl_sasl_decode_cram_md5_message(chlg64, &chlg, &len);
  if(result) {
    /* Send the cancellation */
    result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", "*");

    if(!result)
      state(conn, IMAP_AUTHENTICATE_CANCEL);
  }
  else {
    /* Create the response message */
    result = Curl_sasl_create_cram_md5_message(data, chlg, conn->user,
                                               conn->passwd, &rplyb64, &len);
    if(!result && rplyb64) {
      /* Send the response */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", rplyb64);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_FINAL);
    }
  }

  Curl_safefree(chlg);
  Curl_safefree(rplyb64);

  return result;
}

/* For AUTHENTICATE DIGEST-MD5 challenge responses */
static CURLcode imap_state_auth_digest_resp(struct connectdata *conn,
                                            int imapcode,
                                            imapstate instate)
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

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    return CURLE_LOGIN_DENIED;
  }

  /* Get the challenge message */
  imap_get_message(data->state.buffer, &chlg64);

  /* Decode the challange message */
  result = Curl_sasl_decode_digest_md5_message(chlg64, nonce, sizeof(nonce),
                                               realm, sizeof(realm),
                                               algorithm, sizeof(algorithm));
  if(result || strcmp(algorithm, "md5-sess") != 0) {
    /* Send the cancellation */
    result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", "*");

    if(!result)
      state(conn, IMAP_AUTHENTICATE_CANCEL);
  }
  else {
    /* Create the response message */
    result = Curl_sasl_create_digest_md5_message(data, nonce, realm,
                                                 conn->user, conn->passwd,
                                                 "imap", &rplyb64, &len);
    if(!result && rplyb64) {
      /* Send the response */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", rplyb64);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_DIGESTMD5_RESP);
    }
  }

  Curl_safefree(rplyb64);

  return result;
}

/* For AUTHENTICATE DIGEST-MD5 challenge-response responses */
static CURLcode imap_state_auth_digest_resp_resp(struct connectdata *conn,
                                                 int imapcode,
                                                 imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Authentication failed: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Send an empty response */
    result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", "");

    if(!result)
      state(conn, IMAP_AUTHENTICATE_FINAL);
  }

  return result;
}
#endif

#ifdef USE_NTLM
/* For AUTHENTICATE NTLM (without initial response) responses */
static CURLcode imap_state_auth_ntlm_resp(struct connectdata *conn,
                                          int imapcode,
                                          imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *type1msg = NULL;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the type-1 message */
    result = Curl_sasl_create_ntlm_type1_message(conn->user, conn->passwd,
                                                 &conn->ntlm,
                                                 &type1msg, &len);
    if(!result && type1msg) {
      /* Send the message */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", type1msg);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_NTLM_TYPE2MSG);
    }
  }

  Curl_safefree(type1msg);

  return result;
}

/* For NTLM type-2 responses (sent in reponse to our type-1 message) */
static CURLcode imap_state_auth_ntlm_type2msg_resp(struct connectdata *conn,
                                                   int imapcode,
                                                   imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *type2msg = NULL;
  char *type3msg = NULL;
  size_t len = 0;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Get the challenge message */
    imap_get_message(data->state.buffer, &type2msg);

    /* Decode the type-2 message */
    result = Curl_sasl_decode_ntlm_type2_message(data, type2msg, &conn->ntlm);
    if(result) {
      /* Send the cancellation */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", "*");

      if(!result)
        state(conn, IMAP_AUTHENTICATE_CANCEL);
    }
    else {
      /* Create the type-3 message */
      result = Curl_sasl_create_ntlm_type3_message(data, conn->user,
                                                   conn->passwd, &conn->ntlm,
                                                   &type3msg, &len);
      if(!result && type3msg) {
        /* Send the message */
        result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", type3msg);

        if(!result)
          state(conn, IMAP_AUTHENTICATE_FINAL);
      }
    }
  }

  Curl_safefree(type3msg);

  return result;
}
#endif

/* For AUTHENTICATE XOAUTH2 (without initial response) responses */
static CURLcode imap_state_auth_xoauth2_resp(struct connectdata *conn,
                                             int imapcode,
                                             imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  size_t len = 0;
  char *xoauth = NULL;

  (void)instate; /* no use for this yet */

  if(imapcode != '+') {
    failf(data, "Access denied: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* Create the authorisation message */
    result = Curl_sasl_create_xoauth2_message(conn->data, conn->user,
                                              conn->xoauth2_bearer,
                                              &xoauth, &len);
    if(!result && xoauth) {
      /* Send the message */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", xoauth);

      if(!result)
        state(conn, IMAP_AUTHENTICATE_FINAL);
    }
  }

  Curl_safefree(xoauth);

  return result;
}

/* For AUTHENTICATE cancellation responses */
static CURLcode imap_state_auth_cancel_resp(struct connectdata *conn,
                                            int imapcode,
                                            imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *mech = NULL;
  char *initresp = NULL;
  size_t len = 0;
  imapstate state1 = IMAP_STOP;
  imapstate state2 = IMAP_STOP;

  (void)imapcode;
  (void)instate; /* no use for this yet */

  /* Remove the offending mechanism from the supported list */
  imapc->authmechs ^= imapc->authused;

  /* Calculate alternative SASL login details */
  result = imap_calc_sasl_details(conn, &mech, &initresp, &len, &state1,
                                  &state2);

  if(!result) {
    /* Do we have any mechanisms left or can we fallback to clear text? */
    if(mech) {
      /* Retry SASL based authentication */
      result = imap_perform_authenticate(conn, mech, initresp, state1, state2);

      Curl_safefree(initresp);
    }
    else if((!imapc->login_disabled) &&
            (imapc->preftype & IMAP_TYPE_CLEARTEXT))
      /* Perform clear text authentication */
      result = imap_perform_login(conn);
    else {
      failf(data, "Authentication cancelled");

      result = CURLE_LOGIN_DENIED;
    }
  }

  return result;
}

/* For final responses in the AUTHENTICATE sequence */
static CURLcode imap_state_auth_final_resp(struct connectdata *conn,
                                           int imapcode,
                                           imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    failf(data, "Authentication failed: %d", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else
    /* End of connect phase */
    state(conn, IMAP_STOP);

  return result;
}

/* For LOGIN responses */
static CURLcode imap_state_login_resp(struct connectdata *conn,
                                      int imapcode,
                                      imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    failf(data, "Access denied. %c", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else
    /* End of connect phase */
    state(conn, IMAP_STOP);

  return result;
}

/* For LIST responses */
static CURLcode imap_state_list_resp(struct connectdata *conn, int imapcode,
                                     imapstate instate)
{
  CURLcode result = CURLE_OK;
  char *line = conn->data->state.buffer;
  size_t len = strlen(line);

  (void)instate; /* No use for this yet */

  if(imapcode == '*') {
    /* Temporarily add the LF character back and send as body to the client */
    line[len] = '\n';
    result = Curl_client_write(conn, CLIENTWRITE_BODY, line, len + 1);
    line[len] = '\0';
  }
  else if(imapcode != 'O')
    result = CURLE_QUOTE_ERROR; /* TODO: Fix error code */
  else
    /* End of DO phase */
    state(conn, IMAP_STOP);

  return result;
}

/* For SELECT responses */
static CURLcode imap_state_select_resp(struct connectdata *conn, int imapcode,
                                       imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = conn->data->req.protop;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *line = data->state.buffer;
  char tmp[20];

  (void)instate; /* no use for this yet */

  if(imapcode == '*') {
    /* See if this is an UIDVALIDITY response */
    if(sscanf(line + 2, "OK [UIDVALIDITY %19[0123456789]]", tmp) == 1) {
      Curl_safefree(imapc->mailbox_uidvalidity);
      imapc->mailbox_uidvalidity = strdup(tmp);
    }
  }
  else if(imapcode == 'O') {
    /* Check if the UIDVALIDITY has been specified and matches */
    if(imap->uidvalidity && imapc->mailbox_uidvalidity &&
       strcmp(imap->uidvalidity, imapc->mailbox_uidvalidity)) {
      failf(conn->data, "Mailbox UIDVALIDITY has changed");
      result = CURLE_REMOTE_FILE_NOT_FOUND;
    }
    else {
      /* Note the currently opened mailbox on this connection */
      imapc->mailbox = strdup(imap->mailbox);

      if(imap->custom)
        result = imap_perform_list(conn);
      else
        result = imap_perform_fetch(conn);
    }
  }
  else {
    failf(data, "Select failed");
    result = CURLE_LOGIN_DENIED;
  }

  return result;
}

/* For the (first line of the) FETCH responses */
static CURLcode imap_state_fetch_resp(struct connectdata *conn, int imapcode,
                                      imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;
  const char *ptr = data->state.buffer;
  bool parsed = FALSE;
  curl_off_t size;

  (void)instate; /* no use for this yet */

  if(imapcode != '*') {
    Curl_pgrsSetDownloadSize(data, 0);
    state(conn, IMAP_STOP);
    return CURLE_REMOTE_FILE_NOT_FOUND; /* TODO: Fix error code */
  }

  /* Something like this is received "* 1 FETCH (BODY[TEXT] {2021}\r" so parse
     the continuation data contained within the curly brackets */
  while(*ptr && (*ptr != '{'))
    ptr++;

  if(*ptr == '{') {
    char *endptr;
    size = curlx_strtoofft(ptr + 1, &endptr, 10);
    if(endptr - ptr > 1 && endptr[0] == '}' &&
       endptr[1] == '\r' && endptr[2] == '\0')
      parsed = TRUE;
  }

  if(parsed) {
    infof(data, "Found %" CURL_FORMAT_CURL_OFF_TU " bytes to download\n",
          size);
    Curl_pgrsSetDownloadSize(data, size);

    if(pp->cache) {
      /* At this point there is a bunch of data in the header "cache" that is
         actually body content, send it as body and then skip it. Do note
         that there may even be additional "headers" after the body. */
      size_t chunk = pp->cache_size;

      if(chunk > (size_t)size)
        /* The conversion from curl_off_t to size_t is always fine here */
        chunk = (size_t)size;

      result = Curl_client_write(conn, CLIENTWRITE_BODY, pp->cache, chunk);
      if(result)
        return result;

      data->req.bytecount += chunk;

      infof(data, "Written %" CURL_FORMAT_CURL_OFF_TU
            " bytes, %" CURL_FORMAT_CURL_OFF_TU
            " bytes are left for transfer\n", (curl_off_t)chunk,
            size - chunk);

      /* Have we used the entire cache or just part of it?*/
      if(pp->cache_size > chunk) {
        /* Only part of it so shrink the cache to fit the trailing data */
        memmove(pp->cache, pp->cache + chunk, pp->cache_size - chunk);
        pp->cache_size -= chunk;
      }
      else {
        /* Free the cache */
        Curl_safefree(pp->cache);

        /* Reset the cache size */
        pp->cache_size = 0;
      }
    }

    if(data->req.bytecount == size)
      /* The entire data is already transferred! */
      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    else {
      /* IMAP download */
      data->req.maxdownload = size;
      Curl_setup_transfer(conn, FIRSTSOCKET, size, FALSE, NULL, -1, NULL);
    }
  }
  else {
    /* We don't know how to parse this line */
    failf(pp->conn->data, "Failed to parse FETCH response.");
    result = CURLE_FTP_WEIRD_SERVER_REPLY; /* TODO: fix this code */
  }

  /* End of DO phase */
  state(conn, IMAP_STOP);

  return result;
}

/* For final FETCH responses performed after the download */
static CURLcode imap_state_fetch_final_resp(struct connectdata *conn,
                                            int imapcode,
                                            imapstate instate)
{
  CURLcode result = CURLE_OK;

  (void)instate; /* No use for this yet */

  if(imapcode != 'O')
    result = CURLE_FTP_WEIRD_SERVER_REPLY; /* TODO: Fix error code */
  else
    /* End of DONE phase */
    state(conn, IMAP_STOP);

  return result;
}

/* For APPEND responses */
static CURLcode imap_state_append_resp(struct connectdata *conn, int imapcode,
                                       imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  (void)instate; /* No use for this yet */

  if(imapcode != '+') {
    result = CURLE_UPLOAD_FAILED;
  }
  else {
    /* Set the progress upload size */
    Curl_pgrsSetUploadSize(data, data->set.infilesize);

    /* IMAP upload */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, FIRSTSOCKET, NULL);

    /* End of DO phase */
    state(conn, IMAP_STOP);
  }

  return result;
}

/* For final APPEND responses performed after the upload */
static CURLcode imap_state_append_final_resp(struct connectdata *conn,
                                             int imapcode,
                                             imapstate instate)
{
  CURLcode result = CURLE_OK;

  (void)instate; /* No use for this yet */

  if(imapcode != 'O')
    result = CURLE_UPLOAD_FAILED;
  else
    /* End of DONE phase */
    state(conn, IMAP_STOP);

  return result;
}

static CURLcode imap_statemach_act(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int imapcode;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;
  size_t nread = 0;

  /* Busy upgrading the connection; right now all I/O is SSL/TLS, not IMAP */
  if(imapc->state == IMAP_UPGRADETLS)
    return imap_perform_upgrade_tls(conn);

  /* Flush any data that needs to be sent */
  if(pp->sendleft)
    return Curl_pp_flushsend(pp);

  do {
    /* Read the response from the server */
    result = Curl_pp_readresp(sock, pp, &imapcode, &nread);
    if(result)
      return result;

    /* Was there an error parsing the response line? */
    if(imapcode == -1)
      return CURLE_FTP_WEIRD_SERVER_REPLY;

    if(!imapcode)
      break;

    /* We have now received a full IMAP server response */
    switch(imapc->state) {
    case IMAP_SERVERGREET:
      result = imap_state_servergreet_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_CAPABILITY:
      result = imap_state_capability_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_STARTTLS:
      result = imap_state_starttls_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_PLAIN:
      result = imap_state_auth_plain_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_LOGIN:
      result = imap_state_auth_login_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_LOGIN_PASSWD:
      result = imap_state_auth_login_password_resp(conn, imapcode,
                                                   imapc->state);
      break;

#ifndef CURL_DISABLE_CRYPTO_AUTH
    case IMAP_AUTHENTICATE_CRAMMD5:
      result = imap_state_auth_cram_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_DIGESTMD5:
      result = imap_state_auth_digest_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_DIGESTMD5_RESP:
      result = imap_state_auth_digest_resp_resp(conn, imapcode, imapc->state);
      break;
#endif

#ifdef USE_NTLM
    case IMAP_AUTHENTICATE_NTLM:
      result = imap_state_auth_ntlm_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_NTLM_TYPE2MSG:
      result = imap_state_auth_ntlm_type2msg_resp(conn, imapcode,
                                                  imapc->state);
      break;
#endif

    case IMAP_AUTHENTICATE_XOAUTH2:
      result = imap_state_auth_xoauth2_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_CANCEL:
      result = imap_state_auth_cancel_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_AUTHENTICATE_FINAL:
      result = imap_state_auth_final_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_LOGIN:
      result = imap_state_login_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_LIST:
      result = imap_state_list_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_SELECT:
      result = imap_state_select_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_FETCH:
      result = imap_state_fetch_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_FETCH_FINAL:
      result = imap_state_fetch_final_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_APPEND:
      result = imap_state_append_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_APPEND_FINAL:
      result = imap_state_append_final_resp(conn, imapcode, imapc->state);
      break;

    case IMAP_LOGOUT:
      /* fallthrough, just stop! */
    default:
      /* internal error */
      state(conn, IMAP_STOP);
      break;
    }
  } while(!result && imapc->state != IMAP_STOP && Curl_pp_moredata(pp));

  return result;
}

/* Called repeatedly until done from multi.c */
static CURLcode imap_multi_statemach(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;

  if((conn->handler->flags & PROTOPT_SSL) && !imapc->ssldone) {
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &imapc->ssldone);
    if(result || !imapc->ssldone)
      return result;
  }

  result = Curl_pp_statemach(&imapc->pp, FALSE);
  *done = (imapc->state == IMAP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode imap_block_statemach(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;

  while(imapc->state != IMAP_STOP && !result)
    result = Curl_pp_statemach(&imapc->pp, TRUE);

  return result;
}

/* Allocate and initialize the struct IMAP for the current SessionHandle if
   required */
static CURLcode imap_init(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap;

  imap = data->req.protop = calloc(sizeof(struct IMAP), 1);
  if(!imap)
    result = CURLE_OUT_OF_MEMORY;

  return result;
}

/* For the IMAP "protocol connect" and "doing" phases only */
static int imap_getsock(struct connectdata *conn, curl_socket_t *socks,
                        int numsocks)
{
  return Curl_pp_getsock(&conn->proto.imapc.pp, socks, numsocks);
}

/***********************************************************************
 *
 * imap_connect()
 *
 * This function should do everything that is to be considered a part of the
 * connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE if not.
 */
static CURLcode imap_connect(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections in IMAP */
  conn->bits.close = FALSE;

  /* Set the default response time-out */
  pp->response_time = RESP_TIMEOUT;
  pp->statemach_act = imap_statemach_act;
  pp->endofresp = imap_endofresp;
  pp->conn = conn;

  /* Set the default preferred authentication type and mechanism */
  imapc->preftype = IMAP_TYPE_ANY;
  imapc->prefmech = SASL_AUTH_ANY;

  /* Initialise the pingpong layer */
  Curl_pp_init(pp);

  /* Parse the URL options */
  result = imap_parse_url_options(conn);
  if(result)
    return result;

  /* Start off waiting for the server greeting response */
  state(conn, IMAP_SERVERGREET);

  /* Start off with an response id of '*' */
  strcpy(imapc->resptag, "*");

  result = imap_multi_statemach(conn, done);

  return result;
}

/***********************************************************************
 *
 * imap_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
static CURLcode imap_done(struct connectdata *conn, CURLcode status,
                          bool premature)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = data->req.protop;

  (void)premature;

  if(!imap)
    /* When the easy handle is removed from the multi interface while libcurl
       is still trying to resolve the host name, the IMAP struct is not yet
       initialized. However, the removal action calls Curl_done() which in
       turn calls this function, so we simply return success. */
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; /* marked for closure */
    result = status;         /* use the already set error code */
  }
  else if(!data->set.connect_only && !imap->custom &&
          (imap->uid || data->set.upload)) {
    /* Handle responses after FETCH or APPEND transfer has finished */
    if(!data->set.upload)
      state(conn, IMAP_FETCH_FINAL);
    else {
      /* End the APPEND command first by sending an empty line */
      result = Curl_pp_sendf(&conn->proto.imapc.pp, "%s", "");
      if(!result)
        state(conn, IMAP_APPEND_FINAL);
    }

    /* Run the state-machine

       TODO: when the multi interface is used, this _really_ should be using
       the imap_multi_statemach function but we have no general support for
       non-blocking DONE operations, not in the multi state machine and with
       Curl_done() invokes on several places in the code!
    */
    if(!result)
      result = imap_block_statemach(conn);
  }

  /* Cleanup our per-request based variables */
  Curl_safefree(imap->mailbox);
  Curl_safefree(imap->uidvalidity);
  Curl_safefree(imap->uid);
  Curl_safefree(imap->section);
  Curl_safefree(imap->custom);
  Curl_safefree(imap->custom_params);

  /* Clear the transfer mode for the next request */
  imap->transfer = FTPTRANSFER_BODY;

  return result;
}

/***********************************************************************
 *
 * imap_perform()
 *
 * This is the actual DO function for IMAP. Fetch or append a message, or do
 * other things according to the options previously setup.
 */
static CURLcode imap_perform(struct connectdata *conn, bool *connected,
                             bool *dophase_done)
{
  /* This is IMAP and no proxy */
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = data->req.protop;
  struct imap_conn *imapc = &conn->proto.imapc;
  bool selected = FALSE;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    /* Requested no body means no transfer */
    imap->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  /* Determine if the requested mailbox (with the same UIDVALIDITY if set)
     has already been selected on this connection */
  if(imap->mailbox && imapc->mailbox &&
     !strcmp(imap->mailbox, imapc->mailbox) &&
     (!imap->uidvalidity || !imapc->mailbox_uidvalidity ||
      !strcmp(imap->uidvalidity, imapc->mailbox_uidvalidity)))
    selected = TRUE;

  /* Start the first command in the DO phase */
  if(conn->data->set.upload)
    /* APPEND can be executed directly */
    result = imap_perform_append(conn);
  else if(imap->custom && (selected || !imap->mailbox))
    /* Custom command using the same mailbox or no mailbox */
    result = imap_perform_list(conn);
  else if(!imap->custom && selected && imap->uid)
    /* FETCH from the same mailbox */
    result = imap_perform_fetch(conn);
  else if(imap->mailbox && !selected && (imap->custom || imap->uid))
    /* SELECT the mailbox */
    result = imap_perform_select(conn);
  else
    /* LIST */
    result = imap_perform_list(conn);

  if(result)
    return result;

  /* Run the state-machine */
  result = imap_multi_statemach(conn, dophase_done);

  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}

/***********************************************************************
 *
 * imap_do()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (imap_perform).
 *
 * The input argument is already checked for validity.
 */
static CURLcode imap_do(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;

  *done = FALSE; /* default to false */

  /* Parse the URL path */
  result = imap_parse_url_path(conn);
  if(result)
    return result;

  /* Parse the custom request */
  result = imap_parse_custom_request(conn);
  if(result)
    return result;

  result = imap_regular_transfer(conn, done);

  return result;
}

/***********************************************************************
 *
 * imap_disconnect()
 *
 * Disconnect from an IMAP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode imap_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct imap_conn *imapc = &conn->proto.imapc;

  /* We cannot send quit unconditionally. If this connection is stale or
     bad in any way, sending quit and waiting around here will make the
     disconnect wait in vain and cause more problems than we need to. */

  /* The IMAP session may or may not have been allocated/setup at this
     point! */
  if(!dead_connection && imapc->pp.conn && imapc->pp.conn->bits.protoconnstart)
    if(!imap_perform_logout(conn))
      (void)imap_block_statemach(conn); /* ignore errors on LOGOUT */

  /* Disconnect from the server */
  Curl_pp_disconnect(&imapc->pp);

  /* Cleanup the SASL module */
  Curl_sasl_cleanup(conn, imapc->authused);

  /* Cleanup our connection based variables */
  Curl_safefree(imapc->mailbox);
  Curl_safefree(imapc->mailbox_uidvalidity);

  return CURLE_OK;
}

/* Call this when the DO phase has completed */
static CURLcode imap_dophase_done(struct connectdata *conn, bool connected)
{
  struct IMAP *imap = conn->data->req.protop;

  (void)connected;

  if(imap->transfer != FTPTRANSFER_BODY)
    /* no data to transfer */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return CURLE_OK;
}

/* Called from multi.c while DOing */
static CURLcode imap_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result = imap_multi_statemach(conn, dophase_done);

  if(result)
    DEBUGF(infof(conn->data, "DO phase failed\n"));
  else if(*dophase_done) {
    result = imap_dophase_done(conn, FALSE /* not connected */);

    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

/***********************************************************************
 *
 * imap_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 */
static CURLcode imap_regular_transfer(struct connectdata *conn,
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
  result = imap_perform(conn, &connected, dophase_done);

  /* Perform post DO phase operations if necessary */
  if(!result && *dophase_done)
    result = imap_dophase_done(conn, connected);

  return result;
}

static CURLcode imap_setup_connection(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;

  /* Initialise the IMAP layer */
  CURLcode result = imap_init(conn);
  if(result)
    return result;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    /* Unless we have asked to tunnel IMAP operations through the proxy, we
       switch and use HTTP operations only */
#ifndef CURL_DISABLE_HTTP
    if(conn->handler == &Curl_handler_imap)
      conn->handler = &Curl_handler_imap_proxy;
    else {
#ifdef USE_SSL
      conn->handler = &Curl_handler_imaps_proxy;
#else
      failf(data, "IMAPS not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif
    }

    /* set it up as an HTTP connection instead */
    return conn->handler->setup_connection(conn);
#else
    failf(data, "IMAP over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }

  data->state.path++;   /* don't include the initial slash */

  return CURLE_OK;
}

/***********************************************************************
 *
 * imap_sendf()
 *
 * Sends the formated string as an IMAP command to the server.
 *
 * Designed to never block.
 */
static CURLcode imap_sendf(struct connectdata *conn, const char *fmt, ...)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;
  char *taggedfmt;
  va_list ap;

  DEBUGASSERT(fmt);

  /* Calculate the next command ID wrapping at 3 digits */
  imapc->cmdid = (imapc->cmdid + 1) % 1000;

  /* Calculate the tag based on the connection ID and command ID */
  snprintf(imapc->resptag, sizeof(imapc->resptag), "%c%03d",
           'A' + curlx_sltosi(conn->connection_id % 26), imapc->cmdid);

  /* Prefix the format with the tag */
  taggedfmt = aprintf("%s %s", imapc->resptag, fmt);
  if(!taggedfmt)
    return CURLE_OUT_OF_MEMORY;

  /* Send the data with the tag */
  va_start(ap, fmt);
  result = Curl_pp_vsendf(&imapc->pp, taggedfmt, ap);
  va_end(ap);

  Curl_safefree(taggedfmt);

  return result;
}

/***********************************************************************
 *
 * imap_atom()
 *
 * Checks the input string for characters that need escaping and returns an
 * atom ready for sending to the server.
 *
 * The returned string needs to be freed.
 *
 */
static char *imap_atom(const char *str)
{
  const char *p1;
  char *p2;
  size_t backsp_count = 0;
  size_t quote_count = 0;
  bool space_exists = FALSE;
  size_t newlen = 0;
  char *newstr = NULL;

  if(!str)
    return NULL;

  /* Count any unescapped characters */
  p1 = str;
  while(*p1) {
    if(*p1 == '\\')
      backsp_count++;
    else if(*p1 == '"')
      quote_count++;
    else if(*p1 == ' ')
      space_exists = TRUE;

    p1++;
  }

  /* Does the input contain any unescapped characters? */
  if(!backsp_count && !quote_count && !space_exists)
    return strdup(str);

  /* Calculate the new string length */
  newlen = strlen(str) + backsp_count + quote_count + (space_exists ? 2 : 0);

  /* Allocate the new string */
  newstr = (char *) malloc((newlen + 1) * sizeof(char));
  if(!newstr)
    return NULL;

  /* Surround the string in quotes if necessary */
  p2 = newstr;
  if(space_exists) {
    newstr[0] = '"';
    newstr[newlen - 1] = '"';
    p2++;
  }

  /* Copy the string, escaping backslash and quote characters along the way */
  p1 = str;
  while(*p1) {
    if(*p1 == '\\' || *p1 == '"') {
      *p2 = '\\';
      p2++;
    }

   *p2 = *p1;

    p1++;
    p2++;
  }

  /* Terminate the string */
  newstr[newlen] = '\0';

  return newstr;
}

/***********************************************************************
 *
 * imap_is_bchar()
 *
 * Portable test of whether the specified char is a "bchar" as defined in the
 * grammar of RFC-5092.
 */
static bool imap_is_bchar(char ch)
{
  switch(ch) {
    /* bchar */
    case ':': case '@': case '/':
    /* bchar -> achar */
    case '&': case '=':
    /* bchar -> achar -> uchar -> unreserved */
    case '0': case '1': case '2': case '3': case '4': case '5': case '6':
    case '7': case '8': case '9':
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G':
    case 'H': case 'I': case 'J': case 'K': case 'L': case 'M': case 'N':
    case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T': case 'U':
    case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g':
    case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':
    case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u':
    case 'v': case 'w': case 'x': case 'y': case 'z':
    case '-': case '.': case '_': case '~':
    /* bchar -> achar -> uchar -> sub-delims-sh */
    case '!': case '$': case '\'': case '(': case ')': case '*':
    case '+': case ',':
    /* bchar -> achar -> uchar -> pct-encoded */
    case '%': /* HEXDIG chars are already included above */
      return true;

    default:
      return false;
  }
}

/***********************************************************************
 *
 * imap_parse_url_options()
 *
 * Parse the URL login options.
 */
static CURLcode imap_parse_url_options(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;
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
        imapc->preftype = IMAP_TYPE_NONE;
        imapc->prefmech = SASL_AUTH_NONE;
      }

      while(*ptr && *ptr != ';') {
        ptr++;
        len++;
      }

      if(strnequal(value, "*", len)) {
        imapc->preftype = IMAP_TYPE_ANY;
        imapc->prefmech = SASL_AUTH_ANY;
      }
      else if(strnequal(value, SASL_MECH_STRING_LOGIN, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_LOGIN;
      }
      else if(strnequal(value, SASL_MECH_STRING_PLAIN, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_PLAIN;
      }
      else if(strnequal(value, SASL_MECH_STRING_CRAM_MD5, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_CRAM_MD5;
      }
      else if(strnequal(value, SASL_MECH_STRING_DIGEST_MD5, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_DIGEST_MD5;
      }
      else if(strnequal(value, SASL_MECH_STRING_GSSAPI, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_GSSAPI;
      }
      else if(strnequal(value, SASL_MECH_STRING_NTLM, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_NTLM;
      }
      else if(strnequal(value, SASL_MECH_STRING_XOAUTH2, len)) {
        imapc->preftype = IMAP_TYPE_SASL;
        imapc->prefmech |= SASL_MECH_XOAUTH2;
      }

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
 * imap_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
static CURLcode imap_parse_url_path(struct connectdata *conn)
{
  /* The imap struct is already initialised in imap_connect() */
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = data->req.protop;
  const char *begin = data->state.path;
  const char *ptr = begin;

  /* See how much of the URL is a valid path and decode it */
  while(imap_is_bchar(*ptr))
    ptr++;

  if(ptr != begin) {
    /* Remove the trailing slash if present */
    const char *end = ptr;
    if(end > begin && end[-1] == '/')
      end--;

    result = Curl_urldecode(data, begin, end - begin, &imap->mailbox, NULL,
                            TRUE);
    if(result)
      return result;
  }
  else
    imap->mailbox = NULL;

  /* There can be any number of parameters in the form ";NAME=VALUE" */
  while(*ptr == ';') {
    char *name;
    char *value;
    size_t valuelen;

    /* Find the length of the name parameter */
    begin = ++ptr;
    while(*ptr && *ptr != '=')
      ptr++;

    if(!*ptr)
      return CURLE_URL_MALFORMAT;

    /* Decode the name parameter */
    result = Curl_urldecode(data, begin, ptr - begin, &name, NULL, TRUE);
    if(result)
      return result;

    /* Find the length of the value parameter */
    begin = ++ptr;
    while(imap_is_bchar(*ptr))
      ptr++;

    /* Decode the value parameter */
    result = Curl_urldecode(data, begin, ptr - begin, &value, &valuelen, TRUE);
    if(result) {
      Curl_safefree(name);
      return result;
    }

    DEBUGF(infof(conn->data, "IMAP URL parameter '%s' = '%s'\n", name, value));

    /* Process the known hierarchical parameters (UIDVALIDITY, UID and SECTION)
       stripping of the trailing slash character if it is present.

       Note: Unknown parameters trigger a URL_MALFORMAT error. */
    if(Curl_raw_equal(name, "UIDVALIDITY") && !imap->uidvalidity) {
      if(valuelen > 0 && value[valuelen - 1] == '/')
        value[valuelen - 1] = '\0';

      imap->uidvalidity = value;
      value = NULL;
    }
    else if(Curl_raw_equal(name, "UID") && !imap->uid) {
      if(valuelen > 0 && value[valuelen - 1] == '/')
        value[valuelen - 1] = '\0';

      imap->uid = value;
      value = NULL;
    }
    else if(Curl_raw_equal(name, "SECTION") && !imap->section) {
      if(valuelen > 0 && value[valuelen - 1] == '/')
        value[valuelen - 1] = '\0';

      imap->section = value;
      value = NULL;
    }
    else {
      Curl_safefree(name);
      Curl_safefree(value);

      return CURLE_URL_MALFORMAT;
    }

    Curl_safefree(name);
    Curl_safefree(value);
  }

  /* Any extra stuff at the end of the URL is an error */
  if(*ptr)
    return CURLE_URL_MALFORMAT;

  return CURLE_OK;
}

/***********************************************************************
 *
 * imap_parse_custom_request()
 *
 * Parse the custom request.
 */
static CURLcode imap_parse_custom_request(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct IMAP *imap = data->req.protop;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  if(custom) {
    /* URL decode the custom request */
    result = Curl_urldecode(data, custom, 0, &imap->custom, NULL, TRUE);

    /* Extract the parameters if specified */
    if(!result) {
      const char *params = imap->custom;

      while(*params && *params != ' ')
        params++;

      if(*params) {
        imap->custom_params = strdup(params);
        imap->custom[params - imap->custom] = '\0';

        if(!imap->custom_params)
          result = CURLE_OUT_OF_MEMORY;
      }
    }
  }

  return result;
}

/***********************************************************************
 *
 * imap_calc_sasl_details()
 *
 * Calculate the required login details for SASL authentication.
 */
static CURLcode imap_calc_sasl_details(struct connectdata *conn,
                                       const char **mech,
                                       char **initresp, size_t *len,
                                       imapstate *state1, imapstate *state2)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;

  /* Calculate the supported authentication mechanism, by decreasing order of
     security, as well as the initial response where appropriate */
#ifndef CURL_DISABLE_CRYPTO_AUTH
  if((imapc->authmechs & SASL_MECH_DIGEST_MD5) &&
     (imapc->prefmech & SASL_MECH_DIGEST_MD5)) {
    *mech = SASL_MECH_STRING_DIGEST_MD5;
    *state1 = IMAP_AUTHENTICATE_DIGESTMD5;
    imapc->authused = SASL_MECH_DIGEST_MD5;
  }
  else if((imapc->authmechs & SASL_MECH_CRAM_MD5) &&
          (imapc->prefmech & SASL_MECH_CRAM_MD5)) {
    *mech = SASL_MECH_STRING_CRAM_MD5;
    *state1 = IMAP_AUTHENTICATE_CRAMMD5;
    imapc->authused = SASL_MECH_CRAM_MD5;
  }
  else
#endif
#ifdef USE_NTLM
    if((imapc->authmechs & SASL_MECH_NTLM) &&
       (imapc->prefmech & SASL_MECH_NTLM)) {
    *mech = SASL_MECH_STRING_NTLM;
    *state1 = IMAP_AUTHENTICATE_NTLM;
    *state2 = IMAP_AUTHENTICATE_NTLM_TYPE2MSG;
    imapc->authused = SASL_MECH_NTLM;

    if(imapc->ir_supported || data->set.sasl_ir)
      result = Curl_sasl_create_ntlm_type1_message(conn->user, conn->passwd,
                                                   &conn->ntlm,
                                                   initresp, len);
  }
  else
#endif
  if(((imapc->authmechs & SASL_MECH_XOAUTH2) &&
      (imapc->prefmech & SASL_MECH_XOAUTH2) &&
      (imapc->prefmech != SASL_AUTH_ANY)) || conn->xoauth2_bearer) {
    *mech = SASL_MECH_STRING_XOAUTH2;
    *state1 = IMAP_AUTHENTICATE_XOAUTH2;
    *state2 = IMAP_AUTHENTICATE_FINAL;
    imapc->authused = SASL_MECH_XOAUTH2;

    if(imapc->ir_supported || data->set.sasl_ir)
      result = Curl_sasl_create_xoauth2_message(data, conn->user,
                                                conn->xoauth2_bearer,
                                                initresp, len);
  }
  else if((imapc->authmechs & SASL_MECH_LOGIN) &&
          (imapc->prefmech & SASL_MECH_LOGIN)) {
    *mech = SASL_MECH_STRING_LOGIN;
    *state1 = IMAP_AUTHENTICATE_LOGIN;
    *state2 = IMAP_AUTHENTICATE_LOGIN_PASSWD;
    imapc->authused = SASL_MECH_LOGIN;

    if(imapc->ir_supported || data->set.sasl_ir)
      result = Curl_sasl_create_login_message(data, conn->user, initresp, len);
  }
  else if((imapc->authmechs & SASL_MECH_PLAIN) &&
          (imapc->prefmech & SASL_MECH_PLAIN)) {
    *mech = SASL_MECH_STRING_PLAIN;
    *state1 = IMAP_AUTHENTICATE_PLAIN;
    *state2 = IMAP_AUTHENTICATE_FINAL;
    imapc->authused = SASL_MECH_PLAIN;

    if(imapc->ir_supported || data->set.sasl_ir)
      result = Curl_sasl_create_plain_message(data, conn->user, conn->passwd,
                                              initresp, len);
  }

  return result;
}

#endif /* CURL_DISABLE_IMAP */
