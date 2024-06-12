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
 * RFC5804 A Protocol for Remotely Managing Sieve Scripts
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_SIEVE

#include "urldata.h"
#include "connect.h"
#include "sendf.h"
#include "progress.h"
#include "curl_sasl.h"
#include "sieve.h"
#include "dynbuf.h"
#include "bufref.h"
#include "url.h"
#include "transfer.h"
#include "strtoofft.h"
#include "strcase.h"
#include "escape.h"
#include "vtls/vtls.h"
#include "cfilters.h"
#include "curl_ctype.h"
#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define MAX_STRING_LENGTH       1024    /* Maximum quoted string length. */
#define MAX_ITEMS               10      /* Max. item count in a response. */
#define LIT_START               '{'
#define LIT_END                 '}'

/* Response codes. */
#define SIEVE_RESP_OK           0       /* OK response. */
#define SIEVE_RESP_NO           1       /* NO response. */
#define SIEVE_RESP_OTHER        2       /* Non-atomic response. */
#define SIEVE_RESP_MORE         3       /* Need more data (literal). */
#define SIEVE_RESP_BODY         4       /* Body literal follows. */
#define SIEVE_RESP_ERROR        6       /* Syntax/memory error. */

/* Protocol item types */
typedef enum {
  SIEVE_ITEM_ATOM,
  SIEVE_ITEM_NUMBER,
  SIEVE_ITEM_STRING,
  SIEVE_ITEM_LPARENT,
  SIEVE_ITEM_RPARENT
} sieveitemtype;

/* Item storage */
struct sieveitem {
  sieveitemtype type;
  struct bufref str;
  unsigned int num;
};

/* Local API functions */
static CURLcode sieve_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn);
static CURLcode sieve_multi_statemach(struct Curl_easy *data, bool *done);
static int sieve_getsock(struct Curl_easy *data, struct connectdata *conn,
                         curl_socket_t *socks);
static CURLcode sieve_connect(struct Curl_easy *data, bool *done);
static CURLcode sieve_do(struct Curl_easy *data, bool *done);
static CURLcode sieve_doing(struct Curl_easy *data, bool *dophase_done);
static CURLcode sieve_done(struct Curl_easy *data, CURLcode status,
                           bool premature);
static CURLcode sieve_disconnect(struct Curl_easy *data,
                                 struct connectdata *conn,
                                 bool dead_connection);

static CURLcode sieve_sasl_start(struct Curl_easy *data, const char *mech,
                                 const struct bufref *initresp);
static CURLcode sieve_sasl_continue(struct Curl_easy *data, const char *mech,
                                    const struct bufref *resp);
static CURLcode sieve_sasl_cancel(struct Curl_easy *data, const char *mech);
static CURLcode sieve_sasl_get_message(struct Curl_easy *data,
                                       struct bufref *out);

/*
 * Sieve (aka ManageSieve) protocol handler.
 */

const struct Curl_handler Curl_handler_sieve = {
  "SIEVE",                          /* scheme */
  sieve_setup_connection,           /* setup_connection */
  sieve_do,                         /* do_it */
  sieve_done,                       /* done */
  ZERO_NULL,                        /* do_more */
  sieve_connect,                    /* connect_it */
  sieve_multi_statemach,            /* connecting */
  sieve_doing,                      /* doing */
  sieve_getsock,                    /* proto_getsock */
  sieve_getsock,                    /* doing_getsock */
  ZERO_NULL,                        /* domore_getsock */
  ZERO_NULL,                        /* perform_getsock */
  sieve_disconnect,                 /* disconnect */
  ZERO_NULL,                        /* write_resp */
  ZERO_NULL,                        /* write_resp_hd */
  ZERO_NULL,                        /* connection_check */
  ZERO_NULL,                        /* attach_connection */
  PORT_SIEVE,                       /* defport */
  CURLPROTO_SIEVE,                  /* protocol */
  CURLPROTO_SIEVE,                  /* family */
  PROTOPT_CLOSEACTION |             /* flags */
  PROTOPT_URLOPTIONS
};

/* SASL parameters for the sieve protocol */
static const struct SASLproto saslsieve = {
  "sieve",                /* The service name */
  sieve_sasl_start,       /* Send authentication command */
  sieve_sasl_continue,    /* Send authentication continuation */
  sieve_sasl_cancel,      /* Cancel authentication */
  sieve_sasl_get_message, /* Get SASL response message */
  0,                      /* No maximum initial response length */
  SIEVE_RESP_OTHER,       /* Code received when continuation is expected */
  SIEVE_RESP_OK,          /* Code to receive upon authentication success */
  SASL_AUTH_DEFAULT,      /* Default mechanisms */
  SASL_FLAG_BASE64        /* Configuration flags */
};


/*
 * sieve_state()
 *
 * This is the ONLY way to change sieve state!
 */
static void sieve_state(struct Curl_easy *data, sievestate newstate)
{

  struct sieve_conn *sievec = &data->conn->proto.sievec;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[] = {
    "STOP",
    "SERVERGREET",
    "STARTTLS",
    "UPGRADETLS",
    "TLS",
    "AUTHENTICATE",
    "CAPABILITY",
    "LISTSCRIPTS",
    "PUTSCRIPT",
    "GETSCRIPT",
    "GETSCRIPT_FINAL",
    "LOGOUT",
    /* LAST */
  };

  if(sievec->state != newstate)
    infof(data, "sieve %p state change from %s to %s",
          (void *) sievec, names[sievec->state], names[newstate]);
#endif

  sievec->state = newstate;
}


/* Does a bufref case-insensitively match a null-terminated string ? */
static bool refstrcasecompare(const struct bufref *ref, const char *s)
{
  const char *p = (const char *) Curl_bufref_ptr(ref);
  size_t len = Curl_bufref_len(ref);

  if(!p)
    return FALSE;

  return len == strlen(s) && strncasecompare(p, s, len);
}

/* Can the argument be expressed as a quoted string without escapes ? */
static bool can_quote(const char *s, size_t len)
{
  const char *p = s;
  size_t n = len;

  for(;; p++) {
    if(!n--)
      return p - s <= MAX_STRING_LENGTH;
    switch(*p) {
    case '\0':
      return len != CURL_ZERO_TERMINATED? FALSE: p - s <= MAX_STRING_LENGTH;
    case '"':
    case '\\':
    case '\r':
    case '\n':
      return FALSE;
    default:
      if((*p & 0xFC) == 0xFC)
        return FALSE;   /* Not UTF-8 */
      break;
    }
  }

  /* NOTREACHED */
}

static CURLcode sieve_client_write(struct Curl_easy *data, const char *prefix1,
                                   const char *prefix2, const char *value,
                                   size_t len, const char *suffix)
{
  CURLcode result = CURLE_OK;

  if(prefix1)
    result = Curl_client_write(data, CLIENTWRITE_BODY,
                               (char *) prefix1, strlen(prefix1));
  if(!result && prefix2)
    result = Curl_client_write(data, CLIENTWRITE_BODY,
                               (char *) prefix2, strlen(prefix2));
  if(!result && value)
    result = Curl_client_write(data, CLIENTWRITE_BODY, (char *) value, len);
  if(!result && suffix)
    result = Curl_client_write(data, CLIENTWRITE_BODY,
                               (char *) suffix, strlen(suffix));
  return result;
}

/* Parse the URL path into separate path components. */
static CURLcode sieve_parse_url_path(struct Curl_easy *data,
                                     char **owner, char **scriptname)
{
  CURLcode result = CURLE_OK;
  const char *ptr = data->state.up.path;
  int n = 0;
  char *components[2];
  const char *begin;
  size_t olen;

  if(owner)
    *owner = NULL;
  if(scriptname)
    *scriptname = NULL;

  do {
    if(n >= 2) {
      result = CURLE_URL_MALFORMAT;
      break;
    }

    for(begin = ++ptr; *ptr && *ptr != '/'; ptr++)
      ;

    components[n] = NULL;

    if(ptr > begin) {
      result = Curl_urldecode(begin, ptr - begin, components + n,
                              &olen, REJECT_CTRL);
      if(result)
        break;
    }
    n++;
  } while(*ptr);

  if(!result) {
    switch(n) {
    case 1:       /* sieve://authority/[scriptname] */
      if(scriptname) {
        *scriptname = components[0];
        components[0] = NULL;
      }
      break;
    case 2:       /* sieve://authority/[owner]/[scriptname] */
      /* RFC 5804 specifies an empty owner in the URL should direct referencing
       * a global script, but the protocol does not support such a reference:
       * the owner is passed to the server as the SASL authorisation id,
       * but SASL mechanisms do not make a difference between a zero-length
       * authzid and the absence of authzid (whose semantic is to derive the
       * authzid from the authcid). */
      if(!components[0]) {
        failf(data, "global scripts are not supported");
        result = CURLE_URL_MALFORMAT;
        break;
      }
      if(owner) {
        *owner = components[0];
        components[0] = NULL;
      }
      if(scriptname) {
        *scriptname = components[1];
        components[1] = NULL;
      }
      break;
    }
  }

  while(n--)
    free(components[n]);

  return result;
}

static CURLcode sieve_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  CURLcode result;
  char *owner;

  /* Path must be parsed now as it may specify an authzid. */
  result = sieve_parse_url_path(data, &owner, NULL);
  if(result)
    return result;

  if(owner) {
    free(conn->sasl_authzid);
    conn->sasl_authzid = owner;
  }

  data->req.p.sieve = calloc(sizeof(*data->req.p.sieve), 1);
  if(!data->req.p.sieve)
    return CURLE_OUT_OF_MEMORY;

  /* Clear the TLS upgraded flag */
  conn->bits.tls_upgraded = FALSE;

  return result;
}

/* Parse the custom request.  */
static CURLcode sieve_parse_custom_request(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct SIEVE *sieve = data->req.p.sieve;
  const char *custom = data->set.str[STRING_CUSTOMREQUEST];

  Curl_safefree(sieve->custom);
  Curl_safefree(sieve->custom_params);

  if(custom) {
    /* URL decode the custom request */
    result = Curl_urldecode(custom, 0, &sieve->custom, NULL, REJECT_CTRL);

    /* Extract the parameters if specified */
    if(!result) {
      char *params = sieve->custom;
      char c = *params;

      while(c && c != ' ')
        c = *++params;

      if(c) {
        *params = '\0';
        sieve->custom_params = strdup(++params);

        if(!sieve->custom_params)
          result = CURLE_OUT_OF_MEMORY;
      }
    }
  }

  return result;
}

/* For the sieve "protocol connect" and "doing" phases only */
static int sieve_getsock(struct Curl_easy *data,
                         struct connectdata *conn,
                         curl_socket_t *socks)
{
  return Curl_pp_getsock(data, &conn->proto.sievec.pp, socks);
}

/* Check presence and content of an URL part. */
static CURLcode check_url_part(CURLU *uh, CURLUPart part,
                               CURLUcode empty, const char *mustbe)
{
  char *p = NULL;
  CURLcode result = CURLE_URL_MALFORMAT;
  CURLUcode r = curl_url_get(uh, part, &p, 0);

  if(r && r != empty)
    result = Curl_uc_to_curlcode(r);
  else if(!p) {
    if(!mustbe)
      result = CURLE_OK;
  }
  else if(mustbe)
    if(!mustbe[0] || strcasecompare(p, mustbe))
      result = CURLE_OK;

  free(p);
  return result;
}

/* Copy an URL part to another URL. */
static CURLcode copy_url_part(CURLU *to, CURLU *from,
                              CURLUPart part, CURLUcode empty)
{
  char *p = NULL;
  CURLcode result = CURLE_OK;
  CURLUcode r = curl_url_get(from, part, &p, 0);

  if(r && r != empty)
    result = Curl_uc_to_curlcode(r);
  else {
    r = curl_url_set(to, part, p, 0);
    if(r)
      result = Curl_uc_to_curlcode(r);
    free(p);
  }
  return result;
}

/* Handle referral response code. */
static CURLcode sieve_referral(struct Curl_easy *data,
                               size_t itemcount, struct sieveitem *items)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  CURLU *uh = NULL;
  CURLcode result = CURLE_OK;
  CURLUcode r = CURLUE_OK;
  char *url;

  curl_url_cleanup(sievec->referral);
  sievec->referral = NULL;
  sievec->flags &= ~SIEVE_CONN_REDIRECTED;

  if(itemcount < 2 ||
     items->type != SIEVE_ITEM_STRING || items[1].type != SIEVE_ITEM_RPARENT)
    return CURLE_WEIRD_SERVER_REPLY;

  /* Get the new server URL. */
  url = (char *) Curl_bufref_ptr(&items->str);

  /* Make sure it does not contain a null byte. */
  if(strlen(url) != Curl_bufref_len(&items->str))
    return CURLE_WEIRD_SERVER_REPLY;

  /* Parse it. */
  uh = curl_url();
  if(!uh)
    return CURLE_OUT_OF_MEMORY;
  r = curl_url_set(uh, CURLUPART_URL, url, CURLU_PATH_AS_IS);
  if(r)
    result = Curl_uc_to_curlcode(r);

  /* Check URL: it must be an absolute sieve URL and have no path, query
     and fragment. Userinfo is also forbidden here for safety reasons. */
  if(!result)
    result = check_url_part(uh, CURLUPART_SCHEME, CURLUE_NO_SCHEME, "sieve");
  if(!result)
    result = check_url_part(uh, CURLUPART_USER, CURLUE_NO_USER, NULL);
  if(!result)
    result = check_url_part(uh, CURLUPART_PASSWORD, CURLUE_NO_PASSWORD, NULL);
  if(!result)
    result = check_url_part(uh, CURLUPART_OPTIONS, CURLUE_NO_OPTIONS, NULL);
  if(!result)
    result = check_url_part(uh, CURLUPART_HOST, CURLUE_NO_HOST, "");
  if(!result)
    result = check_url_part(uh, CURLUPART_PATH, CURLUE_OK, "/");
  if(!result)
    result = check_url_part(uh, CURLUPART_QUERY, CURLUE_NO_QUERY, NULL);
  if(!result)
    result = check_url_part(uh, CURLUPART_FRAGMENT, CURLUE_NO_FRAGMENT, NULL);
  if(result == CURLE_URL_MALFORMAT)
    result = CURLE_WEIRD_SERVER_REPLY;

  if(!result) {
    sievec->flags |= SIEVE_CONN_REDIRECTED;
    sievec->referral = uh;
  }
  else
    curl_url_cleanup(uh);

  return result;
}

/*
 * Handle retry/redirection by forcing Curl_follow() to be called by the
 * multi state machine.
 */
static CURLcode sieve_follow(struct Curl_easy *data, CURLcode status)
{
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  CURLcode result = CURLE_OK;

  if(sievec->flags & SIEVE_CONN_REDIRECTED) {
    CURLU *uh = sievec->referral;
    bool fake = !data->set.http_follow_location;

    if(!uh)
      return status;    /* Already processed. */

    connclose(conn, "referral");

    /* Check server redirection count limit. */
    fake |= data->state.followlocation >= (long) sievec->maxredirs;

#ifdef USE_SSL
    /* For security reasons, do not redirect if SSL requested and not
       yet established. */
    fake |= data->set.use_ssl && !Curl_conn_is_ssl(conn, FIRSTSOCKET);
#endif

    /* Build the new URL. */
    sievec->referral = NULL;
    if(data->set.allow_auth_to_other_hosts) {
      result = copy_url_part(uh, data->state.uh,
                             CURLUPART_USER, CURLUE_NO_USER);
      if(!result)
        result = copy_url_part(uh, data->state.uh,
                               CURLUPART_PASSWORD, CURLUE_NO_PASSWORD);
    }
    if(!result)
      result = copy_url_part(uh, data->state.uh,
                             CURLUPART_OPTIONS, CURLUE_NO_OPTIONS);
    if(!result)
      result = copy_url_part(uh, data->state.uh, CURLUPART_PATH, CURLUE_OK);
    if(!result)
      result = copy_url_part(uh, data->state.uh,
                             CURLUPART_QUERY, CURLUE_NO_QUERY);
    if(!result)
      result = copy_url_part(uh, data->state.uh,
                             CURLUPART_FRAGMENT, CURLUE_NO_FRAGMENT);

    /* Store the new URL where multi state machine expects to find it. */
    if(result)
      curl_url_cleanup(uh);
    else {
      char *p = NULL;
      CURLUcode r = curl_url_get(uh, CURLUPART_URL, &p, 0);

      curl_url_cleanup(uh);

      if(r)
        result = Curl_uc_to_curlcode(r);
      else if(fake) {
        free(data->info.wouldredirect);
        data->info.wouldredirect = p;
        infof(data, "Faking redirection to %s", p);
        /* This is always an error since the requested command has not
           succeeded. */
        return CURLE_TOO_MANY_REDIRECTS;
      }
      else {
        /* Redirect. */
        free(data->req.newurl);
        data->req.newurl = p;
        infof(data, "Redirected to %s", p);
      }
    }
  }
  else if((sievec->flags & SIEVE_CONN_BYE) && status != CURLE_LOGIN_DENIED) {
    /* Force retry in Curl_retry_request(). */
    data->state.refused_stream = TRUE;
    connclose(conn, "retry");
    infof(data, "BYE received: retrying");
  }
  else
    return status;

  if(!result) {
    sieve_state(data, SIEVE_STOP);
    status = CURLE_OK;
    /* Force a dummy transfer to direct multi state machine to the
       performing state. */
    data->state.select_bits = CURL_CSELECT_IN;
    Curl_xfer_setup1(data, CURL_XFER_RECV, 0, FALSE);
    data->req.headerbytecount = 0;      /* Do not care about headers. */
    data->req.httpcode = 401;    /* Trick Curl_follow() to avoid url change. */
  }

  return status? status: result;
}

/* Send a sieve command with possible data upload. */
static CURLcode send_sieve_command(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   const char *command,
                                   size_t cmdlen,
                                   const char *params,
                                   const char *scriptname,
                                   bool allow_upload,
                                   sievestate newstate)
{
  struct sieve_conn *sievec = &conn->proto.sievec;
  CURLcode result = CURLE_OK;
  struct dynbuf buf;

  /* Do not send a command if BYE received or redirected. */
  if(sievec->flags & (SIEVE_CONN_BYE | SIEVE_CONN_REDIRECTED))
    return sieve_follow(data, CURLE_OK);

  Curl_dyn_init(&buf, CURL_MAX_INPUT_LENGTH);
  sievec->donestate = SIEVE_STOP;
  result = Curl_dyn_addn(&buf, command, cmdlen);
  if(result)
    return result;

  /* Append parameters or script name. */
  if(params) {
    result = Curl_dyn_addn(&buf, STRCONST(" "));
    if(!result)
      result = Curl_dyn_add(&buf, params);
  }
  else if(scriptname) {
    result = Curl_dyn_addn(&buf, STRCONST(" "));
    if(!result) {
      if(can_quote(scriptname, CURL_ZERO_TERMINATED))
        result = Curl_dyn_addf(&buf, "\"%s\"", scriptname);
      else
        result = Curl_dyn_addf(&buf, "{%u+}\r\n%s",
                               (unsigned int) strlen(scriptname), scriptname);
    }
  }

  /* If an upload is required, append the literal header. */
  if(!result && data->state.upload && allow_upload) {
    if(data->state.infilesize < 0) {
      failf(data, "Cannot %s with unknown input file size", command);
      result = CURLE_UPLOAD_FAILED;
    }
    else {
      result = Curl_dyn_addf(&buf, " {%u+}",
                             (unsigned int) data->state.infilesize);
      if(!result) {
        sievec->donestate = newstate;
        newstate = SIEVE_STOP;

        /* Set the progress upload size */
        Curl_pgrsSetUploadSize(data, data->state.infilesize);

        /* Sieve upload. */
        Curl_xfer_setup1(data, CURL_XFER_SEND, -1, FALSE);
      }
    }
  }

  /* Send the command. */
  if(!result)
    result = Curl_pp_sendf(data, &sievec->pp, "%s", Curl_dyn_ptr(&buf));
  Curl_dyn_free(&buf);

  /* Enter new state. */
  if(!result)
    sieve_state(data, newstate);

  return result;
}

/* SASL authentication callbacks. */
static CURLcode sieve_sasl_get_message(struct Curl_easy *data,
                                       struct bufref *out)
{
  *out = data->conn->proto.sievec.saslmsg;
  return CURLE_OK;
}

static CURLcode sieve_sasl_start(struct Curl_easy *data, const char *mech,
                                 const struct bufref *initresp)
{
  CURLcode result = CURLE_OK;
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  const char *ir = (const char *) Curl_bufref_ptr(initresp);
  size_t irlen = Curl_bufref_len(initresp);

  if(!ir) {
    /* Send the AUTHENTICATE command */
    result = Curl_pp_sendf(data, &sievec->pp, "AUTHENTICATE \"%s\"", mech);
  }
  else if(can_quote(ir, irlen)) {
    /* Send the AUTHENTICATE command with the initial response quoted */
    result = Curl_pp_sendf(data, &sievec->pp, "AUTHENTICATE \"%s\" \"%s\"",
                           mech, ir);
  }
  else {
    /* Send the AUTHENTICATE command with the initial response as a literal */
    result = Curl_pp_sendf(data, &sievec->pp,
                           "AUTHENTICATE \"%s\" {%u+}\r\n%s",
                           mech, (unsigned int) irlen, ir);
  }

  return result;
}

static CURLcode sieve_sasl_continue(struct Curl_easy *data, const char *mech,
                                    const struct bufref *resp)
{
  CURLcode result = CURLE_OK;
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  const char *r = (const char *) Curl_bufref_ptr(resp);
  size_t rlen = Curl_bufref_len(resp);

  (void) mech;

  if(can_quote(r, rlen))
    result = Curl_pp_sendf(data, &sievec->pp, "\"%s\"", r);
  else
    result = Curl_pp_sendf(data, &sievec->pp, "{%u+}\r\n%s",
                           (unsigned int) rlen, r);

  return result;
}

static CURLcode sieve_sasl_cancel(struct Curl_easy *data, const char *mech)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;

  (void) mech;

  return Curl_pp_sendf(data, &sievec->pp, "\"*\"");
}

static CURLcode sieve_perform_authenticate(struct Curl_easy *data)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  saslprogress progress;
  CURLcode result = CURLE_OK;

  /* Do not submit a command if BYE received or redirected. */
  if(sievec->flags & (SIEVE_CONN_BYE | SIEVE_CONN_REDIRECTED))
    return sieve_follow(data, CURLE_OK);

  /* If an untrusted redirection occurred, accept to authenticate only
     with mechanisms not involving credentials. */
  if(data->state.this_is_a_follow && !data->set.allow_auth_to_other_hosts) {
    char *svuser = data->state.aptr.user;
    bool can;

    data->state.aptr.user = NULL;
    can = Curl_sasl_can_authenticate(&sievec->sasl, data);
    data->state.aptr.user = svuser;

    if(!can) {
      /* No error, to obey options. */
      sieve_state(data, SIEVE_STOP);
      return result;
    }
  }
  else if(!Curl_sasl_can_authenticate(&sievec->sasl, data)) {
    /* Authentication not possible: error if requested. */
    if(data->state.aptr.user) {
      failf(data, "No enabled authentication mechanism available");
      return CURLE_LOGIN_DENIED;
    }

    /* No authentication requested. */
    sieve_state(data, SIEVE_STOP);
    return result;
  }

  /* Start authentication dialog. */
  result = Curl_sasl_start(&sievec->sasl, data, TRUE, &progress);

  if(!result) {
    if(progress == SASL_INPROGRESS)
      sieve_state(data, SIEVE_AUTHENTICATE);
    else {
      infof(data, "No known authentication mechanisms supported");
      result = CURLE_LOGIN_DENIED;
    }
  }

  return result;
}

static CURLcode sieve_perform_capability(struct Curl_easy *data)
{
  return send_sieve_command(data, data->conn, STRCONST("CAPABILITY"),
                            NULL, NULL, FALSE, SIEVE_CAPABILITY);
}

/* Send a LISTSCRIPTS command. */
static CURLcode sieve_perform_listscripts(struct Curl_easy *data)
{
  return send_sieve_command(data, data->conn, STRCONST("LISTSCRIPTS"),
                            NULL, NULL, FALSE, SIEVE_LISTSCRIPTS);
}

/* Send a PUTSCRIPT command. */
static CURLcode sieve_perform_putscript(struct Curl_easy *data)
{
  struct SIEVE *sieve = data->req.p.sieve;

  return send_sieve_command(data, data->conn, STRCONST("PUTSCRIPT"),
                            NULL, sieve->scriptname, TRUE, SIEVE_PUTSCRIPT);
}

/* Send a GETSCRIPT command. */
static CURLcode sieve_perform_getscript(struct Curl_easy *data)
{
  struct SIEVE *sieve = data->req.p.sieve;

  return send_sieve_command(data, data->conn, STRCONST("GETSCRIPT"),
                            NULL, sieve->scriptname, FALSE, SIEVE_GETSCRIPT);
}

/* Send a LOGOUT command. */
static CURLcode sieve_perform_logout(struct Curl_easy *data,
                                     struct connectdata *conn)
{
  struct sieve_conn *sievec = &conn->proto.sievec;
  unsigned int saveflags = sievec->flags;
  CURLcode result;

  /* Send the logout command even if redirected. */
  sievec->flags &= ~SIEVE_CONN_REDIRECTED;
  result = send_sieve_command(data, conn, STRCONST("LOGOUT"),
                              NULL, NULL, FALSE, SIEVE_LOGOUT);
  sievec->flags = saveflags;
  return result;
}

/*
 *  Read bytes from input stream, taking into account some may be buffered
 * in the pingpong receive buffer.
 */
static CURLcode pp_read(struct Curl_easy *data,
                        struct pingpong *pp,
                        char *buf,
                        size_t size,
                        size_t *gotbytes)
{
  CURLcode result = CURLE_OK;
  ssize_t n;

  DEBUGASSERT(size);
  *gotbytes = 0;

  if(!pp->overflow) {
    result = Curl_xfer_recv(data, buf, size, &n);
    if(!result)
      *gotbytes = (size_t) n;
  }
  else {
    if(size > pp->overflow)
      size = pp->overflow;

    memcpy(buf, Curl_dyn_ptr(&pp->recvbuf) + pp->nfinal, size);
    if(pp->overflow > size)
      Curl_dyn_tail(&pp->recvbuf, pp->overflow - size);
    else
      Curl_dyn_reset(&pp->recvbuf);
    pp->nfinal = 0;
    pp->overflow -= size;
    *gotbytes = size;
  }

  return result;
}

/* Parse a quoted string. */
static CURLcode parse_string(char **buf, struct bufref *string)
{
  char *src = *buf;
  char *dst = src;
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  if(*src++ == '"') {
    for(;;) {
      switch(*src) {
      case '\0':
      case '\r':
      case '\n':
        break;
      case '"':
        *dst = '\0';
        Curl_bufref_set(string, *buf, dst - *buf, NULL);
        *buf = src + 1;
        result = CURLE_OK;
        break;
      case '\\':
        src++;
        if(!*src || *src == '\r' || *src == '\n')
          break;
        *dst++ = *src++;
        continue;
      default:
        *dst++ = *src++;
        continue;
      }

      break;
    }
  }

  return result;
}

/* Parse an atom. */
static CURLcode parse_atom(char **buf, struct bufref *atom)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;
  char *p;
  static const char *stopchars = "() {}\"\r\n";

  for(p = *buf; *p && !strchr(stopchars, *p); p++)
    *p = Curl_raw_toupper(*p);

  if(p - *buf) {
    Curl_bufref_set(atom, *buf, p - *buf, NULL);
    *buf = p;
    result = CURLE_OK;
  }

  return result;
}

/* Parse a number. */
static CURLcode parse_number(char **buf, unsigned int *number)
{
  char *p = *buf;
  curl_off_t num = 0;

  if(!ISDIGIT(*p))
    return CURLE_WEIRD_SERVER_REPLY;

  if(*p == '0')
    p++;
  else if(curlx_strtoofft(p, &p, 10, &num))
    return CURLE_WEIRD_SERVER_REPLY;

  if(p == *buf || (num & ~CURL_OFF_TU_C(0xFFFFFFFF)))
    return CURLE_WEIRD_SERVER_REPLY;

  *number = (unsigned int) num;
  *buf = p;
  return CURLE_OK;
}

/* Parse a literal. Only the length is decoded: the data is not consumed. */
static CURLcode parse_literal(char **buf, size_t length, size_t *litlength)
{
  char *p = *buf;
  unsigned int n = 0;
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  if(*p == LIT_START) {
    p++;
    result = parse_number(&p, &n);
    if(!result) {
      result = CURLE_WEIRD_SERVER_REPLY;
      if(*p == LIT_END) {
        if(*++p == '\r')
          p++;
        if(*p == '\n')
          p++;
        if(p == *buf + length) {
          *buf = p;
          *litlength = (size_t) n;
          result = CURLE_OK;
        }
      }
    }
  }

  return result;
}

static CURLcode parse_item(char **buf, struct sieveitem *item)
{
  char *src = *buf;
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;
  size_t len = 0;
  char *p;
  char *q;

  Curl_bufref_init(&item->str);
  item->num = 0;
  item->type = SIEVE_ITEM_NUMBER;
  switch(*src) {
  case '"':
    item->type = SIEVE_ITEM_STRING;
    result = parse_string(&src, &item->str);
    break;
  case LIT_START:
    item->type = SIEVE_ITEM_STRING;
    p = src;
    q = strchr(p, '\n');
    if(q)
      result = parse_literal(&p, q - p + 1, &len);
    if(!result) {
      /* Move data to insert a null terminator. */
      if(len)
        memmove(src, p, len);
      src[len] = '\0';
      Curl_bufref_set(&item->str, src, len, NULL);
      src = p + len;
    }
    break;
  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
    result = parse_number(&src, &item->num);
    break;
  case '(':
    item->type = SIEVE_ITEM_LPARENT;
    src++;
    result = CURLE_OK;
    break;
  case ')':
    item->type = SIEVE_ITEM_RPARENT;
    src++;
    result = CURLE_OK;
    break;
  case '\r':
  case '\n':
  case '\0':
    break;
  default:
    item->type = SIEVE_ITEM_ATOM;
    result = parse_atom(&src, &item->str);
    break;
  }

  *buf = src;
  return result;
}

/* Called for each line by Curl_pp_readresp(). */
static bool sieve_endofresp(struct Curl_easy *data, struct connectdata *conn,
                            char *line, size_t len, int *resp)
{
  struct sieve_conn *sievec = &conn->proto.sievec;
  CURLcode result = CURLE_OK;
  bool lit;
  size_t n;

  (void) data;

  *resp = SIEVE_RESP_ERROR;

  /* Check for received script: has to be handled as a transfer. */
  if(sievec->state == SIEVE_GETSCRIPT && !Curl_dyn_len(&sievec->respbuf) &&
     line[0] == LIT_START) {
    *resp = SIEVE_RESP_BODY;
    return TRUE;
  }

  /* Strip trailing end of line characters. */
  for(n = len; n--;)
    if(line[n] != '\r' && line[n] != '\n')
      break;

  n++;
  lit = n && line[n - 1] == LIT_END;            /* Literal follows. */

  /* Concatenate lines if response contains at least one literal. */
  if(lit || Curl_dyn_len(&sievec->respbuf)) {
    result = Curl_dyn_addn(&sievec->respbuf, line, len);
    if(result)
      return TRUE;
  }

  /* If a literal follows, prepare to read it. */
  if(lit) {
    char *p;

    result = CURLE_WEIRD_SERVER_REPLY;
    for(n--; n--;)
      if(!ISDIGIT(line[n]))
        break;
    p = line + n;
    if(++n > 0)
      result = parse_literal(&p, line + len - p, &sievec->litlength);
    if(!result)
      *resp = SIEVE_RESP_MORE;
  }
  else {
    /* End of response: delay further code processing after parsing. */
    *resp = SIEVE_RESP_OTHER;
  }

  return TRUE;
}

static CURLcode read_literal(struct Curl_easy *data, size_t *nread)
{
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  char buf[512];
  size_t n = sievec->litlength < sizeof(buf)?  sievec->litlength: sizeof(buf);
  CURLcode result = pp_read(data, &sievec->pp, buf, n, nread);

  if(result == CURLE_AGAIN)
    result = CURLE_OK;

  if(!result && *nread > 0) {
    Curl_debug(data, CURLINFO_HEADER_IN, buf, *nread);
    result = Curl_dyn_addn(&sievec->respbuf, buf, *nread);
    if(!result)
      sievec->litlength -= *nread;
  }

  return result;
}

static CURLcode unexpected_response(struct Curl_easy *data,
                                    const char *command,
                                    const char *custom)
{
  if(custom)
    command = custom;

  failf(data, "Unexpected response to %s command", command);
  return CURLE_WEIRD_SERVER_REPLY;
}

/* Set error message if given in (OK/NO/BYE) response. */
static void sieve_error_message(struct Curl_easy *data, struct sieveitem *p)
{
  if(p->type == SIEVE_ITEM_STRING)
    failf(data, "%.*s", (int) Curl_bufref_len(&p->str),
          Curl_bufref_ptr(&p->str));
}

/* Handle a capability data record. */
static CURLcode sieve_capability_data(struct Curl_easy *data,
                                      size_t itemcount,
                                      struct sieveitem *items)
{
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  CURLcode result = CURLE_OK;

  if(items->type != SIEVE_ITEM_STRING)
    result = CURLE_WEIRD_SERVER_REPLY;
  else {
    if(refstrcasecompare(&items->str, "STARTTLS"))
      sievec->flags |= SIEVE_CONN_HAS_TLS;
    else if(refstrcasecompare(&items->str, "MAXREDIRECTS")) {
      char *p;
      size_t len;

      if(itemcount < 2 || items[1].type != SIEVE_ITEM_STRING)
        result = CURLE_WEIRD_SERVER_REPLY;
      else {
        p = (char *) Curl_bufref_ptr(&items[1].str);
        len = Curl_bufref_len(&items[1].str);
        result = parse_number(&p, &sievec->maxredirs);
        if(!result &&
           (size_t) (p - (char *) Curl_bufref_ptr(&items[1].str)) != len)
          result = CURLE_WEIRD_SERVER_REPLY;
      }
    }
    else if(refstrcasecompare(&items->str, "SASL")) {
      const char *p;
      size_t len;

      if(itemcount < 2 || items[1].type != SIEVE_ITEM_STRING)
        result = CURLE_WEIRD_SERVER_REPLY;
      else {
        p = (const char *) Curl_bufref_ptr(&items[1].str);
        len = Curl_bufref_len(&items[1].str);
        for(;;) {
          const char *q;
          unsigned short mechbit;
          size_t li, lo;

          while(len && *p == ' ') {
            p++;
            len--;
          }

          if(!len)
            break;

          for(q = p; len && *p != ' '; p++)
            len--;

          li = p - q;
          mechbit = Curl_sasl_decode_mech(q, li, &lo);
          if(mechbit && lo == li)
            sievec->sasl.authmechs |= mechbit;
        }
      }
    }
  }

  return result;
}

#ifdef USE_SSL
static CURLcode sieve_perform_starttls(struct Curl_easy *data)
{
  return send_sieve_command(data, data->conn, STRCONST("STARTTLS"),
                            NULL, NULL, FALSE, SIEVE_STARTTLS);
}

static CURLcode sieve_perform_upgrade_tls(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  bool ssldone = FALSE;
  CURLcode result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &ssldone);

  sieve_state(data, SIEVE_UPGRADETLS);
  if(!result && ssldone) {
    conn->bits.tls_upgraded = TRUE;
    sievec->sasl.authmechs = SASL_AUTH_NONE;
    sieve_state(data, SIEVE_TLS);
    result = CURLE_OK;
  }

  return result;
}

static CURLcode sieve_state_tls_resp(struct Curl_easy *data,
                                     size_t itemcount, struct sieveitem *items,
                                     int sievecode)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  switch(sievecode) {
  case SIEVE_RESP_OK:
    result = sieve_perform_authenticate(data);
    break;
  case SIEVE_RESP_NO:
    sieve_error_message(data, &items[itemcount - 1]);
    break;
  case SIEVE_RESP_OTHER:
    result = sieve_capability_data(data, itemcount, items);
    break;
  }

  if(result == CURLE_WEIRD_SERVER_REPLY)
    failf(data, "Unexpected response record in TLS capabilities");

  return result;
}
#endif

static CURLcode sieve_state_servergreet_resp(struct Curl_easy *data,
                                             size_t itemcount,
                                             struct sieveitem *items,
                                             int sievecode)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  switch(sievecode) {
  case SIEVE_RESP_OK:
#ifdef USE_SSL
    if(data->set.use_ssl) {
      struct connectdata *conn = data->conn;
      struct sieve_conn *sievec = &conn->proto.sievec;

      if(sievec->flags & SIEVE_CONN_HAS_TLS)
        result = sieve_perform_starttls(data);
      else if(data->set.use_ssl <= CURLUSESSL_TRY)
        result = sieve_perform_authenticate(data);
      else {
        failf(data, "STARTTLS not supported");
        result = CURLE_USE_SSL_FAILED;
      }
    }
#else
    if(data->set.use_ssl > CURLUSESSL_TRY) {
      failf(data, "SSL/TLS not compiled in");
      result = CURLE_USE_SSL_FAILED;
      break;
    }
#endif
    else
      result = sieve_perform_authenticate(data);
    break;
  case SIEVE_RESP_NO:
    sieve_error_message(data, &items[itemcount - 1]);
    break;
  case SIEVE_RESP_OTHER:
    result = sieve_capability_data(data, itemcount, items);
    break;
  }

  if(result == CURLE_WEIRD_SERVER_REPLY)
    failf(data, "Unexpected response record in server greeting");

  return result;
}

static CURLcode sieve_state_capability_resp(struct Curl_easy *data,
                                            size_t itemcount,
                                            struct sieveitem *items,
                                            int sievecode)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  switch(sievecode) {
  case SIEVE_RESP_NO:
    break;
  case SIEVE_RESP_OK:
    result = CURLE_OK;
    sieve_state(data, SIEVE_STOP);
    break;
  case SIEVE_RESP_OTHER:
    result = sieve_capability_data(data, itemcount, items);
    break;
  }

  if(result == CURLE_WEIRD_SERVER_REPLY)
    unexpected_response(data, "CAPABILITY", NULL);

  return result;
}

static CURLcode sieve_state_authenticate_resp(struct Curl_easy *data,
                                              size_t itemcount,
                                              struct sieveitem *items,
                                              int sievecode)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  CURLcode result = CURLE_OK;
  saslprogress progress;

  Curl_bufref_set(&sievec->saslmsg, "", 0, NULL);
  switch(sievecode) {
  case SIEVE_RESP_OK:
    break;
  case SIEVE_RESP_NO:
    if(sievec->flags & SIEVE_CONN_BYE)
      return CURLE_LOGIN_DENIED;
    break;
  case SIEVE_RESP_OTHER:
    if(items->type != SIEVE_ITEM_STRING || itemcount != 1)
      return unexpected_response(data, "AUTHENTICATE", NULL);

    /* Prepare for SASL get_message callback. */
    Curl_bufref_set(&sievec->saslmsg, Curl_bufref_ptr(&items->str),
                    Curl_bufref_len(&items->str), NULL);
    break;
  default:
    return unexpected_response(data, "AUTHENTICATE", NULL);
  }

  result = Curl_sasl_continue(&sievec->sasl, data, sievecode, &progress);
  if(!result)
    switch(progress) {
    case SASL_DONE:     /* Authenticated. */
      result = sieve_perform_capability(data);
      break;
    case SASL_IDLE:             /* No mechanism left after cancellation. */
      failf(data, "Authentication cancelled");
      result = CURLE_LOGIN_DENIED;
      break;
    default:
      break;
    }

  return result;
}

static CURLcode sieve_state_listscripts_resp(struct Curl_easy *data,
                                             size_t itemcount,
                                             struct sieveitem *items,
                                             int sievecode)
{
  CURLcode result = CURLE_OK;
  struct SIEVE *sieve = data->req.p.sieve;
  char *s;
  const char *sep = "";

  switch(sievecode) {
  case SIEVE_RESP_OK:
    sieve_state(data, SIEVE_STOP);
    break;
  case SIEVE_RESP_NO:
    result = CURLE_QUOTE_ERROR;
    sieve_error_message(data, &items[itemcount - 1]);
    break;
  case SIEVE_RESP_OTHER:
    if(items->type != SIEVE_ITEM_STRING)
      result = unexpected_response(data, "LISTSCRIPTS", sieve->custom);
    else {
      /* Write response record to client. */
      for(; itemcount--; items++) {
        const char *nextsep = " ";
        const char *ptr;

        switch(items->type) {
        case SIEVE_ITEM_ATOM:
          ptr = (const char *) Curl_bufref_ptr(&items->str);
          result = sieve_client_write(data, sep, NULL, ptr,
                                      Curl_bufref_len(&items->str), NULL);
          break;
        case SIEVE_ITEM_STRING:
          ptr = (const char *) Curl_bufref_ptr(&items->str);
          if(can_quote(ptr, Curl_bufref_len(&items->str)))
            result = sieve_client_write(data, sep, "\"", ptr,
                                        Curl_bufref_len(&items->str), "\"");
          else {
            s = aprintf("{%lu}\r\n",
                        (unsigned long) Curl_bufref_len(&items->str));

            if(!s)
              result = CURLE_OUT_OF_MEMORY;
            else {
              result = sieve_client_write(data, sep, s, ptr,
                                          Curl_bufref_len(&items->str), NULL);
              free(s);
            }
          }
          break;
        case SIEVE_ITEM_NUMBER:
          s = aprintf("%u", items->num);
          if(!s)
            result = CURLE_OUT_OF_MEMORY;
          else {
            result = sieve_client_write(data, sep, s, NULL, 0, NULL);
            free(s);
          }
          break;
        case SIEVE_ITEM_LPARENT:
          result = sieve_client_write(data, sep, "(", NULL, 0, NULL);
          nextsep = "";
          break;
        case SIEVE_ITEM_RPARENT:
          result = sieve_client_write(data, ")", NULL, NULL, 0, NULL);
          break;
        default:
          result = unexpected_response(data, "LISTSCRIPTS", sieve->custom);
          break;
        }

        if(data->state.list_only)
          break;

        sep = nextsep;
      }

      if(!result)
        result = sieve_client_write(data, "\r\n", NULL, NULL, 0, NULL);
    }
    break;
  default:
    result = unexpected_response(data, "LISTSCRIPTS", sieve->custom);
    break;
  }

  return result;
}

static CURLcode sieve_state_getscript_final_resp(struct Curl_easy *data,
                                                 size_t itemcount,
                                                 struct sieveitem *items,
                                                 int sievecode)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  switch(sievecode) {
  case SIEVE_RESP_OK:
    result = CURLE_OK;
    sieve_state(data, SIEVE_STOP);
    break;
  case SIEVE_RESP_NO:
    result = CURLE_REMOTE_FILE_NOT_FOUND;
    sieve_error_message(data, &items[itemcount - 1]);
    break;
  }

  if(result == CURLE_WEIRD_SERVER_REPLY)
    unexpected_response(data, "GETSCRIPT", NULL);

  return result;
}

static CURLcode sieve_state_getscript_data(struct Curl_easy *data,
                                           size_t size,
                                           const char *prefix,
                                           size_t prefixsize)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  CURLcode result = CURLE_OK;

  Curl_pgrsSetDownloadSize(data, size);

  if(prefixsize) {
    result = sieve_client_write(data, NULL, NULL, prefix, prefixsize, NULL);

    if(!result)
      Curl_pgrsSetDownloadCounter(data, prefixsize);
  }

  if(result || data->req.bytecount >= curlx_uztoso(size)) {
    Curl_xfer_setup_nop(data);
    sieve_state(data, SIEVE_GETSCRIPT_FINAL);
  }
  else {
    data->req.maxdownload = size;
    data->state.select_bits = CURL_CSELECT_IN;
    Curl_xfer_setup1(data, CURL_XFER_RECV, size, FALSE);
    sievec->donestate = SIEVE_GETSCRIPT_FINAL;
    sieve_state(data, SIEVE_STOP);
  }

  return result;
}

static CURLcode sieve_state_getscript_resp(struct Curl_easy *data,
                                           size_t itemcount,
                                           struct sieveitem *items,
                                           int sievecode,
                                           size_t datasize)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  struct pingpong *pp = &sievec->pp;

  switch(sievecode) {
  case SIEVE_RESP_OTHER:
    if(itemcount == 1 && items[0].type == SIEVE_ITEM_STRING) {
      const char *ptr = (const char *) Curl_bufref_ptr(&items[0].str);
      size_t len = Curl_bufref_len(&items[0].str);

      result = sieve_state_getscript_data(data, len, ptr, len);
    }
    break;
  case SIEVE_RESP_BODY:
    if(pp->overflow) {
      size_t chunk = pp->overflow;

      if(chunk > datasize)
        chunk = datasize;

      result = sieve_state_getscript_data(data, datasize,
                                          Curl_dyn_ptr(&pp->recvbuf) +
                                          pp->nfinal, chunk);
      if(pp->overflow > chunk)
        Curl_dyn_tail(&pp->recvbuf, pp->overflow - chunk);
      else
        Curl_dyn_reset(&pp->recvbuf);
      pp->nfinal = 0;
      pp->overflow -= chunk;
    }
    else
      result = sieve_state_getscript_data(data, datasize, "", 0);
    break;
  default:
    result = sieve_state_getscript_final_resp(data, itemcount, items,
                                              sievecode);
    break;
  }

  if(result == CURLE_WEIRD_SERVER_REPLY)
    unexpected_response(data, "GETSCRIPT", NULL);

  return result;
}

/* Write script analysis diagnostics to client. */
static CURLcode sieve_write_diagnostics(struct Curl_easy *data,
                                        size_t itemcount,
                                        struct sieveitem *items,
                                        bool warnings)
{
  CURLcode result = CURLE_OK;

  items += itemcount - 1;

  if(items->type == SIEVE_ITEM_STRING) {
    const char *ptr = (const char *) Curl_bufref_ptr(&items->str);
    size_t len = Curl_bufref_len(&items->str);

    if(len) {
      if(warnings || len >= CURL_ERROR_SIZE || !can_quote(ptr, len)) {
        result = sieve_client_write(data, NULL, NULL, ptr, len, NULL);
        if(!result)
          failf(data, "%s(s) in script", warnings? "Warning": "Error");
      }
    }
  }

  return result;
}

static CURLcode sieve_state_putscript_resp(struct Curl_easy *data,
                                           size_t itemcount,
                                           struct sieveitem *items,
                                           const struct bufref *respcode,
                                           int sievecode)
{
  struct SIEVE *sieve = data->req.p.sieve;
  CURLcode result = CURLE_OK;

  switch(sievecode) {
  case SIEVE_RESP_OK:
    if(respcode && refstrcasecompare(respcode, "WARNINGS"))
      result = sieve_write_diagnostics(data, itemcount, items, TRUE);
    break;
  case SIEVE_RESP_NO:
    if(!respcode || refstrcasecompare(respcode, "WARNINGS"))
      sieve_write_diagnostics(data, itemcount, items, FALSE);
    else
      sieve_error_message(data, &items[itemcount - 1]);
    result = CURLE_UPLOAD_FAILED;
    break;
  default:
    result = unexpected_response(data, "PUTSCRIPT", sieve->custom);
    break;
  }

  sieve_state(data, SIEVE_STOP);
  return result;
}

static CURLcode sieve_state_logout_resp(struct Curl_easy *data,
                                        size_t itemcount,
                                        struct sieveitem *items,
                                        int sievecode)
{
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  switch(sievecode) {
  case SIEVE_RESP_OK:
    result = CURLE_OK;
    sieve_state(data, SIEVE_STOP);
    break;
  case SIEVE_RESP_NO:
    sieve_error_message(data, &items[itemcount - 1]);
    break;
  }

  if(result == CURLE_WEIRD_SERVER_REPLY)
    unexpected_response(data, "LOGOUT", NULL);

  return result;
}

static CURLcode sieve_statemachine(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  struct sieve_conn *sievec = &conn->proto.sievec;
  struct pingpong *pp = &sievec->pp;
  char *p;
  char *endp;
  int sievecode;
  struct sieveitem items[MAX_ITEMS];
  struct bufref *respcode;
  size_t itemcount;
  size_t nread;
  size_t datasize = 0;
  CURLcode result = CURLE_OK;

#ifdef USE_SSL
  if(sievec->state == SIEVE_UPGRADETLS)
    return sieve_perform_upgrade_tls(data);
#endif

  /* Flush any data that need to be sent. */
  if(pp->sendleft)
    return Curl_pp_flushsend(data, pp);

  do {
    if(sievec->litlength) {       /* Currently reading a literal? */
      result = read_literal(data, &nread);
      if(!nread)
        return result;
      if(result || sievec->litlength)
        continue;
    }

    /* Read some more server response bytes. */
    result = Curl_pp_readresp(data, FIRSTSOCKET, pp, &sievecode, &nread);
    if(result)
      return result;

    itemcount = 0;
    respcode = NULL;

    switch(sievecode) {
    case SIEVE_RESP_ERROR:
      return CURLE_WEIRD_SERVER_REPLY;
    case SIEVE_RESP_MORE:
      continue;
    case SIEVE_RESP_BODY:
      /* Script data is in a literal: prepare transfer. */
      p = Curl_dyn_ptr(&pp->recvbuf);
      result = parse_literal(&p, pp->nfinal, &datasize);
      if(result)
        return result;
      break;
    default:
      /* Parse response items. */
      p = Curl_dyn_ptr(&sievec->respbuf);
      nread = Curl_dyn_len(&sievec->respbuf);
      if(!nread) {
        p = Curl_dyn_ptr(&pp->recvbuf);
        nread = pp->nfinal;
      }
      for(endp = p + nread; !result && p < endp;) {
        switch(*p) {
        case ' ':
        case '\r':
        case '\n':
          p++;
          break;
        default:
          if(itemcount >= MAX_ITEMS)
            result = CURLE_WEIRD_SERVER_REPLY;
          else
            result = parse_item(&p, items + itemcount++);
          break;
        }
      }

      if(result || !itemcount) {  /* Ignore empty line. */
        Curl_dyn_reset(&sievec->respbuf);
        continue;
      }

      /* Determine sieve code from first item. */
      if(items[0].type == SIEVE_ITEM_ATOM) {
        if(refstrcasecompare(&items[0].str, "OK"))
          sievecode = SIEVE_RESP_OK;
        else if(refstrcasecompare(&items[0].str, "NO"))
          sievecode = SIEVE_RESP_NO;
        else if(refstrcasecompare(&items[0].str, "BYE")) {
          /* RFC 5804 does not specify the last command completion status
             when BYE is received. However section 1.2 tells typical uses
             are timeouts or failed authentication excess. This statement
             gives us a hint that the command completion status should be
             understood as "NO". */
          sievec->flags |= SIEVE_CONN_BYE;
          sievecode = SIEVE_RESP_NO;
        }
      }

      /* Process response codes. */
      if(sievecode != SIEVE_RESP_OTHER && itemcount >= 4 &&
         items[1].type == SIEVE_ITEM_LPARENT &&
         items[2].type == SIEVE_ITEM_ATOM) {
        respcode = &items[2].str;
        if(refstrcasecompare(respcode, "REFERRAL"))
          result = sieve_referral(data, itemcount - 3, items + 3);
        else if(sievecode != SIEVE_RESP_OK &&
                (refstrcasecompare(respcode, "QUOTA") ||
                 refstrcasecompare(respcode, "QUOTA/MAXSIZE") ||
                 refstrcasecompare(respcode, "QUOTA/MAXSCRIPTS")))
          result = CURLE_FILESIZE_EXCEEDED;
        else if(refstrcasecompare(respcode, "NONEXISTENT"))
          result = CURLE_REMOTE_FILE_NOT_FOUND;
        else if(refstrcasecompare(respcode, "ACTIVE"))
          result = CURLE_REMOTE_ACCESS_DENIED;
        else if(refstrcasecompare(respcode, "ALREADYEXISTS"))
          result = CURLE_REMOTE_FILE_EXISTS;

        if(result) {
          sieve_error_message(data, &items[itemcount - 1]);
          return result;
        }
      }
      break;
    }

    /* Handle responses. */
    switch(sievec->state) {
    case SIEVE_SERVERGREET:
      result = sieve_state_servergreet_resp(data, itemcount, items, sievecode);
      break;

#ifdef USE_SSL
    case SIEVE_STARTTLS:
      /* Pipelining in response is forbidden. */
      if(pp->overflow) {
        Curl_dyn_reset(&sievec->respbuf);
        return CURLE_WEIRD_SERVER_REPLY;
      }
      switch(sievecode) {
      case SIEVE_RESP_OK:
        result = Curl_ssl_cfilter_add(data, conn, FIRSTSOCKET);
        if(!result)
          result = sieve_perform_upgrade_tls(data);
        Curl_dyn_reset(&sievec->respbuf);
        return result;
      case SIEVE_RESP_NO:
        if(data->set.use_ssl != CURLUSESSL_TRY) {
          result = CURLE_USE_SSL_FAILED;
          sieve_error_message(data, &items[itemcount - 1]);
        }
        else
          result = sieve_perform_authenticate(data);
        break;
      default:
        unexpected_response(data, "STARTTLS", NULL);
        break;
      }
      break;

    case SIEVE_TLS:
      result = sieve_state_tls_resp(data, itemcount, items, sievecode);
      break;
#endif

    case SIEVE_AUTHENTICATE:
      result = sieve_state_authenticate_resp(data,
                                             itemcount, items, sievecode);
      break;
    case SIEVE_CAPABILITY:
      result = sieve_state_capability_resp(data, itemcount, items, sievecode);
      break;
    case SIEVE_LISTSCRIPTS:
      result = sieve_state_listscripts_resp(data, itemcount, items, sievecode);
      break;
    case SIEVE_GETSCRIPT:
      result = sieve_state_getscript_resp(data, itemcount, items, sievecode,
                                          datasize);
      break;
    case SIEVE_GETSCRIPT_FINAL:
      result = sieve_state_getscript_final_resp(data, itemcount, items,
                                                sievecode);
      break;
    case SIEVE_PUTSCRIPT:
      result = sieve_state_putscript_resp(data, itemcount, items,
                                          respcode, sievecode);
      break;
    case SIEVE_LOGOUT:
      result = sieve_state_logout_resp(data, itemcount, items, sievecode);
      break;
    default:
      /* Internal error. */
      sieve_state(data, SIEVE_STOP);
      break;
    }

    Curl_dyn_reset(&sievec->respbuf);

    /* Perform retry/redirection if it as been requested.
       If the current request has been completed, defer this to the
       next connection reuse. */
    if(sievec->state != SIEVE_STOP)
      result = sieve_follow(data, result);
  } while(!result && sievec->state != SIEVE_STOP && Curl_pp_moredata(pp));

  return result;
}

/* Called repeatedly until done from multi.c */
static CURLcode sieve_multi_statemach(struct Curl_easy *data, bool *done)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  CURLcode result = Curl_pp_statemach(data, &sievec->pp, FALSE, FALSE);

  *done = sievec->state == SIEVE_STOP;
  return result;
}

static CURLcode sieve_block_statemach(struct Curl_easy *data,
                                      struct connectdata *conn,
                                      bool disconnecting)
{
  CURLcode result = CURLE_OK;
  struct sieve_conn *sievec = &conn->proto.sievec;

  while(sievec->state != SIEVE_STOP && !result)
    result = Curl_pp_statemach(data, &sievec->pp, TRUE, disconnecting);

  return result;
}

/* Parse the URL login options. */
static CURLcode sieve_parse_url_options(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct sieve_conn *sievec = &conn->proto.sievec;
  const char *ptr = conn->options;

  sievec->sasl.resetprefs = TRUE;

  while(!result && ptr && *ptr) {
    const char *key = ptr;
    const char *value;

    while(*ptr && *ptr != '=')
      ptr++;

    value = ptr + 1;

    while(*ptr && *ptr != ';')
      ptr++;

    if(strncasecompare(key, "AUTH=", 5))
      result = Curl_sasl_parse_url_auth_option(&sievec->sasl,
                                               value, ptr - value);
    else
      result = CURLE_URL_MALFORMAT;

    if(*ptr == ';')
      ptr++;
  }

  return result;
}

static CURLcode sieve_connect(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  struct pingpong *pp = &sievec->pp;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections in IMAP */
  connkeep(conn, "SIEVE default");

  /* Redirect to sieve only. */
  data->state.redir_protocols = CURLPROTO_SIEVE;
  sievec->maxredirs = (unsigned int) data->set.maxredirs;

  Curl_dyn_init(&sievec->respbuf, CURL_MAX_INPUT_LENGTH);
  Curl_sasl_init(&sievec->sasl, data, &saslsieve);
  Curl_bufref_init(&sievec->saslmsg);

  PINGPONG_SETUP(pp, sieve_statemachine, sieve_endofresp);
  Curl_pp_init(pp);

  sievec->flags |= SIEVE_CONN_INITED;

  result = sieve_parse_url_options(conn);
  if(result)
    return result;

  sieve_state(data, SIEVE_SERVERGREET);
  return sieve_multi_statemach(data, done);
}

static CURLcode sieve_do(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  struct SIEVE *sieve = data->req.p.sieve;
  struct sieve_conn *sievec = &conn->proto.sievec;
  CURLcode result = CURLE_OK;

  /* Parse the URL path */
  free(sieve->owner);
  free(sieve->scriptname);
  result = sieve_parse_url_path(data, &sieve->owner, &sieve->scriptname);
  if(result)
    return result;

  /* If redirection or retry requested, do it. */
  *done = !!(sievec->flags & (SIEVE_CONN_BYE | SIEVE_CONN_REDIRECTED));
  if(*done)
    return sieve_follow(data, CURLE_OK);

  /* Parse the custom request */
  result = sieve_parse_custom_request(data);
  if(result)
    return result;

  Curl_xfer_setup_nop(data);
  sievec->donestate = SIEVE_STOP;
  Curl_dyn_reset(&sievec->respbuf);

  /* Determine the request kind and submit it. */
  if(sieve->custom) {
    const char *scriptname = sieve->scriptname;
    sievestate newstate = SIEVE_LISTSCRIPTS;

    if(data->state.upload) {
      newstate = SIEVE_PUTSCRIPT;
      if(strcasecompare(sieve->custom, "CHECKSCRIPT"))
        scriptname = NULL;
    }
    else if(strcasecompare(sieve->custom, "GETSCRIPT"))
      newstate = SIEVE_GETSCRIPT;
    result = send_sieve_command(data, conn, sieve->custom,
                                strlen(sieve->custom), sieve->custom_params,
                                scriptname, TRUE, newstate);
  }
  else if(!sieve->scriptname)
    result = sieve_perform_listscripts(data);
  else if(data->state.upload)
    result = sieve_perform_putscript(data);
  else
    result = sieve_perform_getscript(data);

  Curl_dyn_reset(&sievec->respbuf);
  return result;
}

static CURLcode sieve_doing(struct Curl_easy *data, bool *dophase_done)
{
  struct sieve_conn *sievec = &data->conn->proto.sievec;
  CURLcode result = Curl_pp_statemach(data, &sievec->pp, FALSE, FALSE);

  *dophase_done = sievec->state == SIEVE_STOP;
  return result;
}

static CURLcode sieve_done(struct Curl_easy *data, CURLcode status,
                           bool premature)
{
  CURLcode result = status;
  struct connectdata *conn = data->conn;
  struct sieve_conn *sievec = &conn->proto.sievec;
  struct SIEVE *sieve = data->req.p.sieve;

  (void) premature;

  if(sievec->flags & SIEVE_CONN_INITED)
    Curl_dyn_reset(&sievec->respbuf);

  if(!sieve)
    result = CURLE_OK;
  else {
    if(status) {
      /* Mark for closure. */
      connclose(conn, "sieve done with bad status");
      result = status;          /* Use the previous error code. */
    }
    else if(!(sievec->flags & (SIEVE_CONN_BYE | SIEVE_CONN_REDIRECTED))) {
      if(sievec->donestate == SIEVE_PUTSCRIPT)
        result = Curl_pp_sendf(data, &sievec->pp, "%s", "");
      if(!result)
        sieve_state(data, sievec->donestate);

      /* Run the state-machine */
      if(!result)
        result = sieve_block_statemach(data, conn, FALSE);
    }

    /* Cleanup our per-request based variables. */
    Curl_safefree(sieve->owner);
    Curl_safefree(sieve->scriptname);
    Curl_safefree(sieve->custom);
    Curl_safefree(sieve->custom_params);

    /* Clear the transfer mode for the next request. */
    sieve->transfer = PPTRANSFER_BODY;
  }

  return result;
}

/* Disconnect from a sieve server. Cleanup protocol-specific
 * per-connection resources. BLOCKING. */
static CURLcode sieve_disconnect(struct Curl_easy *data,
                                 struct connectdata *conn,
                                 bool dead_connection)
{
  struct sieve_conn *sievec = &conn->proto.sievec;

  if(sievec->flags & SIEVE_CONN_INITED)
    Curl_dyn_reset(&sievec->respbuf);

  if(!dead_connection && conn->bits.protoconnstart)
    if(!sieve_perform_logout(data, conn) && sievec->state != SIEVE_STOP)
      (void) sieve_block_statemach(data, conn, TRUE);

  Curl_pp_disconnect(&sievec->pp);
  Curl_sasl_cleanup(conn, sievec->sasl.authused);
  curl_url_cleanup(sievec->referral);
  if(sievec->flags & SIEVE_CONN_INITED)
    Curl_dyn_free(&sievec->respbuf);
  return CURLE_OK;
}

#endif /* CURL_DISABLE_SIEVE */
