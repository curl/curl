/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/
#include "setup.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH)
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "urldata.h"
#include "sendf.h"
#include "strequal.h"
#include "base64.h"
#include "md5.h"
#include "http_digest.h"
#include "strtok.h"
#include "url.h" /* for Curl_safefree() */
#include "memory.h"
#include "easyif.h" /* included for Curl_convert_... prototypes */

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* Test example headers:

WWW-Authenticate: Digest realm="testrealm", nonce="1053604598"
Proxy-Authenticate: Digest realm="testrealm", nonce="1053604598"

*/

CURLdigest Curl_input_digest(struct connectdata *conn,
                             bool proxy,
                             char *header) /* rest of the *-authenticate:
                                              header */
{
  bool more = TRUE;
  char *token = NULL;
  char *tmp = NULL;
  bool foundAuth = FALSE;
  bool foundAuthInt = FALSE;
  struct SessionHandle *data=conn->data;
  bool before = FALSE; /* got a nonce before */
  struct digestdata *d;

  if(proxy) {
    d = &data->state.proxydigest;
  }
  else {
    d = &data->state.digest;
  }

  /* skip initial whitespaces */
  while(*header && ISSPACE(*header))
    header++;

  if(checkprefix("Digest", header)) {
    header += strlen("Digest");

    /* If we already have received a nonce, keep that in mind */
    if(d->nonce)
      before = TRUE;

    /* clear off any former leftovers and init to defaults */
    Curl_digest_cleanup_one(d);

    while(more) {
      char value[32];
      char content[128];
      size_t totlen=0;

      while(*header && ISSPACE(*header))
        header++;

      /* how big can these strings be? */
      if((2 == sscanf(header, "%31[^=]=\"%127[^\"]\"",
                      value, content)) ||
         /* try the same scan but without quotes around the content but don't
            include the possibly trailing comma */
         (2 ==  sscanf(header, "%31[^=]=%127[^,]",
                       value, content)) ) {
        if(strequal(value, "nonce")) {
          d->nonce = strdup(content);
          if(!d->nonce)
            return CURLDIGEST_NOMEM;
        }
        else if(strequal(value, "stale")) {
          if(strequal(content, "true")) {
            d->stale = TRUE;
            d->nc = 1; /* we make a new nonce now */
          }
        }
        else if(strequal(value, "realm")) {
          d->realm = strdup(content);
          if(!d->realm)
            return CURLDIGEST_NOMEM;
        }
        else if(strequal(value, "opaque")) {
          d->opaque = strdup(content);
          if(!d->opaque)
            return CURLDIGEST_NOMEM;
        }
        else if(strequal(value, "qop")) {
          char *tok_buf;
          /* tokenize the list and choose auth if possible, use a temporary
             clone of the buffer since strtok_r() ruins it */
          tmp = strdup(content);
          if(!tmp)
            return CURLDIGEST_NOMEM;
          token = strtok_r(tmp, ",", &tok_buf);
          while (token != NULL) {
            if (strequal(token, "auth")) {
              foundAuth = TRUE;
            }
            else if (strequal(token, "auth-int")) {
              foundAuthInt = TRUE;
            }
            token = strtok_r(NULL, ",", &tok_buf);
          }
          free(tmp);
          /*select only auth o auth-int. Otherwise, ignore*/
          if (foundAuth) {
            d->qop = strdup("auth");
            if(!d->qop)
              return CURLDIGEST_NOMEM;
          }
          else if (foundAuthInt) {
            d->qop = strdup("auth-int");
            if(!d->qop)
              return CURLDIGEST_NOMEM;
          }
        }
        else if(strequal(value, "algorithm")) {
          d->algorithm = strdup(content);
          if(!d->algorithm)
            return CURLDIGEST_NOMEM;
          if(strequal(content, "MD5-sess"))
            d->algo = CURLDIGESTALGO_MD5SESS;
          else if(strequal(content, "MD5"))
            d->algo = CURLDIGESTALGO_MD5;
          else
            return CURLDIGEST_BADALGO;
        }
        else {
          /* unknown specifier, ignore it! */
        }
        totlen = strlen(value)+strlen(content)+1;

        if(header[strlen(value)+1] == '\"')
          /* the contents were within quotes, then add 2 for them to the
             length */
          totlen += 2;
      }
      else
        break; /* we're done here */

      header += totlen;
      if(',' == *header)
        /* allow the list to be comma-separated */
        header++;
    }
    /* We had a nonce since before, and we got another one now without
       'stale=true'. This means we provided bad credentials in the previous
       request */
    if(before && !d->stale)
      return CURLDIGEST_BAD;

    /* We got this header without a nonce, that's a bad Digest line! */
    if(!d->nonce)
      return CURLDIGEST_BAD;
  }
  else
    /* else not a digest, get out */
    return CURLDIGEST_NONE;

  return CURLDIGEST_FINE;
}

/* convert md5 chunk to RFC2617 (section 3.1.3) -suitable ascii string*/
static void md5_to_ascii(unsigned char *source, /* 16 bytes */
                         unsigned char *dest) /* 33 bytes */
{
  int i;
  for(i=0; i<16; i++)
    snprintf((char *)&dest[i*2], 3, "%02x", source[i]);
}

CURLcode Curl_output_digest(struct connectdata *conn,
                            bool proxy,
                            unsigned char *request,
                            unsigned char *uripath)
{
  /* We have a Digest setup for this, use it!  Now, to get all the details for
     this sorted out, I must urge you dear friend to read up on the RFC2617
     section 3.2.2, */
  unsigned char md5buf[16]; /* 16 bytes/128 bits */
  unsigned char request_digest[33];
  unsigned char *md5this;
  unsigned char *ha1;
  unsigned char ha2[33];/* 32 digits and 1 zero byte */
  char cnoncebuf[7];
  char *cnonce;
  char *tmp = NULL;
  struct timeval now;

  char **allocuserpwd;
  char *userp;
  char *passwdp;
  struct auth *authp;

  struct SessionHandle *data = conn->data;
  struct digestdata *d;
#ifdef CURL_DOES_CONVERSIONS
  CURLcode rc;
/* The CURL_OUTPUT_DIGEST_CONV macro below is for non-ASCII machines.
   It converts digest text to ASCII so the MD5 will be correct for 
   what ultimately goes over the network.
*/
#define CURL_OUTPUT_DIGEST_CONV(a, b) \
  rc = Curl_convert_to_network(a, (char *)b, strlen((const char*)b)); \
  if (rc != CURLE_OK) { \
    free(b); \
    return rc; \
  }
#else
#define CURL_OUTPUT_DIGEST_CONV(a, b)
#endif /* CURL_DOES_CONVERSIONS */

  if(proxy) {
    d = &data->state.proxydigest;
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    authp = &data->state.authproxy;
  }
  else {
    d = &data->state.digest;
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    authp = &data->state.authhost;
  }

  /* not set means empty */
  if(!userp)
    userp=(char *)"";

  if(!passwdp)
    passwdp=(char *)"";

  if(!d->nonce) {
    authp->done = FALSE;
    return CURLE_OK;
  }
  authp->done = TRUE;

  if(!d->nc)
    d->nc = 1;

  if(!d->cnonce) {
    /* Generate a cnonce */
    now = Curl_tvnow();
    snprintf(cnoncebuf, sizeof(cnoncebuf), "%06ld", now.tv_sec);
    if(Curl_base64_encode(data, cnoncebuf, strlen(cnoncebuf), &cnonce))
      d->cnonce = cnonce;
    else
      return CURLE_OUT_OF_MEMORY;
  }

  /*
    if the algorithm is "MD5" or unspecified (which then defaults to MD5):

    A1 = unq(username-value) ":" unq(realm-value) ":" passwd

    if the algorithm is "MD5-sess" then:

    A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd )
         ":" unq(nonce-value) ":" unq(cnonce-value)
  */

  md5this = (unsigned char *)
    aprintf("%s:%s:%s", userp, d->realm, passwdp);
  if(!md5this)
    return CURLE_OUT_OF_MEMORY;

  CURL_OUTPUT_DIGEST_CONV(data, md5this); /* convert on non-ASCII machines */
  Curl_md5it(md5buf, md5this);
  free(md5this); /* free this again */

  ha1 = (unsigned char *)malloc(33); /* 32 digits and 1 zero byte */
  if(!ha1)
    return CURLE_OUT_OF_MEMORY;

  md5_to_ascii(md5buf, ha1);

  if(d->algo == CURLDIGESTALGO_MD5SESS) {
    /* nonce and cnonce are OUTSIDE the hash */
    tmp = aprintf("%s:%s:%s", ha1, d->nonce, d->cnonce);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;
    CURL_OUTPUT_DIGEST_CONV(data, tmp); /* convert on non-ASCII machines */
    Curl_md5it(md5buf, (unsigned char *)tmp);
    free(tmp); /* free this again */
    md5_to_ascii(md5buf, ha1);
  }

  /*
    If the "qop" directive's value is "auth" or is unspecified, then A2 is:

      A2       = Method ":" digest-uri-value

          If the "qop" value is "auth-int", then A2 is:

      A2       = Method ":" digest-uri-value ":" H(entity-body)

    (The "Method" value is the HTTP request method as specified in section
    5.1.1 of RFC 2616)
  */

  md5this = (unsigned char *)aprintf("%s:%s", request, uripath);
  if(!md5this) {
    free(ha1);
    return CURLE_OUT_OF_MEMORY;
  }

  if (d->qop && strequal(d->qop, "auth-int")) {
    /* We don't support auth-int at the moment. I can't see a easy way to get
       entity-body here */
    /* TODO: Append H(entity-body)*/
  }
  CURL_OUTPUT_DIGEST_CONV(data, md5this); /* convert on non-ASCII machines */
  Curl_md5it(md5buf, md5this);
  free(md5this); /* free this again */
  md5_to_ascii(md5buf, ha2);

  if (d->qop) {
    md5this = (unsigned char *)aprintf("%s:%s:%08x:%s:%s:%s",
                                       ha1,
                                       d->nonce,
                                       d->nc,
                                       d->cnonce,
                                       d->qop,
                                       ha2);
  }
  else {
    md5this = (unsigned char *)aprintf("%s:%s:%s",
                                       ha1,
                                       d->nonce,
                                       ha2);
  }
  free(ha1);
  if(!md5this)
    return CURLE_OUT_OF_MEMORY;

  CURL_OUTPUT_DIGEST_CONV(data, md5this); /* convert on non-ASCII machines */
  Curl_md5it(md5buf, md5this);
  free(md5this); /* free this again */
  md5_to_ascii(md5buf, request_digest);

  /* for test case 64 (snooped from a Mozilla 1.3a request)

    Authorization: Digest username="testuser", realm="testrealm", \
    nonce="1053604145", uri="/64", response="c55f7f30d83d774a3d2dcacf725abaca"
  */

  Curl_safefree(*allocuserpwd);

  if (d->qop) {
    *allocuserpwd =
      aprintf( "%sAuthorization: Digest "
               "username=\"%s\", "
               "realm=\"%s\", "
               "nonce=\"%s\", "
               "uri=\"%s\", "
               "cnonce=\"%s\", "
               "nc=%08x, "
               "qop=\"%s\", "
               "response=\"%s\"",
               proxy?"Proxy-":"",
               userp,
               d->realm,
               d->nonce,
               uripath, /* this is the PATH part of the URL */
               d->cnonce,
               d->nc,
               d->qop,
               request_digest);

    if(strequal(d->qop, "auth"))
      d->nc++; /* The nc (from RFC) has to be a 8 hex digit number 0 padded
                  which tells to the server how many times you are using the
                  same nonce in the qop=auth mode. */
  }
  else {
    *allocuserpwd =
      aprintf( "%sAuthorization: Digest "
               "username=\"%s\", "
               "realm=\"%s\", "
               "nonce=\"%s\", "
               "uri=\"%s\", "
               "response=\"%s\"",
               proxy?"Proxy-":"",
               userp,
               d->realm,
               d->nonce,
               uripath, /* this is the PATH part of the URL */
               request_digest);
  }
  if(!*allocuserpwd)
    return CURLE_OUT_OF_MEMORY;

  /* Add optional fields */
  if(d->opaque) {
    /* append opaque */
    tmp = aprintf("%s, opaque=\"%s\"", *allocuserpwd, d->opaque);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;
    free(*allocuserpwd);
    *allocuserpwd = tmp;
  }

  if(d->algorithm) {
    /* append algorithm */
    tmp = aprintf("%s, algorithm=\"%s\"", *allocuserpwd, d->algorithm);
    if(!tmp)
      return CURLE_OUT_OF_MEMORY;
    free(*allocuserpwd);
    *allocuserpwd = tmp;
  }

  /* append CRLF to the userpwd header */
  tmp = (char*) realloc(*allocuserpwd, strlen(*allocuserpwd) + 3 + 1);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;
  strcat(tmp, "\r\n");
  *allocuserpwd = tmp;

  return CURLE_OK;
}

void Curl_digest_cleanup_one(struct digestdata *d)
{
  if(d->nonce)
    free(d->nonce);
  d->nonce = NULL;

  if(d->cnonce)
    free(d->cnonce);
  d->cnonce = NULL;

  if(d->realm)
    free(d->realm);
  d->realm = NULL;

  if(d->opaque)
    free(d->opaque);
  d->opaque = NULL;

  if(d->qop)
    free(d->qop);
  d->qop = NULL;

  if(d->algorithm)
    free(d->algorithm);
  d->algorithm = NULL;

  d->nc = 0;
  d->algo = CURLDIGESTALGO_MD5; /* default algorithm */
  d->stale = FALSE; /* default means normal, not stale */
}


void Curl_digest_cleanup(struct SessionHandle *data)
{
  Curl_digest_cleanup_one(&data->state.digest);
  Curl_digest_cleanup_one(&data->state.proxydigest);
}

#endif
