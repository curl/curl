/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifndef CURL_DISABLE_HTTP
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "urldata.h"
#include "sendf.h"
#include "strequal.h"

#include "md5.h"
#include "http_digest.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* Test example header:

WWW-Authenticate: Digest realm="testrealm", nonce="1053604598"

*/

CURLdigest Curl_input_digest(struct connectdata *conn,
                             char *header) /* rest of the www-authenticate:
                                              header */
{
  bool more = TRUE;
  struct SessionHandle *data=conn->data;

  /* skip initial whitespaces */
  while(*header && isspace((int)*header))
    header++;

  if(checkprefix("Digest", header)) {
    header += strlen("Digest");

    data->state.digest.algo = CURLDIGESTALGO_MD5; /* default algorithm */

    while(more) {
      char value[32];
      char content[128];
      int totlen=0;

      while(*header && isspace((int)*header))
        header++;
    
      /* how big can these strings be? */
      if(2 == sscanf(header, "%31[^=]=\"%127[^\"]\"",
                     value, content)) {
        if(strequal(value, "nonce")) {
          data->state.digest.nonce = strdup(content);
        }
        else if(strequal(value, "cnonce")) {
          data->state.digest.cnonce = strdup(content);
        }
        else if(strequal(value, "realm")) {
          data->state.digest.realm = strdup(content);
        }
        else if(strequal(value, "algorithm")) {
          if(strequal(content, "MD5-sess"))
            data->state.digest.algo = CURLDIGESTALGO_MD5SESS;
          /* else, remain using the default md5 */
        }
        else {
          /* unknown specifier, ignore it! */
        }
        totlen = strlen(value)+strlen(content)+3;
      }
      else 
        break; /* we're done here */
        
      header += totlen;
      if(',' == *header)
        /* allow the list to be comma-separated */
        header++; 
    }
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
    sprintf((char *)&dest[i*2], "%02x", source[i]);
}

CURLcode Curl_output_digest(struct connectdata *conn,
                            unsigned char *request,
                            unsigned char *uripath)
{
  /* We have a Digest setup for this, use it!
     Now, to get all the details for this sorted out, I must urge you dear friend
     to read up on the RFC2617 section 3.2.2, */
  unsigned char md5buf[16]; /* 16 bytes/128 bits */
  unsigned char ha1[33]; /* 32 digits and 1 zero byte */
  unsigned char ha2[33];
  unsigned char request_digest[33];
  unsigned char *md5this;

  struct SessionHandle *data = conn->data;

  /*
    if the algorithm is "MD5" or unspecified (which then defaults to MD5):
    
    A1 = unq(username-value) ":" unq(realm-value) ":" passwd

    if the algorithm is "MD5-sess" then:

    A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd )
         ":" unq(nonce-value) ":" unq(cnonce-value)
  */
  if(data->state.digest.algo == CURLDIGESTALGO_MD5SESS) {
    md5this = (unsigned char *)
      aprintf("%s:%s:%s:%s:%s",
              data->state.user,
              data->state.digest.realm,
              data->state.passwd,
              data->state.digest.nonce,
              data->state.digest.cnonce);
  }
  else {
    md5this = (unsigned char *)
      aprintf("%s:%s:%s",
              data->state.user,
              data->state.digest.realm,
              data->state.passwd);
  }
  Curl_md5it(md5buf, md5this);
  free(md5this); /* free this again */
  md5_to_ascii(md5buf, ha1);

  /*
    A2 = Method ":" digest-uri-value
    
    (The "Method" value is the HTTP request method as specified in section
    5.1.1 of RFC 2616)
  */

  md5this = (unsigned char *)aprintf("%s:%s", request, uripath);
  Curl_md5it(md5buf, md5this);
  free(md5this); /* free this again */
  md5_to_ascii(md5buf, ha2);
  
  md5this = (unsigned char *)aprintf("%s:%s:%s", ha1, data->state.digest.nonce,
                                     ha2);
  Curl_md5it(md5buf, md5this);
  free(md5this); /* free this again */
  md5_to_ascii(md5buf, request_digest);

  /* for test case 64 (snooped from a Mozilla 1.3a request)

    Authorization: Digest username="testuser", realm="testrealm", \
    nonce="1053604145", uri="/64", response="c55f7f30d83d774a3d2dcacf725abaca"
  */

  conn->allocptr.userpwd =
    aprintf( "Authorization: Digest "
             "username=\"%s\", "
             "realm=\"%s\", "
             "nonce=\"%s\", "
             "uri=\"%s\", "
             "response=\"%s\"\r\n",
             data->state.user,
             data->state.digest.realm,
             data->state.digest.nonce,
             uripath, /* this is the PATH part of the URL */ 
             request_digest );

  return CURLE_OK;
}

#endif
