/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#ifdef CURL_DOES_CONVERSIONS

#include <curl/curl.h>

#include "non-ascii.h"
#include "formdata.h"
#include "sendf.h"
#include "urldata.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#ifdef HAVE_ICONV
#include <iconv.h>
/* set default codesets for iconv */
#ifndef CURL_ICONV_CODESET_OF_NETWORK
#define CURL_ICONV_CODESET_OF_NETWORK "ISO8859-1"
#endif
#ifndef CURL_ICONV_CODESET_FOR_UTF8
#define CURL_ICONV_CODESET_FOR_UTF8   "UTF-8"
#endif
#define ICONV_ERROR  (size_t)-1
#endif /* HAVE_ICONV */

/*
 * Curl_convert_clone() returns a malloced copy of the source string (if
 * returning CURLE_OK), with the data converted to network format.
 */
CURLcode Curl_convert_clone(struct SessionHandle *data,
                           const char *indata,
                           size_t insize,
                           char **outbuf)
{
  char *convbuf;
  CURLcode result;

  convbuf = malloc(insize);
  if(!convbuf)
    return CURLE_OUT_OF_MEMORY;

  memcpy(convbuf, indata, insize);
  result = Curl_convert_to_network(data, convbuf, insize);
  if(result) {
    free(convbuf);
    return result;
  }

  *outbuf = convbuf; /* return the converted buffer */

  return CURLE_OK;
}

/*
 * Curl_convert_to_network() is an internal function for performing ASCII
 * conversions on non-ASCII platforms. It convers the buffer _in place_.
 */
CURLcode Curl_convert_to_network(struct SessionHandle *data,
                                 char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convtonetwork) {
    /* use translation callback */
    rc = data->set.convtonetwork(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_TO_NETWORK_FUNCTION callback returned %d: %s",
            (int)rc, curl_easy_strerror(rc));
    }
    return rc;
  }
  else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;
    int error;

    /* open an iconv conversion descriptor if necessary */
    if(data->outbound_cd == (iconv_t)-1) {
      data->outbound_cd = iconv_open(CURL_ICONV_CODESET_OF_NETWORK,
                                     CURL_ICONV_CODESET_OF_HOST);
      if(data->outbound_cd == (iconv_t)-1) {
        error = ERRNO;
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
              CURL_ICONV_CODESET_OF_NETWORK,
              CURL_ICONV_CODESET_OF_HOST,
              error, strerror(error));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->outbound_cd, (const char**)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if((rc == ICONV_ERROR) || (in_bytes != 0)) {
      error = ERRNO;
      failf(data,
            "The Curl_convert_to_network iconv call failed with errno %i: %s",
            error, strerror(error));
      return CURLE_CONV_FAILED;
    }
#else
    failf(data, "CURLOPT_CONV_TO_NETWORK_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Curl_convert_from_network() is an internal function for performing ASCII
 * conversions on non-ASCII platforms. It convers the buffer _in place_.
 */
CURLcode Curl_convert_from_network(struct SessionHandle *data,
                                   char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convfromnetwork) {
    /* use translation callback */
    rc = data->set.convfromnetwork(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_FROM_NETWORK_FUNCTION callback returned %d: %s",
            (int)rc, curl_easy_strerror(rc));
    }
    return rc;
  }
  else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    char *input_ptr, *output_ptr;
    size_t in_bytes, out_bytes, rc;
    int error;

    /* open an iconv conversion descriptor if necessary */
    if(data->inbound_cd == (iconv_t)-1) {
      data->inbound_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                    CURL_ICONV_CODESET_OF_NETWORK);
      if(data->inbound_cd == (iconv_t)-1) {
        error = ERRNO;
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
              CURL_ICONV_CODESET_OF_HOST,
              CURL_ICONV_CODESET_OF_NETWORK,
              error, strerror(error));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->inbound_cd, (const char **)&input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if((rc == ICONV_ERROR) || (in_bytes != 0)) {
      error = ERRNO;
      failf(data,
            "Curl_convert_from_network iconv call failed with errno %i: %s",
            error, strerror(error));
      return CURLE_CONV_FAILED;
    }
#else
    failf(data, "CURLOPT_CONV_FROM_NETWORK_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Curl_convert_from_utf8() is an internal function for performing UTF-8
 * conversions on non-ASCII platforms.
 */
CURLcode Curl_convert_from_utf8(struct SessionHandle *data,
                                char *buffer, size_t length)
{
  CURLcode rc;

  if(data->set.convfromutf8) {
    /* use translation callback */
    rc = data->set.convfromutf8(buffer, length);
    if(rc != CURLE_OK) {
      failf(data,
            "CURLOPT_CONV_FROM_UTF8_FUNCTION callback returned %d: %s",
            (int)rc, curl_easy_strerror(rc));
    }
    return rc;
  }
  else {
#ifdef HAVE_ICONV
    /* do the translation ourselves */
    const char *input_ptr;
    char *output_ptr;
    size_t in_bytes, out_bytes, rc;
    int error;

    /* open an iconv conversion descriptor if necessary */
    if(data->utf8_cd == (iconv_t)-1) {
      data->utf8_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                 CURL_ICONV_CODESET_FOR_UTF8);
      if(data->utf8_cd == (iconv_t)-1) {
        error = ERRNO;
        failf(data,
              "The iconv_open(\"%s\", \"%s\") call failed with errno %i: %s",
              CURL_ICONV_CODESET_OF_HOST,
              CURL_ICONV_CODESET_FOR_UTF8,
              error, strerror(error));
        return CURLE_CONV_FAILED;
      }
    }
    /* call iconv */
    input_ptr = output_ptr = buffer;
    in_bytes = out_bytes = length;
    rc = iconv(data->utf8_cd, &input_ptr, &in_bytes,
               &output_ptr, &out_bytes);
    if((rc == ICONV_ERROR) || (in_bytes != 0)) {
      error = ERRNO;
      failf(data,
            "The Curl_convert_from_utf8 iconv call failed with errno %i: %s",
            error, strerror(error));
      return CURLE_CONV_FAILED;
    }
    if(output_ptr < input_ptr) {
      /* null terminate the now shorter output string */
      *output_ptr = 0x00;
    }
#else
    failf(data, "CURLOPT_CONV_FROM_UTF8_FUNCTION callback required");
    return CURLE_CONV_REQD;
#endif /* HAVE_ICONV */
  }

  return CURLE_OK;
}

/*
 * Init conversion stuff for a SessionHandle
 */
void Curl_convert_init(struct SessionHandle *data)
{
#if defined(CURL_DOES_CONVERSIONS) && defined(HAVE_ICONV)
  /* conversion descriptors for iconv calls */
  data->outbound_cd = (iconv_t)-1;
  data->inbound_cd  = (iconv_t)-1;
  data->utf8_cd     = (iconv_t)-1;
#else
  (void)data;
#endif /* CURL_DOES_CONVERSIONS && HAVE_ICONV */
}

/*
 * Setup conversion stuff for a SessionHandle
 */
void Curl_convert_setup(struct SessionHandle *data)
{
  data->inbound_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                                CURL_ICONV_CODESET_OF_NETWORK);
  data->outbound_cd = iconv_open(CURL_ICONV_CODESET_OF_NETWORK,
                                 CURL_ICONV_CODESET_OF_HOST);
  data->utf8_cd = iconv_open(CURL_ICONV_CODESET_OF_HOST,
                             CURL_ICONV_CODESET_FOR_UTF8);
}

/*
 * Close conversion stuff for a SessionHandle
 */

void Curl_convert_close(struct SessionHandle *data)
{
#ifdef HAVE_ICONV
  /* close iconv conversion descriptors */
  if(data->inbound_cd != (iconv_t)-1) {
    iconv_close(data->inbound_cd);
  }
  if(data->outbound_cd != (iconv_t)-1) {
    iconv_close(data->outbound_cd);
  }
  if(data->utf8_cd != (iconv_t)-1) {
    iconv_close(data->utf8_cd);
  }
#else
  (void)data;
#endif /* HAVE_ICONV */
}

/*
 * Curl_convert_form() is used from http.c, this converts any form items that
   need to be sent in the network encoding.  Returns CURLE_OK on success.
 */
CURLcode Curl_convert_form(struct SessionHandle *data, struct FormData *form)
{
  struct FormData *next;
  CURLcode rc;

  if(!form)
    return CURLE_OK;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  do {
    next=form->next;  /* the following form line */
    if(form->type == FORM_DATA) {
      rc = Curl_convert_to_network(data, form->line, form->length);
      /* Curl_convert_to_network calls failf if unsuccessful */
      if(rc != CURLE_OK)
        return rc;
    }
  } while((form = next) != NULL); /* continue */
  return CURLE_OK;
}

#endif /* CURL_DOES_CONVERSIONS */
