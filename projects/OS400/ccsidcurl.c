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
 *
 ***************************************************************************/

/* CCSID API wrappers for OS/400. */

#include <iconv.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <stdarg.h>

#pragma enum(int)

#include "curl_setup.h"
#include "curl.h"
#include "mprintf.h"
#include "slist.h"
#include "urldata.h"
#include "url.h"
#include "setopt.h"
#include "getinfo.h"
#include "curlx/dynbuf.h"
#include "ccsidcurl.h"

#include "os400sys.h"

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) ~0)
#endif

#define ASCII_CCSID         819     /* Use ISO-8859-1 as ASCII. */
#define NOCONV_CCSID        65535   /* No conversion. */
#define ICONV_ID_SIZE       32 /* Size of iconv_open() code identifier. */
#define ICONV_OPEN_ERROR(t) ((t).return_value == -1)

#define ALLOC_GRANULE 8 /* Alloc. granule for curl_formadd_ccsid(). */


/* A string terminator that works for all CCSIDs. */
static const char universal_terminator[] = {0, 0, 0, 0};

/* Freeing const pointers more easily. */
#define untyped_free(p) curlx_free(CURL_UNCONST(p))


static void makeOS400IconvCode(char buf[ICONV_ID_SIZE], unsigned int ccsid)
{
  /*
   * Convert a CCSID to the corresponding IBM iconv_open() character
   * code identifier.
   * This code is specific to the OS400 implementation of the iconv library.
   * CCSID 65535 (no conversion) is replaced by the ASCII CCSID.
   * CCSID 0 is interpreted by the OS400 as the job's CCSID.
   */

  ccsid &= 0xFFFF;

  if(ccsid == NOCONV_CCSID)
    ccsid = ASCII_CCSID;

  memset(buf, 0, ICONV_ID_SIZE);
  curl_msprintf(buf, "IBMCCSID%05u0000000", ccsid);
}

static iconv_t iconv_open_CCSID(unsigned int ccsidout, unsigned int ccsidin,
                                unsigned int cstr)
{
  char fromcode[ICONV_ID_SIZE];
  char tocode[ICONV_ID_SIZE];

  /*
   * Like iconv_open(), but character codes are given as CCSIDs.
   * If `cstr' is non-zero, conversion is set up to stop whenever a
   * null character is encountered.
   * See iconv_open() IBM description in "National Language Support API".
   */

  makeOS400IconvCode(fromcode, ccsidin);
  makeOS400IconvCode(tocode, ccsidout);
  memset(tocode + 13, 0, sizeof(tocode) - 13); /* Dest. code id format. */

  if(cstr)
    fromcode[18] = '1'; /* Set null-terminator flag. */

  return iconv_open(tocode, fromcode);
}

static int convert(char *d, size_t dlen, const char *s, size_t slen,
                   unsigned int ccsidin, unsigned int ccsidout)
{
  int i;
  iconv_t cd;
  size_t lslen;

  /*
   * Convert `ccsidin'-coded `slen'-data bytes at `s' into `ccsidout'-coded
   * data stored in the `dlen'-byte buffer at `d'.
   * If `slen' is CURL_ZERO_TERMINATED, let iconv() detect the end of
   * input string.
   * CCSID 65535 (no conversion) is replaced by the ASCII CCSID.
   * Return the converted destination byte count, or -1 if error.
   */

  if(ccsidin == 65535)
    ccsidin = ASCII_CCSID;

  if(ccsidout == 65535)
    ccsidout = ASCII_CCSID;

  if(slen == CURL_ZERO_TERMINATED) {
    lslen = 0;
    cd = iconv_open_CCSID(ccsidout, ccsidin, 1);
  }
  else {
    lslen = (size_t) slen;
    cd = iconv_open_CCSID(ccsidout, ccsidin, 0);
  }

  if(ICONV_OPEN_ERROR(cd))
    return -1;

  i = dlen;

  if((int) iconv(cd, (char **) &s, &lslen, &d, &dlen) < 0)
    i = -1;
  else
    i -= dlen;

  iconv_close(cd);
  return i;
}

static CURLcode dyn_addn_CCSID(struct dynbuf *db,
                               const void *mem, size_t len,
                               unsigned int ccsidin, unsigned int ccsidout)
{
  iconv_t cd;
  size_t dlen;
  CURLcode result = CURLE_OK;
  char buffer[128];

  if(ccsidin == 65535)
    ccsidin = ASCII_CCSID;

  if(ccsidout == 65535)
    ccsidout = ASCII_CCSID;

  cd = iconv_open_CCSID(ccsidout, ccsidin, len == CURL_ZERO_TERMINATED);

  if(ICONV_OPEN_ERROR(cd)) {
    curlx_dyn_free(db);
    return CURLE_NOT_BUILT_IN;
  }

  while(len) {
    size_t dummylen = 0;
    char *dptr = buffer;
    int err = 0;

    dlen = sizeof(buffer);
    if((int) iconv(cd, (char **) &mem,
                   len == CURL_ZERO_TERMINATED ? &dummylen : &len,
                   &dptr, &dlen) < 0) {
      /* !checksrc! disable ERRNOVAR 1 */
      err = errno;
    }
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    switch(err) {
    case 0:
    case E2BIG:
      break;
    case ENOMEM:
      result = CURLE_OUT_OF_MEMORY;
      FALLTHROUGH();
    default:
      curlx_dyn_free(db);
      iconv_close(cd);
      return result;
    }

    result = curlx_dyn_addn(db, (const void *) buffer, dptr - buffer);
    if(result) {
      iconv_close(cd);
      return result;
    }

    if(!err)
      break;
  }

  iconv_close(cd);
  dlen = curlx_dyn_len(db);

  if(len == CURL_ZERO_TERMINATED) {
    /* The null terminator has been converted AND counted as a character.
     * Measure it by an additional conversion and drop it. */
    int tlen = convert(buffer, sizeof(buffer), universal_terminator, 1,
                        ASCII_CCSID, ccsidout);

    if(tlen < 0 || tlen > dlen) {
      curlx_dyn_free(db);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    dlen -= tlen;
  }
  else {
    /* Make sure the string is followed by an universal terminator. */
    result = curlx_dyn_addn(db, universal_terminator,
                            sizeof(universal_terminator));
  }

  /* Restore the real string length. */
  if(!result)
    result = curlx_dyn_setlen(db, dlen);

  return result;
}

static struct curl_slist *slist_convert(struct curl_slist *from,
                                        unsigned int ccsidin,
                                        unsigned int ccsidout)
{
  struct curl_slist *to = (struct curl_slist *) NULL;
  struct dynbuf db;
  size_t plen;

  curlx_dyn_init(&db, MAX_CONV_EXPANSION * CURL_MAX_HTTP_HEADER);

  for(; from; from = from->next) {
    struct curl_slist *nl;

    if(dyn_addn_CCSID(&db, from->data, CURL_ZERO_TERMINATED,
                      ccsidin, ccsidout)) {
      curl_slist_free_all(to);
      return NULL;
    }
    nl = Curl_slist_append_nodup(to, curlx_dyn_take(&db, &plen));
    if(!nl) {
      curl_slist_free_all(to);
      return NULL;
    }
    to = nl;
  }
  return to;
}

static char *keyed_string(localkey_t key, const char *ascii,
                          unsigned int ccsid)
{
  size_t len;
  char *ebcdic;
  struct dynbuf db;

  if(!ascii)
    return NULL;

  curlx_dyn_init(&db, MAX_CONV_EXPANSION * CURL_MAX_INPUT_LENGTH);
  if(dyn_addn_CCSID(&db, ascii, CURL_ZERO_TERMINATED, ASCII_CCSID, ccsid))
    return NULL;

  len = curlx_dyn_len(&db);
  ebcdic = Curl_thread_buffer(key, len + sizeof(universal_terminator));
  if(ebcdic) {
    memcpy(ebcdic, curlx_dyn_ptr(&db), len);
    memcpy(ebcdic + len, universal_terminator, sizeof(universal_terminator));
  }
  curlx_dyn_free(&db);
  return ebcdic;
}

const char *curl_to_ccsid(const char *string, unsigned int ccsid)
{
  char *s = NULL;

  if(string) {
    struct dynbuf db;
    size_t len;

    curlx_dyn_init(&db, MAX_CONV_EXPANSION * CURL_MAX_INPUT_LENGTH);
    dyn_addn_CCSID(&db, string, CURL_ZERO_TERMINATED, ASCII_CCSID, ccsid);
    s = curlx_dyn_take(&db, &len);
  }

  return s;
}

const char *curl_from_ccsid(const char *string, unsigned int ccsid)
{
  char *s = NULL;

  if(string) {
    struct dynbuf db;
    size_t len;

    curlx_dyn_init(&db, CURL_MAX_INPUT_LENGTH);
    dyn_addn_CCSID(&db, string, CURL_ZERO_TERMINATED, ccsid, ASCII_CCSID);
    s = curlx_dyn_take(&db, &len);
  }

  return s;
}

char *curl_version_ccsid(unsigned int ccsid)
{
  return keyed_string(LK_CURL_VERSION, curl_version(), ccsid);
}

char *curl_easy_escape_ccsid(CURL *handle, const char *string, int length,
                             unsigned int ccsidin, unsigned int ccsidout)
{
  struct dynbuf db;
  char *d;
  size_t len;

  if(!string)
    return NULL;

  curlx_dyn_init(&db, MAX_CONV_EXPANSION * CURL_MAX_INPUT_LENGTH);

  if(dyn_addn_CCSID(&db, string, length ? length : CURL_ZERO_TERMINATED,
                    ccsidin, ASCII_CCSID))
    return NULL;

  d = curl_easy_escape(handle, curlx_dyn_ptr(&db), curlx_dyn_len(&db));
  curlx_dyn_free(&db);

  if(!d)
    return NULL;

  dyn_addn_CCSID(&db, d, CURL_ZERO_TERMINATED, ASCII_CCSID, ccsidout);
  untyped_free(d);
  return curlx_dyn_take(&db, &len);
}

char *curl_easy_unescape_ccsid(CURL *handle, const char *string, int length,
                               int *outlength,
                               unsigned int ccsidin, unsigned int ccsidout)
{
  struct dynbuf db;
  char *d;
  size_t len;

  if(!string)
    return NULL;

  curlx_dyn_init(&db, MAX_CONV_EXPANSION * CURL_MAX_INPUT_LENGTH);

  if(dyn_addn_CCSID(&db, string, length ? length : CURL_ZERO_TERMINATED,
                    ccsidin, ASCII_CCSID))
    return NULL;

  d = curl_easy_unescape(handle,
                         curlx_dyn_ptr(&db), curlx_dyn_len(&db), outlength);
  curlx_dyn_free(&db);

  if(!d)
    return NULL;

  if(!dyn_addn_CCSID(&db, d, CURL_ZERO_TERMINATED, ASCII_CCSID, ccsidout))
    if(outlength)
      *outlength = curlx_dyn_len(&db);
  untyped_free(d);
  return curlx_dyn_take(&db, &len);
}

struct curl_slist *curl_slist_append_ccsid(struct curl_slist *list,
                                           const char *data,
                                           unsigned int ccsid)
{
  const char *s;

  if(!data)
    return curl_slist_append(list, data);

  s = curl_from_ccsid(data, ccsid);

  if(!s)
    return NULL;

  list = Curl_slist_append_nodup(list, s);
  if(!list)
    untyped_free(s);
  return list;
}

time_t curl_getdate_ccsid(const char *p, const time_t *unused,
                          unsigned int ccsid)
{
  const char *s;
  time_t t;

  if(!p)
    return curl_getdate(p, unused);

  s = curl_from_ccsid(p, ccsid);

  if(!s)
    return (time_t) -1;

  t = curl_getdate(s, unused);
  untyped_free(s);
  return t;
}

static int convert_version_info_string(const char **stringp, char **bufp,
                                       int *left, unsigned int ccsid)
{
  /* Helper for curl_version_info_ccsid(): convert a string if defined.
     Result is stored in the `*left'-byte buffer at `*bufp'.
     `*bufp' and `*left' are updated accordingly.
     Return 0 if ok, else -1. */

  if(*stringp) {
    int l = convert(*bufp, *left, *stringp, CURL_ZERO_TERMINATED,
                    ASCII_CCSID, ccsid);

    if(l <= 0)
      return -1;

    *stringp = *bufp;
    *bufp += l;
    *left -= l;
  }

  return 0;
}

curl_version_info_data *curl_version_info_ccsid(CURLversion stamp,
                                                unsigned int ccsid)
{
  curl_version_info_data *p;
  char *cp;
  int n;
  int nproto;
  curl_version_info_data *id;
  int i;
  const char **cpp;
  static const size_t charfields[] = {
    offsetof(curl_version_info_data, version),
    offsetof(curl_version_info_data, host),
    offsetof(curl_version_info_data, ssl_version),
    offsetof(curl_version_info_data, libz_version),
    offsetof(curl_version_info_data, ares),
    offsetof(curl_version_info_data, libidn),
    offsetof(curl_version_info_data, libssh_version),
    offsetof(curl_version_info_data, brotli_version),
    offsetof(curl_version_info_data, nghttp2_version),
    offsetof(curl_version_info_data, quic_version),
    offsetof(curl_version_info_data, cainfo),
    offsetof(curl_version_info_data, capath),
    offsetof(curl_version_info_data, zstd_version),
    offsetof(curl_version_info_data, hyper_version),
    offsetof(curl_version_info_data, gsasl_version),
    offsetof(curl_version_info_data, feature_names),
    offsetof(curl_version_info_data, rtmp_version)
  };

  /* The assertion below is possible, because although the second operand
     is an enum member, the first is a #define. In that case, the OS/400 C
     compiler seems to compare string values after substitution. */

#if CURLVERSION_NOW != CURLVERSION_ELEVENTH
#error curl_version_info_data structure has changed: upgrade this procedure.
#endif

  /* If caller has been compiled with a newer version, error. */

  if(stamp > CURLVERSION_NOW)
    return NULL;

  p = curl_version_info(stamp);

  if(!p)
    return p;

  /* Measure thread space needed. */

  n = 0;
  nproto = 0;

  if(p->protocols) {
    while(p->protocols[nproto])
      n += strlen(p->protocols[nproto++]);

    n += nproto++;
  }

  for(i = 0; i < sizeof(charfields) / sizeof(charfields[0]); i++) {
    cpp = (const char **) ((char *) p + charfields[i]);
    if(*cpp)
      n += strlen(*cpp) + 1;
  }

  /* Allocate thread space. */

  n *= MAX_CONV_EXPANSION;

  if(nproto)
    n += nproto * sizeof(const char *);

  cp = Curl_thread_buffer(LK_VERSION_INFO_DATA, n);
  id = (curl_version_info_data *) Curl_thread_buffer(LK_VERSION_INFO,
                                                     sizeof(*id));

  if(!id || !cp)
    return NULL;

  /* Copy data and convert strings. */

  memcpy(id, p, sizeof(*p));

  if(id->protocols) {
    i = nproto * sizeof(id->protocols[0]);

    id->protocols = (const char * const *) cp;
    memcpy(cp, (char *) p->protocols, i);
    cp += i;
    n -= i;

    for(i = 0; id->protocols[i]; i++)
      if(convert_version_info_string(((const char **) id->protocols) + i,
                                      &cp, &n, ccsid))
        return NULL;
  }

  for(i = 0; i < sizeof(charfields) / sizeof(charfields[0]); i++) {
    cpp = (const char **) ((char *) p + charfields[i]);
    if(*cpp && convert_version_info_string(cpp, &cp, &n, ccsid))
      return NULL;
  }

  return id;
}

const char *curl_easy_strerror_ccsid(CURLcode error, unsigned int ccsid)
{
  return keyed_string(LK_EASY_STRERROR, curl_easy_strerror(error), ccsid);
}

const char *curl_share_strerror_ccsid(CURLSHcode error, unsigned int ccsid)
{
  return keyed_string(LK_SHARE_STRERROR, curl_share_strerror(error), ccsid);
}

const char *curl_multi_strerror_ccsid(CURLMcode error, unsigned int ccsid)
{
  return keyed_string(LK_MULTI_STRERROR, curl_multi_strerror(error), ccsid);
}

const char *curl_url_strerror_ccsid(CURLUcode error, unsigned int ccsid)
{
  return keyed_string(LK_URL_STRERROR, curl_url_strerror(error), ccsid);
}

void curl_certinfo_free_all(struct curl_certinfo *info)
{
  /* Free all memory used by certificate info. */
  if(info) {
    if(info->certinfo) {
      int i;

      for(i = 0; i < info->num_of_certs; i++)
        curl_slist_free_all(info->certinfo[i]);
      untyped_free(info->certinfo);
    }
    untyped_free(info);
  }
}

CURLcode curl_easy_getinfo_ccsid(CURL *curl, CURLINFO info, ...)
{
  va_list arg;
  void *paramp;
  CURLcode ret;
  struct Curl_easy *data;

  /* WARNING: unlike curl_easy_getinfo(), the strings returned by this
     procedure have to be free'ed. */

  data = (struct Curl_easy *) curl;
  va_start(arg, info);
  paramp = va_arg(arg, void *);
  ret = Curl_getinfo(data, info, paramp);

  if(ret == CURLE_OK) {
    unsigned int ccsid;
    const char **cpp;
    struct curl_slist **slp;
    struct curl_certinfo *cipf;
    struct curl_certinfo *cipt;

    switch((int) info & CURLINFO_TYPEMASK) {

    case CURLINFO_STRING:
      ccsid = va_arg(arg, unsigned int);
      cpp = (const char **) paramp;

      if(*cpp) {
        const char *s = curl_to_ccsid(*cpp, ccsid);

        if(!s)
          ret = CURLE_OUT_OF_MEMORY;
        else
          *cpp = s;
      }

      break;

    case CURLINFO_SLIST:
      ccsid = va_arg(arg, unsigned int);
      switch(info) {
      case CURLINFO_CERTINFO:
        cipf = *(struct curl_certinfo **) paramp;
        if(cipf) {
          cipt = (struct curl_certinfo *) curlx_malloc(sizeof(*cipt));
          if(!cipt)
            ret = CURLE_OUT_OF_MEMORY;
          else {
            cipt->certinfo =
              (struct curl_slist **) curlx_calloc(cipf->num_of_certs + 1,
                                                  sizeof(struct curl_slist *));
            if(!cipt->certinfo)
              ret = CURLE_OUT_OF_MEMORY;
            else {
              int i;

              cipt->num_of_certs = cipf->num_of_certs;
              for(i = 0; i < cipf->num_of_certs; i++)
                if(cipf->certinfo[i]) {
                  cipt->certinfo[i] = slist_convert(cipf->certinfo[i],
                                                    ASCII_CCSID, ccsid);
                  if(!cipt->certinfo[i]) {
                    ret = CURLE_OUT_OF_MEMORY;
                    break;
                  }
                }
            }
          }

          if(ret != CURLE_OK) {
            curl_certinfo_free_all(cipt);
            cipt = NULL;
          }

          *(struct curl_certinfo **) paramp = cipt;
        }

        break;

      case CURLINFO_TLS_SESSION:
      case CURLINFO_TLS_SSL_PTR:
      case CURLINFO_SOCKET:
        break;

      default:
        slp = (struct curl_slist **) paramp;
        if(*slp) {
          *slp = slist_convert(*slp, ASCII_CCSID, ccsid);
          if(!*slp)
            ret = CURLE_OUT_OF_MEMORY;
        }
        break;
      }
    }
  }

  va_end(arg);
  return ret;
}

static int Curl_is_formadd_string(CURLformoption option)
{
  switch(option) {

  case CURLFORM_FILENAME:
  case CURLFORM_CONTENTTYPE:
  case CURLFORM_BUFFER:
  case CURLFORM_FILE:
  case CURLFORM_FILECONTENT:
  case CURLFORM_COPYCONTENTS:
  case CURLFORM_COPYNAME:
    return 1;
  }

  return 0;
}

static void Curl_formadd_release_local(struct curl_forms *forms, int nargs,
                                       int skip)
{
  while(nargs--)
    if(nargs != skip)
      if(Curl_is_formadd_string(forms[nargs].option))
        if(forms[nargs].value)
          untyped_free(forms[nargs].value);

  untyped_free(forms);
}

static int Curl_formadd_convert(struct curl_forms *forms, int formx,
                                int lengthx, unsigned int ccsid)
{
  size_t len = CURL_ZERO_TERMINATED;
  char *cp;
  struct dynbuf db;

  if(formx < 0 || !forms[formx].value)
    return 0;

  curlx_dyn_init(&db, CURL_MAX_INPUT_LENGTH);

  if(lengthx >= 0)
    len = (size_t) forms[lengthx].value;

  if(dyn_addn_CCSID(&db, forms[formx].value, len, ccsid, ASCII_CCSID))
    return -1;

  cp = curlx_dyn_take(&db, &len);
  forms[formx].value = cp;

  if(lengthx >= 0)
    forms[lengthx].value = (char *) len;  /* Update length after conversion. */

  return len;
}

CURLFORMcode curl_formadd_ccsid(struct curl_httppost **httppost,
                                struct curl_httppost **last_post, ...)
{
  va_list arg;
  CURLformoption option;
  CURLFORMcode result;
  struct curl_forms *forms;
  struct curl_forms *lforms;
  struct curl_forms *tforms;
  unsigned int lformlen;
  const char *value;
  unsigned int ccsid;
  int nargs;
  int namex;
  int namelengthx;
  int contentx;
  int lengthx;
  unsigned int contentccsid;
  unsigned int nameccsid;

  /* A single curl_formadd() call cannot be split in several calls to deal
     with all parameters: the original parameters are thus copied to a local
     curl_forms array and converted to ASCII when needed.
     CURLFORM_PTRNAME is processed as if it were CURLFORM_COPYNAME.
     CURLFORM_COPYNAME and CURLFORM_NAMELENGTH occurrence order in
     parameters is not defined; for this reason, the actual conversion is
     delayed to the end of parameter processing. The same applies to
     CURLFORM_COPYCONTENTS/CURLFORM_CONTENTSLENGTH, but these may appear
     several times in the parameter list; the problem resides here in knowing
     which CURLFORM_CONTENTSLENGTH applies to which CURLFORM_COPYCONTENTS and
     when we can be sure to have both info for conversion: end of parameter
     list is such a point, but CURLFORM_CONTENTTYPE is also used here as a
     natural separator between content data definitions; this seems to be
     in accordance with FormAdd() behavior. */

  /* Allocate the local curl_forms array. */

  lformlen = ALLOC_GRANULE;
  lforms = curlx_malloc(lformlen * sizeof(*lforms));

  if(!lforms)
    return CURL_FORMADD_MEMORY;

  /* Process the arguments, copying them into local array, latching conversion
     indexes and converting when needed. */

  result = CURL_FORMADD_OK;
  nargs = 0;
  contentx = -1;
  lengthx = -1;
  namex = -1;
  namelengthx = -1;
  forms = NULL;
  va_start(arg, last_post);

  for(;;) {
    /* Make sure there is still room for an item in local array. */

    if(nargs >= lformlen) {
      lformlen += ALLOC_GRANULE;
      tforms = curlx_realloc(lforms, lformlen * sizeof(*lforms));

      if(!tforms) {
        result = CURL_FORMADD_MEMORY;
        break;
      }

      lforms = tforms;
    }

    /* Get next option. */

    if(forms) {
      /* Get option from array. */

      option = forms->option;
      value = forms->value;
      forms++;
    }
    else {
      /* Get option from arguments. */

      option = va_arg(arg, CURLformoption);

      if(option == CURLFORM_END)
        break;
    }

    /* Dispatch by option. */

    switch(option) {

    case CURLFORM_END:
      forms = NULL;     /* Leave array mode. */
      continue;

    case CURLFORM_ARRAY:
      if(!forms) {
        forms = va_arg(arg, struct curl_forms *);
        continue;
      }

      result = CURL_FORMADD_ILLEGAL_ARRAY;
      break;

    case CURLFORM_COPYNAME:
      option = CURLFORM_PTRNAME; /* Static for now. */

    case CURLFORM_PTRNAME:
      if(namex >= 0)
        result = CURL_FORMADD_OPTION_TWICE;

      namex = nargs;

      if(!forms) {
        value = va_arg(arg, char *);
        nameccsid = (unsigned int) va_arg(arg, long);
      }
      else {
        nameccsid = (unsigned int) forms->value;
        forms++;
      }

      break;

    case CURLFORM_COPYCONTENTS:
      if(contentx >= 0)
        result = CURL_FORMADD_OPTION_TWICE;

      contentx = nargs;

      if(!forms) {
        value = va_arg(arg, char *);
        contentccsid = (unsigned int) va_arg(arg, long);
      }
      else {
        contentccsid = (unsigned int) forms->value;
        forms++;
      }

      break;

    case CURLFORM_PTRCONTENTS:
    case CURLFORM_BUFFERPTR:
      if(!forms)
        value = va_arg(arg, char *); /* No conversion. */

      break;

    case CURLFORM_CONTENTSLENGTH:
      lengthx = nargs;

      if(!forms)
        value = (char *) va_arg(arg, long);

      break;

    case CURLFORM_CONTENTLEN:
      lengthx = nargs;

      if(!forms)
        value = (char *) va_arg(arg, curl_off_t);

      break;

    case CURLFORM_NAMELENGTH:
      namelengthx = nargs;

      if(!forms)
        value = (char *) va_arg(arg, long);

      break;

    case CURLFORM_BUFFERLENGTH:
      if(!forms)
        value = (char *) va_arg(arg, long);

      break;

    case CURLFORM_CONTENTHEADER:
      if(!forms)
        value = (char *) va_arg(arg, struct curl_slist *);

      break;

    case CURLFORM_STREAM:
      if(!forms)
        value = (char *) va_arg(arg, void *);

      break;

    case CURLFORM_CONTENTTYPE:
      /* If a previous content has been encountered, convert it now. */

      if(Curl_formadd_convert(lforms, contentx, lengthx, contentccsid) < 0) {
        result = CURL_FORMADD_MEMORY;
        break;
      }

      contentx = -1;
      lengthx = -1;
      /* Fall into default. */

    default:
      /* Must be a convertible string. */

      if(!Curl_is_formadd_string(option)) {
        result = CURL_FORMADD_UNKNOWN_OPTION;
        break;
      }

      if(!forms) {
        value = va_arg(arg, char *);
        ccsid = (unsigned int) va_arg(arg, long);
      }
      else {
        ccsid = (unsigned int) forms->value;
        forms++;
      }

      /* Do the conversion. */

      lforms[nargs].value = value;

      if(Curl_formadd_convert(lforms, nargs, -1, ccsid) < 0) {
        result = CURL_FORMADD_MEMORY;
        break;
      }

      value = lforms[nargs].value;
    }

    if(result != CURL_FORMADD_OK)
      break;

    lforms[nargs].value = value;
    lforms[nargs++].option = option;
  }

  va_end(arg);

  /* Convert the name and the last content, now that we know their lengths. */

  if(result == CURL_FORMADD_OK && namex >= 0) {
    if(Curl_formadd_convert(lforms, namex, namelengthx, nameccsid) < 0)
      result = CURL_FORMADD_MEMORY;
    else
      lforms[namex].option = CURLFORM_COPYNAME; /* Force copy. */
  }

  if(result == CURL_FORMADD_OK) {
    if(Curl_formadd_convert(lforms, contentx, lengthx, contentccsid) < 0)
      result = CURL_FORMADD_MEMORY;
    else
      contentx = -1;
  }

  /* Do the formadd with our converted parameters. */

  if(result == CURL_FORMADD_OK) {
    lforms[nargs].option = CURLFORM_END;
    result = curl_formadd(httppost, last_post,
                          CURLFORM_ARRAY, lforms, CURLFORM_END);
  }

  /* Terminate. */

  Curl_formadd_release_local(lforms, nargs, contentx);
  return result;
}

struct cfcdata {
  curl_formget_callback append;
  void *                arg;
  unsigned int          ccsid;
};

static size_t formget_callback_ccsid(void *arg, const char *buf, size_t len)
{
  struct cfcdata *p;
  size_t olen;
  size_t ret;
  struct dynbuf db;

  p = (struct cfcdata *) arg;

  if((long) len <= 0)
    return p->append(p->arg, buf, len);

  curlx_dyn_init(&db, MAX_CONV_EXPANSION * CURL_MAX_INPUT_LENGTH);

  if(dyn_addn_CCSID(&db, buf, len, ASCII_CCSID, p->ccsid))
    return (size_t) -1;

  olen = curlx_dyn_len(&db);
  ret = p->append(p->arg, curlx_dyn_ptr(&db), olen);
  curlx_dyn_free(&db);
  return ret == olen ? len : -1;
}

int curl_formget_ccsid(struct curl_httppost *form, void *arg,
                       curl_formget_callback append, unsigned int ccsid)
{
  struct cfcdata lcfc;

  lcfc.append = append;
  lcfc.arg = arg;
  lcfc.ccsid = ccsid;
  return curl_formget(form, (void *) &lcfc, formget_callback_ccsid);
}

CURLcode curl_easy_setopt_ccsid(CURL *easy, CURLoption tag, ...)
{
  CURLcode result;
  va_list arg;
  const char *s;
  unsigned int ccsid;
  struct dynbuf db;
  curl_off_t pfsize;
  size_t len;
  struct Curl_easy *data = easy;

  curlx_dyn_init(&db, CURL_MAX_INPUT_LENGTH);
  va_start(arg, tag);

  switch(tag) {

  /* BEGIN TRANSLATABLE STRING OPTIONS */
  /* Keep option symbols in alphanumeric order and retain the BEGIN/END
     armor comments. */
  case CURLOPT_ABSTRACT_UNIX_SOCKET:
  case CURLOPT_ACCEPT_ENCODING:
  case CURLOPT_ALTSVC:
  case CURLOPT_AWS_SIGV4:
  case CURLOPT_CAINFO:
  case CURLOPT_CAPATH:
  case CURLOPT_COOKIE:
  case CURLOPT_COOKIEFILE:
  case CURLOPT_COOKIEJAR:
  case CURLOPT_COOKIELIST:
  case CURLOPT_CRLFILE:
  case CURLOPT_CUSTOMREQUEST:
  case CURLOPT_DEFAULT_PROTOCOL:
  case CURLOPT_DNS_INTERFACE:
  case CURLOPT_DNS_LOCAL_IP4:
  case CURLOPT_DNS_LOCAL_IP6:
  case CURLOPT_DNS_SERVERS:
  case CURLOPT_DOH_URL:
  case CURLOPT_ECH:
  case CURLOPT_EGDSOCKET:
  case CURLOPT_FTPPORT:
  case CURLOPT_FTP_ACCOUNT:
  case CURLOPT_FTP_ALTERNATIVE_TO_USER:
  case CURLOPT_HAPROXY_CLIENT_IP:
  case CURLOPT_HSTS:
  case CURLOPT_INTERFACE:
  case CURLOPT_ISSUERCERT:
  case CURLOPT_KEYPASSWD:
  case CURLOPT_KRBLEVEL:
  case CURLOPT_LOGIN_OPTIONS:
  case CURLOPT_MAIL_AUTH:
  case CURLOPT_MAIL_FROM:
  case CURLOPT_NETRC_FILE:
  case CURLOPT_NOPROXY:
  case CURLOPT_PASSWORD:
  case CURLOPT_PINNEDPUBLICKEY:
  case CURLOPT_PRE_PROXY:
  case CURLOPT_PROTOCOLS_STR:
  case CURLOPT_PROXY:
  case CURLOPT_PROXYPASSWORD:
  case CURLOPT_PROXYUSERNAME:
  case CURLOPT_PROXYUSERPWD:
  case CURLOPT_PROXY_CAINFO:
  case CURLOPT_PROXY_CAPATH:
  case CURLOPT_PROXY_CRLFILE:
  case CURLOPT_PROXY_ISSUERCERT:
  case CURLOPT_PROXY_KEYPASSWD:
  case CURLOPT_PROXY_PINNEDPUBLICKEY:
  case CURLOPT_PROXY_SERVICE_NAME:
  case CURLOPT_PROXY_SSLCERT:
  case CURLOPT_PROXY_SSLCERTTYPE:
  case CURLOPT_PROXY_SSLKEY:
  case CURLOPT_PROXY_SSLKEYTYPE:
  case CURLOPT_PROXY_SSL_CIPHER_LIST:
  case CURLOPT_PROXY_TLS13_CIPHERS:
  case CURLOPT_PROXY_TLSAUTH_PASSWORD:
  case CURLOPT_PROXY_TLSAUTH_TYPE:
  case CURLOPT_PROXY_TLSAUTH_USERNAME:
  case CURLOPT_RANDOM_FILE:
  case CURLOPT_RANGE:
  case CURLOPT_REDIR_PROTOCOLS_STR:
  case CURLOPT_REFERER:
  case CURLOPT_REQUEST_TARGET:
  case CURLOPT_RTSP_SESSION_ID:
  case CURLOPT_RTSP_STREAM_URI:
  case CURLOPT_RTSP_TRANSPORT:
  case CURLOPT_SASL_AUTHZID:
  case CURLOPT_SERVICE_NAME:
  case CURLOPT_SOCKS5_GSSAPI_SERVICE:
  case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
  case CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256:
  case CURLOPT_SSH_KNOWNHOSTS:
  case CURLOPT_SSH_PRIVATE_KEYFILE:
  case CURLOPT_SSH_PUBLIC_KEYFILE:
  case CURLOPT_SSLCERT:
  case CURLOPT_SSLCERTTYPE:
  case CURLOPT_SSLENGINE:
  case CURLOPT_SSLKEY:
  case CURLOPT_SSLKEYTYPE:
  case CURLOPT_SSL_CIPHER_LIST:
  case CURLOPT_SSL_EC_CURVES:
  case CURLOPT_SSL_SIGNATURE_ALGORITHMS:
  case CURLOPT_TLS13_CIPHERS:
  case CURLOPT_TLSAUTH_PASSWORD:
  case CURLOPT_TLSAUTH_TYPE:
  case CURLOPT_TLSAUTH_USERNAME:
  case CURLOPT_UNIX_SOCKET_PATH:
  case CURLOPT_URL:
  case CURLOPT_USERAGENT:
  case CURLOPT_USERNAME:
  case CURLOPT_USERPWD:
  case CURLOPT_XOAUTH2_BEARER:
  /* END TRANSLATABLE STRING OPTIONS */
    s = va_arg(arg, const char *);
    ccsid = va_arg(arg, unsigned int);

    if(s) {
      s = curl_from_ccsid(s, ccsid);

      if(!s) {
        result = CURLE_OUT_OF_MEMORY;
        break;
      }
    }

    result = curl_easy_setopt(easy, tag, s);
    untyped_free(s);
    break;

  case CURLOPT_COPYPOSTFIELDS:
    /* Special case: byte count may have been given by CURLOPT_POSTFIELDSIZE
       prior to this call. In this case, convert the given byte count and
       replace the length according to the conversion result. */
    s = va_arg(arg, const char *);
    ccsid = va_arg(arg, unsigned int);

    pfsize = data->set.postfieldsize;

    if(!s || !pfsize || ccsid == NOCONV_CCSID || ccsid == ASCII_CCSID) {
      result = curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, s);
      break;
    }

    if(pfsize != -1) {
      /* Data length specified. */
      if(pfsize < 0 || pfsize > SIZE_MAX) {
        result = CURLE_OUT_OF_MEMORY;
        break;
      }
      result = dyn_addn_CCSID(&db, s, CURL_ZERO_TERMINATED,
                              ccsid, ASCII_CCSID);
    }
    else
      result = dyn_addn_CCSID(&db, s, (size_t) pfsize, ccsid, ASCII_CCSID);

    if(result)
      break;

    s = curlx_dyn_take(&db, &len);

    /* The following lines give data ownership to the library without
       copying them. */
    result = curl_easy_setopt(easy, CURLOPT_POSTFIELDS, s);
    if(!result) {
      data->set.str[STRING_COPYPOSTFIELDS] = CURL_UNCONST(s); /* Adopt. */
      if(pfsize != -1)
        data->set.postfieldsize = len;
    }
    else
      untyped_free(s);

    break;

  default:
    if(tag / 10000 == CURLOPTTYPE_BLOB) {
      struct curl_blob *bp = va_arg(arg, struct curl_blob *);
      struct curl_blob blob;

      ccsid = va_arg(arg, unsigned int);

      if(bp && bp->data && bp->len &&
         ccsid != NOCONV_CCSID && ccsid != ASCII_CCSID) {
       result = dyn_addn_CCSID(&db, bp->data, bp->len, ccsid, ASCII_CCSID);
       if(result)
         break;

        blob.data = curlx_dyn_ptr(&db);
        blob.len = curlx_dyn_len(&db);
        blob.flags = bp->flags | CURL_BLOB_COPY;
        bp = &blob;
      }
      result = curl_easy_setopt(easy, tag, bp);
      break;
    }
    FALLTHROUGH();
  case CURLOPT_ERRORBUFFER: /* This is an output buffer. */
    result = Curl_vsetopt(easy, tag, arg);
    break;
  }

  va_end(arg);
  curlx_dyn_free(&db);
  return result;
}

/* ILE/RPG helper functions. */

char *curl_form_long_value(long value)
{
  /* ILE/RPG cannot cast an integer to a pointer. This procedure does it.
     As OS/400 is unable to dereference a pointer built from an integer only,
     the goal here is only to keep the integer value as a (invalid) pointer
     for a later reverse conversion. */

  return (char *) value;
}

CURLcode curl_easy_setopt_RPGnum_(CURL *easy, CURLoption tag, curl_off_t arg)
{
  /* ILE/RPG procedure overloading cannot discriminate between different
     size and/or signedness of format arguments. This provides a generic
     wrapper that adapts size to the given tag expectation.
     This procedure is not intended to be explicitly called from user code. */
  if(tag / 10000 != CURLOPTTYPE_OFF_T)
    return curl_easy_setopt(easy, tag, (long) arg);
  return curl_easy_setopt(easy, tag, arg);
}

CURLcode curl_multi_setopt_RPGnum_(CURLM *multi, CURLMoption tag,
                                   curl_off_t arg)
{
  /* Likewise, for multi handle. */
  if(tag / 10000 != CURLOPTTYPE_OFF_T)
    return curl_multi_setopt(multi, tag, (long) arg);
  return curl_multi_setopt(multi, tag, arg);
}

char *curl_pushheader_bynum_cssid(struct curl_pushheaders *h, size_t num,
                                  unsigned int ccsid)
{
  return CURL_UNCONST(curl_to_ccsid(curl_pushheader_bynum(h, num), ccsid));
}

char *curl_pushheader_byname_ccsid(struct curl_pushheaders *h,
                                   const char *header, unsigned int ccsidin,
                                   unsigned int ccsidout)
{
  const char *d = NULL;

  if(header) {
    const char *hdr = curl_from_ccsid(header, ccsidin);

    if(hdr) {
      char *s = curl_pushheader_byname(h, hdr);

      untyped_free(hdr);

      if(s)
        d = curl_to_ccsid(s, ccsidout);
    }
  }

  return CURL_UNCONST(d);
}

static CURLcode
mime_string_call(curl_mimepart *part, const char *string, unsigned int ccsid,
                 CURLcode (*mimefunc)(curl_mimepart *part, const char *string))
{
  const char *s;
  CURLcode result;

  if(!string)
    return mimefunc(part, string);
  s = curl_from_ccsid(string, ccsid);
  if(!s)
    return CURLE_OUT_OF_MEMORY;

  result = mimefunc(part, s);
  untyped_free(s);
  return result;
}

CURLcode curl_mime_name_ccsid(curl_mimepart *part, const char *name,
                              unsigned int ccsid)
{
  return mime_string_call(part, name, ccsid, curl_mime_name);
}

CURLcode curl_mime_filename_ccsid(curl_mimepart *part, const char *filename,
                                  unsigned int ccsid)
{
  return mime_string_call(part, filename, ccsid, curl_mime_filename);
}

CURLcode curl_mime_type_ccsid(curl_mimepart *part, const char *mimetype,
                              unsigned int ccsid)
{
  return mime_string_call(part, mimetype, ccsid, curl_mime_type);
}

CURLcode curl_mime_encoder_ccsid(curl_mimepart *part, const char *encoding,
                                 unsigned int ccsid)
{
  return mime_string_call(part, encoding, ccsid, curl_mime_encoder);
}

CURLcode curl_mime_filedata_ccsid(curl_mimepart *part, const char *filename,
                                  unsigned int ccsid)
{
  return mime_string_call(part, filename, ccsid, curl_mime_filedata);
}

CURLcode curl_mime_data_ccsid(curl_mimepart *part, const char *data,
                              size_t datasize, unsigned int ccsid)
{
  struct dynbuf db;
  CURLcode result;

  if(!data)
    return curl_mime_data(part, data, datasize);

  curlx_dyn_init(&db, CURL_MAX_INPUT_LENGTH);

  result = dyn_addn_CCSID(&db, data, datasize, ccsid, ASCII_CCSID);

  if(!result) {
    size_t osize;
    char *newdata = curlx_dyn_take(&db, &osize);

    result = curl_mime_data(part, newdata, datasize == CURL_ZERO_TERMINATED ?
                                           datasize : osize);
    untyped_free(newdata);
  }

  return result;
}

CURLUcode curl_url_get_ccsid(CURLU *handle, CURLUPart what, char **part,
                             unsigned int flags, unsigned int ccsid)
{
  char *s = NULL;
  CURLUcode result;

  if(!part)
    return CURLUE_BAD_PARTPOINTER;

  *part = NULL;
  result = curl_url_get(handle, what, &s, flags);
  if(result == CURLUE_OK) {
    if(s) {
      const char *d = curl_to_ccsid(s, ccsid);

      if(d)
        *part = CURL_UNCONST(d);
      else
        result = CURLUE_OUT_OF_MEMORY;
    }
  }
  if(s)
    untyped_free(s);
  return result;
}

CURLUcode curl_url_set_ccsid(CURLU *handle, CURLUPart what, const char *part,
                             unsigned int flags, unsigned int ccsid)
{
  const char *s = NULL;
  CURLUcode result;

  if(part) {
    s = curl_from_ccsid(part, ccsid);
    if(!s)
      return CURLUE_OUT_OF_MEMORY;
  }
  result = curl_url_set(handle, what, s, flags);
  if(s)
    untyped_free(s);
  return result;
}

const struct curl_easyoption *
curl_easy_option_by_name_ccsid(const char *name, unsigned int ccsid)
{
  const struct curl_easyoption *option = NULL;

  if(name) {
    const char *s = curl_from_ccsid(name, ccsid);

    if(s) {
      option = curl_easy_option_by_name(s);
      untyped_free(s);
    }
  }

  return option;
}

/* Return option name in the given ccsid. */
const char *
curl_easy_option_get_name_ccsid(const struct curl_easyoption *option,
                                unsigned int ccsid)
{
  const char *name = NULL;

  if(option && option->name)
    name = curl_to_ccsid(option->name, ccsid);

  return name;
}

/* Header API CCSID support. */
CURLHcode curl_easy_header_ccsid(CURL *easy, const char *name, size_t index,
                                 unsigned int origin, int request,
                                 struct curl_header **hout, unsigned int ccsid)
{
  CURLHcode result = CURLHE_BAD_ARGUMENT;

  if(name) {
    const char *s = curl_from_ccsid(name, ccsid);

    result = CURLHE_OUT_OF_MEMORY;
    if(s) {
      result = curl_easy_header(easy, s, index, origin, request, hout);
      untyped_free(s);
    }
  }

  return result;
}
