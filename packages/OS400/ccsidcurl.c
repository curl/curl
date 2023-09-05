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

#include "curl.h"
#include "mprintf.h"
#include "slist.h"
#include "urldata.h"
#include "url.h"
#include "setopt.h"
#include "getinfo.h"
#include "ccsidcurl.h"

#include "os400sys.h"

#ifndef SIZE_MAX
#define SIZE_MAX        ((size_t) ~0)   /* Is unsigned on OS/400. */
#endif


#define ASCII_CCSID     819     /* Use ISO-8859-1 as ASCII. */
#define NOCONV_CCSID    65535   /* No conversion. */
#define ICONV_ID_SIZE   32      /* Size of iconv_open() code identifier. */
#define ICONV_OPEN_ERROR(t)     ((t).return_value == -1)

#define ALLOC_GRANULE   8       /* Alloc. granule for curl_formadd_ccsid(). */


static void
makeOS400IconvCode(char buf[ICONV_ID_SIZE], unsigned int ccsid)
{
  /**
  *** Convert a CCSID to the corresponding IBM iconv_open() character
  ***  code identifier.
  ***  This code is specific to the OS400 implementation of the iconv library.
  ***  CCSID 65535 (no conversion) is replaced by the ASCII CCSID.
  ***  CCSID 0 is interpreted by the OS400 as the job's CCSID.
  **/

  ccsid &= 0xFFFF;

  if(ccsid == NOCONV_CCSID)
    ccsid = ASCII_CCSID;

  memset(buf, 0, ICONV_ID_SIZE);
  curl_msprintf(buf, "IBMCCSID%05u0000000", ccsid);
}


static iconv_t
iconv_open_CCSID(unsigned int ccsidout, unsigned int ccsidin,
                 unsigned int cstr)
{
  char fromcode[ICONV_ID_SIZE];
  char tocode[ICONV_ID_SIZE];

  /**
  ***  Like iconv_open(), but character codes are given as CCSIDs.
  ***  If `cstr' is non-zero, conversion is set up to stop whenever a
  ***   null character is encountered.
  ***  See iconv_open() IBM description in "National Language Support API".
  **/

  makeOS400IconvCode(fromcode, ccsidin);
  makeOS400IconvCode(tocode, ccsidout);
  memset(tocode + 13, 0, sizeof(tocode) - 13);   /* Dest. code id format. */

  if(cstr)
    fromcode[18] = '1';                         /* Set null-terminator flag. */

  return iconv_open(tocode, fromcode);
}


static int
convert(char *d, size_t dlen, int dccsid,
        const char *s, int slen, int sccsid)
{
  int i;
  iconv_t cd;
  size_t lslen;

  /**
  ***  Convert `sccsid'-coded `slen'-data bytes at `s' into `dccsid'-coded
  ***   data stored in the `dlen'-byte buffer at `d'.
  ***  If `slen' < 0, source string is null-terminated.
  ***  CCSID 65535 (no conversion) is replaced by the ASCII CCSID.
  ***  Return the converted destination byte count, or -1 if error.
  **/

  if(sccsid == 65535)
    sccsid = ASCII_CCSID;

  if(dccsid == 65535)
    dccsid = ASCII_CCSID;

  if(sccsid == dccsid) {
    lslen = slen >= 0? slen: strlen(s) + 1;
    i = lslen < dlen? lslen: dlen;

    if(s != d && i > 0)
      memcpy(d, s, i);

    return i;
    }

  if(slen < 0) {
    lslen = 0;
    cd = iconv_open_CCSID(dccsid, sccsid, 1);
    }
  else {
    lslen = (size_t) slen;
    cd = iconv_open_CCSID(dccsid, sccsid, 0);
    }

  if(ICONV_OPEN_ERROR(cd))
    return -1;

  i = dlen;

  if((int) iconv(cd, (char * *) &s, &lslen, &d, &dlen) < 0)
    i = -1;
  else
    i -= dlen;

  iconv_close(cd);
  return i;
}


static char *dynconvert(int dccsid, const char *s, int slen, int sccsid)
{
  char *d;
  char *cp;
  size_t dlen;
  int l;
  static const char nullbyte = 0;

  /* Like convert, but the destination is allocated and returned. */

  dlen = (size_t) (slen < 0? strlen(s): slen) + 1;
  dlen *= MAX_CONV_EXPANSION;           /* Allow some expansion. */
  d = malloc(dlen);

  if(!d)
    return (char *) NULL;

  l = convert(d, dlen, dccsid, s, slen, sccsid);

  if(l < 0) {
    free(d);
    return (char *) NULL;
    }

  if(slen < 0) {
    /* Need to null-terminate even when source length is given.
       Since destination code size is unknown, use a conversion to generate
       terminator. */

    int l2 = convert(d + l, dlen - l, dccsid, &nullbyte, -1, ASCII_CCSID);

    if(l2 < 0) {
      free(d);
      return (char *) NULL;
      }

    l += l2;
    }

  if((size_t) l < dlen) {
    cp = realloc(d, l);         /* Shorten to minimum needed. */

    if(cp)
      d = cp;
    }

  return d;
}


static struct curl_slist *
slist_convert(int dccsid, struct curl_slist *from, int sccsid)
{
  struct curl_slist *to = (struct curl_slist *) NULL;

  for(; from; from = from->next) {
    struct curl_slist *nl;
    char *cp = dynconvert(dccsid, from->data, -1, sccsid);

    if(!cp) {
      curl_slist_free_all(to);
      return (struct curl_slist *) NULL;
    }
    nl = Curl_slist_append_nodup(to, cp);
    if(!nl) {
      curl_slist_free_all(to);
      free(cp);
      return NULL;
    }
    to = nl;
  }
  return to;
}


static char *
keyed_string(localkey_t key, const char *ascii, unsigned int ccsid)
{
  int i;
  char *ebcdic;

  if(!ascii)
    return (char *) NULL;

  i = MAX_CONV_EXPANSION * (strlen(ascii) + 1);

  ebcdic = Curl_thread_buffer(key, i);
  if(!ebcdic)
    return ebcdic;

  if(convert(ebcdic, i, ccsid, ascii, -1, ASCII_CCSID) < 0)
    return (char *) NULL;

  return ebcdic;
}


const char *
curl_to_ccsid(const char *s, unsigned int ccsid)
{
  if(s)
    s = dynconvert(ccsid, s, -1, ASCII_CCSID);
  return s;
}


const char *
curl_from_ccsid(const char *s, unsigned int ccsid)
{
  if(s)
    s = dynconvert(ASCII_CCSID, s, -1, ccsid);
  return s;
}


char *
curl_version_ccsid(unsigned int ccsid)
{
  return keyed_string(LK_CURL_VERSION, curl_version(), ccsid);
}


char *
curl_easy_escape_ccsid(CURL *handle, const char *string, int length,
                       unsigned int sccsid, unsigned int dccsid)
{
  char *s;
  char *d;

  if(!string) {
    errno = EINVAL;
    return (char *) NULL;
    }

  s = dynconvert(ASCII_CCSID, string, length? length: -1, sccsid);

  if(!s)
    return (char *) NULL;

  d = curl_easy_escape(handle, s, 0);
  free(s);

  if(!d)
    return (char *) NULL;

  s = dynconvert(dccsid, d, -1, ASCII_CCSID);
  free(d);
  return s;
}


char *
curl_easy_unescape_ccsid(CURL *handle, const char *string, int length,
                         int *outlength,
                         unsigned int sccsid, unsigned int dccsid)
{
  char *s;
  char *d;

  if(!string) {
    errno = EINVAL;
    return (char *) NULL;
    }

  s = dynconvert(ASCII_CCSID, string, length? length: -1, sccsid);

  if(!s)
    return (char *) NULL;

  d = curl_easy_unescape(handle, s, 0, outlength);
  free(s);

  if(!d)
    return (char *) NULL;

  s = dynconvert(dccsid, d, -1, ASCII_CCSID);
  free(d);

  if(s && outlength)
    *outlength = strlen(s);

  return s;
}


struct curl_slist *
curl_slist_append_ccsid(struct curl_slist *list,
                        const char *data, unsigned int ccsid)
{
  char *s;

  s = (char *) NULL;

  if(!data)
    return curl_slist_append(list, data);

  s = dynconvert(ASCII_CCSID, data, -1, ccsid);

  if(!s)
    return (struct curl_slist *) NULL;

  list = curl_slist_append(list, s);
  free(s);
  return list;
}


time_t
curl_getdate_ccsid(const char *p, const time_t *unused, unsigned int ccsid)
{
  char *s;
  time_t t;

  if(!p)
    return curl_getdate(p, unused);

  s = dynconvert(ASCII_CCSID, p, -1, ccsid);

  if(!s)
    return (time_t) -1;

  t = curl_getdate(s, unused);
  free(s);
  return t;
}


static int
convert_version_info_string(const char **stringp,
                            char **bufp, int *left, unsigned int ccsid)
{
  /* Helper for curl_version_info_ccsid(): convert a string if defined.
     Result is stored in the `*left'-byte buffer at `*bufp'.
     `*bufp' and `*left' are updated accordingly.
     Return 0 if ok, else -1. */

  if(*stringp) {
    int l = convert(*bufp, *left, ccsid, *stringp, -1, ASCII_CCSID);

    if(l <= 0)
      return -1;

    *stringp = *bufp;
    *bufp += l;
    *left -= l;
    }

  return 0;
}


curl_version_info_data *
curl_version_info_ccsid(CURLversion stamp, unsigned int ccsid)
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
    offsetof(curl_version_info_data, feature_names)
  };

  /* The assertion below is possible, because although the second operand
     is an enum member, the first is a #define. In that case, the OS/400 C
     compiler seems to compare string values after substitution. */

#if CURLVERSION_NOW != CURLVERSION_ELEVENTH
#error curl_version_info_data structure has changed: upgrade this procedure.
#endif

  /* If caller has been compiled with a newer version, error. */

  if(stamp > CURLVERSION_NOW)
    return (curl_version_info_data *) NULL;

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
    return (curl_version_info_data *) NULL;

  /* Copy data and convert strings. */

  memcpy((char *) id, (char *) p, sizeof(*p));

  if(id->protocols) {
    i = nproto * sizeof(id->protocols[0]);

    id->protocols = (const char * const *) cp;
    memcpy(cp, (char *) p->protocols, i);
    cp += i;
    n -= i;

    for(i = 0; id->protocols[i]; i++)
      if(convert_version_info_string(((const char * *) id->protocols) + i,
                                      &cp, &n, ccsid))
        return (curl_version_info_data *) NULL;
  }

  for(i = 0; i < sizeof(charfields) / sizeof(charfields[0]); i++) {
    cpp = (const char **) ((char *) p + charfields[i]);
    if(*cpp && convert_version_info_string(cpp, &cp, &n, ccsid))
      return (curl_version_info_data *) NULL;
  }

  return id;
}


const char *
curl_easy_strerror_ccsid(CURLcode error, unsigned int ccsid)
{
  return keyed_string(LK_EASY_STRERROR, curl_easy_strerror(error), ccsid);
}


const char *
curl_share_strerror_ccsid(CURLSHcode error, unsigned int ccsid)
{
  return keyed_string(LK_SHARE_STRERROR, curl_share_strerror(error), ccsid);
}


const char *
curl_multi_strerror_ccsid(CURLMcode error, unsigned int ccsid)
{
  return keyed_string(LK_MULTI_STRERROR, curl_multi_strerror(error), ccsid);
}


const char *
curl_url_strerror_ccsid(CURLUcode error, unsigned int ccsid)
{
  return keyed_string(LK_URL_STRERROR, curl_url_strerror(error), ccsid);
}


void
curl_certinfo_free_all(struct curl_certinfo *info)
{
  /* Free all memory used by certificate info. */
  if(info) {
    if(info->certinfo) {
      int i;

      for(i = 0; i < info->num_of_certs; i++)
        curl_slist_free_all(info->certinfo[i]);
      free((char *) info->certinfo);
    }
    free((char *) info);
  }
}


CURLcode
curl_easy_getinfo_ccsid(CURL *curl, CURLINFO info, ...)
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
    char **cpp;
    struct curl_slist **slp;
    struct curl_certinfo *cipf;
    struct curl_certinfo *cipt;

    switch((int) info & CURLINFO_TYPEMASK) {

    case CURLINFO_STRING:
      ccsid = va_arg(arg, unsigned int);
      cpp = (char * *) paramp;

      if(*cpp) {
        *cpp = dynconvert(ccsid, *cpp, -1, ASCII_CCSID);

        if(!*cpp)
          ret = CURLE_OUT_OF_MEMORY;
      }

      break;

    case CURLINFO_SLIST:
      ccsid = va_arg(arg, unsigned int);
      switch(info) {
      case CURLINFO_CERTINFO:
        cipf = *(struct curl_certinfo * *) paramp;
        if(cipf) {
          cipt = (struct curl_certinfo *) malloc(sizeof(*cipt));
          if(!cipt)
            ret = CURLE_OUT_OF_MEMORY;
          else {
            cipt->certinfo = (struct curl_slist **)
              calloc(cipf->num_of_certs +
                     1, sizeof(struct curl_slist *));
            if(!cipt->certinfo)
              ret = CURLE_OUT_OF_MEMORY;
            else {
              int i;

              cipt->num_of_certs = cipf->num_of_certs;
              for(i = 0; i < cipf->num_of_certs; i++)
                if(cipf->certinfo[i])
                  if(!(cipt->certinfo[i] = slist_convert(ccsid,
                                                          cipf->certinfo[i],
                                                          ASCII_CCSID))) {
                    ret = CURLE_OUT_OF_MEMORY;
                    break;
                  }
              }
            }

          if(ret != CURLE_OK) {
            curl_certinfo_free_all(cipt);
            cipt = (struct curl_certinfo *) NULL;
          }

          *(struct curl_certinfo * *) paramp = cipt;
        }

        break;

      case CURLINFO_TLS_SESSION:
      case CURLINFO_TLS_SSL_PTR:
      case CURLINFO_SOCKET:
        break;

      default:
        slp = (struct curl_slist **) paramp;
        if(*slp) {
          *slp = slist_convert(ccsid, *slp, ASCII_CCSID);
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


static int
Curl_is_formadd_string(CURLformoption option)
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


static void
Curl_formadd_release_local(struct curl_forms *forms, int nargs, int skip)
{
  while(nargs--)
    if(nargs != skip)
      if(Curl_is_formadd_string(forms[nargs].option))
        if(forms[nargs].value)
          free((char *) forms[nargs].value);

  free((char *) forms);
}


static int
Curl_formadd_convert(struct curl_forms *forms,
                     int formx, int lengthx, unsigned int ccsid)
{
  int l;
  char *cp;
  char *cp2;

  if(formx < 0 || !forms[formx].value)
    return 0;

  if(lengthx >= 0)
    l = (int) forms[lengthx].value;
  else
    l = strlen(forms[formx].value) + 1;

  cp = malloc(MAX_CONV_EXPANSION * l);

  if(!cp)
    return -1;

  l = convert(cp, MAX_CONV_EXPANSION * l, ASCII_CCSID,
              forms[formx].value, l, ccsid);

  if(l < 0) {
    free(cp);
    return -1;
    }

  cp2 = realloc(cp, l);         /* Shorten buffer to the string size. */

  if(cp2)
    cp = cp2;

  forms[formx].value = cp;

  if(lengthx >= 0)
    forms[lengthx].value = (char *) l;  /* Update length after conversion. */

  return l;
}


CURLFORMcode
curl_formadd_ccsid(struct curl_httppost **httppost,
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
  lforms = malloc(lformlen * sizeof(*lforms));

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
  forms = (struct curl_forms *) NULL;
  va_start(arg, last_post);

  for(;;) {
    /* Make sure there is still room for an item in local array. */

    if(nargs >= lformlen) {
      lformlen += ALLOC_GRANULE;
      tforms = realloc(lforms, lformlen * sizeof(*lforms));

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
      forms = (struct curl_forms *) NULL;       /* Leave array mode. */
      continue;

    case CURLFORM_ARRAY:
      if(!forms) {
        forms = va_arg(arg, struct curl_forms *);
        continue;
        }

      result = CURL_FORMADD_ILLEGAL_ARRAY;
      break;

    case CURLFORM_COPYNAME:
      option = CURLFORM_PTRNAME;                /* Static for now. */

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
        value = va_arg(arg, char *);            /* No conversion. */

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
      lforms[namex].option = CURLFORM_COPYNAME;         /* Force copy. */
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


static size_t
Curl_formget_callback_ccsid(void *arg, const char *buf, size_t len)
{
  struct cfcdata *p;
  char *b;
  int l;
  size_t ret;

  p = (struct cfcdata *) arg;

  if((long) len <= 0)
    return (*p->append)(p->arg, buf, len);

  b = malloc(MAX_CONV_EXPANSION * len);

  if(!b)
    return (size_t) -1;

  l = convert(b, MAX_CONV_EXPANSION * len, p->ccsid, buf, len, ASCII_CCSID);

  if(l < 0) {
    free(b);
    return (size_t) -1;
    }

  ret = (*p->append)(p->arg, b, l);
  free(b);
  return ret == l? len: -1;
}


int
curl_formget_ccsid(struct curl_httppost *form, void *arg,
                   curl_formget_callback append, unsigned int ccsid)
{
  struct cfcdata lcfc;

  lcfc.append = append;
  lcfc.arg = arg;
  lcfc.ccsid = ccsid;
  return curl_formget(form, (void *) &lcfc, Curl_formget_callback_ccsid);
}


CURLcode
curl_easy_setopt_ccsid(CURL *easy, CURLoption tag, ...)
{
  CURLcode result;
  va_list arg;
  char *s;
  char *cp = NULL;
  unsigned int ccsid;
  curl_off_t pfsize;

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
    s = va_arg(arg, char *);
    ccsid = va_arg(arg, unsigned int);

    if(s) {
      s = dynconvert(ASCII_CCSID, s, -1, ccsid);

      if(!s) {
        result = CURLE_OUT_OF_MEMORY;
        break;
      }
    }

    result = curl_easy_setopt(easy, tag, s);
    free(s);
    break;

  case CURLOPT_COPYPOSTFIELDS:
    /* Special case: byte count may have been given by CURLOPT_POSTFIELDSIZE
       prior to this call. In this case, convert the given byte count and
       replace the length according to the conversion result. */
    s = va_arg(arg, char *);
    ccsid = va_arg(arg, unsigned int);

    pfsize = easy->set.postfieldsize;

    if(!s || !pfsize || ccsid == NOCONV_CCSID || ccsid == ASCII_CCSID) {
      result = curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, s);
      break;
    }

    if(pfsize == -1) {
      /* Data is null-terminated. */
      s = dynconvert(ASCII_CCSID, s, -1, ccsid);

      if(!s) {
        result = CURLE_OUT_OF_MEMORY;
        break;
        }
      }
    else {
      /* Data length specified. */
      size_t len;

      if(pfsize < 0 || pfsize > SIZE_MAX) {
        result = CURLE_OUT_OF_MEMORY;
        break;
      }

      len = pfsize;
      pfsize = len * MAX_CONV_EXPANSION;

      if(pfsize > SIZE_MAX)
        pfsize = SIZE_MAX;

      cp = malloc(pfsize);

      if(!cp) {
        result = CURLE_OUT_OF_MEMORY;
        break;
      }

      pfsize = convert(cp, pfsize, ASCII_CCSID, s, len, ccsid);

      if(pfsize < 0) {
        result = CURLE_OUT_OF_MEMORY;
        break;
      }

      easy->set.postfieldsize = pfsize;         /* Replace data size. */
      s = cp;
    }

    result = curl_easy_setopt(easy, CURLOPT_POSTFIELDS, s);
    easy->set.str[STRING_COPYPOSTFIELDS] = s;   /* Give to library. */
    break;

  default:
    if(tag / 10000 == CURLOPTTYPE_BLOB) {
      struct curl_blob *bp = va_arg(arg, struct curl_blob *);
      struct curl_blob blob;

      ccsid = va_arg(arg, unsigned int);

      if(bp && bp->data && bp->len &&
         ccsid != NOCONV_CCSID && ccsid != ASCII_CCSID) {
        pfsize = (curl_off_t) bp->len * MAX_CONV_EXPANSION;

        if(pfsize > SIZE_MAX)
          pfsize = SIZE_MAX;

        cp = malloc(pfsize);

        if(!cp) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }

        pfsize = convert(cp, pfsize, ASCII_CCSID, bp->data, bp->len, ccsid);

        if(pfsize < 0) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }

        blob.data = cp;
        blob.len = pfsize;
        blob.flags = bp->flags | CURL_BLOB_COPY;
        bp = &blob;
      }
      result = curl_easy_setopt(easy, tag, &blob);
      break;
    }
    /* FALLTHROUGH */
  case CURLOPT_ERRORBUFFER:                     /* This is an output buffer. */
    result = Curl_vsetopt(easy, tag, arg);
    break;
  }

  va_end(arg);
  free(cp);
  return result;
}


/* ILE/RPG helper functions. */

char *
curl_form_long_value(long value)
{
  /* ILE/RPG cannot cast an integer to a pointer. This procedure does it. */

  return (char *) value;
}


CURLcode
curl_easy_setopt_RPGnum_(CURL *easy, CURLoption tag, curl_off_t arg)
{
  /* ILE/RPG procedure overloading cannot discriminate between different
     size and/or signedness of format arguments. This provides a generic
     wrapper that adapts size to the given tag expectation.
     This procedure is not intended to be explicitly called from user code. */
  if(tag / 10000 != CURLOPTTYPE_OFF_T)
    return curl_easy_setopt(easy, tag, (long) arg);
  return curl_easy_setopt(easy, tag, arg);
}


CURLcode
curl_multi_setopt_RPGnum_(CURLM *multi, CURLMoption tag, curl_off_t arg)
{
  /* Likewise, for multi handle. */
  if(tag / 10000 != CURLOPTTYPE_OFF_T)
    return curl_multi_setopt(multi, tag, (long) arg);
  return curl_multi_setopt(multi, tag, arg);
}


char *
curl_pushheader_bynum_cssid(struct curl_pushheaders *h,
                            size_t num, unsigned int ccsid)
{
  char *d = (char *) NULL;
  char *s = curl_pushheader_bynum(h, num);

  if(s)
    d = dynconvert(ccsid, s, -1, ASCII_CCSID);

  return d;
}


char *
curl_pushheader_byname_ccsid(struct curl_pushheaders *h, const char *header,
                             unsigned int ccsidin, unsigned int ccsidout)
{
  char *d = (char *) NULL;

  if(header) {
    header = dynconvert(ASCII_CCSID, header, -1, ccsidin);

    if(header) {
      char *s = curl_pushheader_byname(h, header);
      free((char *) header);

      if(s)
        d = dynconvert(ccsidout, s, -1, ASCII_CCSID);
    }
  }

  return d;
}

static CURLcode
mime_string_call(curl_mimepart *part, const char *string, unsigned int ccsid,
                 CURLcode (*mimefunc)(curl_mimepart *part, const char *string))
{
  char *s = (char *) NULL;
  CURLcode result;

  if(!string)
    return mimefunc(part, string);
  s = dynconvert(ASCII_CCSID, string, -1, ccsid);
  if(!s)
    return CURLE_OUT_OF_MEMORY;

  result = mimefunc(part, s);
  free(s);
  return result;
}

CURLcode
curl_mime_name_ccsid(curl_mimepart *part, const char *name, unsigned int ccsid)
{
  return mime_string_call(part, name, ccsid, curl_mime_name);
}

CURLcode
curl_mime_filename_ccsid(curl_mimepart *part,
                         const char *filename, unsigned int ccsid)
{
  return mime_string_call(part, filename, ccsid, curl_mime_filename);
}

CURLcode
curl_mime_type_ccsid(curl_mimepart *part,
                     const char *mimetype, unsigned int ccsid)
{
  return mime_string_call(part, mimetype, ccsid, curl_mime_type);
}

CURLcode
curl_mime_encoder_ccsid(curl_mimepart *part,
                       const char *encoding, unsigned int ccsid)
{
  return mime_string_call(part, encoding, ccsid, curl_mime_encoder);
}

CURLcode
curl_mime_filedata_ccsid(curl_mimepart *part,
                         const char *filename, unsigned int ccsid)
{
  return mime_string_call(part, filename, ccsid, curl_mime_filedata);
}

CURLcode
curl_mime_data_ccsid(curl_mimepart *part,
                     const char *data, size_t datasize, unsigned int ccsid)
{
  char *s = (char *) NULL;
  CURLcode result;

  if(!data)
    return curl_mime_data(part, data, datasize);
  s = dynconvert(ASCII_CCSID, data, datasize, ccsid);
  if(!s)
    return CURLE_OUT_OF_MEMORY;

  result = curl_mime_data(part, s, datasize);
  free(s);
  return result;
}

CURLUcode
curl_url_get_ccsid(CURLU *handle, CURLUPart what, char **part,
                   unsigned int flags, unsigned int ccsid)
{
  char *s = (char *)NULL;
  CURLUcode result;

  if(!part)
    return CURLUE_BAD_PARTPOINTER;

  *part = (char *)NULL;
  result = curl_url_get(handle, what, &s, flags);
  if(result == CURLUE_OK) {
    if(s) {
      *part = dynconvert(ccsid, s, -1, ASCII_CCSID);
      if(!*part)
        result = CURLUE_OUT_OF_MEMORY;
    }
  }
  if(s)
    free(s);
  return result;
}

CURLUcode
curl_url_set_ccsid(CURLU *handle, CURLUPart what, const char *part,
                   unsigned int flags, unsigned int ccsid)
{
  char *s = (char *)NULL;
  CURLUcode result;

  if(part) {
    s = dynconvert(ASCII_CCSID, part, -1, ccsid);
    if(!s)
      return CURLUE_OUT_OF_MEMORY;
  }
  result = curl_url_set(handle, what, s, flags);
  if(s)
    free(s);
  return result;
}

const struct curl_easyoption *
curl_easy_option_by_name_ccsid(const char *name, unsigned int ccsid)
{
  const struct curl_easyoption *option = NULL;

  if(name) {
    char *s = dynconvert(ASCII_CCSID, name, -1, ccsid);

    if(s) {
      option = curl_easy_option_by_name(s);
      free(s);
    }
  }

  return option;
}

/* Return option name in the given ccsid. */
const char *
curl_easy_option_get_name_ccsid(const struct curl_easyoption *option,
                                unsigned int ccsid)
{
  char *name = NULL;

  if(option && option->name)
    name = dynconvert(ccsid, option->name, -1, ASCII_CCSID);

  return (const char *) name;
}

/* Header API CCSID support. */
CURLHcode
curl_easy_header_ccsid(CURL *easy, const char *name, size_t index,
                       unsigned int origin, int request,
                       struct curl_header **hout, unsigned int ccsid)
{
  CURLHcode result = CURLHE_BAD_ARGUMENT;

  if(name) {
    char *s = dynconvert(ASCII_CCSID, name, -1, ccsid);

    result = CURLHE_OUT_OF_MEMORY;
    if(s) {
      result = curl_easy_header(easy, s, index, origin, request, hout);
      free(s);
    }
  }

  return result;
}
