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
 * SPDX-License-Identifier: fetch
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

#include "fetch.h"
#include "mprintf.h"
#include "slist.h"
#include "urldata.h"
#include "url.h"
#include "setopt.h"
#include "getinfo.h"
#include "ccsidfetch.h"

#include "os400sys.h"

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)~0) /* Is unsigned on OS/400. */
#endif

#define ASCII_CCSID 819    /* Use ISO-8859-1 as ASCII. */
#define NOCONV_CCSID 65535 /* No conversion. */
#define ICONV_ID_SIZE 32   /* Size of iconv_open() code identifier. */
#define ICONV_OPEN_ERROR(t) ((t).return_value == -1)

#define ALLOC_GRANULE 8 /* Alloc. granule for fetch_formadd_ccsid(). */

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

  if (ccsid == NOCONV_CCSID)
    ccsid = ASCII_CCSID;

  memset(buf, 0, ICONV_ID_SIZE);
  fetch_msprintf(buf, "IBMCCSID%05u0000000", ccsid);
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
  memset(tocode + 13, 0, sizeof(tocode) - 13); /* Dest. code id format. */

  if (cstr)
    fromcode[18] = '1'; /* Set null-terminator flag. */

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

  if (sccsid == 65535)
    sccsid = ASCII_CCSID;

  if (dccsid == 65535)
    dccsid = ASCII_CCSID;

  if (sccsid == dccsid)
  {
    lslen = slen >= 0 ? slen : strlen(s) + 1;
    i = lslen < dlen ? lslen : dlen;

    if (s != d && i > 0)
      memcpy(d, s, i);

    return i;
  }

  if (slen < 0)
  {
    lslen = 0;
    cd = iconv_open_CCSID(dccsid, sccsid, 1);
  }
  else
  {
    lslen = (size_t)slen;
    cd = iconv_open_CCSID(dccsid, sccsid, 0);
  }

  if (ICONV_OPEN_ERROR(cd))
    return -1;

  i = dlen;

  if ((int)iconv(cd, (char **)&s, &lslen, &d, &dlen) < 0)
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

  dlen = (size_t)(slen < 0 ? strlen(s) : slen) + 1;
  dlen *= MAX_CONV_EXPANSION; /* Allow some expansion. */
  d = malloc(dlen);

  if (!d)
    return (char *)NULL;

  l = convert(d, dlen, dccsid, s, slen, sccsid);

  if (l < 0)
  {
    free(d);
    return (char *)NULL;
  }

  if (slen < 0)
  {
    /* Need to null-terminate even when source length is given.
       Since destination code size is unknown, use a conversion to generate
       terminator. */

    int l2 = convert(d + l, dlen - l, dccsid, &nullbyte, -1, ASCII_CCSID);

    if (l2 < 0)
    {
      free(d);
      return (char *)NULL;
    }

    l += l2;
  }

  if ((size_t)l < dlen)
  {
    cp = realloc(d, l); /* Shorten to minimum needed. */

    if (cp)
      d = cp;
  }

  return d;
}

static struct fetch_slist *
slist_convert(int dccsid, struct fetch_slist *from, int sccsid)
{
  struct fetch_slist *to = (struct fetch_slist *)NULL;

  for (; from; from = from->next)
  {
    struct fetch_slist *nl;
    char *cp = dynconvert(dccsid, from->data, -1, sccsid);

    if (!cp)
    {
      fetch_slist_free_all(to);
      return (struct fetch_slist *)NULL;
    }
    nl = Curl_slist_append_nodup(to, cp);
    if (!nl)
    {
      fetch_slist_free_all(to);
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

  if (!ascii)
    return (char *)NULL;

  i = MAX_CONV_EXPANSION * (strlen(ascii) + 1);

  ebcdic = Curl_thread_buffer(key, i);
  if (!ebcdic)
    return ebcdic;

  if (convert(ebcdic, i, ccsid, ascii, -1, ASCII_CCSID) < 0)
    return (char *)NULL;

  return ebcdic;
}

const char *
fetch_to_ccsid(const char *s, unsigned int ccsid)
{
  if (s)
    s = dynconvert(ccsid, s, -1, ASCII_CCSID);
  return s;
}

const char *
fetch_from_ccsid(const char *s, unsigned int ccsid)
{
  if (s)
    s = dynconvert(ASCII_CCSID, s, -1, ccsid);
  return s;
}

char *
fetch_version_ccsid(unsigned int ccsid)
{
  return keyed_string(LK_FETCH_VERSION, fetch_version(), ccsid);
}

char *
fetch_easy_escape_ccsid(FETCH *handle, const char *string, int length,
                        unsigned int sccsid, unsigned int dccsid)
{
  char *s;
  char *d;

  if (!string)
  {
    errno = EINVAL;
    return (char *)NULL;
  }

  s = dynconvert(ASCII_CCSID, string, length ? length : -1, sccsid);

  if (!s)
    return (char *)NULL;

  d = fetch_easy_escape(handle, s, 0);
  free(s);

  if (!d)
    return (char *)NULL;

  s = dynconvert(dccsid, d, -1, ASCII_CCSID);
  free(d);
  return s;
}

char *
fetch_easy_unescape_ccsid(FETCH *handle, const char *string, int length,
                          int *outlength,
                          unsigned int sccsid, unsigned int dccsid)
{
  char *s;
  char *d;

  if (!string)
  {
    errno = EINVAL;
    return (char *)NULL;
  }

  s = dynconvert(ASCII_CCSID, string, length ? length : -1, sccsid);

  if (!s)
    return (char *)NULL;

  d = fetch_easy_unescape(handle, s, 0, outlength);
  free(s);

  if (!d)
    return (char *)NULL;

  s = dynconvert(dccsid, d, -1, ASCII_CCSID);
  free(d);

  if (s && outlength)
    *outlength = strlen(s);

  return s;
}

struct fetch_slist *
fetch_slist_append_ccsid(struct fetch_slist *list,
                         const char *data, unsigned int ccsid)
{
  char *s;

  s = (char *)NULL;

  if (!data)
    return fetch_slist_append(list, data);

  s = dynconvert(ASCII_CCSID, data, -1, ccsid);

  if (!s)
    return (struct fetch_slist *)NULL;

  list = fetch_slist_append(list, s);
  free(s);
  return list;
}

time_t
fetch_getdate_ccsid(const char *p, const time_t *unused, unsigned int ccsid)
{
  char *s;
  time_t t;

  if (!p)
    return fetch_getdate(p, unused);

  s = dynconvert(ASCII_CCSID, p, -1, ccsid);

  if (!s)
    return (time_t)-1;

  t = fetch_getdate(s, unused);
  free(s);
  return t;
}

static int
convert_version_info_string(const char **stringp,
                            char **bufp, int *left, unsigned int ccsid)
{
  /* Helper for fetch_version_info_ccsid(): convert a string if defined.
     Result is stored in the `*left'-byte buffer at `*bufp'.
     `*bufp' and `*left' are updated accordingly.
     Return 0 if ok, else -1. */

  if (*stringp)
  {
    int l = convert(*bufp, *left, ccsid, *stringp, -1, ASCII_CCSID);

    if (l <= 0)
      return -1;

    *stringp = *bufp;
    *bufp += l;
    *left -= l;
  }

  return 0;
}

fetch_version_info_data *
fetch_version_info_ccsid(FETCHversion stamp, unsigned int ccsid)
{
  fetch_version_info_data *p;
  char *cp;
  int n;
  int nproto;
  fetch_version_info_data *id;
  int i;
  const char **cpp;
  static const size_t charfields[] = {
      offsetof(fetch_version_info_data, version),
      offsetof(fetch_version_info_data, host),
      offsetof(fetch_version_info_data, ssl_version),
      offsetof(fetch_version_info_data, libz_version),
      offsetof(fetch_version_info_data, ares),
      offsetof(fetch_version_info_data, libidn),
      offsetof(fetch_version_info_data, libssh_version),
      offsetof(fetch_version_info_data, brotli_version),
      offsetof(fetch_version_info_data, nghttp2_version),
      offsetof(fetch_version_info_data, quic_version),
      offsetof(fetch_version_info_data, cainfo),
      offsetof(fetch_version_info_data, capath),
      offsetof(fetch_version_info_data, zstd_version),
      offsetof(fetch_version_info_data, hyper_version),
      offsetof(fetch_version_info_data, gsasl_version),
      offsetof(fetch_version_info_data, feature_names),
      offsetof(fetch_version_info_data, rtmp_version)};

  /* The assertion below is possible, because although the second operand
     is an enum member, the first is a #define. In that case, the OS/400 C
     compiler seems to compare string values after substitution. */

#if FETCHVERSION_NOW != FETCHVERSION_ELEVENTH
#error fetch_version_info_data structure has changed: upgrade this procedure.
#endif

  /* If caller has been compiled with a newer version, error. */

  if (stamp > FETCHVERSION_NOW)
    return (fetch_version_info_data *)NULL;

  p = fetch_version_info(stamp);

  if (!p)
    return p;

  /* Measure thread space needed. */

  n = 0;
  nproto = 0;

  if (p->protocols)
  {
    while (p->protocols[nproto])
      n += strlen(p->protocols[nproto++]);

    n += nproto++;
  }

  for (i = 0; i < sizeof(charfields) / sizeof(charfields[0]); i++)
  {
    cpp = (const char **)((char *)p + charfields[i]);
    if (*cpp)
      n += strlen(*cpp) + 1;
  }

  /* Allocate thread space. */

  n *= MAX_CONV_EXPANSION;

  if (nproto)
    n += nproto * sizeof(const char *);

  cp = Curl_thread_buffer(LK_VERSION_INFO_DATA, n);
  id = (fetch_version_info_data *)Curl_thread_buffer(LK_VERSION_INFO,
                                                     sizeof(*id));

  if (!id || !cp)
    return (fetch_version_info_data *)NULL;

  /* Copy data and convert strings. */

  memcpy((char *)id, (char *)p, sizeof(*p));

  if (id->protocols)
  {
    i = nproto * sizeof(id->protocols[0]);

    id->protocols = (const char *const *)cp;
    memcpy(cp, (char *)p->protocols, i);
    cp += i;
    n -= i;

    for (i = 0; id->protocols[i]; i++)
      if (convert_version_info_string(((const char **)id->protocols) + i,
                                      &cp, &n, ccsid))
        return (fetch_version_info_data *)NULL;
  }

  for (i = 0; i < sizeof(charfields) / sizeof(charfields[0]); i++)
  {
    cpp = (const char **)((char *)p + charfields[i]);
    if (*cpp && convert_version_info_string(cpp, &cp, &n, ccsid))
      return (fetch_version_info_data *)NULL;
  }

  return id;
}

const char *
fetch_easy_strerror_ccsid(FETCHcode error, unsigned int ccsid)
{
  return keyed_string(LK_EASY_STRERROR, fetch_easy_strerror(error), ccsid);
}

const char *
fetch_share_strerror_ccsid(FETCHSHcode error, unsigned int ccsid)
{
  return keyed_string(LK_SHARE_STRERROR, fetch_share_strerror(error), ccsid);
}

const char *
fetch_multi_strerror_ccsid(FETCHMcode error, unsigned int ccsid)
{
  return keyed_string(LK_MULTI_STRERROR, fetch_multi_strerror(error), ccsid);
}

const char *
fetch_url_strerror_ccsid(FETCHUcode error, unsigned int ccsid)
{
  return keyed_string(LK_URL_STRERROR, fetch_url_strerror(error), ccsid);
}

void fetch_certinfo_free_all(struct fetch_certinfo *info)
{
  /* Free all memory used by certificate info. */
  if (info)
  {
    if (info->certinfo)
    {
      int i;

      for (i = 0; i < info->num_of_certs; i++)
        fetch_slist_free_all(info->certinfo[i]);
      free((char *)info->certinfo);
    }
    free((char *)info);
  }
}

FETCHcode
fetch_easy_getinfo_ccsid(FETCH *fetch, FETCHINFO info, ...)
{
  va_list arg;
  void *paramp;
  FETCHcode ret;
  struct Curl_easy *data;

  /* WARNING: unlike fetch_easy_getinfo(), the strings returned by this
     procedure have to be free'ed. */

  data = (struct Curl_easy *)fetch;
  va_start(arg, info);
  paramp = va_arg(arg, void *);
  ret = Curl_getinfo(data, info, paramp);

  if (ret == FETCHE_OK)
  {
    unsigned int ccsid;
    char **cpp;
    struct fetch_slist **slp;
    struct fetch_certinfo *cipf;
    struct fetch_certinfo *cipt;

    switch ((int)info & FETCHINFO_TYPEMASK)
    {

    case FETCHINFO_STRING:
      ccsid = va_arg(arg, unsigned int);
      cpp = (char **)paramp;

      if (*cpp)
      {
        *cpp = dynconvert(ccsid, *cpp, -1, ASCII_CCSID);

        if (!*cpp)
          ret = FETCHE_OUT_OF_MEMORY;
      }

      break;

    case FETCHINFO_SLIST:
      ccsid = va_arg(arg, unsigned int);
      switch (info)
      {
      case FETCHINFO_CERTINFO:
        cipf = *(struct fetch_certinfo **)paramp;
        if (cipf)
        {
          cipt = (struct fetch_certinfo *)malloc(sizeof(*cipt));
          if (!cipt)
            ret = FETCHE_OUT_OF_MEMORY;
          else
          {
            cipt->certinfo = (struct fetch_slist **)
                calloc(cipf->num_of_certs +
                           1,
                       sizeof(struct fetch_slist *));
            if (!cipt->certinfo)
              ret = FETCHE_OUT_OF_MEMORY;
            else
            {
              int i;

              cipt->num_of_certs = cipf->num_of_certs;
              for (i = 0; i < cipf->num_of_certs; i++)
                if (cipf->certinfo[i])
                  if (!(cipt->certinfo[i] = slist_convert(ccsid,
                                                          cipf->certinfo[i],
                                                          ASCII_CCSID)))
                  {
                    ret = FETCHE_OUT_OF_MEMORY;
                    break;
                  }
            }
          }

          if (ret != FETCHE_OK)
          {
            fetch_certinfo_free_all(cipt);
            cipt = (struct fetch_certinfo *)NULL;
          }

          *(struct fetch_certinfo **)paramp = cipt;
        }

        break;

      case FETCHINFO_TLS_SESSION:
      case FETCHINFO_TLS_SSL_PTR:
      case FETCHINFO_SOCKET:
        break;

      default:
        slp = (struct fetch_slist **)paramp;
        if (*slp)
        {
          *slp = slist_convert(ccsid, *slp, ASCII_CCSID);
          if (!*slp)
            ret = FETCHE_OUT_OF_MEMORY;
        }
        break;
      }
    }
  }

  va_end(arg);
  return ret;
}

static int
Curl_is_formadd_string(FETCHformoption option)
{
  switch (option)
  {

  case FETCHFORM_FILENAME:
  case FETCHFORM_CONTENTTYPE:
  case FETCHFORM_BUFFER:
  case FETCHFORM_FILE:
  case FETCHFORM_FILECONTENT:
  case FETCHFORM_COPYCONTENTS:
  case FETCHFORM_COPYNAME:
    return 1;
  }

  return 0;
}

static void
Curl_formadd_release_local(struct fetch_forms *forms, int nargs, int skip)
{
  while (nargs--)
    if (nargs != skip)
      if (Curl_is_formadd_string(forms[nargs].option))
        if (forms[nargs].value)
          free((char *)forms[nargs].value);

  free((char *)forms);
}

static int
Curl_formadd_convert(struct fetch_forms *forms,
                     int formx, int lengthx, unsigned int ccsid)
{
  int l;
  char *cp;
  char *cp2;

  if (formx < 0 || !forms[formx].value)
    return 0;

  if (lengthx >= 0)
    l = (int)forms[lengthx].value;
  else
    l = strlen(forms[formx].value) + 1;

  cp = malloc(MAX_CONV_EXPANSION * l);

  if (!cp)
    return -1;

  l = convert(cp, MAX_CONV_EXPANSION * l, ASCII_CCSID,
              forms[formx].value, l, ccsid);

  if (l < 0)
  {
    free(cp);
    return -1;
  }

  cp2 = realloc(cp, l); /* Shorten buffer to the string size. */

  if (cp2)
    cp = cp2;

  forms[formx].value = cp;

  if (lengthx >= 0)
    forms[lengthx].value = (char *)l; /* Update length after conversion. */

  return l;
}

FETCHFORMcode
fetch_formadd_ccsid(struct fetch_httppost **httppost,
                    struct fetch_httppost **last_post, ...)
{
  va_list arg;
  FETCHformoption option;
  FETCHFORMcode result;
  struct fetch_forms *forms;
  struct fetch_forms *lforms;
  struct fetch_forms *tforms;
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

  /* A single fetch_formadd() call cannot be split in several calls to deal
     with all parameters: the original parameters are thus copied to a local
     fetch_forms array and converted to ASCII when needed.
     FETCHFORM_PTRNAME is processed as if it were FETCHFORM_COPYNAME.
     FETCHFORM_COPYNAME and FETCHFORM_NAMELENGTH occurrence order in
     parameters is not defined; for this reason, the actual conversion is
     delayed to the end of parameter processing. The same applies to
     FETCHFORM_COPYCONTENTS/FETCHFORM_CONTENTSLENGTH, but these may appear
     several times in the parameter list; the problem resides here in knowing
     which FETCHFORM_CONTENTSLENGTH applies to which FETCHFORM_COPYCONTENTS and
     when we can be sure to have both info for conversion: end of parameter
     list is such a point, but FETCHFORM_CONTENTTYPE is also used here as a
     natural separator between content data definitions; this seems to be
     in accordance with FormAdd() behavior. */

  /* Allocate the local fetch_forms array. */

  lformlen = ALLOC_GRANULE;
  lforms = malloc(lformlen * sizeof(*lforms));

  if (!lforms)
    return FETCH_FORMADD_MEMORY;

  /* Process the arguments, copying them into local array, latching conversion
     indexes and converting when needed. */

  result = FETCH_FORMADD_OK;
  nargs = 0;
  contentx = -1;
  lengthx = -1;
  namex = -1;
  namelengthx = -1;
  forms = (struct fetch_forms *)NULL;
  va_start(arg, last_post);

  for (;;)
  {
    /* Make sure there is still room for an item in local array. */

    if (nargs >= lformlen)
    {
      lformlen += ALLOC_GRANULE;
      tforms = realloc(lforms, lformlen * sizeof(*lforms));

      if (!tforms)
      {
        result = FETCH_FORMADD_MEMORY;
        break;
      }

      lforms = tforms;
    }

    /* Get next option. */

    if (forms)
    {
      /* Get option from array. */

      option = forms->option;
      value = forms->value;
      forms++;
    }
    else
    {
      /* Get option from arguments. */

      option = va_arg(arg, FETCHformoption);

      if (option == FETCHFORM_END)
        break;
    }

    /* Dispatch by option. */

    switch (option)
    {

    case FETCHFORM_END:
      forms = (struct fetch_forms *)NULL; /* Leave array mode. */
      continue;

    case FETCHFORM_ARRAY:
      if (!forms)
      {
        forms = va_arg(arg, struct fetch_forms *);
        continue;
      }

      result = FETCH_FORMADD_ILLEGAL_ARRAY;
      break;

    case FETCHFORM_COPYNAME:
      option = FETCHFORM_PTRNAME; /* Static for now. */

    case FETCHFORM_PTRNAME:
      if (namex >= 0)
        result = FETCH_FORMADD_OPTION_TWICE;

      namex = nargs;

      if (!forms)
      {
        value = va_arg(arg, char *);
        nameccsid = (unsigned int)va_arg(arg, long);
      }
      else
      {
        nameccsid = (unsigned int)forms->value;
        forms++;
      }

      break;

    case FETCHFORM_COPYCONTENTS:
      if (contentx >= 0)
        result = FETCH_FORMADD_OPTION_TWICE;

      contentx = nargs;

      if (!forms)
      {
        value = va_arg(arg, char *);
        contentccsid = (unsigned int)va_arg(arg, long);
      }
      else
      {
        contentccsid = (unsigned int)forms->value;
        forms++;
      }

      break;

    case FETCHFORM_PTRCONTENTS:
    case FETCHFORM_BUFFERPTR:
      if (!forms)
        value = va_arg(arg, char *); /* No conversion. */

      break;

    case FETCHFORM_CONTENTSLENGTH:
      lengthx = nargs;

      if (!forms)
        value = (char *)va_arg(arg, long);

      break;

    case FETCHFORM_CONTENTLEN:
      lengthx = nargs;

      if (!forms)
        value = (char *)va_arg(arg, fetch_off_t);

      break;

    case FETCHFORM_NAMELENGTH:
      namelengthx = nargs;

      if (!forms)
        value = (char *)va_arg(arg, long);

      break;

    case FETCHFORM_BUFFERLENGTH:
      if (!forms)
        value = (char *)va_arg(arg, long);

      break;

    case FETCHFORM_CONTENTHEADER:
      if (!forms)
        value = (char *)va_arg(arg, struct fetch_slist *);

      break;

    case FETCHFORM_STREAM:
      if (!forms)
        value = (char *)va_arg(arg, void *);

      break;

    case FETCHFORM_CONTENTTYPE:
      /* If a previous content has been encountered, convert it now. */

      if (Curl_formadd_convert(lforms, contentx, lengthx, contentccsid) < 0)
      {
        result = FETCH_FORMADD_MEMORY;
        break;
      }

      contentx = -1;
      lengthx = -1;
      /* Fall into default. */

    default:
      /* Must be a convertible string. */

      if (!Curl_is_formadd_string(option))
      {
        result = FETCH_FORMADD_UNKNOWN_OPTION;
        break;
      }

      if (!forms)
      {
        value = va_arg(arg, char *);
        ccsid = (unsigned int)va_arg(arg, long);
      }
      else
      {
        ccsid = (unsigned int)forms->value;
        forms++;
      }

      /* Do the conversion. */

      lforms[nargs].value = value;

      if (Curl_formadd_convert(lforms, nargs, -1, ccsid) < 0)
      {
        result = FETCH_FORMADD_MEMORY;
        break;
      }

      value = lforms[nargs].value;
    }

    if (result != FETCH_FORMADD_OK)
      break;

    lforms[nargs].value = value;
    lforms[nargs++].option = option;
  }

  va_end(arg);

  /* Convert the name and the last content, now that we know their lengths. */

  if (result == FETCH_FORMADD_OK && namex >= 0)
  {
    if (Curl_formadd_convert(lforms, namex, namelengthx, nameccsid) < 0)
      result = FETCH_FORMADD_MEMORY;
    else
      lforms[namex].option = FETCHFORM_COPYNAME; /* Force copy. */
  }

  if (result == FETCH_FORMADD_OK)
  {
    if (Curl_formadd_convert(lforms, contentx, lengthx, contentccsid) < 0)
      result = FETCH_FORMADD_MEMORY;
    else
      contentx = -1;
  }

  /* Do the formadd with our converted parameters. */

  if (result == FETCH_FORMADD_OK)
  {
    lforms[nargs].option = FETCHFORM_END;
    result = fetch_formadd(httppost, last_post,
                           FETCHFORM_ARRAY, lforms, FETCHFORM_END);
  }

  /* Terminate. */

  Curl_formadd_release_local(lforms, nargs, contentx);
  return result;
}

struct cfcdata
{
  fetch_formget_callback append;
  void *arg;
  unsigned int ccsid;
};

static size_t
Curl_formget_callback_ccsid(void *arg, const char *buf, size_t len)
{
  struct cfcdata *p;
  char *b;
  int l;
  size_t ret;

  p = (struct cfcdata *)arg;

  if ((long)len <= 0)
    return (*p->append)(p->arg, buf, len);

  b = malloc(MAX_CONV_EXPANSION * len);

  if (!b)
    return (size_t)-1;

  l = convert(b, MAX_CONV_EXPANSION * len, p->ccsid, buf, len, ASCII_CCSID);

  if (l < 0)
  {
    free(b);
    return (size_t)-1;
  }

  ret = (*p->append)(p->arg, b, l);
  free(b);
  return ret == l ? len : -1;
}

int fetch_formget_ccsid(struct fetch_httppost *form, void *arg,
                        fetch_formget_callback append, unsigned int ccsid)
{
  struct cfcdata lcfc;

  lcfc.append = append;
  lcfc.arg = arg;
  lcfc.ccsid = ccsid;
  return fetch_formget(form, (void *)&lcfc, Curl_formget_callback_ccsid);
}

FETCHcode
fetch_easy_setopt_ccsid(FETCH *easy, FETCHoption tag, ...)
{
  FETCHcode result;
  va_list arg;
  char *s;
  char *cp = NULL;
  unsigned int ccsid;
  fetch_off_t pfsize;
  struct Curl_easy *data = easy;

  va_start(arg, tag);

  switch (tag)
  {

  /* BEGIN TRANSLATABLE STRING OPTIONS */
  /* Keep option symbols in alphanumeric order and retain the BEGIN/END
     armor comments. */
  case FETCHOPT_ABSTRACT_UNIX_SOCKET:
  case FETCHOPT_ACCEPT_ENCODING:
  case FETCHOPT_ALTSVC:
  case FETCHOPT_AWS_SIGV4:
  case FETCHOPT_CAINFO:
  case FETCHOPT_CAPATH:
  case FETCHOPT_COOKIE:
  case FETCHOPT_COOKIEFILE:
  case FETCHOPT_COOKIEJAR:
  case FETCHOPT_COOKIELIST:
  case FETCHOPT_CRLFILE:
  case FETCHOPT_CUSTOMREQUEST:
  case FETCHOPT_DEFAULT_PROTOCOL:
  case FETCHOPT_DNS_INTERFACE:
  case FETCHOPT_DNS_LOCAL_IP4:
  case FETCHOPT_DNS_LOCAL_IP6:
  case FETCHOPT_DNS_SERVERS:
  case FETCHOPT_DOH_URL:
  case FETCHOPT_ECH:
  case FETCHOPT_EGDSOCKET:
  case FETCHOPT_FTPPORT:
  case FETCHOPT_FTP_ACCOUNT:
  case FETCHOPT_FTP_ALTERNATIVE_TO_USER:
  case FETCHOPT_HAPROXY_CLIENT_IP:
  case FETCHOPT_HSTS:
  case FETCHOPT_INTERFACE:
  case FETCHOPT_ISSUERCERT:
  case FETCHOPT_KEYPASSWD:
  case FETCHOPT_KRBLEVEL:
  case FETCHOPT_LOGIN_OPTIONS:
  case FETCHOPT_MAIL_AUTH:
  case FETCHOPT_MAIL_FROM:
  case FETCHOPT_NETRC_FILE:
  case FETCHOPT_NOPROXY:
  case FETCHOPT_PASSWORD:
  case FETCHOPT_PINNEDPUBLICKEY:
  case FETCHOPT_PRE_PROXY:
  case FETCHOPT_PROTOCOLS_STR:
  case FETCHOPT_PROXY:
  case FETCHOPT_PROXYPASSWORD:
  case FETCHOPT_PROXYUSERNAME:
  case FETCHOPT_PROXYUSERPWD:
  case FETCHOPT_PROXY_CAINFO:
  case FETCHOPT_PROXY_CAPATH:
  case FETCHOPT_PROXY_CRLFILE:
  case FETCHOPT_PROXY_ISSUERCERT:
  case FETCHOPT_PROXY_KEYPASSWD:
  case FETCHOPT_PROXY_PINNEDPUBLICKEY:
  case FETCHOPT_PROXY_SERVICE_NAME:
  case FETCHOPT_PROXY_SSLCERT:
  case FETCHOPT_PROXY_SSLCERTTYPE:
  case FETCHOPT_PROXY_SSLKEY:
  case FETCHOPT_PROXY_SSLKEYTYPE:
  case FETCHOPT_PROXY_SSL_CIPHER_LIST:
  case FETCHOPT_PROXY_TLS13_CIPHERS:
  case FETCHOPT_PROXY_TLSAUTH_PASSWORD:
  case FETCHOPT_PROXY_TLSAUTH_TYPE:
  case FETCHOPT_PROXY_TLSAUTH_USERNAME:
  case FETCHOPT_RANDOM_FILE:
  case FETCHOPT_RANGE:
  case FETCHOPT_REDIR_PROTOCOLS_STR:
  case FETCHOPT_REFERER:
  case FETCHOPT_REQUEST_TARGET:
  case FETCHOPT_RTSP_SESSION_ID:
  case FETCHOPT_RTSP_STREAM_URI:
  case FETCHOPT_RTSP_TRANSPORT:
  case FETCHOPT_SASL_AUTHZID:
  case FETCHOPT_SERVICE_NAME:
  case FETCHOPT_SOCKS5_GSSAPI_SERVICE:
  case FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5:
  case FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256:
  case FETCHOPT_SSH_KNOWNHOSTS:
  case FETCHOPT_SSH_PRIVATE_KEYFILE:
  case FETCHOPT_SSH_PUBLIC_KEYFILE:
  case FETCHOPT_SSLCERT:
  case FETCHOPT_SSLCERTTYPE:
  case FETCHOPT_SSLENGINE:
  case FETCHOPT_SSLKEY:
  case FETCHOPT_SSLKEYTYPE:
  case FETCHOPT_SSL_CIPHER_LIST:
  case FETCHOPT_SSL_EC_CURVES:
  case FETCHOPT_TLS13_CIPHERS:
  case FETCHOPT_TLSAUTH_PASSWORD:
  case FETCHOPT_TLSAUTH_TYPE:
  case FETCHOPT_TLSAUTH_USERNAME:
  case FETCHOPT_UNIX_SOCKET_PATH:
  case FETCHOPT_URL:
  case FETCHOPT_USERAGENT:
  case FETCHOPT_USERNAME:
  case FETCHOPT_USERPWD:
  case FETCHOPT_XOAUTH2_BEARER:
    /* END TRANSLATABLE STRING OPTIONS */
    s = va_arg(arg, char *);
    ccsid = va_arg(arg, unsigned int);

    if (s)
    {
      s = dynconvert(ASCII_CCSID, s, -1, ccsid);

      if (!s)
      {
        result = FETCHE_OUT_OF_MEMORY;
        break;
      }
    }

    result = fetch_easy_setopt(easy, tag, s);
    free(s);
    break;

  case FETCHOPT_COPYPOSTFIELDS:
    /* Special case: byte count may have been given by FETCHOPT_POSTFIELDSIZE
       prior to this call. In this case, convert the given byte count and
       replace the length according to the conversion result. */
    s = va_arg(arg, char *);
    ccsid = va_arg(arg, unsigned int);

    pfsize = data->set.postfieldsize;

    if (!s || !pfsize || ccsid == NOCONV_CCSID || ccsid == ASCII_CCSID)
    {
      result = fetch_easy_setopt(easy, FETCHOPT_COPYPOSTFIELDS, s);
      break;
    }

    if (pfsize == -1)
    {
      /* Data is null-terminated. */
      s = dynconvert(ASCII_CCSID, s, -1, ccsid);

      if (!s)
      {
        result = FETCHE_OUT_OF_MEMORY;
        break;
      }
    }
    else
    {
      /* Data length specified. */
      size_t len;

      if (pfsize < 0 || pfsize > SIZE_MAX)
      {
        result = FETCHE_OUT_OF_MEMORY;
        break;
      }

      len = pfsize;
      pfsize = len * MAX_CONV_EXPANSION;

      if (pfsize > SIZE_MAX)
        pfsize = SIZE_MAX;

      cp = malloc(pfsize);

      if (!cp)
      {
        result = FETCHE_OUT_OF_MEMORY;
        break;
      }

      pfsize = convert(cp, pfsize, ASCII_CCSID, s, len, ccsid);

      if (pfsize < 0)
      {
        result = FETCHE_OUT_OF_MEMORY;
        break;
      }

      data->set.postfieldsize = pfsize; /* Replace data size. */
      s = cp;
    }

    result = fetch_easy_setopt(easy, FETCHOPT_POSTFIELDS, s);
    data->set.str[STRING_COPYPOSTFIELDS] = s; /* Give to library. */
    break;

  default:
    if (tag / 10000 == FETCHOPTTYPE_BLOB)
    {
      struct fetch_blob *bp = va_arg(arg, struct fetch_blob *);
      struct fetch_blob blob;

      ccsid = va_arg(arg, unsigned int);

      if (bp && bp->data && bp->len &&
          ccsid != NOCONV_CCSID && ccsid != ASCII_CCSID)
      {
        pfsize = (fetch_off_t)bp->len * MAX_CONV_EXPANSION;

        if (pfsize > SIZE_MAX)
          pfsize = SIZE_MAX;

        cp = malloc(pfsize);

        if (!cp)
        {
          result = FETCHE_OUT_OF_MEMORY;
          break;
        }

        pfsize = convert(cp, pfsize, ASCII_CCSID, bp->data, bp->len, ccsid);

        if (pfsize < 0)
        {
          result = FETCHE_OUT_OF_MEMORY;
          break;
        }

        blob.data = cp;
        blob.len = pfsize;
        blob.flags = bp->flags | FETCH_BLOB_COPY;
        bp = &blob;
      }
      result = fetch_easy_setopt(easy, tag, &blob);
      break;
    }
    FALLTHROUGH();
  case FETCHOPT_ERRORBUFFER: /* This is an output buffer. */
    result = Curl_vsetopt(easy, tag, arg);
    break;
  }

  va_end(arg);
  free(cp);
  return result;
}

/* ILE/RPG helper functions. */

char *
fetch_form_long_value(long value)
{
  /* ILE/RPG cannot cast an integer to a pointer. This procedure does it. */

  return (char *)value;
}

FETCHcode
fetch_easy_setopt_RPGnum_(FETCH *easy, FETCHoption tag, fetch_off_t arg)
{
  /* ILE/RPG procedure overloading cannot discriminate between different
     size and/or signedness of format arguments. This provides a generic
     wrapper that adapts size to the given tag expectation.
     This procedure is not intended to be explicitly called from user code. */
  if (tag / 10000 != FETCHOPTTYPE_OFF_T)
    return fetch_easy_setopt(easy, tag, (long)arg);
  return fetch_easy_setopt(easy, tag, arg);
}

FETCHcode
fetch_multi_setopt_RPGnum_(FETCHM *multi, FETCHMoption tag, fetch_off_t arg)
{
  /* Likewise, for multi handle. */
  if (tag / 10000 != FETCHOPTTYPE_OFF_T)
    return fetch_multi_setopt(multi, tag, (long)arg);
  return fetch_multi_setopt(multi, tag, arg);
}

char *
fetch_pushheader_bynum_cssid(struct fetch_pushheaders *h,
                             size_t num, unsigned int ccsid)
{
  char *d = (char *)NULL;
  char *s = fetch_pushheader_bynum(h, num);

  if (s)
    d = dynconvert(ccsid, s, -1, ASCII_CCSID);

  return d;
}

char *
fetch_pushheader_byname_ccsid(struct fetch_pushheaders *h, const char *header,
                              unsigned int ccsidin, unsigned int ccsidout)
{
  char *d = (char *)NULL;

  if (header)
  {
    header = dynconvert(ASCII_CCSID, header, -1, ccsidin);

    if (header)
    {
      char *s = fetch_pushheader_byname(h, header);
      free((char *)header);

      if (s)
        d = dynconvert(ccsidout, s, -1, ASCII_CCSID);
    }
  }

  return d;
}

static FETCHcode
mime_string_call(fetch_mimepart *part, const char *string, unsigned int ccsid,
                 FETCHcode (*mimefunc)(fetch_mimepart *part, const char *string))
{
  char *s = (char *)NULL;
  FETCHcode result;

  if (!string)
    return mimefunc(part, string);
  s = dynconvert(ASCII_CCSID, string, -1, ccsid);
  if (!s)
    return FETCHE_OUT_OF_MEMORY;

  result = mimefunc(part, s);
  free(s);
  return result;
}

FETCHcode
fetch_mime_name_ccsid(fetch_mimepart *part, const char *name, unsigned int ccsid)
{
  return mime_string_call(part, name, ccsid, fetch_mime_name);
}

FETCHcode
fetch_mime_filename_ccsid(fetch_mimepart *part,
                          const char *filename, unsigned int ccsid)
{
  return mime_string_call(part, filename, ccsid, fetch_mime_filename);
}

FETCHcode
fetch_mime_type_ccsid(fetch_mimepart *part,
                      const char *mimetype, unsigned int ccsid)
{
  return mime_string_call(part, mimetype, ccsid, fetch_mime_type);
}

FETCHcode
fetch_mime_encoder_ccsid(fetch_mimepart *part,
                         const char *encoding, unsigned int ccsid)
{
  return mime_string_call(part, encoding, ccsid, fetch_mime_encoder);
}

FETCHcode
fetch_mime_filedata_ccsid(fetch_mimepart *part,
                          const char *filename, unsigned int ccsid)
{
  return mime_string_call(part, filename, ccsid, fetch_mime_filedata);
}

FETCHcode
fetch_mime_data_ccsid(fetch_mimepart *part,
                      const char *data, size_t datasize, unsigned int ccsid)
{
  char *s = (char *)NULL;
  FETCHcode result;

  if (!data)
    return fetch_mime_data(part, data, datasize);
  s = dynconvert(ASCII_CCSID, data, datasize, ccsid);
  if (!s)
    return FETCHE_OUT_OF_MEMORY;

  result = fetch_mime_data(part, s, datasize);
  free(s);
  return result;
}

FETCHUcode
fetch_url_get_ccsid(FETCHU *handle, FETCHUPart what, char **part,
                    unsigned int flags, unsigned int ccsid)
{
  char *s = (char *)NULL;
  FETCHUcode result;

  if (!part)
    return FETCHUE_BAD_PARTPOINTER;

  *part = (char *)NULL;
  result = fetch_url_get(handle, what, &s, flags);
  if (result == FETCHUE_OK)
  {
    if (s)
    {
      *part = dynconvert(ccsid, s, -1, ASCII_CCSID);
      if (!*part)
        result = FETCHUE_OUT_OF_MEMORY;
    }
  }
  if (s)
    free(s);
  return result;
}

FETCHUcode
fetch_url_set_ccsid(FETCHU *handle, FETCHUPart what, const char *part,
                    unsigned int flags, unsigned int ccsid)
{
  char *s = (char *)NULL;
  FETCHUcode result;

  if (part)
  {
    s = dynconvert(ASCII_CCSID, part, -1, ccsid);
    if (!s)
      return FETCHUE_OUT_OF_MEMORY;
  }
  result = fetch_url_set(handle, what, s, flags);
  if (s)
    free(s);
  return result;
}

const struct fetch_easyoption *
fetch_easy_option_by_name_ccsid(const char *name, unsigned int ccsid)
{
  const struct fetch_easyoption *option = NULL;

  if (name)
  {
    char *s = dynconvert(ASCII_CCSID, name, -1, ccsid);

    if (s)
    {
      option = fetch_easy_option_by_name(s);
      free(s);
    }
  }

  return option;
}

/* Return option name in the given ccsid. */
const char *
fetch_easy_option_get_name_ccsid(const struct fetch_easyoption *option,
                                 unsigned int ccsid)
{
  char *name = NULL;

  if (option && option->name)
    name = dynconvert(ccsid, option->name, -1, ASCII_CCSID);

  return (const char *)name;
}

/* Header API CCSID support. */
FETCHHcode
fetch_easy_header_ccsid(FETCH *easy, const char *name, size_t index,
                        unsigned int origin, int request,
                        struct fetch_header **hout, unsigned int ccsid)
{
  FETCHHcode result = FETCHHE_BAD_ARGUMENT;

  if (name)
  {
    char *s = dynconvert(ASCII_CCSID, name, -1, ccsid);

    result = FETCHHE_OUT_OF_MEMORY;
    if (s)
    {
      result = fetch_easy_header(easy, s, index, origin, request, hout);
      free(s);
    }
  }

  return result;
}
