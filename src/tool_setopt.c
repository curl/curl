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
 ***************************************************************************/
#include "tool_setup.h"

#ifndef CURL_DISABLE_LIBCURL_OPTION

#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_easysrc.h"
#include "tool_setopt.h"
#include "tool_msgs.h"
#include "dynbuf.h"

#include "memdebug.h" /* keep this as LAST include */

/* Lookup tables for converting setopt values back to symbols */
/* For enums, values may be in any order. */
/* For bit masks, put combinations first, then single bits, */
/* and finally any "NONE" value. */

#define NV(e) {#e, e}
#define NV1(e, v) {#e, (v)}
#define NVEND {NULL, 0}         /* sentinel to mark end of list */

const struct NameValue setopt_nv_CURLPROXY[] = {
  NV(CURLPROXY_HTTP),
  NV(CURLPROXY_HTTP_1_0),
  NV(CURLPROXY_HTTPS),
  NV(CURLPROXY_SOCKS4),
  NV(CURLPROXY_SOCKS5),
  NV(CURLPROXY_SOCKS4A),
  NV(CURLPROXY_SOCKS5_HOSTNAME),
  NVEND,
};

const struct NameValue setopt_nv_CURL_SOCKS_PROXY[] = {
  NV(CURLPROXY_SOCKS4),
  NV(CURLPROXY_SOCKS5),
  NV(CURLPROXY_SOCKS4A),
  NV(CURLPROXY_SOCKS5_HOSTNAME),
  NVEND,
};

const struct NameValueUnsigned setopt_nv_CURLHSTS[] = {
  NV(CURLHSTS_ENABLE),
  NVEND,
};

const struct NameValueUnsigned setopt_nv_CURLAUTH[] = {
  NV(CURLAUTH_ANY),             /* combination */
  NV(CURLAUTH_ANYSAFE),         /* combination */
  NV(CURLAUTH_BASIC),
  NV(CURLAUTH_DIGEST),
  NV(CURLAUTH_GSSNEGOTIATE),
  NV(CURLAUTH_NTLM),
  NV(CURLAUTH_DIGEST_IE),
  NV(CURLAUTH_ONLY),
  NV(CURLAUTH_NONE),
  NVEND,
};

const struct NameValue setopt_nv_CURL_HTTP_VERSION[] = {
  NV(CURL_HTTP_VERSION_NONE),
  NV(CURL_HTTP_VERSION_1_0),
  NV(CURL_HTTP_VERSION_1_1),
  NV(CURL_HTTP_VERSION_2_0),
  NV(CURL_HTTP_VERSION_2TLS),
  NV(CURL_HTTP_VERSION_3),
  NV(CURL_HTTP_VERSION_3ONLY),
  NVEND,
};

const struct NameValue setopt_nv_CURL_SSLVERSION[] = {
  NV(CURL_SSLVERSION_DEFAULT),
  NV(CURL_SSLVERSION_TLSv1),
  NV(CURL_SSLVERSION_SSLv2),
  NV(CURL_SSLVERSION_SSLv3),
  NV(CURL_SSLVERSION_TLSv1_0),
  NV(CURL_SSLVERSION_TLSv1_1),
  NV(CURL_SSLVERSION_TLSv1_2),
  NV(CURL_SSLVERSION_TLSv1_3),
  NVEND,
};

const struct NameValue setopt_nv_CURL_SSLVERSION_MAX[] = {
  NV(CURL_SSLVERSION_MAX_NONE),
  NV(CURL_SSLVERSION_MAX_DEFAULT),
  NV(CURL_SSLVERSION_MAX_TLSv1_0),
  NV(CURL_SSLVERSION_MAX_TLSv1_1),
  NV(CURL_SSLVERSION_MAX_TLSv1_2),
  NV(CURL_SSLVERSION_MAX_TLSv1_3),
  NVEND,
};

const struct NameValue setopt_nv_CURL_TIMECOND[] = {
  NV(CURL_TIMECOND_IFMODSINCE),
  NV(CURL_TIMECOND_IFUNMODSINCE),
  NV(CURL_TIMECOND_LASTMOD),
  NV(CURL_TIMECOND_NONE),
  NVEND,
};

const struct NameValue setopt_nv_CURLFTPSSL_CCC[] = {
  NV(CURLFTPSSL_CCC_NONE),
  NV(CURLFTPSSL_CCC_PASSIVE),
  NV(CURLFTPSSL_CCC_ACTIVE),
  NVEND,
};

const struct NameValue setopt_nv_CURLUSESSL[] = {
  NV(CURLUSESSL_NONE),
  NV(CURLUSESSL_TRY),
  NV(CURLUSESSL_CONTROL),
  NV(CURLUSESSL_ALL),
  NVEND,
};

const struct NameValueUnsigned setopt_nv_CURLSSLOPT[] = {
  NV(CURLSSLOPT_ALLOW_BEAST),
  NV(CURLSSLOPT_NO_REVOKE),
  NV(CURLSSLOPT_NO_PARTIALCHAIN),
  NV(CURLSSLOPT_REVOKE_BEST_EFFORT),
  NV(CURLSSLOPT_NATIVE_CA),
  NV(CURLSSLOPT_AUTO_CLIENT_CERT),
  NVEND,
};

const struct NameValue setopt_nv_CURL_NETRC[] = {
  NV(CURL_NETRC_IGNORED),
  NV(CURL_NETRC_OPTIONAL),
  NV(CURL_NETRC_REQUIRED),
  NVEND,
};

/* These options have non-zero default values. */
static const struct NameValue setopt_nv_CURLNONZERODEFAULTS[] = {
  NV1(CURLOPT_SSL_VERIFYPEER, 1),
  NV1(CURLOPT_SSL_VERIFYHOST, 1),
  NV1(CURLOPT_SSL_ENABLE_NPN, 1),
  NV1(CURLOPT_SSL_ENABLE_ALPN, 1),
  NV1(CURLOPT_TCP_NODELAY, 1),
  NV1(CURLOPT_PROXY_SSL_VERIFYPEER, 1),
  NV1(CURLOPT_PROXY_SSL_VERIFYHOST, 1),
  NV1(CURLOPT_SOCKS5_AUTH, 1),
  NV1(CURLOPT_UPLOAD_FLAGS, CURLULFLAG_SEEN),
  NVEND
};

/* Escape string to C string syntax. Return NULL if out of memory. */
#define MAX_STRING_LENGTH_OUTPUT 2000
#define ZERO_TERMINATED -1

static char *c_escape(const char *str, curl_off_t len)
{
  const char *s;
  unsigned int cutoff = 0;
  CURLcode result;
  struct curlx_dynbuf escaped;

  curlx_dyn_init(&escaped, 4 * MAX_STRING_LENGTH_OUTPUT + 3);

  if(len == ZERO_TERMINATED)
    len = strlen(str);

  if(len > MAX_STRING_LENGTH_OUTPUT) {
    /* cap ridiculously long strings */
    len = MAX_STRING_LENGTH_OUTPUT;
    cutoff = 3;
  }

  result = curlx_dyn_addn(&escaped, STRCONST(""));
  for(s = str; !result && len; s++, len--) {
    /* escape question marks as well, to prevent generating accidental
       trigraphs */
    static const char from[] = "\t\r\n?\"\\";
    static const char to[] = "\\t\\r\\n\\?\\\"\\\\";
    const char *p = strchr(from, *s);

    if(!p && ISPRINT(*s))
      continue;

    result = curlx_dyn_addn(&escaped, str, s - str);
    str = s + 1;

    if(!result) {
      if(p && *p)
        result = curlx_dyn_addn(&escaped, to + 2 * (p - from), 2);
      else {
        result = curlx_dyn_addf(&escaped,
                                /* Octal escape to avoid >2 digit hex. */
                                (len > 1 && ISXDIGIT(s[1])) ?
                                  "\\%03o" : "\\x%02x",
                                (unsigned int) *(const unsigned char *) s);
      }
    }
  }

  if(!result)
    result = curlx_dyn_addn(&escaped, str, s - str);

  if(!result)
    (void) !curlx_dyn_addn(&escaped, "...", cutoff);

  return curlx_dyn_ptr(&escaped);
}

/* setopt wrapper for enum types */
CURLcode tool_setopt_enum(CURL *curl, struct GlobalConfig *config,
                          const char *name, CURLoption tag,
                          const struct NameValue *nvlist, long lval)
{
  CURLcode ret = CURLE_OK;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, lval);
  if(!lval)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */
    const struct NameValue *nv = NULL;
    for(nv = nvlist; nv->name; nv++) {
      if(nv->value == lval)
        break; /* found it */
    }
    if(!nv->name) {
      /* If no definition was found, output an explicit value.
       * This could happen if new values are defined and used
       * but the NameValue list is not updated. */
      ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, %ldL);",
                         name, lval);
    }
    else {
      ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, (long)%s);",
                         name, nv->name);
    }
  }

#ifdef DEBUGBUILD
  if(ret)
    warnf(config, "option %s returned error (%d)", name, (int)ret);
#endif
  return ret;
}

/* setopt wrapper for CURLOPT_SSLVERSION */
CURLcode tool_setopt_SSLVERSION(CURL *curl, struct GlobalConfig *config,
                                const char *name, CURLoption tag,
                                long lval)
{
  CURLcode ret = CURLE_OK;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, lval);
  if(!lval)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */
    const struct NameValue *nv = NULL;
    const struct NameValue *nv2 = NULL;
    for(nv = setopt_nv_CURL_SSLVERSION; nv->name; nv++) {
      if(nv->value == (lval & 0xffff))
        break; /* found it */
    }
    for(nv2 = setopt_nv_CURL_SSLVERSION_MAX; nv2->name; nv2++) {
      if(nv2->value == (lval & ~0xffff))
        break; /* found it */
    }
    if(!nv->name) {
      /* If no definition was found, output an explicit value.
       * This could happen if new values are defined and used
       * but the NameValue list is not updated. */
      ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, %ldL);",
                         name, lval);
    }
    else {
      ret = easysrc_addf(&easysrc_code,
                         "curl_easy_setopt(hnd, %s, (long)(%s | %s));",
                         name, nv->name, nv2->name);
    }
  }

#ifdef DEBUGBUILD
  if(ret)
    warnf(config, "option %s returned error (%d)", name, (int)ret);
#endif
  return ret;
}

/* setopt wrapper for bitmasks */
CURLcode tool_setopt_bitmask(CURL *curl, struct GlobalConfig *config,
                             const char *name, CURLoption tag,
                             const struct NameValueUnsigned *nvlist,
                             long lval)
{
  bool skip = FALSE;
  CURLcode ret = curl_easy_setopt(curl, tag, lval);
  if(!lval)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */
    char preamble[80];
    unsigned long rest = (unsigned long)lval;
    const struct NameValueUnsigned *nv = NULL;
    msnprintf(preamble, sizeof(preamble),
              "curl_easy_setopt(hnd, %s, ", name);
    for(nv = nvlist; nv->name; nv++) {
      if((nv->value & ~ rest) == 0) {
        /* all value flags contained in rest */
        rest &= ~ nv->value;    /* remove bits handled here */
        ret = easysrc_addf(&easysrc_code, "%s(long)%s%s",
                           preamble, nv->name, rest ? " |" : ");");
        if(!rest || ret)
          break;                /* handled them all */
        /* replace with all spaces for continuation line */
        msnprintf(preamble, sizeof(preamble), "%*s", (int)strlen(preamble),
                  "");
      }
    }
    /* If any bits have no definition, output an explicit value.
     * This could happen if new bits are defined and used
     * but the NameValue list is not updated. */
    if(rest && !ret)
      ret = easysrc_addf(&easysrc_code, "%s%luUL);", preamble, rest);
  }

  return ret;
}

/* Generate code for a struct curl_slist. */
static CURLcode libcurl_generate_slist(struct curl_slist *slist, int *slistno)
{
  CURLcode ret = CURLE_OK;

  /* May need several slist variables, so invent name */
  *slistno = ++easysrc_slist_count;

  ret = easysrc_addf(&easysrc_decl, "struct curl_slist *slist%d;", *slistno);
  if(!ret)
    ret = easysrc_addf(&easysrc_data, "slist%d = NULL;", *slistno);
  if(!ret)
    ret = easysrc_addf(&easysrc_clean, "curl_slist_free_all(slist%d);",
                       *slistno);
  if(!ret)
    ret = easysrc_addf(&easysrc_clean, "slist%d = NULL;", *slistno);
  if(ret)
    return ret;
  for(; slist && !ret; slist = slist->next) {
    char *escaped = c_escape(slist->data, ZERO_TERMINATED);
    if(!escaped)
      return CURLE_OUT_OF_MEMORY;
    ret = easysrc_addf(&easysrc_data,
                       "slist%d = curl_slist_append(slist%d, \"%s\");",
                       *slistno, *slistno, escaped);
    free(escaped);
  }

  return ret;
}

static CURLcode libcurl_generate_mime(CURL *curl,
                                      struct GlobalConfig *config,
                                      struct tool_mime *toolmime,
                                      int *mimeno);     /* Forward. */

/* Wrapper to generate source code for a mime part. */
static CURLcode libcurl_generate_mime_part(CURL *curl,
                                           struct GlobalConfig *config,
                                           struct tool_mime *part,
                                           int mimeno)
{
  CURLcode ret = CURLE_OK;
  int submimeno = 0;
  const char *data = NULL;
  const char *filename = part->filename;

  /* Parts are linked in reverse order. */
  if(part->prev)
    ret = libcurl_generate_mime_part(curl, config, part->prev, mimeno);

  /* Create the part. */
  if(!ret)
    ret = easysrc_addf(&easysrc_code, "part%d = curl_mime_addpart(mime%d);",
                       mimeno, mimeno);
  if(ret)
    return ret;

  switch(part->kind) {
  case TOOLMIME_PARTS:
    ret = libcurl_generate_mime(curl, config, part, &submimeno);
    if(!ret) {
      ret = easysrc_addf(&easysrc_code, "curl_mime_subparts(part%d, mime%d);",
                         mimeno, submimeno);
      if(!ret)
        /* Avoid freeing in CLEAN. */
        ret = easysrc_addf(&easysrc_code,
                           "mime%d = NULL;", submimeno);
    }
    break;

  case TOOLMIME_DATA:
    data = part->data;
    if(!ret) {
      char *escaped = c_escape(data, ZERO_TERMINATED);
      ret =
        easysrc_addf(&easysrc_code,
                     "curl_mime_data(part%d, \"%s\", CURL_ZERO_TERMINATED);",
                     mimeno, escaped);
      free(escaped);
    }
    break;

  case TOOLMIME_FILE:
  case TOOLMIME_FILEDATA: {
    char *escaped = c_escape(part->data, ZERO_TERMINATED);
    ret = easysrc_addf(&easysrc_code,
                       "curl_mime_filedata(part%d, \"%s\");", mimeno, escaped);
    if(part->kind == TOOLMIME_FILEDATA && !filename && !ret) {
      ret = easysrc_addf(&easysrc_code,
                         "curl_mime_filename(part%d, NULL);", mimeno);
    }
    free(escaped);
    break;
  }

  case TOOLMIME_STDIN:
    if(!filename)
      filename = "-";
    FALLTHROUGH();
  case TOOLMIME_STDINDATA:
    /* Can only be reading stdin in the current context. */
    ret = easysrc_addf(&easysrc_code, "curl_mime_data_cb(part%d, -1, "
                       "(curl_read_callback) fread, \\", mimeno);
    if(!ret)
      ret = easysrc_addf(&easysrc_code, "                  "
                         "(curl_seek_callback) fseek, NULL, stdin);");
    break;
  default:
    /* Other cases not possible in this context. */
    break;
  }

  if(!ret && part->encoder) {
    char *escaped = c_escape(part->encoder, ZERO_TERMINATED);
    ret = easysrc_addf(&easysrc_code, "curl_mime_encoder(part%d, \"%s\");",
                       mimeno, escaped);
    free(escaped);
  }

  if(!ret && filename) {
    char *escaped = c_escape(filename, ZERO_TERMINATED);
    ret = easysrc_addf(&easysrc_code, "curl_mime_filename(part%d, \"%s\");",
                       mimeno, escaped);
    free(escaped);
  }

  if(!ret && part->name) {
    char *escaped = c_escape(part->name, ZERO_TERMINATED);
    ret = easysrc_addf(&easysrc_code, "curl_mime_name(part%d, \"%s\");",
                       mimeno, escaped);
    free(escaped);
  }

  if(!ret && part->type) {
    char *escaped = c_escape(part->type, ZERO_TERMINATED);
    ret = easysrc_addf(&easysrc_code, "curl_mime_type(part%d, \"%s\");",
                       mimeno, escaped);
    free(escaped);
  }

  if(!ret && part->headers) {
    int slistno;

    ret = libcurl_generate_slist(part->headers, &slistno);
    if(!ret) {
      ret = easysrc_addf(&easysrc_code,
                         "curl_mime_headers(part%d, slist%d, 1);",
                         mimeno, slistno);
      if(!ret)
        ret = easysrc_addf(&easysrc_code,
                           "slist%d = NULL;", slistno); /* Prevent CLEANing. */
    }
  }

  return ret;
}

/* Wrapper to generate source code for a mime structure. */
static CURLcode libcurl_generate_mime(CURL *curl,
                                      struct GlobalConfig *config,
                                      struct tool_mime *toolmime,
                                      int *mimeno)
{
  CURLcode ret = CURLE_OK;

  /* May need several mime variables, so invent name. */
  *mimeno = ++easysrc_mime_count;
  ret = easysrc_addf(&easysrc_decl, "curl_mime *mime%d;", *mimeno);
  if(!ret)
    ret = easysrc_addf(&easysrc_data, "mime%d = NULL;", *mimeno);
  if(!ret)
    ret = easysrc_addf(&easysrc_code, "mime%d = curl_mime_init(hnd);",
                       *mimeno);
  if(!ret)
    ret = easysrc_addf(&easysrc_clean, "curl_mime_free(mime%d);", *mimeno);
  if(!ret)
    ret = easysrc_addf(&easysrc_clean, "mime%d = NULL;", *mimeno);

  if(toolmime->subparts && !ret) {
    ret = easysrc_addf(&easysrc_decl, "curl_mimepart *part%d;", *mimeno);
    if(!ret)
      ret = libcurl_generate_mime_part(curl, config,
                                       toolmime->subparts, *mimeno);
  }

  return ret;
}

/* setopt wrapper for CURLOPT_MIMEPOST */
CURLcode tool_setopt_mimepost(CURL *curl, struct GlobalConfig *config,
                              const char *name, CURLoption tag,
                              curl_mime *mimepost)
{
  CURLcode ret = curl_easy_setopt(curl, tag, mimepost);
  int mimeno = 0;

  if(!ret && config->libcurl) {
    ret = libcurl_generate_mime(curl, config,
                                config->current->mimeroot, &mimeno);

    if(!ret)
      ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, mime%d);",
                         name, mimeno);
  }

  return ret;
}

/* setopt wrapper for curl_slist options */
CURLcode tool_setopt_slist(CURL *curl, struct GlobalConfig *config,
                           const char *name, CURLoption tag,
                           struct curl_slist *list)
{
  CURLcode ret = CURLE_OK;

  ret = curl_easy_setopt(curl, tag, list);

  if(config->libcurl && list && !ret) {
    int i;

    ret = libcurl_generate_slist(list, &i);
    if(!ret)
      ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, slist%d);",
                         name, i);
  }

  return ret;
}

/* options that set long */
CURLcode tool_setopt_long(CURL *curl, struct GlobalConfig *global,
                          const char *name, CURLoption tag,
                          long lval)
{
  long defval = 0L;
  const struct NameValue *nv = NULL;
  CURLcode ret = CURLE_OK;
  DEBUGASSERT(tag < CURLOPTTYPE_OBJECTPOINT);

  for(nv = setopt_nv_CURLNONZERODEFAULTS; nv->name; nv++) {
    if(!strcmp(name, nv->name)) {
      defval = nv->value;
      break; /* found it */
    }
  }

  ret = curl_easy_setopt(curl, tag, lval);
  if((lval != defval) && global->libcurl && !ret) {
    /* we only use this for real if --libcurl was used */
    ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, %ldL);",
                       name, lval);
  }
  return ret;
}

/* options that set curl_off_t */
CURLcode tool_setopt_offt(CURL *curl, struct GlobalConfig *global,
                          const char *name, CURLoption tag,
                          curl_off_t lval)
{
  CURLcode ret = CURLE_OK;
  DEBUGASSERT((tag >= CURLOPTTYPE_OFF_T) && (tag < CURLOPTTYPE_BLOB));

  ret = curl_easy_setopt(curl, tag, lval);
  if(global->libcurl && !ret && lval) {
    /* we only use this for real if --libcurl was used */
    ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, (curl_off_t)%"
          CURL_FORMAT_CURL_OFF_T ");", name, lval);
  }

  return ret;
}

/* setopt wrapper for setting object and function pointer options */
CURLcode tool_setopt(CURL *curl, bool str, struct GlobalConfig *global,
                     struct OperationConfig *config,
                     const char *name, CURLoption tag, ...)
{
  va_list arg;
  CURLcode ret = CURLE_OK;
  void *pval;

  va_start(arg, tag);

  DEBUGASSERT(tag >= CURLOPTTYPE_OBJECTPOINT);
  DEBUGASSERT((tag < CURLOPTTYPE_OFF_T) || (tag >= CURLOPTTYPE_BLOB));

  /* we never set _BLOB options in the curl tool */
  DEBUGASSERT(tag < CURLOPTTYPE_BLOB);

  /* argument is an object or function pointer */
  pval = va_arg(arg, void *);

  ret = curl_easy_setopt(curl, tag, pval);

  va_end(arg);

  if(global->libcurl && pval && !ret) {
    /* we only use this if --libcurl was used */

    if(!str) {
      /* function pointers are never printable */
      const char *remark = (tag >= CURLOPTTYPE_FUNCTIONPOINT) ?
        "function" : "object";
      ret = easysrc_addf(&easysrc_toohard,
                         "%s was set to a%s %s pointer", name,
                         (*remark == 'o' ? "n" : ""), remark);
    }
    else {
      curl_off_t len = ZERO_TERMINATED;
      char *escaped;
      if(tag == CURLOPT_POSTFIELDS)
        len = curlx_dyn_len(&config->postdata);
      escaped = c_escape(pval, len);
      if(escaped) {
        ret = easysrc_addf(&easysrc_code, "curl_easy_setopt(hnd, %s, \"%s\");",
                           name, escaped);
        free(escaped);
      }
    }
  }

  return ret;
}

#endif /* CURL_DISABLE_LIBCURL_OPTION */
