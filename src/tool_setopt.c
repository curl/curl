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
 ***************************************************************************/
#include "tool_setup.h"

#ifndef FETCH_DISABLE_LIBFETCH_OPTION

#include "fetchx.h"

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
#define NVEND {NULL, 0} /* sentinel to mark end of list */

const struct NameValue setopt_nv_FETCHPROXY[] = {
    NV(FETCHPROXY_HTTP),
    NV(FETCHPROXY_HTTP_1_0),
    NV(FETCHPROXY_HTTPS),
    NV(FETCHPROXY_SOCKS4),
    NV(FETCHPROXY_SOCKS5),
    NV(FETCHPROXY_SOCKS4A),
    NV(FETCHPROXY_SOCKS5_HOSTNAME),
    NVEND,
};

const struct NameValue setopt_nv_FETCH_SOCKS_PROXY[] = {
    NV(FETCHPROXY_SOCKS4),
    NV(FETCHPROXY_SOCKS5),
    NV(FETCHPROXY_SOCKS4A),
    NV(FETCHPROXY_SOCKS5_HOSTNAME),
    NVEND,
};

const struct NameValueUnsigned setopt_nv_FETCHHSTS[] = {
    NV(FETCHHSTS_ENABLE),
    NVEND,
};

const struct NameValueUnsigned setopt_nv_FETCHAUTH[] = {
    NV(FETCHAUTH_ANY),     /* combination */
    NV(FETCHAUTH_ANYSAFE), /* combination */
    NV(FETCHAUTH_BASIC),
    NV(FETCHAUTH_DIGEST),
    NV(FETCHAUTH_GSSNEGOTIATE),
    NV(FETCHAUTH_NTLM),
    NV(FETCHAUTH_DIGEST_IE),
    NV(FETCHAUTH_ONLY),
    NV(FETCHAUTH_NONE),
    NVEND,
};

const struct NameValue setopt_nv_FETCH_HTTP_VERSION[] = {
    NV(FETCH_HTTP_VERSION_NONE),
    NV(FETCH_HTTP_VERSION_1_0),
    NV(FETCH_HTTP_VERSION_1_1),
    NV(FETCH_HTTP_VERSION_2_0),
    NV(FETCH_HTTP_VERSION_2TLS),
    NV(FETCH_HTTP_VERSION_3),
    NV(FETCH_HTTP_VERSION_3ONLY),
    NVEND,
};

const struct NameValue setopt_nv_FETCH_SSLVERSION[] = {
    NV(FETCH_SSLVERSION_DEFAULT),
    NV(FETCH_SSLVERSION_TLSv1),
    NV(FETCH_SSLVERSION_SSLv2),
    NV(FETCH_SSLVERSION_SSLv3),
    NV(FETCH_SSLVERSION_TLSv1_0),
    NV(FETCH_SSLVERSION_TLSv1_1),
    NV(FETCH_SSLVERSION_TLSv1_2),
    NV(FETCH_SSLVERSION_TLSv1_3),
    NVEND,
};

const struct NameValue setopt_nv_FETCH_SSLVERSION_MAX[] = {
    NV(FETCH_SSLVERSION_MAX_NONE),
    NV(FETCH_SSLVERSION_MAX_DEFAULT),
    NV(FETCH_SSLVERSION_MAX_TLSv1_0),
    NV(FETCH_SSLVERSION_MAX_TLSv1_1),
    NV(FETCH_SSLVERSION_MAX_TLSv1_2),
    NV(FETCH_SSLVERSION_MAX_TLSv1_3),
    NVEND,
};

const struct NameValue setopt_nv_FETCH_TIMECOND[] = {
    NV(FETCH_TIMECOND_IFMODSINCE),
    NV(FETCH_TIMECOND_IFUNMODSINCE),
    NV(FETCH_TIMECOND_LASTMOD),
    NV(FETCH_TIMECOND_NONE),
    NVEND,
};

const struct NameValue setopt_nv_FETCHFTPSSL_CCC[] = {
    NV(FETCHFTPSSL_CCC_NONE),
    NV(FETCHFTPSSL_CCC_PASSIVE),
    NV(FETCHFTPSSL_CCC_ACTIVE),
    NVEND,
};

const struct NameValue setopt_nv_FETCHUSESSL[] = {
    NV(FETCHUSESSL_NONE),
    NV(FETCHUSESSL_TRY),
    NV(FETCHUSESSL_CONTROL),
    NV(FETCHUSESSL_ALL),
    NVEND,
};

const struct NameValueUnsigned setopt_nv_FETCHSSLOPT[] = {
    NV(FETCHSSLOPT_ALLOW_BEAST),
    NV(FETCHSSLOPT_NO_REVOKE),
    NV(FETCHSSLOPT_NO_PARTIALCHAIN),
    NV(FETCHSSLOPT_REVOKE_BEST_EFFORT),
    NV(FETCHSSLOPT_NATIVE_CA),
    NV(FETCHSSLOPT_AUTO_CLIENT_CERT),
    NVEND,
};

const struct NameValue setopt_nv_FETCH_NETRC[] = {
    NV(FETCH_NETRC_IGNORED),
    NV(FETCH_NETRC_OPTIONAL),
    NV(FETCH_NETRC_REQUIRED),
    NVEND,
};

/* These options have non-zero default values. */
static const struct NameValue setopt_nv_FETCHNONZERODEFAULTS[] = {
    NV1(FETCHOPT_SSL_VERIFYPEER, 1),
    NV1(FETCHOPT_SSL_VERIFYHOST, 1),
    NV1(FETCHOPT_SSL_ENABLE_NPN, 1),
    NV1(FETCHOPT_SSL_ENABLE_ALPN, 1),
    NV1(FETCHOPT_TCP_NODELAY, 1),
    NV1(FETCHOPT_PROXY_SSL_VERIFYPEER, 1),
    NV1(FETCHOPT_PROXY_SSL_VERIFYHOST, 1),
    NV1(FETCHOPT_SOCKS5_AUTH, 1),
    NVEND};

/* Format and add code; jump to nomem on malloc error */
#define ADD(args)           \
  do                        \
  {                         \
    ret = easysrc_add args; \
    if (ret)                \
      goto nomem;           \
  } while (0)
#define ADDF(args)           \
  do                         \
  {                          \
    ret = easysrc_addf args; \
    if (ret)                 \
      goto nomem;            \
  } while (0)
#define NULL_CHECK(p)             \
  do                              \
  {                               \
    if (!p)                       \
    {                             \
      ret = FETCHE_OUT_OF_MEMORY; \
      goto nomem;                 \
    }                             \
  } while (0)

#define DECL0(s) ADD((&easysrc_decl, s))
#define DECL1(f, a) ADDF((&easysrc_decl, f, a))

#define DATA0(s) ADD((&easysrc_data, s))
#define DATA1(f, a) ADDF((&easysrc_data, f, a))
#define DATA2(f, a, b) ADDF((&easysrc_data, f, a, b))
#define DATA3(f, a, b, c) ADDF((&easysrc_data, f, a, b, c))

#define CODE0(s) ADD((&easysrc_code, s))
#define CODE1(f, a) ADDF((&easysrc_code, f, a))
#define CODE2(f, a, b) ADDF((&easysrc_code, f, a, b))
#define CODE3(f, a, b, c) ADDF((&easysrc_code, f, a, b, c))

#define CLEAN0(s) ADD((&easysrc_clean, s))
#define CLEAN1(f, a) ADDF((&easysrc_clean, f, a))

#define REM0(s) ADD((&easysrc_toohard, s))
#define REM1(f, a) ADDF((&easysrc_toohard, f, a))
#define REM3(f, a, b, c) ADDF((&easysrc_toohard, f, a, b, c))

/* Escape string to C string syntax. Return NULL if out of memory.
 * Is this correct for those wacky EBCDIC guys? */

#define MAX_STRING_LENGTH_OUTPUT 2000
#define ZERO_TERMINATED -1

static char *c_escape(const char *str, fetch_off_t len)
{
  const char *s;
  unsigned int cutoff = 0;
  FETCHcode result;
  struct fetchx_dynbuf escaped;

  fetchx_dyn_init(&escaped, 4 * MAX_STRING_LENGTH_OUTPUT + 3);

  if (len == ZERO_TERMINATED)
    len = strlen(str);

  if (len > MAX_STRING_LENGTH_OUTPUT)
  {
    /* cap ridiculously long strings */
    len = MAX_STRING_LENGTH_OUTPUT;
    cutoff = 3;
  }

  result = fetchx_dyn_addn(&escaped, STRCONST(""));
  for (s = str; !result && len; s++, len--)
  {
    /* escape question marks as well, to prevent generating accidental
       trigraphs */
    static const char from[] = "\t\r\n?\"\\";
    static const char to[] = "\\t\\r\\n\\?\\\"\\\\";
    const char *p = strchr(from, *s);

    if (!p && ISPRINT(*s))
      continue;

    result = fetchx_dyn_addn(&escaped, str, s - str);
    str = s + 1;

    if (!result)
    {
      if (p && *p)
        result = fetchx_dyn_addn(&escaped, to + 2 * (p - from), 2);
      else
      {
        result = fetchx_dyn_addf(&escaped,
                                 /* Octal escape to avoid >2 digit hex. */
                                 (len > 1 && ISXDIGIT(s[1])) ? "\\%03o" : "\\x%02x",
                                 (unsigned int)*(unsigned char *)s);
      }
    }
  }

  if (!result)
    result = fetchx_dyn_addn(&escaped, str, s - str);

  if (!result)
    (void)!fetchx_dyn_addn(&escaped, "...", cutoff);

  return fetchx_dyn_ptr(&escaped);
}

/* setopt wrapper for enum types */
FETCHcode tool_setopt_enum(FETCH *fetch, struct GlobalConfig *config,
                           const char *name, FETCHoption tag,
                           const struct NameValue *nvlist, long lval)
{
  FETCHcode ret = FETCHE_OK;
  bool skip = FALSE;

  ret = fetch_easy_setopt(fetch, tag, lval);
  if (!lval)
    skip = TRUE;

  if (config->libfetch && !skip && !ret)
  {
    /* we only use this for real if --libfetch was used */
    const struct NameValue *nv = NULL;
    for (nv = nvlist; nv->name; nv++)
    {
      if (nv->value == lval)
        break; /* found it */
    }
    if (!nv->name)
    {
      /* If no definition was found, output an explicit value.
       * This could happen if new values are defined and used
       * but the NameValue list is not updated. */
      CODE2("fetch_easy_setopt(hnd, %s, %ldL);", name, lval);
    }
    else
    {
      CODE2("fetch_easy_setopt(hnd, %s, (long)%s);", name, nv->name);
    }
  }

#ifdef DEBUGBUILD
  if (ret)
    warnf(config, "option %s returned error (%d)", name, (int)ret);
#endif
nomem:
  return ret;
}

/* setopt wrapper for FETCHOPT_SSLVERSION */
FETCHcode tool_setopt_SSLVERSION(FETCH *fetch, struct GlobalConfig *config,
                                 const char *name, FETCHoption tag,
                                 long lval)
{
  FETCHcode ret = FETCHE_OK;
  bool skip = FALSE;

  ret = fetch_easy_setopt(fetch, tag, lval);
  if (!lval)
    skip = TRUE;

  if (config->libfetch && !skip && !ret)
  {
    /* we only use this for real if --libfetch was used */
    const struct NameValue *nv = NULL;
    const struct NameValue *nv2 = NULL;
    for (nv = setopt_nv_FETCH_SSLVERSION; nv->name; nv++)
    {
      if (nv->value == (lval & 0xffff))
        break; /* found it */
    }
    for (nv2 = setopt_nv_FETCH_SSLVERSION_MAX; nv2->name; nv2++)
    {
      if (nv2->value == (lval & ~0xffff))
        break; /* found it */
    }
    if (!nv->name)
    {
      /* If no definition was found, output an explicit value.
       * This could happen if new values are defined and used
       * but the NameValue list is not updated. */
      CODE2("fetch_easy_setopt(hnd, %s, %ldL);", name, lval);
    }
    else
    {
      CODE3("fetch_easy_setopt(hnd, %s, (long)(%s | %s));",
            name, nv->name, nv2->name);
    }
  }

#ifdef DEBUGBUILD
  if (ret)
    warnf(config, "option %s returned error (%d)", name, (int)ret);
#endif
nomem:
  return ret;
}

/* setopt wrapper for bitmasks */
FETCHcode tool_setopt_bitmask(FETCH *fetch, struct GlobalConfig *config,
                              const char *name, FETCHoption tag,
                              const struct NameValueUnsigned *nvlist,
                              long lval)
{
  FETCHcode ret = FETCHE_OK;
  bool skip = FALSE;

  ret = fetch_easy_setopt(fetch, tag, lval);
  if (!lval)
    skip = TRUE;

  if (config->libfetch && !skip && !ret)
  {
    /* we only use this for real if --libfetch was used */
    char preamble[80];
    unsigned long rest = (unsigned long)lval;
    const struct NameValueUnsigned *nv = NULL;
    msnprintf(preamble, sizeof(preamble),
              "fetch_easy_setopt(hnd, %s, ", name);
    for (nv = nvlist; nv->name; nv++)
    {
      if ((nv->value & ~rest) == 0)
      {
        /* all value flags contained in rest */
        rest &= ~nv->value; /* remove bits handled here */
        CODE3("%s(long)%s%s",
              preamble, nv->name, rest ? " |" : ");");
        if (!rest)
          break; /* handled them all */
        /* replace with all spaces for continuation line */
        msnprintf(preamble, sizeof(preamble), "%*s", (int)strlen(preamble),
                  "");
      }
    }
    /* If any bits have no definition, output an explicit value.
     * This could happen if new bits are defined and used
     * but the NameValue list is not updated. */
    if (rest)
      CODE2("%s%luUL);", preamble, rest);
  }

nomem:
  return ret;
}

/* Generate code for a struct fetch_slist. */
static FETCHcode libfetch_generate_slist(struct fetch_slist *slist, int *slistno)
{
  FETCHcode ret = FETCHE_OK;
  char *escaped = NULL;

  /* May need several slist variables, so invent name */
  *slistno = ++easysrc_slist_count;

  DECL1("struct fetch_slist *slist%d;", *slistno);
  DATA1("slist%d = NULL;", *slistno);
  CLEAN1("fetch_slist_free_all(slist%d);", *slistno);
  CLEAN1("slist%d = NULL;", *slistno);
  for (; slist; slist = slist->next)
  {
    Curl_safefree(escaped);
    escaped = c_escape(slist->data, ZERO_TERMINATED);
    if (!escaped)
      return FETCHE_OUT_OF_MEMORY;
    DATA3("slist%d = fetch_slist_append(slist%d, \"%s\");",
          *slistno, *slistno, escaped);
  }

nomem:
  Curl_safefree(escaped);
  return ret;
}

static FETCHcode libfetch_generate_mime(FETCH *fetch,
                                        struct GlobalConfig *config,
                                        struct tool_mime *toolmime,
                                        int *mimeno); /* Forward. */

/* Wrapper to generate source code for a mime part. */
static FETCHcode libfetch_generate_mime_part(FETCH *fetch,
                                             struct GlobalConfig *config,
                                             struct tool_mime *part,
                                             int mimeno)
{
  FETCHcode ret = FETCHE_OK;
  int submimeno = 0;
  char *escaped = NULL;
  const char *data = NULL;
  const char *filename = part->filename;

  /* Parts are linked in reverse order. */
  if (part->prev)
  {
    ret = libfetch_generate_mime_part(fetch, config, part->prev, mimeno);
    if (ret)
      return ret;
  }

  /* Create the part. */
  CODE2("part%d = fetch_mime_addpart(mime%d);", mimeno, mimeno);

  switch (part->kind)
  {
  case TOOLMIME_PARTS:
    ret = libfetch_generate_mime(fetch, config, part, &submimeno);
    if (!ret)
    {
      CODE2("fetch_mime_subparts(part%d, mime%d);", mimeno, submimeno);
      CODE1("mime%d = NULL;", submimeno); /* Avoid freeing in CLEAN. */
    }
    break;

  case TOOLMIME_DATA:
    data = part->data;
    if (!ret)
    {
      Curl_safefree(escaped);
      escaped = c_escape(data, ZERO_TERMINATED);
      NULL_CHECK(escaped);
      CODE2("fetch_mime_data(part%d, \"%s\", FETCH_ZERO_TERMINATED);",
            mimeno, escaped);
    }
    break;

  case TOOLMIME_FILE:
  case TOOLMIME_FILEDATA:
    escaped = c_escape(part->data, ZERO_TERMINATED);
    NULL_CHECK(escaped);
    CODE2("fetch_mime_filedata(part%d, \"%s\");", mimeno, escaped);
    if (part->kind == TOOLMIME_FILEDATA && !filename)
    {
      CODE1("fetch_mime_filename(part%d, NULL);", mimeno);
    }
    break;

  case TOOLMIME_STDIN:
    if (!filename)
      filename = "-";
    FALLTHROUGH();
  case TOOLMIME_STDINDATA:
    /* Can only be reading stdin in the current context. */
    CODE1("fetch_mime_data_cb(part%d, -1, (fetch_read_callback) fread, \\",
          mimeno);
    CODE0("                  (fetch_seek_callback) fseek, NULL, stdin);");
    break;
  default:
    /* Other cases not possible in this context. */
    break;
  }

  if (!ret && part->encoder)
  {
    Curl_safefree(escaped);
    escaped = c_escape(part->encoder, ZERO_TERMINATED);
    NULL_CHECK(escaped);
    CODE2("fetch_mime_encoder(part%d, \"%s\");", mimeno, escaped);
  }

  if (!ret && filename)
  {
    Curl_safefree(escaped);
    escaped = c_escape(filename, ZERO_TERMINATED);
    NULL_CHECK(escaped);
    CODE2("fetch_mime_filename(part%d, \"%s\");", mimeno, escaped);
  }

  if (!ret && part->name)
  {
    Curl_safefree(escaped);
    escaped = c_escape(part->name, ZERO_TERMINATED);
    NULL_CHECK(escaped);
    CODE2("fetch_mime_name(part%d, \"%s\");", mimeno, escaped);
  }

  if (!ret && part->type)
  {
    Curl_safefree(escaped);
    escaped = c_escape(part->type, ZERO_TERMINATED);
    NULL_CHECK(escaped);
    CODE2("fetch_mime_type(part%d, \"%s\");", mimeno, escaped);
  }

  if (!ret && part->headers)
  {
    int slistno;

    ret = libfetch_generate_slist(part->headers, &slistno);
    if (!ret)
    {
      CODE2("fetch_mime_headers(part%d, slist%d, 1);", mimeno, slistno);
      CODE1("slist%d = NULL;", slistno); /* Prevent CLEANing. */
    }
  }

nomem:
  Curl_safefree(escaped);
  return ret;
}

/* Wrapper to generate source code for a mime structure. */
static FETCHcode libfetch_generate_mime(FETCH *fetch,
                                        struct GlobalConfig *config,
                                        struct tool_mime *toolmime,
                                        int *mimeno)
{
  FETCHcode ret = FETCHE_OK;

  /* May need several mime variables, so invent name. */
  *mimeno = ++easysrc_mime_count;
  DECL1("fetch_mime *mime%d;", *mimeno);
  DATA1("mime%d = NULL;", *mimeno);
  CODE1("mime%d = fetch_mime_init(hnd);", *mimeno);
  CLEAN1("fetch_mime_free(mime%d);", *mimeno);
  CLEAN1("mime%d = NULL;", *mimeno);

  if (toolmime->subparts)
  {
    DECL1("fetch_mimepart *part%d;", *mimeno);
    ret = libfetch_generate_mime_part(fetch, config,
                                      toolmime->subparts, *mimeno);
  }

nomem:
  return ret;
}

/* setopt wrapper for FETCHOPT_MIMEPOST */
FETCHcode tool_setopt_mimepost(FETCH *fetch, struct GlobalConfig *config,
                               const char *name, FETCHoption tag,
                               fetch_mime *mimepost)
{
  FETCHcode ret = fetch_easy_setopt(fetch, tag, mimepost);
  int mimeno = 0;

  if (!ret && config->libfetch)
  {
    ret = libfetch_generate_mime(fetch, config,
                                 config->current->mimeroot, &mimeno);

    if (!ret)
      CODE2("fetch_easy_setopt(hnd, %s, mime%d);", name, mimeno);
  }

nomem:
  return ret;
}

/* setopt wrapper for fetch_slist options */
FETCHcode tool_setopt_slist(FETCH *fetch, struct GlobalConfig *config,
                            const char *name, FETCHoption tag,
                            struct fetch_slist *list)
{
  FETCHcode ret = FETCHE_OK;

  ret = fetch_easy_setopt(fetch, tag, list);

  if (config->libfetch && list && !ret)
  {
    int i;

    ret = libfetch_generate_slist(list, &i);
    if (!ret)
      CODE2("fetch_easy_setopt(hnd, %s, slist%d);", name, i);
  }

nomem:
  return ret;
}

/* generic setopt wrapper for all other options.
 * Some type information is encoded in the tag value. */
FETCHcode tool_setopt(FETCH *fetch, bool str, struct GlobalConfig *global,
                      struct OperationConfig *config,
                      const char *name, FETCHoption tag, ...)
{
  va_list arg;
  char buf[256];
  const char *value = NULL;
  bool remark = FALSE;
  bool skip = FALSE;
  bool escape = FALSE;
  char *escaped = NULL;
  FETCHcode ret = FETCHE_OK;

  va_start(arg, tag);

  if (tag < FETCHOPTTYPE_OBJECTPOINT)
  {
    /* Value is expected to be a long */
    long lval = va_arg(arg, long);
    long defval = 0L;
    const struct NameValue *nv = NULL;
    for (nv = setopt_nv_FETCHNONZERODEFAULTS; nv->name; nv++)
    {
      if (!strcmp(name, nv->name))
      {
        defval = nv->value;
        break; /* found it */
      }
    }

    msnprintf(buf, sizeof(buf), "%ldL", lval);
    value = buf;
    ret = fetch_easy_setopt(fetch, tag, lval);
    if (lval == defval)
      skip = TRUE;
  }
  else if (tag < FETCHOPTTYPE_OFF_T)
  {
    /* Value is some sort of object pointer */
    void *pval = va_arg(arg, void *);

    /* function pointers are never printable */
    if (tag >= FETCHOPTTYPE_FUNCTIONPOINT)
    {
      if (pval)
      {
        value = "function pointer";
        remark = TRUE;
      }
      else
        skip = TRUE;
    }

    else if (pval && str)
    {
      value = (char *)pval;
      escape = TRUE;
    }
    else if (pval)
    {
      value = "object pointer";
      remark = TRUE;
    }
    else
      skip = TRUE;

    ret = fetch_easy_setopt(fetch, tag, pval);
  }
  else if (tag < FETCHOPTTYPE_BLOB)
  {
    /* Value is expected to be fetch_off_t */
    fetch_off_t oval = va_arg(arg, fetch_off_t);
    msnprintf(buf, sizeof(buf),
              "(fetch_off_t)%" FETCH_FORMAT_FETCH_OFF_T, oval);
    value = buf;
    ret = fetch_easy_setopt(fetch, tag, oval);

    if (!oval)
      skip = TRUE;
  }
  else
  {
    /* Value is a blob */
    void *pblob = va_arg(arg, void *);

    /* blobs are never printable */
    if (pblob)
    {
      value = "blob pointer";
      remark = TRUE;
    }
    else
      skip = TRUE;

    ret = fetch_easy_setopt(fetch, tag, pblob);
  }

  va_end(arg);

  if (global->libfetch && !skip && !ret)
  {
    /* we only use this for real if --libfetch was used */

    if (remark)
      REM3("%s was set to a%s %s", name, (*value == 'o' ? "n" : ""), value);
    else
    {
      if (escape)
      {
        fetch_off_t len = ZERO_TERMINATED;
        if (tag == FETCHOPT_POSTFIELDS)
          len = fetchx_dyn_len(&config->postdata);
        escaped = c_escape(value, len);
        NULL_CHECK(escaped);
        CODE2("fetch_easy_setopt(hnd, %s, \"%s\");", name, escaped);
      }
      else
        CODE2("fetch_easy_setopt(hnd, %s, %s);", name, value);
    }
  }

nomem:
  Curl_safefree(escaped);
  return ret;
}

#else /* FETCH_DISABLE_LIBFETCH_OPTION */

#endif /* FETCH_DISABLE_LIBFETCH_OPTION */
