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
#include "tool_setup.h"

#ifndef CURL_DISABLE_LIBCURL_OPTION

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_easysrc.h"
#include "tool_setopt.h"

#include "memdebug.h" /* keep this as LAST include */

/* Lookup tables for converting setopt values back to symbols */
/* For enums, values may be in any order. */
/* For bit masks, put combinations first, then single bits, */
/* and finally any "NONE" value. */

#define NV(e) {#e, e}
#define NVEND {NULL, 0}         /* sentinel to mark end of list */

const NameValue setopt_nv_CURLPROXY[] = {
  NV(CURLPROXY_HTTP),
  NV(CURLPROXY_HTTP_1_0),
  NV(CURLPROXY_SOCKS4),
  NV(CURLPROXY_SOCKS5),
  NV(CURLPROXY_SOCKS4A),
  NV(CURLPROXY_SOCKS5_HOSTNAME),
  NVEND,
};

const NameValueUnsigned setopt_nv_CURLAUTH[] = {
  NV(CURLAUTH_ANY),             /* combination */
  NV(CURLAUTH_ANYSAFE),         /* combination */
  NV(CURLAUTH_BASIC),
  NV(CURLAUTH_DIGEST),
  NV(CURLAUTH_GSSNEGOTIATE),
  NV(CURLAUTH_NTLM),
  NV(CURLAUTH_DIGEST_IE),
  NV(CURLAUTH_NTLM_WB),
  NV(CURLAUTH_ONLY),
  NV(CURLAUTH_NONE),
  NVEND,
};

const NameValue setopt_nv_CURL_HTTP_VERSION[] = {
  NV(CURL_HTTP_VERSION_NONE),
  NV(CURL_HTTP_VERSION_1_0),
  NV(CURL_HTTP_VERSION_1_1),
  NVEND,
};

const NameValue setopt_nv_CURL_SSLVERSION[] = {
  NV(CURL_SSLVERSION_DEFAULT),
  NV(CURL_SSLVERSION_TLSv1),
  NV(CURL_SSLVERSION_SSLv2),
  NV(CURL_SSLVERSION_SSLv3),
  NVEND,
};

const NameValue setopt_nv_CURL_TIMECOND[] = {
  NV(CURL_TIMECOND_IFMODSINCE),
  NV(CURL_TIMECOND_IFUNMODSINCE),
  NV(CURL_TIMECOND_LASTMOD),
  NV(CURL_TIMECOND_NONE),
  NVEND,
};

const NameValue setopt_nv_CURLFTPSSL_CCC[] = {
  NV(CURLFTPSSL_CCC_NONE),
  NV(CURLFTPSSL_CCC_PASSIVE),
  NV(CURLFTPSSL_CCC_ACTIVE),
  NVEND,
};

/* These mappings essentially triplicated - see
 * tool_libinfo.c and tool_paramhlp.c */
const NameValue setopt_nv_CURLPROTO[] = {
  NV(CURLPROTO_ALL),            /* combination */
  NV(CURLPROTO_DICT),
  NV(CURLPROTO_FILE),
  NV(CURLPROTO_FTP),
  NV(CURLPROTO_FTPS),
  NV(CURLPROTO_GOPHER),
  NV(CURLPROTO_HTTP),
  NV(CURLPROTO_HTTPS),
  NV(CURLPROTO_IMAP),
  NV(CURLPROTO_IMAPS),
  NV(CURLPROTO_LDAP),
  NV(CURLPROTO_LDAPS),
  NV(CURLPROTO_POP3),
  NV(CURLPROTO_POP3S),
  NV(CURLPROTO_RTSP),
  NV(CURLPROTO_SCP),
  NV(CURLPROTO_SFTP),
  NV(CURLPROTO_SMTP),
  NV(CURLPROTO_SMTPS),
  NV(CURLPROTO_TELNET),
  NV(CURLPROTO_TFTP),
  NVEND,
};

/* Format and add code; jump to nomem on malloc error */
#define ADD(args) do { \
  ret = easysrc_add args; \
  if(ret) \
    goto nomem; \
} WHILE_FALSE
#define ADDF(args) do { \
  ret = easysrc_addf args; \
  if(ret) \
    goto nomem; \
} WHILE_FALSE

#define DECL0(s) ADD((&easysrc_decl, s))
#define DECL1(f,a) ADDF((&easysrc_decl, f,a))

#define DATA0(s) ADD((&easysrc_data, s))
#define DATA1(f,a) ADDF((&easysrc_data, f,a))
#define DATA2(f,a,b) ADDF((&easysrc_data, f,a,b))
#define DATA3(f,a,b,c) ADDF((&easysrc_data, f,a,b,c))

#define CODE0(s) ADD((&easysrc_code, s))
#define CODE1(f,a) ADDF((&easysrc_code, f,a))
#define CODE2(f,a,b) ADDF((&easysrc_code, f,a,b))
#define CODE3(f,a,b,c) ADDF((&easysrc_code, f,a,b,c))

#define CLEAN0(s) ADD((&easysrc_clean, s))
#define CLEAN1(f,a) ADDF((&easysrc_clean, f,a))

#define REM0(s) ADD((&easysrc_toohard, s))
#define REM1(f,a) ADDF((&easysrc_toohard, f,a))
#define REM2(f,a,b) ADDF((&easysrc_toohard, f,a,b))

/* Escape string to C string syntax.  Return NULL if out of memory.
 * Is this correct for those wacky EBCDIC guys? */
static char *c_escape(const char *str)
{
  size_t len = 0;
  const char *s;
  unsigned char c;
  char *escaped, *e;
  /* Allocate space based on worst-case */
  len = strlen(str);
  escaped = malloc(4 * len + 1);
  if(!escaped)
    return NULL;

  e = escaped;
  for(s=str; (c=*s) != '\0'; s++) {
    if(c=='\n') {
      strcpy(e, "\\n");
      e += 2;
    }
    else if(c=='\r') {
      strcpy(e, "\\r");
      e += 2;
    }
    else if(c=='\t') {
      strcpy(e, "\\t");
      e += 2;
    }
    else if(c=='\\') {
      strcpy(e, "\\\\");
      e += 2;
    }
    else if(c=='"') {
      strcpy(e, "\\\"");
      e += 2;
    }
    else if(! isprint(c)) {
      sprintf(e, "\\%03o", c);
      e += 4;
    }
    else
      *e++ = c;
  }
  *e = '\0';
  return escaped;
}

/* setopt wrapper for enum types */
CURLcode tool_setopt_enum(CURL *curl, struct Configurable *config,
                          const char *name, CURLoption tag,
                          const NameValue *nvlist, long lval)
{
  CURLcode ret = CURLE_OK;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, lval);
  if(!lval)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */
    const NameValue *nv = NULL;
    for(nv=nvlist; nv->name; nv++) {
      if(nv->value == lval) break; /* found it */
    }
    if(! nv->name) {
      /* If no definition was found, output an explicit value.
       * This could happen if new values are defined and used
       * but the NameValue list is not updated. */
      CODE2("curl_easy_setopt(hnd, %s, %ldL);", name, lval);
    }
    else {
      CODE2("curl_easy_setopt(hnd, %s, (long)%s);", name, nv->name);
    }
  }

 nomem:
  return ret;
}

/* setopt wrapper for flags */
CURLcode tool_setopt_flags(CURL *curl, struct Configurable *config,
                           const char *name, CURLoption tag,
                           const NameValue *nvlist, long lval)
{
  CURLcode ret = CURLE_OK;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, lval);
  if(!lval)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */
    char preamble[80];          /* should accommodate any symbol name */
    long rest = lval;           /* bits not handled yet */
    const NameValue *nv = NULL;
    snprintf(preamble, sizeof(preamble),
             "curl_easy_setopt(hnd, %s, ", name);
    for(nv=nvlist; nv->name; nv++) {
      if((nv->value & ~ rest) == 0) {
        /* all value flags contained in rest */
        rest &= ~ nv->value;    /* remove bits handled here */
        CODE3("%s(long)%s%s",
              preamble, nv->name, rest ? " |" : ");");
        if(!rest)
          break;                /* handled them all */
        /* replace with all spaces for continuation line */
        sprintf(preamble, "%*s", strlen(preamble), "");
      }
    }
    /* If any bits have no definition, output an explicit value.
     * This could happen if new bits are defined and used
     * but the NameValue list is not updated. */
    if(rest)
      CODE2("%s%ldL);", preamble, rest);
  }

 nomem:
  return ret;
}

/* setopt wrapper for bitmasks */
CURLcode tool_setopt_bitmask(CURL *curl, struct Configurable *config,
                             const char *name, CURLoption tag,
                             const NameValueUnsigned *nvlist,
                             long lval)
{
  CURLcode ret = CURLE_OK;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, lval);
  if(!lval)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */
    char preamble[80];
    unsigned long rest = (unsigned long)lval;
    const NameValueUnsigned *nv = NULL;
    snprintf(preamble, sizeof(preamble),
             "curl_easy_setopt(hnd, %s, ", name);
    for(nv=nvlist; nv->name; nv++) {
      if((nv->value & ~ rest) == 0) {
        /* all value flags contained in rest */
        rest &= ~ nv->value;    /* remove bits handled here */
        CODE3("%s(long)%s%s",
              preamble, nv->name, rest ? " |" : ");");
        if(!rest)
          break;                /* handled them all */
        /* replace with all spaces for continuation line */
        sprintf(preamble, "%*s", strlen(preamble), "");
      }
    }
    /* If any bits have no definition, output an explicit value.
     * This could happen if new bits are defined and used
     * but the NameValue list is not updated. */
    if(rest)
      CODE2("%s%luUL);", preamble, rest);
  }

 nomem:
  return ret;
}

/* setopt wrapper for CURLOPT_HTTPPOST */
CURLcode tool_setopt_httppost(CURL *curl, struct Configurable *config,
                              const char *name, CURLoption tag,
                              struct curl_httppost *post)
{
  CURLcode ret = CURLE_OK;
  char *escaped = NULL;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, post);
  if(!post)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    struct curl_httppost *pp, *p;
    int i;
    /* May use several httppost lists, if multiple POST actions */
    i = ++ easysrc_form_count;
    DECL1("struct curl_httppost *post%d;", i);
    DATA1("post%d = NULL;", i);
    CLEAN1("curl_formfree(post%d);", i);
    CLEAN1("post%d = NULL;", i);
    if(i == 1)
      DECL0("struct curl_httppost *postend;");
    DATA0("postend = NULL;");
    for(p=post; p; p=p->next) {
      DATA1("curl_formadd(&post%d, &postend,", i);
      DATA1("             CURLFORM_COPYNAME, \"%s\",", p->name);
      for(pp=p; pp; pp=pp->more) {
        /* May be several files uploaded for one name;
         * these are linked through the 'more' pointer */
        Curl_safefree(escaped);
        escaped = c_escape(pp->contents);
        if(!escaped) {
          ret = CURLE_OUT_OF_MEMORY;
          goto nomem;
        }
        if(pp->flags & HTTPPOST_FILENAME) {
          /* file upload as for -F @filename */
          DATA1("             CURLFORM_FILE, \"%s\",", escaped);
        }
        else if(pp->flags & HTTPPOST_READFILE) {
          /* content from file as for -F <filename */
          DATA1("             CURLFORM_FILECONTENT, \"%s\",", escaped);
        }
        else
          DATA1("             CURLFORM_COPYCONTENTS, \"%s\",", escaped);
        if(pp->showfilename) {
          Curl_safefree(escaped);
          escaped = c_escape(pp->showfilename);
          if(!escaped) {
            ret = CURLE_OUT_OF_MEMORY;
            goto nomem;
          }
          DATA1("             CURLFORM_FILENAME, \"%s\",", escaped);
        }
        if(pp->contenttype) {
          Curl_safefree(escaped);
          escaped = c_escape(pp->contenttype);
          if(!escaped) {
            ret = CURLE_OUT_OF_MEMORY;
            goto nomem;
          }
          DATA1("             CURLFORM_CONTENTTYPE, \"%s\",", escaped);
        }
      }
      DATA0("             CURLFORM_END);");
    }
    CODE2("curl_easy_setopt(hnd, %s, post%d);", name, i);
  }

 nomem:
  Curl_safefree(escaped);
  return ret;
}

/* setopt wrapper for curl_slist options */
CURLcode tool_setopt_slist(CURL *curl, struct Configurable *config,
                           const char *name, CURLoption tag,
                           struct curl_slist *list)
{
  CURLcode ret = CURLE_OK;
  char *escaped = NULL;
  bool skip = FALSE;

  ret = curl_easy_setopt(curl, tag, list);
  if(!list)
    skip = TRUE;

  if(config->libcurl && !skip && !ret) {
    struct curl_slist *s;
    int i;
    /* May need several slist variables, so invent name */
    i = ++ easysrc_slist_count;
    DECL1("struct curl_slist *slist%d;", i);
    DATA1("slist%d = NULL;", i);
    CLEAN1("curl_slist_free_all(slist%d);", i);
    CLEAN1("slist%d = NULL;", i);
    for(s=list; s; s=s->next) {
      Curl_safefree(escaped);
      escaped = c_escape(s->data);
      if(!escaped) {
        ret = CURLE_OUT_OF_MEMORY;
        goto nomem;
      }
      DATA3("slist%d = curl_slist_append(slist%d, \"%s\");", i, i, escaped);
    }
    CODE2("curl_easy_setopt(hnd, %s, slist%d);", name, i);
  }

 nomem:
  Curl_safefree(escaped);
  return ret;
}

/* generic setopt wrapper for all other options.
 * Some type information is encoded in the tag value. */
CURLcode tool_setopt(CURL *curl, bool str, struct Configurable *config,
                     const char *name, CURLoption tag, ...)
{
  va_list arg;
  char buf[256];
  const char *value = NULL;
  bool remark = FALSE;
  bool skip = FALSE;
  bool escape = FALSE;
  char *escaped = NULL;
  CURLcode ret = CURLE_OK;

  va_start(arg, tag);

  if(tag < CURLOPTTYPE_OBJECTPOINT) {
    /* Value is expected to be a long */
    long lval = va_arg(arg, long);
    snprintf(buf, sizeof(buf), "%ldL", lval);
    value = buf;
    ret = curl_easy_setopt(curl, tag, lval);
    if(!lval)
      skip = TRUE;
  }
  else if(tag < CURLOPTTYPE_OFF_T) {
    /* Value is some sort of object pointer */
    void *pval = va_arg(arg, void *);

    /* function pointers are never printable */
    if(tag >= CURLOPTTYPE_FUNCTIONPOINT) {
      if(pval) {
        value = "functionpointer";
        remark = TRUE;
      }
      else
        skip = TRUE;
    }

    else if(pval && str) {
      value = (char *)pval;
      escape = TRUE;
    }
    else if(pval) {
      value = "objectpointer";
      remark = TRUE;
    }
    else
      skip = TRUE;

    ret = curl_easy_setopt(curl, tag, pval);

  }
  else {
    /* Value is expected to be curl_off_t */
    curl_off_t oval = va_arg(arg, curl_off_t);
    snprintf(buf, sizeof(buf),
             "(curl_off_t)%" CURL_FORMAT_CURL_OFF_T, oval);
    value = buf;
    ret = curl_easy_setopt(curl, tag, oval);

    if(!oval)
      skip = TRUE;
  }

  va_end(arg);

  if(config->libcurl && !skip && !ret) {
    /* we only use this for real if --libcurl was used */

    if(remark)
      REM2("%s set to a %s", name, value);
    else {
      if(escape) {
        escaped = c_escape(value);
        if(!escaped) {
          ret = CURLE_OUT_OF_MEMORY;
          goto nomem;
        }
        CODE2("curl_easy_setopt(hnd, %s, \"%s\");", name, escaped);
      }
      else
        CODE2("curl_easy_setopt(hnd, %s, %s);", name, value);
    }
  }

 nomem:
  Curl_safefree(escaped);
  return ret;
}

#endif /* CURL_DISABLE_LIBCURL_OPTION */
