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

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_findfile.h"
#include "tool_msgs.h"
#include "tool_parsecfg.h"
#include "dynbuf.h"
#include "curl_base64.h"
#include "tool_paramhlp.h"
#include "tool_writeout_json.h"
#include "var.h"

#include "memdebug.h" /* keep this as LAST include */

#define MAX_EXPAND_CONTENT 10000000
#define MAX_VAR_LEN 128 /* max length of a name */

static char *Memdup(const char *data, size_t len)
{
  char *p = malloc(len + 1);
  if(!p)
    return NULL;
  if(len)
    memcpy(p, data, len);
  p[len] = 0;
  return p;
}

/* free everything */
void varcleanup(struct GlobalConfig *global)
{
  struct var *list = global->variables;
  while(list) {
    struct var *t = list;
    list = list->next;
    free((char *)t->content);
    free(t);
  }
}

static const struct var *varcontent(struct GlobalConfig *global,
                                    const char *name, size_t nlen)
{
  struct var *list = global->variables;
  while(list) {
    if((strlen(list->name) == nlen) &&
       !strncmp(name, list->name, nlen)) {
      return list;
    }
    list = list->next;
  }
  return NULL;
}

#define ENDOFFUNC(x) (((x) == '}') || ((x) == ':'))
#define FUNCMATCH(ptr,name,len)                         \
  (!strncmp(ptr, name, len) && ENDOFFUNC(ptr[len]))

#define FUNC_TRIM "trim"
#define FUNC_TRIM_LEN (sizeof(FUNC_TRIM) - 1)
#define FUNC_JSON "json"
#define FUNC_JSON_LEN (sizeof(FUNC_JSON) - 1)
#define FUNC_URL "url"
#define FUNC_URL_LEN (sizeof(FUNC_URL) - 1)
#define FUNC_B64 "b64"
#define FUNC_B64_LEN (sizeof(FUNC_B64) - 1)

static ParameterError varfunc(struct GlobalConfig *global,
                              char *c, /* content */
                              size_t clen, /* content length */
                              char *f, /* functions */
                              size_t flen, /* function string length */
                              struct curlx_dynbuf *out)
{
  bool alloc = FALSE;
  ParameterError err = PARAM_OK;
  const char *finput = f;

  /* The functions are independent and runs left to right */
  while(*f && !err) {
    if(*f == '}')
      /* end of functions */
      break;
    /* On entry, this is known to be a colon already. In subsequent laps, it
       is also known to be a colon since that is part of the FUNCMATCH()
       checks */
    f++;
    if(FUNCMATCH(f, FUNC_TRIM, FUNC_TRIM_LEN)) {
      size_t len = clen;
      f += FUNC_TRIM_LEN;
      if(clen) {
        /* skip leading white space, including CRLF */
        while(*c && ISSPACE(*c)) {
          c++;
          len--;
        }
        while(len && ISSPACE(c[len-1]))
          len--;
      }
      /* put it in the output */
      curlx_dyn_reset(out);
      if(curlx_dyn_addn(out, c, len)) {
        err = PARAM_NO_MEM;
        break;
      }
    }
    else if(FUNCMATCH(f, FUNC_JSON, FUNC_JSON_LEN)) {
      f += FUNC_JSON_LEN;
      curlx_dyn_reset(out);
      if(clen) {
        if(jsonquoted(c, clen, out, FALSE)) {
          err = PARAM_NO_MEM;
          break;
        }
      }
    }
    else if(FUNCMATCH(f, FUNC_URL, FUNC_URL_LEN)) {
      f += FUNC_URL_LEN;
      curlx_dyn_reset(out);
      if(clen) {
        char *enc = curl_easy_escape(NULL, c, (int)clen);
        if(!enc) {
          err = PARAM_NO_MEM;
          break;
        }

        /* put it in the output */
        if(curlx_dyn_add(out, enc))
          err = PARAM_NO_MEM;
        curl_free(enc);
        if(err)
          break;
      }
    }
    else if(FUNCMATCH(f, FUNC_B64, FUNC_B64_LEN)) {
      f += FUNC_B64_LEN;
      curlx_dyn_reset(out);
      if(clen) {
        char *enc;
        size_t elen;
        CURLcode result = curlx_base64_encode(c, clen, &enc, &elen);
        if(result) {
          err = PARAM_NO_MEM;
          break;
        }

        /* put it in the output */
        if(curlx_dyn_addn(out, enc, elen))
          err = PARAM_NO_MEM;
        curl_free(enc);
        if(err)
          break;
      }
    }
    else {
      /* unsupported function */
      errorf(global, "unknown variable function in '%.*s'",
             (int)flen, finput);
      err = PARAM_EXPAND_ERROR;
      break;
    }
    if(alloc)
      free(c);

    clen = curlx_dyn_len(out);
    c = Memdup(curlx_dyn_ptr(out), clen);
    if(!c) {
      err = PARAM_NO_MEM;
      break;
    }
    alloc = TRUE;
  }
  if(alloc)
    free(c);
  if(err)
    curlx_dyn_free(out);
  return err;
}

ParameterError varexpand(struct GlobalConfig *global,
                         const char *line, struct curlx_dynbuf *out,
                         bool *replaced)
{
  CURLcode result;
  char *envp;
  bool added = FALSE;
  const char *input = line;
  *replaced = FALSE;
  curlx_dyn_init(out, MAX_EXPAND_CONTENT);
  do {
    envp = strstr(line, "{{");
    if((envp > line) && envp[-1] == '\\') {
      /* preceding backslash, we want this verbatim */

      /* insert the text up to this point, minus the backslash */
      result = curlx_dyn_addn(out, line, envp - line - 1);
      if(result)
        return PARAM_NO_MEM;

      /* output '{{' then continue from here */
      result = curlx_dyn_addn(out, "{{", 2);
      if(result)
        return PARAM_NO_MEM;
      line = &envp[2];
    }
    else if(envp) {
      char name[MAX_VAR_LEN];
      size_t nlen;
      size_t i;
      char *funcp;
      char *clp = strstr(envp, "}}");
      size_t prefix;

      if(!clp) {
        /* uneven braces */
        warnf(global, "missing close '}}' in '%s'", input);
        break;
      }

      prefix = 2;
      envp += 2; /* move over the {{ */

      /* if there is a function, it ends the name with a colon */
      funcp = memchr(envp, ':', clp - envp);
      if(funcp)
        nlen = funcp - envp;
      else
        nlen = clp - envp;
      if(!nlen || (nlen >= sizeof(name))) {
        warnf(global, "bad variable name length '%s'", input);
        /* insert the text as-is since this is not an env variable */
        result = curlx_dyn_addn(out, line, clp - line + prefix);
        if(result)
          return PARAM_NO_MEM;
      }
      else {
        /* insert the text up to this point */
        result = curlx_dyn_addn(out, line, envp - prefix - line);
        if(result)
          return PARAM_NO_MEM;

        /* copy the name to separate buffer */
        memcpy(name, envp, nlen);
        name[nlen] = 0;

        /* verify that the name looks sensible */
        for(i = 0; (i < nlen) &&
              (ISALNUM(name[i]) || (name[i] == '_')); i++);
        if(i != nlen) {
          warnf(global, "bad variable name: %s", name);
          /* insert the text as-is since this is not an env variable */
          result = curlx_dyn_addn(out, envp - prefix,
                                  clp - envp + prefix + 2);
          if(result)
            return PARAM_NO_MEM;
        }
        else {
          char *value;
          size_t vlen = 0;
          struct curlx_dynbuf buf;
          const struct var *v = varcontent(global, name, nlen);
          if(v) {
            value = (char *)v->content;
            vlen = v->clen;
          }
          else
            value = NULL;

          curlx_dyn_init(&buf, MAX_EXPAND_CONTENT);
          if(funcp) {
            /* apply the list of functions on the value */
            size_t flen = clp - funcp;
            ParameterError err = varfunc(global, value, vlen, funcp, flen,
                                         &buf);
            if(err)
              return err;
            value = curlx_dyn_ptr(&buf);
            vlen = curlx_dyn_len(&buf);
          }

          if(value && vlen > 0) {
            /* A variable might contain null bytes. Such bytes cannot be shown
               using normal means, this is an error. */
            char *nb = memchr(value, '\0', vlen);
            if(nb) {
              errorf(global, "variable contains null byte");
              return PARAM_EXPAND_ERROR;
            }
          }
          /* insert the value */
          result = curlx_dyn_addn(out, value, vlen);
          curlx_dyn_free(&buf);
          if(result)
            return PARAM_NO_MEM;

          added = true;
        }
      }
      line = &clp[2];
    }

  } while(envp);
  if(added && *line) {
    /* add the "suffix" as well */
    result = curlx_dyn_add(out, line);
    if(result)
      return PARAM_NO_MEM;
  }
  *replaced = added;
  if(!added)
    curlx_dyn_free(out);
  return PARAM_OK;
}

/*
 * Created in a way that is not revealing how variables are actually stored so
 * that we can improve this if we want better performance when managing many
 * at a later point.
 */
static ParameterError addvariable(struct GlobalConfig *global,
                                  const char *name,
                                  size_t nlen,
                                  const char *content,
                                  size_t clen,
                                  bool contalloc)
{
  struct var *p;
  const struct var *check = varcontent(global, name, nlen);
  DEBUGASSERT(nlen);
  if(check)
    notef(global, "Overwriting variable '%s'", check->name);

  p = calloc(1, sizeof(struct var) + nlen);
  if(p) {
    memcpy(p->name, name, nlen);

    p->content = contalloc ? content: Memdup(content, clen);
    if(p->content) {
      p->clen = clen;

      p->next = global->variables;
      global->variables = p;
      return PARAM_OK;
    }
    free(p);
  }
  return PARAM_NO_MEM;
}

ParameterError setvariable(struct GlobalConfig *global,
                           const char *input)
{
  const char *name;
  size_t nlen;
  char *content = NULL;
  size_t clen = 0;
  bool contalloc = FALSE;
  const char *line = input;
  ParameterError err = PARAM_OK;
  bool import = FALSE;
  char *ge = NULL;
  char buf[MAX_VAR_LEN];

  if(*input == '%') {
    import = TRUE;
    line++;
  }
  name = line;
  while(*line && (ISALNUM(*line) || (*line == '_')))
    line++;
  nlen = line - name;
  if(!nlen || (nlen >= MAX_VAR_LEN)) {
    warnf(global, "Bad variable name length (%zd), skipping", nlen);
    return PARAM_OK;
  }
  if(import) {
    /* this does not use curl_getenv() because we want "" support for blank
       content */
    if(*line) {
      /* if there is a default action, we need to copy the name */
      memcpy(buf, name, nlen);
      buf[nlen] = 0;
      name = buf;
    }
    ge = getenv(name);
    if(!*line && !ge) {
      /* no assign, no variable, fail */
      errorf(global, "Variable '%s' import fail, not set", name);
      return PARAM_EXPAND_ERROR;
    }
    else if(ge) {
      /* there is a value to use */
      content = ge;
      clen = strlen(ge);
    }
  }
  if(content)
    ;
  else if(*line == '@') {
    /* read from file or stdin */
    FILE *file;
    bool use_stdin;
    line++;
    use_stdin = !strcmp(line, "-");
    if(use_stdin)
      file = stdin;
    else {
      file = fopen(line, "rb");
      if(!file) {
        errorf(global, "Failed to open %s", line);
        return PARAM_READ_ERROR;
      }
    }
    err = file2memory(&content, &clen, file);
    /* in case of out of memory, this should fail the entire operation */
    contalloc = TRUE;
    if(!use_stdin)
      fclose(file);
    if(err)
      return err;
  }
  else if(*line == '=') {
    line++;
    /* this is the exact content */
    content = (char *)line;
    clen = strlen(line);
  }
  else {
    warnf(global, "Bad --variable syntax, skipping: %s", input);
    return PARAM_OK;
  }
  err = addvariable(global, name, nlen, content, clen, contalloc);
  if(err) {
    if(contalloc)
      free(content);
  }
  return err;
}
