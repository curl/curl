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

#include "tool_cfgable.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_findfile.h"
#include "tool_msgs.h"
#include "tool_parsecfg.h"
#include "tool_paramhlp.h"
#include "tool_writeout_json.h"
#include "tool_strdup.h"
#include "var.h"
#include "memdebug.h" /* keep this as LAST include */

#define MAX_EXPAND_CONTENT 10000000
#define MAX_VAR_LEN 128 /* max length of a name */

/* free everything */
void varcleanup(void)
{
  struct tool_var *list = global->variables;
  while(list) {
    struct tool_var *t = list;
    list = list->next;
    free(CURL_UNCONST(t->content));
    free(t);
  }
}

static const struct tool_var *varcontent(const char *name, size_t nlen)
{
  struct tool_var *list = global->variables;
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
#define FUNC_64DEC "64dec" /* base64 decode */
#define FUNC_64DEC_LEN (sizeof(FUNC_64DEC) - 1)

static ParameterError varfunc(char *c, /* content */
                              size_t clen, /* content length */
                              char *f, /* functions */
                              size_t flen, /* function string length */
                              struct dynbuf *out)
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
        while(ISSPACE(*c)) {
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
    else if(FUNCMATCH(f, FUNC_64DEC, FUNC_64DEC_LEN)) {
      f += FUNC_64DEC_LEN;
      curlx_dyn_reset(out);
      if(clen) {
        unsigned char *enc;
        size_t elen;
        CURLcode result = curlx_base64_decode(c, &enc, &elen);
        /* put it in the output */
        if(result) {
          if(curlx_dyn_add(out, "[64dec-fail]"))
            err = PARAM_NO_MEM;
        }
        else {
          if(curlx_dyn_addn(out, enc, elen))
            err = PARAM_NO_MEM;
          curl_free(enc);
        }
        if(err)
          break;
      }
    }
    else {
      /* unsupported function */
      errorf("unknown variable function in '%.*s'", (int)flen, finput);
      err = PARAM_EXPAND_ERROR;
      break;
    }
    if(alloc)
      free(c);

    clen = curlx_dyn_len(out);
    c = memdup0(curlx_dyn_ptr(out), clen);
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

ParameterError varexpand(const char *line, struct dynbuf *out,
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
        warnf("missing close '}}' in '%s'", input);
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
        warnf("bad variable name length '%s'", input);
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
          warnf("bad variable name: %s", name);
          /* insert the text as-is since this is not an env variable */
          result = curlx_dyn_addn(out, envp - prefix,
                                  clp - envp + prefix + 2);
          if(result)
            return PARAM_NO_MEM;
        }
        else {
          char *value;
          size_t vlen = 0;
          struct dynbuf buf;
          const struct tool_var *v = varcontent(name, nlen);
          if(v) {
            value = (char *)CURL_UNCONST(v->content);
            vlen = v->clen;
          }
          else
            value = NULL;

          curlx_dyn_init(&buf, MAX_EXPAND_CONTENT);
          if(funcp) {
            /* apply the list of functions on the value */
            size_t flen = clp - funcp;
            ParameterError err = varfunc(value, vlen, funcp, flen, &buf);
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
              errorf("variable contains null byte");
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
static ParameterError addvariable(const char *name,
                                  size_t nlen,
                                  const char *content,
                                  size_t clen,
                                  bool contalloc)
{
  struct tool_var *p;
  const struct tool_var *check = varcontent(name, nlen);
  DEBUGASSERT(nlen);
  if(check)
    notef("Overwriting variable '%s'", check->name);

  p = calloc(1, sizeof(struct tool_var) + nlen);
  if(p) {
    memcpy(p->name, name, nlen);

    p->content = contalloc ? content : memdup0(content, clen);
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

#define MAX_FILENAME 10000

ParameterError setvariable(const char *input)
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
  curl_off_t startoffset = 0;
  curl_off_t endoffset = CURL_OFF_T_MAX;

  if(*input == '%') {
    import = TRUE;
    line++;
  }
  name = line;
  while(*line && (ISALNUM(*line) || (*line == '_')))
    line++;
  nlen = line - name;
  if(!nlen || (nlen >= MAX_VAR_LEN)) {
    warnf("Bad variable name length (%zd), skipping", nlen);
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
      errorf("Variable '%s' import fail, not set", name);
      return PARAM_EXPAND_ERROR;
    }
    else if(ge) {
      /* there is a value to use */
      content = ge;
      clen = strlen(ge);
    }
  }
  if(*line == '[' && ISDIGIT(line[1])) {
    /* is there a byte range specified? [num-num] */
    line++;
    if(curlx_str_number(&line, &startoffset, CURL_OFF_T_MAX) ||
       curlx_str_single(&line, '-'))
      return PARAM_VAR_SYNTAX;
    if(curlx_str_single(&line, ']')) {
      if(curlx_str_number(&line, &endoffset, CURL_OFF_T_MAX) ||
         curlx_str_single(&line, ']'))
        return PARAM_VAR_SYNTAX;
    }
    if(startoffset > endoffset)
      return PARAM_VAR_SYNTAX;
  }
  if(content)
    ;
  else if(*line == '@') {
    /* read from file or stdin */
    FILE *file;
    bool use_stdin;
    struct dynbuf fname;
    line++;

    curlx_dyn_init(&fname, MAX_FILENAME);

    use_stdin = !strcmp(line, "-");
    if(use_stdin)
      file = stdin;
    else {
      file = fopen(line, "rb");
      if(!file) {
        errorf("Failed to open %s: %s", line, strerror(errno));
        err = PARAM_READ_ERROR;
      }
    }
    if(!err) {
      err = file2memory_range(&content, &clen, file, startoffset, endoffset);
      /* in case of out of memory, this should fail the entire operation */
      if(clen)
        contalloc = TRUE;
    }
    curlx_dyn_free(&fname);
    if(!use_stdin && file)
      fclose(file);
    if(err)
      return err;
  }
  else if(*line == '=') {
    line++;
    clen = strlen(line);
    /* this is the exact content */
    content = (char *)CURL_UNCONST(line);
    if(startoffset || (endoffset != CURL_OFF_T_MAX)) {
      if(startoffset >= (curl_off_t)clen)
        clen = 0;
      else {
        /* make the end offset no larger than the last byte */
        if(endoffset >= (curl_off_t)clen)
          endoffset = clen - 1;
        clen = (size_t)(endoffset - startoffset) + 1;
        content += startoffset;
      }
    }
  }
  else {
    warnf("Bad --variable syntax, skipping: %s", input);
    return PARAM_OK;
  }
  err = addvariable(name, nlen, content, clen, contalloc);
  if(err) {
    if(contalloc)
      free(content);
  }
  return err;
}
