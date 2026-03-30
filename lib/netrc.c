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
#include "curl_setup.h"

#ifndef CURL_DISABLE_NETRC

#ifdef HAVE_PWD_H
#ifdef __AMIGA__
#undef __NO_NET_API /* required for AmigaOS to declare getpwuid() */
#endif
#include <pwd.h>
#ifdef __AMIGA__
#define __NO_NET_API
#endif
#endif

#include "netrc.h"
#include "strcase.h"
#include "curl_get_line.h"
#include "curlx/fopen.h"
#include "curlx/strparse.h"

/* Get user and password from .netrc when given a machine name */

enum host_lookup_state {
  NOTHING,
  HOSTFOUND,    /* the 'machine' keyword was found */
  HOSTVALID,    /* this is "our" machine! */
  MACDEF
};

enum found_state {
  NONE,
  LOGIN,
  PASSWORD
};

#define FOUND_LOGIN    1
#define FOUND_PASSWORD 2

#define MAX_NETRC_LINE  16384
#define MAX_NETRC_FILE  (128 * 1024)
#define MAX_NETRC_TOKEN 4096

/* convert a dynbuf call CURLcode error to a NETRCcode error */
#define curl2netrc(result)                     \
  (((result) == CURLE_OUT_OF_MEMORY) ?         \
   NETRC_OUT_OF_MEMORY : NETRC_SYNTAX_ERROR)

static NETRCcode file2memory(const char *filename, struct dynbuf *filebuf)
{
  NETRCcode ret = NETRC_FILE_MISSING; /* if it cannot open the file */
  FILE *file = curlx_fopen(filename, FOPEN_READTEXT);

  if(file) {
    curlx_struct_stat stat;
    if((curlx_fstat(fileno(file), &stat) == -1) || !S_ISDIR(stat.st_mode)) {
      CURLcode result = CURLE_OK;
      bool eof;
      struct dynbuf linebuf;
      curlx_dyn_init(&linebuf, MAX_NETRC_LINE);
      ret = NETRC_OK;
      do {
        const char *line;
        /* Curl_get_line always returns lines ending with a newline */
        result = Curl_get_line(&linebuf, file, &eof);
        if(!result) {
          line = curlx_dyn_ptr(&linebuf);
          /* skip comments on load */
          curlx_str_passblanks(&line);
          if(*line == '#')
            continue;
          result = curlx_dyn_add(filebuf, line);
        }
        if(result) {
          curlx_dyn_free(filebuf);
          ret = curl2netrc(result);
          break;
        }
      } while(!eof);
      curlx_dyn_free(&linebuf);
    }
    curlx_fclose(file);
  }
  return ret;
}

/* bundled parser state to keep function signatures compact */
struct netrc_state {
  char *login;
  char *password;
  enum host_lookup_state state;
  enum found_state keyword;
  NETRCcode retcode;
  unsigned char found; /* FOUND_LOGIN | FOUND_PASSWORD bits */
  bool our_login;
  bool done;
  bool specific_login;
};

/*
 * Parse a quoted token starting after the opening '"'. Handles \n, \r, \t
 * escape sequences. Advances *tok_endp past the closing '"'.
 *
 * Returns NETRC_OK or error.
 */
static NETRCcode netrc_quoted_token(const char **tok_endp,
                                    struct dynbuf *token)
{
  bool escape = FALSE;
  NETRCcode rc = NETRC_SYNTAX_ERROR;
  const char *tok_end = *tok_endp;
  tok_end++; /* pass the leading quote */
  while(*tok_end) {
    CURLcode result;
    char s = *tok_end;
    if(escape) {
      escape = FALSE;
      switch(s) {
      case 'n':
        s = '\n';
        break;
      case 'r':
        s = '\r';
        break;
      case 't':
        s = '\t';
        break;
      }
    }
    else if(s == '\\') {
      escape = TRUE;
      tok_end++;
      continue;
    }
    else if(s == '\"') {
      tok_end++; /* pass the ending quote */
      rc = NETRC_OK;
      break;
    }
    result = curlx_dyn_addn(token, &s, 1);
    if(result) {
      *tok_endp = tok_end;
      return curl2netrc(result);
    }
    tok_end++;
  }
  *tok_endp = tok_end;
  return rc;
}

/*
 * Gets the next token from the netrc buffer at *tokp. Writes the token into
 * the 'token' dynbuf. Advances *tok_endp past the consumed token in the input
 * buffer. Updates *statep for MACDEF newline handling. Sets *lineend = TRUE
 * when the line is exhausted.
 *
 * Returns NETRC_OK or an error code.
 */
static NETRCcode netrc_get_token(const char **tokp,
                                 const char **tok_endp,
                                 struct dynbuf *token,
                                 enum host_lookup_state *statep,
                                 bool *lineend)
{
  const char *tok = *tokp;
  const char *tok_end;

  *lineend = FALSE;
  curlx_dyn_reset(token);
  curlx_str_passblanks(&tok);

  /* tok is first non-space letter */
  if(*statep == MACDEF) {
    if((*tok == '\n') || (*tok == '\r'))
      *statep = NOTHING; /* end of macro definition */
    *lineend = TRUE;
    *tokp = tok;
    return NETRC_OK;
  }

  if(!*tok || (*tok == '\n')) {
    /* end of line */
    *lineend = TRUE;
    *tokp = tok;
    return NETRC_OK;
  }

  tok_end = tok;
  if(*tok == '\"') {
    /* quoted string */
    NETRCcode ret = netrc_quoted_token(&tok_end, token);
    if(ret)
      return ret;
  }
  else {
    /* unquoted token */
    size_t len = 0;
    CURLcode result;
    while(*tok_end > ' ') {
      tok_end++;
      len++;
    }
    if(!len)
      return NETRC_SYNTAX_ERROR;
    result = curlx_dyn_addn(token, tok, len);
    if(result)
      return curl2netrc(result);
  }

  *tok_endp = tok_end;

  if(curlx_dyn_len(token))
    *tokp = curlx_dyn_ptr(token);
  else
    /* set it to blank to avoid NULL */
    *tokp = "";

  return NETRC_OK;
}

/*
 * Reset parser for a new machine entry. Frees password and optionally login
 * if it was not user-specified.
 */
static void netrc_new_machine(struct netrc_state *ns)
{
  ns->keyword = NONE;
  ns->found = 0;
  ns->our_login = FALSE;
  curlx_safefree(ns->password);
  if(!ns->specific_login)
    curlx_safefree(ns->login);
}

/*
 * Process a parsed token through the HOSTVALID state machine branch. This
 * handles login/password values and keyword transitions for the matched host.
 *
 * Returns NETRC_OK or an error code.
 */
static NETRCcode netrc_hostvalid(struct netrc_state *ns, const char *tok)
{
  if(ns->keyword == LOGIN) {
    if(ns->specific_login)
      ns->our_login = !Curl_timestrcmp(ns->login, tok);
    else {
      ns->our_login = TRUE;
      curlx_free(ns->login);
      ns->login = curlx_strdup(tok);
      if(!ns->login)
        return NETRC_OUT_OF_MEMORY;
    }
    ns->found |= FOUND_LOGIN;
    ns->keyword = NONE;
  }
  else if(ns->keyword == PASSWORD) {
    curlx_free(ns->password);
    ns->password = curlx_strdup(tok);
    if(!ns->password)
      return NETRC_OUT_OF_MEMORY;
    ns->found |= FOUND_PASSWORD;
    ns->keyword = NONE;
  }
  else if(curl_strequal("login", tok))
    ns->keyword = LOGIN;
  else if(curl_strequal("password", tok))
    ns->keyword = PASSWORD;
  else if(curl_strequal("machine", tok)) {
    /* a new machine here */

    if(ns->found & FOUND_PASSWORD &&
      /* a password was provided for this host */

       ((!ns->specific_login || ns->our_login) ||
        /* either there was no specific login to search for, or this
           is the specific one we wanted */
        (ns->specific_login && !(ns->found & FOUND_LOGIN)))) {
      /* or we look for a specific login, but that was not specified */

      ns->done = TRUE;
      return NETRC_OK;
    }

    ns->state = HOSTFOUND;
    netrc_new_machine(ns);
  }
  else if(curl_strequal("default", tok)) {
    ns->state = HOSTVALID;
    ns->retcode = NETRC_OK;
    netrc_new_machine(ns);
  }
  if((ns->found == (FOUND_PASSWORD | FOUND_LOGIN)) && ns->our_login)
    ns->done = TRUE;
  return NETRC_OK;
}

/*
 * Process one parsed token through the netrc state
 * machine. Updates the parser state in *ns.
 * Returns NETRC_OK or an error code.
 */
static NETRCcode netrc_handle_token(struct netrc_state *ns,
                                    const char *tok,
                                    const char *host)
{
  switch(ns->state) {
  case NOTHING:
    if(curl_strequal("macdef", tok))
      ns->state = MACDEF;
    else if(curl_strequal("machine", tok)) {
      ns->state = HOSTFOUND;
      netrc_new_machine(ns);
    }
    else if(curl_strequal("default", tok)) {
      ns->state = HOSTVALID;
      ns->retcode = NETRC_OK;
    }
    break;
  case MACDEF:
    if(!*tok)
      ns->state = NOTHING;
    break;
  case HOSTFOUND:
    if(curl_strequal(host, tok)) {
      ns->state = HOSTVALID;
      ns->retcode = NETRC_OK;
    }
    else
      ns->state = NOTHING;
    break;
  case HOSTVALID:
    return netrc_hostvalid(ns, tok);
  }
  return NETRC_OK;
}

/*
 * Finalize the parse result: fill in defaults and free
 * resources on error.
 */
static NETRCcode netrc_finalize(struct netrc_state *ns,
                                char **loginp,
                                char **passwordp,
                                struct store_netrc *store)
{
  NETRCcode retcode = ns->retcode;
  if(!retcode) {
    if(!ns->password && ns->our_login) {
      /* success without a password, set a blank one */
      ns->password = curlx_strdup("");
      if(!ns->password)
        retcode = NETRC_OUT_OF_MEMORY;
    }
    else if(!ns->login && !ns->password)
      /* a default with no credentials */
      retcode = NETRC_NO_MATCH;
  }
  if(!retcode) {
    /* success */
    if(!ns->specific_login)
      *loginp = ns->login;

    /* netrc_finalize() can return a password even when specific_login is set
       but our_login is false (e.g., host matched but the requested login
       never matched). See test 685. */
    *passwordp = ns->password;
  }
  else {
    curlx_dyn_free(&store->filebuf);
    store->loaded = FALSE;
    if(!ns->specific_login)
      curlx_free(ns->login);
    curlx_free(ns->password);
  }
  return retcode;
}

/*
 * Returns zero on success.
 */
static NETRCcode parsenetrc(struct store_netrc *store,
                            const char *host,
                            char **loginp,
                            char **passwordp,
                            const char *netrcfile)
{
  const char *netrcbuffer;
  struct dynbuf token;
  struct dynbuf *filebuf = &store->filebuf;
  struct netrc_state ns;

  memset(&ns, 0, sizeof(ns));
  ns.retcode = NETRC_NO_MATCH;
  ns.login = *loginp;
  ns.specific_login = !!ns.login;

  DEBUGASSERT(!*passwordp);
  curlx_dyn_init(&token, MAX_NETRC_TOKEN);

  if(!store->loaded) {
    NETRCcode ret = file2memory(netrcfile, filebuf);
    if(ret)
      return ret;
    store->loaded = TRUE;
  }

  netrcbuffer = curlx_dyn_ptr(filebuf);

  while(!ns.done) {
    const char *tok = netrcbuffer;
    while(tok && !ns.done) {
      const char *tok_end;
      bool lineend;
      NETRCcode ret;

      ret = netrc_get_token(&tok, &tok_end, &token, &ns.state, &lineend);
      if(ret) {
        ns.retcode = ret;
        goto out;
      }
      if(lineend)
        break;

      ret = netrc_handle_token(&ns, tok, host);
      if(ret) {
        ns.retcode = ret;
        goto out;
      }
      /* tok_end cannot point to a null byte here since lines are always
         newline terminated */
      DEBUGASSERT(*tok_end);
      tok = ++tok_end;
    }
    if(!ns.done) {
      const char *nl = NULL;
      if(tok)
        nl = strchr(tok, '\n');
      if(!nl)
        break;
      /* point to next line */
      netrcbuffer = &nl[1];
    }
  } /* while !done */

out:
  curlx_dyn_free(&token);
  return netrc_finalize(&ns, loginp, passwordp, store);
}

const char *Curl_netrc_strerror(NETRCcode ret)
{
  switch(ret) {
  default:
    return ""; /* not a legit error */
  case NETRC_FILE_MISSING:
    return "no such file";
  case NETRC_NO_MATCH:
    return "no matching entry";
  case NETRC_OUT_OF_MEMORY:
    return "out of memory";
  case NETRC_SYNTAX_ERROR:
    return "syntax error";
  }
  /* never reached */
}

/*
 * @unittest: 1304
 *
 * *loginp and *passwordp MUST be allocated if they are not NULL when passed
 * in.
 */
NETRCcode Curl_parsenetrc(struct store_netrc *store, const char *host,
                          char **loginp, char **passwordp,
                          const char *netrcfile)
{
  NETRCcode retcode = NETRC_OK;
  char *filealloc = NULL;

  if(!netrcfile) {
    char *home = NULL;
    char *homea = NULL;
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
    char pwbuf[1024];
#endif
    filealloc = curl_getenv("NETRC");
    if(!filealloc) {
      homea = curl_getenv("HOME"); /* portable environment reader */
      if(homea) {
        home = homea;
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
      }
      else {
        struct passwd pw, *pw_res;
        if(!getpwuid_r(geteuid(), &pw, pwbuf, sizeof(pwbuf), &pw_res) &&
           pw_res) {
          home = pw.pw_dir;
        }
#elif defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
      }
      else {
        struct passwd *pw;
        pw = getpwuid(geteuid());
        if(pw) {
          home = pw->pw_dir;
        }
#elif defined(_WIN32)
      }
      else {
        homea = curl_getenv("USERPROFILE");
        if(homea) {
          home = homea;
        }
#endif
      }

      if(!home)
        return NETRC_FILE_MISSING; /* no home directory found (or possibly out
                                      of memory) */

      filealloc = curl_maprintf("%s%s.netrc", home, DIR_CHAR);
      if(!filealloc) {
        curlx_free(homea);
        return NETRC_OUT_OF_MEMORY;
      }
    }
    retcode = parsenetrc(store, host, loginp, passwordp, filealloc);
    curlx_free(filealloc);
#ifdef _WIN32
    if(retcode == NETRC_FILE_MISSING) {
      /* fallback to the old-style "_netrc" file */
      filealloc = curl_maprintf("%s%s_netrc", home, DIR_CHAR);
      if(!filealloc) {
        curlx_free(homea);
        return NETRC_OUT_OF_MEMORY;
      }
      retcode = parsenetrc(store, host, loginp, passwordp, filealloc);
      curlx_free(filealloc);
    }
#endif
    curlx_free(homea);
  }
  else
    retcode = parsenetrc(store, host, loginp, passwordp, netrcfile);
  return retcode;
}

void Curl_netrc_init(struct store_netrc *store)
{
  curlx_dyn_init(&store->filebuf, MAX_NETRC_FILE);
  store->loaded = FALSE;
}
void Curl_netrc_cleanup(struct store_netrc *store)
{
  curlx_dyn_free(&store->filebuf);
  store->loaded = FALSE;
}
#endif
