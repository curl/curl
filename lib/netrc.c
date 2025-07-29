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

#include <curl/curl.h>
#include "netrc.h"
#include "strcase.h"
#include "curl_get_line.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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

#define MAX_NETRC_LINE 16384
#define MAX_NETRC_FILE (128*1024)
#define MAX_NETRC_TOKEN 4096

/* convert a dynbuf call CURLcode error to a NETRCcode error */
#define curl2netrc(result)                     \
  (((result) == CURLE_OUT_OF_MEMORY) ?         \
   NETRC_OUT_OF_MEMORY : NETRC_SYNTAX_ERROR)

static NETRCcode file2memory(const char *filename, struct dynbuf *filebuf)
{
  NETRCcode ret = NETRC_FILE_MISSING; /* if it cannot open the file */
  FILE *file = fopen(filename, FOPEN_READTEXT);
  struct dynbuf linebuf;
  curlx_dyn_init(&linebuf, MAX_NETRC_LINE);

  if(file) {
    ret = NETRC_OK;
    while(Curl_get_line(&linebuf, file)) {
      CURLcode result;
      const char *line = curlx_dyn_ptr(&linebuf);
      /* skip comments on load */
      curlx_str_passblanks(&line);
      if(*line == '#')
        continue;
      result = curlx_dyn_add(filebuf, line);
      if(result) {
        ret = curl2netrc(result);
        goto done;
      }
    }
  }
done:
  curlx_dyn_free(&linebuf);
  if(file)
    fclose(file);
  return ret;
}

/*
 * Returns zero on success.
 */
static NETRCcode parsenetrc(struct store_netrc *store,
                            const char *host,
                            char **loginp, /* might point to a username */
                            char **passwordp,
                            const char *netrcfile)
{
  NETRCcode retcode = NETRC_NO_MATCH;
  char *login = *loginp;
  char *password = NULL;
  bool specific_login = !!login; /* points to something */
  enum host_lookup_state state = NOTHING;
  enum found_state keyword = NONE;
  unsigned char found = 0; /* login + password found bits, as they can come in
                              any order */
  bool our_login = FALSE;  /* found our login name */
  bool done = FALSE;
  char *netrcbuffer;
  struct dynbuf token;
  struct dynbuf *filebuf = &store->filebuf;
  DEBUGASSERT(!*passwordp);
  curlx_dyn_init(&token, MAX_NETRC_TOKEN);

  if(!store->loaded) {
    NETRCcode ret = file2memory(netrcfile, filebuf);
    if(ret)
      return ret;
    store->loaded = TRUE;
  }

  netrcbuffer = curlx_dyn_ptr(filebuf);

  while(!done) {
    const char *tok = netrcbuffer;
    while(tok && !done) {
      const char *tok_end;
      bool quoted;
      curlx_dyn_reset(&token);
      curlx_str_passblanks(&tok);
      /* tok is first non-space letter */
      if(state == MACDEF) {
        if((*tok == '\n') || (*tok == '\r'))
          state = NOTHING; /* end of macro definition */
      }

      if(!*tok || (*tok == '\n'))
        /* end of line  */
        break;

      /* leading double-quote means quoted string */
      quoted = (*tok == '\"');

      tok_end = tok;
      if(!quoted) {
        size_t len = 0;
        CURLcode result;
        while(*tok_end > ' ') {
          tok_end++;
          len++;
        }
        if(!len) {
          retcode = NETRC_SYNTAX_ERROR;
          goto out;
        }
        result = curlx_dyn_addn(&token, tok, len);
        if(result) {
          retcode = curl2netrc(result);
          goto out;
        }
      }
      else {
        bool escape = FALSE;
        bool endquote = FALSE;
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
            endquote = TRUE;
            break;
          }
          result = curlx_dyn_addn(&token, &s, 1);
          if(result) {
            retcode = curl2netrc(result);
            goto out;
          }
          tok_end++;
        }
        if(escape || !endquote) {
          /* bad syntax, get out */
          retcode = NETRC_SYNTAX_ERROR;
          goto out;
        }
      }

      if(curlx_dyn_len(&token))
        tok = curlx_dyn_ptr(&token);
      else
        /* since tok might actually be NULL for no content, set it to blank
           to avoid having to deal with it being NULL */
        tok = "";

      switch(state) {
      case NOTHING:
        if(curl_strequal("macdef", tok))
          /* Define a macro. A macro is defined with the specified name; its
             contents begin with the next .netrc line and continue until a
             null line (consecutive new-line characters) is encountered. */
          state = MACDEF;
        else if(curl_strequal("machine", tok)) {
          /* the next tok is the machine name, this is in itself the delimiter
             that starts the stuff entered for this machine, after this we
             need to search for 'login' and 'password'. */
          state = HOSTFOUND;
          keyword = NONE;
          found = 0;
          our_login = FALSE;
          Curl_safefree(password);
          if(!specific_login)
            Curl_safefree(login);
        }
        else if(curl_strequal("default", tok)) {
          state = HOSTVALID;
          retcode = NETRC_OK; /* we did find our host */
        }
        break;
      case MACDEF:
        if(!*tok)
          state = NOTHING;
        break;
      case HOSTFOUND:
        if(curl_strequal(host, tok)) {
          /* and yes, this is our host! */
          state = HOSTVALID;
          retcode = NETRC_OK; /* we did find our host */
        }
        else
          /* not our host */
          state = NOTHING;
        break;
      case HOSTVALID:
        /* we are now parsing sub-keywords concerning "our" host */
        if(keyword == LOGIN) {
          if(specific_login)
            our_login = !Curl_timestrcmp(login, tok);
          else {
            our_login = TRUE;
            free(login);
            login = strdup(tok);
            if(!login) {
              retcode = NETRC_OUT_OF_MEMORY; /* allocation failed */
              goto out;
            }
          }
          found |= FOUND_LOGIN;
          keyword = NONE;
        }
        else if(keyword == PASSWORD) {
          free(password);
          password = strdup(tok);
          if(!password) {
            retcode = NETRC_OUT_OF_MEMORY; /* allocation failed */
            goto out;
          }
          if(!specific_login || our_login)
            found |= FOUND_PASSWORD;
          keyword = NONE;
        }
        else if(curl_strequal("login", tok))
          keyword = LOGIN;
        else if(curl_strequal("password", tok))
          keyword = PASSWORD;
        else if(curl_strequal("machine", tok)) {
          /* a new machine here */
          if(found & FOUND_PASSWORD) {
            done = TRUE;
            break;
          }
          state = HOSTFOUND;
          keyword = NONE;
          found = 0;
          Curl_safefree(password);
          if(!specific_login)
            Curl_safefree(login);
        }
        else if(curl_strequal("default", tok)) {
          state = HOSTVALID;
          retcode = NETRC_OK; /* we did find our host */
          Curl_safefree(password);
          if(!specific_login)
            Curl_safefree(login);
        }
        if((found == (FOUND_PASSWORD|FOUND_LOGIN)) && our_login) {
          done = TRUE;
          break;
        }
        break;
      } /* switch (state) */
      tok = ++tok_end;
    }
    if(!done) {
      char *nl = NULL;
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
  if(!retcode) {
    if(!password && our_login) {
      /* success without a password, set a blank one */
      password = strdup("");
      if(!password)
        retcode = NETRC_OUT_OF_MEMORY; /* out of memory */
    }
    else if(!login && !password)
      /* a default with no credentials */
      retcode = NETRC_NO_MATCH;
  }
  if(!retcode) {
    /* success */
    if(!specific_login)
      *loginp = login;
    *passwordp = password;
  }
  else {
    curlx_dyn_free(filebuf);
    if(!specific_login)
      free(login);
    free(password);
  }

  return retcode;
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
        if(!getpwuid_r(geteuid(), &pw, pwbuf, sizeof(pwbuf), &pw_res)
           && pw_res) {
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

      filealloc = aprintf("%s%s.netrc", home, DIR_CHAR);
      if(!filealloc) {
        free(homea);
        return NETRC_OUT_OF_MEMORY;
      }
    }
    retcode = parsenetrc(store, host, loginp, passwordp, filealloc);
    free(filealloc);
#ifdef _WIN32
    if(retcode == NETRC_FILE_MISSING) {
      /* fallback to the old-style "_netrc" file */
      filealloc = aprintf("%s%s_netrc", home, DIR_CHAR);
      if(!filealloc) {
        free(homea);
        return NETRC_OUT_OF_MEMORY;
      }
      retcode = parsenetrc(store, host, loginp, passwordp, filealloc);
      free(filealloc);
    }
#endif
    free(homea);
  }
  else
    retcode = parsenetrc(store, host, loginp, passwordp, netrcfile);
  return retcode;
}

void Curl_netrc_init(struct store_netrc *s)
{
  curlx_dyn_init(&s->filebuf, MAX_NETRC_FILE);
  s->loaded = FALSE;
}
void Curl_netrc_cleanup(struct store_netrc *s)
{
  curlx_dyn_free(&s->filebuf);
  s->loaded = FALSE;
}
#endif
