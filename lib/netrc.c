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
#include <pwd.h>
#endif

#include <curl/curl.h>
#include "netrc.h"
#include "strtok.h"
#include "strcase.h"
#include "curl_get_line.h"

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

#define NETRC_FILE_MISSING 1
#define NETRC_FAILED -1
#define NETRC_SUCCESS 0

#define MAX_NETRC_LINE 4096

/*
 * Returns zero on success.
 */
static int parsenetrc(const char *host,
                      char **loginp,
                      char **passwordp,
                      char *netrcfile)
{
  FILE *file;
  int retcode = NETRC_FILE_MISSING;
  char *login = *loginp;
  char *password = *passwordp;
  bool specific_login = (login && *login != 0);
  bool login_alloc = FALSE;
  bool password_alloc = FALSE;
  enum host_lookup_state state = NOTHING;

  char state_login = 0;      /* Found a login keyword */
  char state_password = 0;   /* Found a password keyword */
  int state_our_login = TRUE;  /* With specific_login, found *our* login
                                  name (or login-less line) */

  DEBUGASSERT(netrcfile);

  file = fopen(netrcfile, FOPEN_READTEXT);
  if(file) {
    bool done = FALSE;
    struct dynbuf buf;
    Curl_dyn_init(&buf, MAX_NETRC_LINE);

    while(!done && Curl_get_line(&buf, file)) {
      char *tok;
      char *tok_end;
      bool quoted;
      char *netrcbuffer = Curl_dyn_ptr(&buf);
      if(state == MACDEF) {
        if((netrcbuffer[0] == '\n') || (netrcbuffer[0] == '\r'))
          state = NOTHING;
        else
          continue;
      }
      tok = netrcbuffer;
      while(tok) {
        while(ISBLANK(*tok))
          tok++;
        /* tok is first non-space letter */
        if(!*tok || (*tok == '#'))
          /* end of line or the rest is a comment */
          break;

        /* leading double-quote means quoted string */
        quoted = (*tok == '\"');

        tok_end = tok;
        if(!quoted) {
          while(!ISSPACE(*tok_end))
            tok_end++;
          *tok_end = 0;
        }
        else {
          bool escape = FALSE;
          bool endquote = FALSE;
          char *store = tok;
          tok_end++; /* pass the leading quote */
          while(*tok_end) {
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
            *store++ = s;
            tok_end++;
          }
          *store = 0;
          if(escape || !endquote) {
            /* bad syntax, get out */
            retcode = NETRC_FAILED;
            goto out;
          }
        }

        if((login && *login) && (password && *password)) {
          done = TRUE;
          break;
        }

        switch(state) {
        case NOTHING:
          if(strcasecompare("macdef", tok)) {
            /* Define a macro. A macro is defined with the specified name; its
               contents begin with the next .netrc line and continue until a
               null line (consecutive new-line characters) is encountered. */
            state = MACDEF;
          }
          else if(strcasecompare("machine", tok)) {
            /* the next tok is the machine name, this is in itself the
               delimiter that starts the stuff entered for this machine,
               after this we need to search for 'login' and
               'password'. */
            state = HOSTFOUND;
          }
          else if(strcasecompare("default", tok)) {
            state = HOSTVALID;
            retcode = NETRC_SUCCESS; /* we did find our host */
          }
          break;
        case MACDEF:
          if(!strlen(tok)) {
            state = NOTHING;
          }
          break;
        case HOSTFOUND:
          if(strcasecompare(host, tok)) {
            /* and yes, this is our host! */
            state = HOSTVALID;
            retcode = NETRC_SUCCESS; /* we did find our host */
          }
          else
            /* not our host */
            state = NOTHING;
          break;
        case HOSTVALID:
          /* we are now parsing sub-keywords concerning "our" host */
          if(state_login) {
            if(specific_login) {
              state_our_login = !Curl_timestrcmp(login, tok);
            }
            else if(!login || Curl_timestrcmp(login, tok)) {
              if(login_alloc) {
                free(login);
                login_alloc = FALSE;
              }
              login = strdup(tok);
              if(!login) {
                retcode = NETRC_FAILED; /* allocation failed */
                goto out;
              }
              login_alloc = TRUE;
            }
            state_login = 0;
          }
          else if(state_password) {
            if((state_our_login || !specific_login)
               && (!password || Curl_timestrcmp(password, tok))) {
              if(password_alloc) {
                free(password);
                password_alloc = FALSE;
              }
              password = strdup(tok);
              if(!password) {
                retcode = NETRC_FAILED; /* allocation failed */
                goto out;
              }
              password_alloc = TRUE;
            }
            state_password = 0;
          }
          else if(strcasecompare("login", tok))
            state_login = 1;
          else if(strcasecompare("password", tok))
            state_password = 1;
          else if(strcasecompare("machine", tok)) {
            /* ok, there is machine here go => */
            state = HOSTFOUND;
            state_our_login = FALSE;
          }
          break;
        } /* switch (state) */
        tok = ++tok_end;
      }
    } /* while Curl_get_line() */

out:
    Curl_dyn_free(&buf);
    if(!retcode) {
      /* success */
      if(login_alloc) {
        if(*loginp)
          free(*loginp);
        *loginp = login;
      }
      if(password_alloc) {
        if(*passwordp)
          free(*passwordp);
        *passwordp = password;
      }
    }
    else {
      if(login_alloc)
        free(login);
      if(password_alloc)
        free(password);
    }
    fclose(file);
  }

  return retcode;
}

/*
 * @unittest: 1304
 *
 * *loginp and *passwordp MUST be allocated if they are not NULL when passed
 * in.
 */
int Curl_parsenetrc(const char *host, char **loginp, char **passwordp,
                    char *netrcfile)
{
  int retcode = 1;
  char *filealloc = NULL;

  if(!netrcfile) {
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
    char pwbuf[1024];
#endif
    char *home = NULL;
    char *homea = curl_getenv("HOME"); /* portable environment reader */
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
      return retcode; /* no home directory found (or possibly out of
                         memory) */

    filealloc = curl_maprintf("%s%s.netrc", home, DIR_CHAR);
    if(!filealloc) {
      free(homea);
      return -1;
    }
    retcode = parsenetrc(host, loginp, passwordp, filealloc);
    free(filealloc);
#ifdef _WIN32
    if(retcode == NETRC_FILE_MISSING) {
      /* fallback to the old-style "_netrc" file */
      filealloc = curl_maprintf("%s%s_netrc", home, DIR_CHAR);
      if(!filealloc) {
        free(homea);
        return -1;
      }
      retcode = parsenetrc(host, loginp, passwordp, filealloc);
      free(filealloc);
    }
#endif
    free(homea);
  }
  else
    retcode = parsenetrc(host, loginp, passwordp, netrcfile);
  return retcode;
}

#endif
