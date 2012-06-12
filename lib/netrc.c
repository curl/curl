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

#include "setup.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef __VMS
#include <unixlib.h>
#endif

#include <curl/curl.h>
#include "netrc.h"

#include "strequal.h"
#include "strtok.h"
#include "curl_memory.h"
#include "rawstr.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

/* Get user and password from .netrc when given a machine name */

enum host_lookup_state {
  NOTHING,
  HOSTFOUND,    /* the 'machine' keyword was found */
  HOSTVALID     /* this is "our" machine! */
};

/*
 * @unittest: 1304
 */
int Curl_parsenetrc(const char *host,
                    char *login,
                    char *password,
                    char *netrcfile)
{
  FILE *file;
  int retcode=1;
  int specific_login = (login[0] != 0);
  char *home = NULL;
  bool home_alloc = FALSE;
  bool netrc_alloc = FALSE;
  enum host_lookup_state state=NOTHING;

  char state_login=0;      /* Found a login keyword */
  char state_password=0;   /* Found a password keyword */
  int state_our_login=FALSE;  /* With specific_login, found *our* login name */

#define NETRC DOT_CHAR "netrc"

  if(!netrcfile) {
    home = curl_getenv("HOME"); /* portable environment reader */
    if(home) {
      home_alloc = TRUE;
#if defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
    }
    else {
      struct passwd *pw;
      pw= getpwuid(geteuid());
      if(pw) {
#ifdef __VMS
        home = decc_translate_vms(pw->pw_dir);
#else
        home = pw->pw_dir;
#endif
      }
#endif
    }

    if(!home)
      return -1;

    netrcfile = curl_maprintf("%s%s%s", home, DIR_CHAR, NETRC);
    if(!netrcfile) {
      if(home_alloc)
        free(home);
      return -1;
    }
    netrc_alloc = TRUE;
  }

  file = fopen(netrcfile, "r");
  if(file) {
    char *tok;
    char *tok_buf;
    bool done=FALSE;
    char netrcbuffer[256];
    int  netrcbuffsize = (int)sizeof(netrcbuffer);

    while(!done && fgets(netrcbuffer, netrcbuffsize, file)) {
      tok=strtok_r(netrcbuffer, " \t\n", &tok_buf);
      while(!done && tok) {

        if(login[0] && password[0]) {
          done=TRUE;
          break;
        }

        switch(state) {
        case NOTHING:
          if(Curl_raw_equal("machine", tok)) {
            /* the next tok is the machine name, this is in itself the
               delimiter that starts the stuff entered for this machine,
               after this we need to search for 'login' and
               'password'. */
            state=HOSTFOUND;
          }
          break;
        case HOSTFOUND:
          if(Curl_raw_equal(host, tok)) {
            /* and yes, this is our host! */
            state=HOSTVALID;
            retcode=0; /* we did find our host */
          }
          else
            /* not our host */
            state=NOTHING;
          break;
        case HOSTVALID:
          /* we are now parsing sub-keywords concerning "our" host */
          if(state_login) {
            if(specific_login) {
              state_our_login = Curl_raw_equal(login, tok);
            }
            else {
              strncpy(login, tok, LOGINSIZE-1);
            }
            state_login=0;
          }
          else if(state_password) {
            if(state_our_login || !specific_login) {
              strncpy(password, tok, PASSWORDSIZE-1);
            }
            state_password=0;
          }
          else if(Curl_raw_equal("login", tok))
            state_login=1;
          else if(Curl_raw_equal("password", tok))
            state_password=1;
          else if(Curl_raw_equal("machine", tok)) {
            /* ok, there's machine here go => */
            state = HOSTFOUND;
            state_our_login = FALSE;
          }
          break;
        } /* switch (state) */

        tok = strtok_r(NULL, " \t\n", &tok_buf);
      } /* while(tok) */
    } /* while fgets() */

    fclose(file);
  }

  if(home_alloc)
    free(home);
  if(netrc_alloc)
    free(netrcfile);

  return retcode;
}
