/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif


#include <curl/curl.h>

#include "strequal.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* Debug this single source file with:
   'make netrc' then run './netrc'!

   Oh, make sure you have a .netrc file too ;-)
 */

/* Get user and password from .netrc when given a machine name */

enum {
  NOTHING,
  HOSTFOUND,    /* the 'machine' keyword was found */
  HOSTCOMPLETE, /* the machine name following the keyword was found too */
  HOSTVALID,    /* this is "our" machine! */

  HOSTEND /* LAST enum */
};

/* make sure we have room for at least this size: */
#define LOGINSIZE 64
#define PASSWORDSIZE 64

int Curl_parsenetrc(char *host,
                    char *login,
                    char *password)
{
  FILE *file;
  char netrcbuffer[256];
  int retcode=1;
  
  char *home = NULL; 
  int state=NOTHING;

  char state_login=0;
  char state_password=0;

#define NETRC DOT_CHAR "netrc"

#if defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
  struct passwd *pw;
  pw= getpwuid(geteuid());
  if (pw)
    home = pw->pw_dir;
#else
  void *pw=NULL;
#endif
  
  if(NULL == pw) {
    home = curl_getenv("HOME"); /* portable environment reader */
    if(!home) {
      return -1;
    }
  }

  if(strlen(home)>(sizeof(netrcbuffer)-strlen(NETRC))) {
    if(NULL==pw)
      free(home);
    return -1;
  }

  sprintf(netrcbuffer, "%s%s%s", home, DIR_CHAR, NETRC);

  file = fopen(netrcbuffer, "r");
  if(file) {
    char *tok;
	char *tok_buf;
    while(fgets(netrcbuffer, sizeof(netrcbuffer), file)) {
      tok=strtok_r(netrcbuffer, " \t\n", &tok_buf);
      while(tok) {
	switch(state) {
	case NOTHING:
	  if(strequal("machine", tok)) {
	    /* the next tok is the machine name, this is in itself the
	       delimiter that starts the stuff entered for this machine,
	       after this we need to search for 'login' and
	       'password'. */
	    state=HOSTFOUND;
	  }
	  break;
	case HOSTFOUND:
	  if(strequal(host, tok)) {
	    /* and yes, this is our host! */
	    state=HOSTVALID;
#ifdef _NETRC_DEBUG
	    printf("HOST: %s\n", tok);
#endif
	    retcode=0; /* we did find our host */
	  }
	  else
	    /* not our host */
	    state=NOTHING;
	  break;
	case HOSTVALID:
	  /* we are now parsing sub-keywords concerning "our" host */
	  if(state_login) {
	    strncpy(login, tok, LOGINSIZE-1);
#ifdef _NETRC_DEBUG
	    printf("LOGIN: %s\n", login);
#endif
	    state_login=0;
	  }
	  else if(state_password) {
	    strncpy(password, tok, PASSWORDSIZE-1);
#if _NETRC_DEBUG
	    printf("PASSWORD: %s\n", password);
#endif
	    state_password=0;
	  }
	  else if(strequal("login", tok))
	    state_login=1;
	  else if(strequal("password", tok))
	    state_password=1;
	  else if(strequal("machine", tok)) {
	    /* ok, there's machine here go => */
	    state = HOSTFOUND;
	  }
	  break;
	} /* switch (state) */
	tok = strtok_r(NULL, " \t\n", &tok_buf);
      } /* while (tok) */
    } /* while fgets() */

    fclose(file);
  }

  if(NULL==pw)
    free(home);

  return retcode;
}

#ifdef _NETRC_DEBUG
int main(int argc, char **argv)
{
  char login[64]="";
  char password[64]="";

  if(argc<2)
    return -1;

  if(0 == ParseNetrc(argv[1], login, password)) {
    printf("HOST: %s LOGIN: %s PASSWORD: %s\n",
	   argv[1], login, password);
  }
}

#endif
