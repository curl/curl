/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 *  Contributor(s):
 *   Rafael Sagula <sagula@inf.ufrgs.br>
 *   Sampo Kellomaki <sampo@iki.fi>
 *   Linas Vepstas <linas@linas.org>
 *   Bjorn Reese <breese@imada.ou.dk>
 *   Johan Anderson <johan@homemail.com>
 *   Kjell Ericson <Kjell.Ericson@haxx.nu>
 *   Troy Engel <tengel@palladium.net>
 *   Ryan Nelson <ryan@inch.com>
 *   Bjorn Stenberg <Bjorn.Stenberg@haxx.nu>
 *   Angus Mackay <amackay@gus.ml.org>
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "setup.h"
#include "getenv.h"

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

int ParseNetrc(char *host,
	       char *login,
	       char *password)
{
  FILE *file;
  char netrcbuffer[256];
  int retcode=1;
  
  char *home = GetEnv("HOME"); /* portable environment reader */
  int state=NOTHING;

  char state_login=0;
  char state_password=0;

#define NETRC DOT_CHAR "netrc"

  if(!home || (strlen(home)>(sizeof(netrcbuffer)-strlen(NETRC))))
    return -1;

  sprintf(netrcbuffer, "%s%s%s", home, DIR_CHAR, NETRC);

  file = fopen(netrcbuffer, "r");
  if(file) {
    char *tok;
    while(fgets(netrcbuffer, sizeof(netrcbuffer), file)) {
      tok=strtok(netrcbuffer, " \t\n");
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
	tok = strtok(NULL, " \t\n");
      } /* while (tok) */
    } /* while fgets() */

    fclose(file);
  }

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
