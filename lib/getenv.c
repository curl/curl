/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#endif

#ifdef VMS
#include <unixlib.h>
#endif

#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

static
char *GetEnv(const char *variable)
{
#ifdef WIN32
  /* This shit requires windows.h (HUGE) to be included */
  char env[MAX_PATH]; /* MAX_PATH is from windef.h */
  char *temp = getenv(variable);
  env[0] = '\0';
  if (temp != NULL)
    ExpandEnvironmentStrings(temp, env, sizeof(env));
#else
#ifdef	VMS
  char *env = getenv(variable);
  if (env && strcmp("HOME",variable) == 0) {
	env = decc$translate_vms(env);
  }
#else
  /* no length control */
  char *env = getenv(variable);
#endif
#endif
  return (env && env[0])?strdup(env):NULL;
}

char *curl_getenv(const char *v)
{
  return GetEnv(v);
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
