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
char *GetEnv(char *variable)
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
/*  printf ("Getenv: %s=%s\n",variable,env); */
#else
  /* no length control */
  char *env = getenv(variable);
#endif
#endif
  return (env && env[0])?strdup(env):NULL;
}

char *curl_getenv(char *v)
{
  return GetEnv(v);
}
