/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "tool_setup.h"

#ifdef HAVE_PWD_H
#  include <pwd.h>
#endif

#include <curl/mprintf.h>

#include "tool_homedir.h"

#include "memdebug.h" /* keep this as LAST include */

static char *GetEnv(const char *variable)
{
  char *dupe, *env;

  env = curl_getenv(variable);
  if(!env)
    return NULL;

  dupe = strdup(env);
  curl_free(env);
  return dupe;
}

/* return the home directory of the current user as an allocated string */
char *homedir(void)
{
  char *home;

  home = GetEnv("CURL_HOME");
  if(home)
    return home;

  home = GetEnv("HOME");
  if(home)
    return home;

#if defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
 {
   struct passwd *pw = getpwuid(geteuid());

   if(pw) {
     home = pw->pw_dir;
     if(home && home[0])
       home = strdup(home);
     else
       home = NULL;
   }
 }
#endif /* PWD-stuff */
#ifdef WIN32
  home = GetEnv("APPDATA");
  if(!home) {
    char *env = GetEnv("USERPROFILE");
    if(env) {
      char *path = curl_maprintf("%s\\Application Data", env);
      if(path) {
        home = strdup(path);
        curl_free(path);
      }
      free(env);
    }
  }
#endif /* WIN32 */
  return home;
}
