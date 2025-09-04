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

#ifdef HAVE_PWD_H
#undef __NO_NET_API /* required for AmigaOS to declare getpwuid() */
#include <pwd.h>
#define __NO_NET_API
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "tool_findfile.h"
#include "tool_cfgable.h"

#include "memdebug.h" /* keep this as LAST include */

struct finder {
  const char *env;
  const char *append;
  bool withoutdot;
};

/* The order of the variables below is important, as the index number is used
   in the findfile() function */
static const struct finder conf_list[] = {
  { "CURL_HOME", NULL, FALSE },
  { "XDG_CONFIG_HOME", NULL, TRUE },
  { "HOME", NULL, FALSE },
#ifdef _WIN32
  { "USERPROFILE", NULL, FALSE },
  { "APPDATA", NULL, FALSE },
  { "USERPROFILE", "\\Application Data", FALSE},
#endif
  /* these are for .curlrc if XDG_CONFIG_HOME is not defined */
  { "CURL_HOME", "/.config", TRUE },
  { "HOME", "/.config", TRUE },

  { NULL, NULL, FALSE }
};

static char *checkhome(const char *home, const char *fname, bool dotscore)
{
  const char pref[2] = { '.', '_' };
  int i;
  for(i = 0; i < (dotscore ? 2 : 1); i++) {
    char *c;
    if(dotscore)
      c = aprintf("%s" DIR_CHAR "%c%s", home, pref[i], &fname[1]);
    else
      c = aprintf("%s" DIR_CHAR "%s", home, fname);
    if(c) {
      int fd = open(c, O_RDONLY);
      if(fd >= 0) {
        char *path = strdup(c);
        close(fd);
        curl_free(c);
        return path;
      }
      curl_free(c);
    }
  }
  return NULL;
}

/*
 * findfile() - return the full path name of the file.
 *
 * If 'dotscore' is TRUE, then check for the file first with a leading dot
 * and then with a leading underscore.
 *
 * 1. Iterate over the environment variables in order, and if set, check for
 *    the given file to be accessed there, then it is a match.
 * 2. Non-Windows: try getpwuid
 */
char *findfile(const char *fname, int dotscore)
{
  int i;
  DEBUGASSERT(fname && fname[0]);
  DEBUGASSERT((dotscore != 1) || (fname[0] == '.'));

  if(!fname[0])
    return NULL;

  for(i = 0; conf_list[i].env; i++) {
    char *home = curl_getenv(conf_list[i].env);
    if(home) {
      char *path;
      const char *filename = fname;
      if(!home[0]) {
        curl_free(home);
        continue;
      }
      if(conf_list[i].append) {
        char *c = aprintf("%s%s", home, conf_list[i].append);
        curl_free(home);
        if(!c)
          return NULL;
        home = c;
      }
      if(conf_list[i].withoutdot) {
        if(!dotscore) {
          /* this is not looking for .curlrc, or the XDG_CONFIG_HOME was
             defined so we skip the extended check */
          curl_free(home);
          continue;
        }
        filename++; /* move past the leading dot */
        dotscore = 0; /* disable it for this check */
      }
      path = checkhome(home, filename, dotscore ? dotscore - 1 : 0);
      curl_free(home);
      if(path)
        return path;
    }
  }
#if defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
  {
    struct passwd *pw = getpwuid(geteuid());
    if(pw) {
      char *home = pw->pw_dir;
      if(home && home[0])
        return checkhome(home, fname, FALSE);
    }
  }
#endif /* PWD-stuff */
  return NULL;
}
