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
#  undef __NO_NET_API /* required for building for AmigaOS */
#  include <pwd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <string.h>

#include <curl/mprintf.h>

#include "tool_findfile.h"

#include "memdebug.h" /* keep this as LAST include */

struct finder {
  const char *env;
  const char *append;
  bool xdg;
};

/* The order of the variables below is important, as the index number is used
   in the findfile() function */
static const struct finder conf_list[] = {
  { "CURL_HOME", NULL, FALSE },
  { "XDG_CONFIG_HOME", NULL, TRUE }, /* index == 1, used in the code */
  /* XDG Base Directory spec says if XDG_CONFIG_HOME is not set (the findfile
     function keeps track of this) then treat as if set to homedir/.config */
  { "CURL_HOME", "/.config", TRUE }, /* XDG fallback */
  { "HOME", "/.config", TRUE }, /* XDG fallback */
  { "HOME", NULL, FALSE },
#ifdef WIN32
  { "USERPROFILE", NULL, FALSE },
  { "APPDATA", NULL, FALSE },
  { "USERPROFILE", "\\Application Data", FALSE},
#endif
  { NULL, NULL, FALSE }
};

static char *checkhome(const char *home, const char *fname, bool dotscore)
{
  const char pref[2] = { '.', '_' };
  int i;
  for(i = 0; i < (dotscore ? 2 : 1); i++) {
    char *c;
    if(dotscore)
      c = curl_maprintf("%s" DIR_CHAR "%c%s", home, pref[i], &fname[1]);
    else
      c = curl_maprintf("%s" DIR_CHAR "%s", home, fname);
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
 * findfile() - return the full path name of the configuration file 'fname'.
 *
 * 1. Iterate over the environment variables in order, and if set, check for
 *    the given file to be accessed there, then it is a match.
 * 2. Non-windows: try getpwuid
 *
 * On Windows if 'fname' is .curlrc then each location is checked for .curlrc
 * and _curlrc for legacy reasons.
 *
 * When XDG locations are searched, if 'fname' has a leading dot and is just a
 * filename and not a relative path, then the filename is first searched for
 * with the dot stripped. For example, if 'fname' is .curlrc and the
 * $XDG_CONFIG_HOME location is being searched, it happens in this order:
 *
 * $XDG_CONFIG_HOME/curlrc
 * $XDG_CONFIG_HOME/.curlrc
 * $XDG_CONFIG_HOME/_curlrc (only if 'fname' is .curlrc on Windows)
 */
char *findfile(const char *fname)
{
  int i;
  bool dotscore;
  bool fname_is_relative_path;
  bool xdg_main_found = FALSE;
  DEBUGASSERT(fname && fname[0]);

  if(!fname[0])
    return NULL;

#ifdef WIN32
  /* dotscore means also check for fname with a leading underscore: _curlrc */
  dotscore = !strcmp(".curlrc", fname);
#else
  dotscore = false;
#endif

  fname_is_relative_path = !!strpbrk(fname, "\\/");

  DEBUGASSERT(!dotscore || !fname_is_relative_path);

  for(i = 0; conf_list[i].env; i++) {
    char *home;
    home = curl_getenv(conf_list[i].env);

    if(home) {
      char *path;
      if(i == 1 /* XDG_CONFIG_HOME is set */)
        xdg_main_found = TRUE;
      if(!home[0]) {
        curl_free(home);
        continue;
      }
      if(conf_list[i].append) {
        char *c = curl_maprintf("%s%s", home, conf_list[i].append);
        curl_free(home);
        if(!c)
          return NULL;
        home = c;
      }
      if(conf_list[i].xdg && fname[0] == '.' && !fname_is_relative_path) {
        /* skip fallbacks for XDG home if XDG_CONFIG_HOME was set */
        if(i != 1 && xdg_main_found) {
          curl_free(home);
          continue;
        }
        /* check for filename without the dot */
        path = checkhome(home, fname + 1, false);
        if(path) {
          curl_free(home);
          return path;
        }
      }
      path = checkhome(home, fname, fname_is_relative_path ? false : dotscore);
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
