/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(MSDOS) || defined(WIN32)

#if defined(HAVE_LIBGEN_H) && defined(HAVE_BASENAME)
#  include <libgen.h>
#endif

#ifdef WIN32
#  include <curl/curl.h>
#  include "tool_cfgable.h"
#  include "tool_libinfo.h"
#endif

#include "tool_bname.h"
#include "tool_doswin.h"

#include "memdebug.h" /* keep this as LAST include */

/*
 * Macros ALWAYS_TRUE and ALWAYS_FALSE are used to avoid compiler warnings.
 */

#define ALWAYS_TRUE   (1)
#define ALWAYS_FALSE  (0)

#if defined(_MSC_VER) && !defined(__POCC__)
#  undef ALWAYS_TRUE
#  undef ALWAYS_FALSE
#  if (_MSC_VER < 1500)
#    define ALWAYS_TRUE   (0, 1)
#    define ALWAYS_FALSE  (1, 0)
#  else
#    define ALWAYS_TRUE \
__pragma(warning(push)) \
__pragma(warning(disable:4127)) \
(1) \
__pragma(warning(pop))
#    define ALWAYS_FALSE \
__pragma(warning(push)) \
__pragma(warning(disable:4127)) \
(0) \
__pragma(warning(pop))
#  endif
#endif

#ifdef WIN32
#  undef  PATH_MAX
#  define PATH_MAX MAX_PATH
#endif

#ifndef S_ISCHR
#  ifdef S_IFCHR
#    define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#  else
#    define S_ISCHR(m) (0) /* cannot tell if file is a device */
#  endif
#endif

#ifdef WIN32
#  define _use_lfn(f) ALWAYS_TRUE   /* long file names always available */
#elif !defined(__DJGPP__) || (__DJGPP__ < 2)  /* DJGPP 2.0 has _use_lfn() */
#  define _use_lfn(f) ALWAYS_FALSE  /* long file names never available */
#endif

static const char *msdosify (const char *file_name);
static char *rename_if_dos_device_name (char *file_name);

/*
 * sanitize_dos_name: returns a newly allocated string holding a
 * valid file name which will be a transformation of given argument
 * in case this wasn't already a valid file name.
 *
 * This function takes ownership of given argument, free'ing it before
 * returning. Caller is responsible of free'ing returned string. Upon
 * out of memory condition function returns NULL.
 */

char *sanitize_dos_name(char *file_name)
{
  char new_name[PATH_MAX];

  if(!file_name)
    return NULL;

  if(strlen(file_name) >= PATH_MAX)
    file_name[PATH_MAX-1] = '\0'; /* truncate it */

  strcpy(new_name, msdosify(file_name));

  Curl_safefree(file_name);

  return strdup(rename_if_dos_device_name(new_name));
}

/* The following functions are taken with modification from the DJGPP
 * port of tar 1.12. They use algorithms originally from DJTAR. */

static const char *msdosify (const char *file_name)
{
  static char dos_name[PATH_MAX];
  static const char illegal_chars_dos[] = ".+, ;=[]" /* illegal in DOS */
    "|<>\\\":?*"; /* illegal in DOS & W95 */
  static const char *illegal_chars_w95 = &illegal_chars_dos[8];
  int idx, dot_idx;
  const char *s = file_name;
  char *d = dos_name;
  const char *const dlimit = dos_name + sizeof(dos_name) - 1;
  const char *illegal_aliens = illegal_chars_dos;
  size_t len = sizeof(illegal_chars_dos) - 1;

  /* Support for Windows 9X VFAT systems, when available. */
  if(_use_lfn(file_name)) {
    illegal_aliens = illegal_chars_w95;
    len -= (illegal_chars_w95 - illegal_chars_dos);
  }

  /* Get past the drive letter, if any. */
  if(s[0] >= 'A' && s[0] <= 'z' && s[1] == ':') {
    *d++ = *s++;
    *d++ = *s++;
  }

  for(idx = 0, dot_idx = -1; *s && d < dlimit; s++, d++) {
    if(memchr(illegal_aliens, *s, len)) {
      /* Dots are special: DOS doesn't allow them as the leading character,
         and a file name cannot have more than a single dot.  We leave the
         first non-leading dot alone, unless it comes too close to the
         beginning of the name: we want sh.lex.c to become sh_lex.c, not
         sh.lex-c.  */
      if(*s == '.') {
        if(idx == 0 && (s[1] == '/' || (s[1] == '.' && s[2] == '/'))) {
          /* Copy "./" and "../" verbatim.  */
          *d++ = *s++;
          if(*s == '.')
            *d++ = *s++;
          *d = *s;
        }
        else if(idx == 0)
          *d = '_';
        else if(dot_idx >= 0) {
          if(dot_idx < 5) { /* 5 is a heuristic ad-hoc'ery */
            d[dot_idx - idx] = '_'; /* replace previous dot */
            *d = '.';
          }
          else
            *d = '-';
        }
        else
          *d = '.';

        if(*s == '.')
          dot_idx = idx;
      }
      else if(*s == '+' && s[1] == '+') {
        if(idx - 2 == dot_idx) { /* .c++, .h++ etc. */
          *d++ = 'x';
          *d   = 'x';
        }
        else {
          /* libg++ etc.  */
          memcpy (d, "plus", 4);
          d += 3;
        }
        s++;
        idx++;
      }
      else
        *d = '_';
    }
    else
      *d = *s;
    if(*s == '/') {
      idx = 0;
      dot_idx = -1;
    }
    else
      idx++;
  }

  *d = '\0';
  return dos_name;
}

static char *rename_if_dos_device_name (char *file_name)
{
  /* We could have a file whose name is a device on MS-DOS.  Trying to
   * retrieve such a file would fail at best and wedge us at worst.  We need
   * to rename such files. */
  char *base;
  struct_stat st_buf;
  char fname[PATH_MAX];

  strncpy(fname, file_name, PATH_MAX-1);
  fname[PATH_MAX-1] = '\0';
  base = basename(fname);
  if(((stat(base, &st_buf)) == 0) && (S_ISCHR(st_buf.st_mode))) {
    size_t blen = strlen(base);

    if(strlen(fname) >= PATH_MAX-1) {
      /* Make room for the '_' */
      blen--;
      base[blen] = '\0';
    }
    /* Prepend a '_'.  */
    memmove(base + 1, base, blen + 1);
    base[0] = '_';
    strcpy(file_name, fname);
  }
  return file_name;
}

#if defined(MSDOS) && (defined(__DJGPP__) || defined(__GO32__))

/*
 * Disable program default argument globbing. We do it on our own.
 */
char **__crt0_glob_function(char *arg)
{
  (void)arg;
  return (char**)0;
}

#endif /* MSDOS && (__DJGPP__ || __GO32__) */

#ifdef WIN32

/*
 * Function to find CACert bundle on a Win32 platform using SearchPath.
 * (SearchPath is already declared via inclusions done in setup header file)
 * (Use the ASCII version instead of the unicode one!)
 * The order of the directories it searches is:
 *  1. application's directory
 *  2. current working directory
 *  3. Windows System directory (e.g. C:\windows\system32)
 *  4. Windows Directory (e.g. C:\windows)
 *  5. all directories along %PATH%
 *
 * For WinXP and later search order actually depends on registry value:
 * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeProcessSearchMode
 */

CURLcode FindWin32CACert(struct Configurable *config, const char *bundle_file)
{
  CURLcode result = CURLE_OK;

  /* search and set cert file only if libcurl supports SSL */
  if(curlinfo->features & CURL_VERSION_SSL) {

    DWORD res_len;
    DWORD buf_tchar_size = PATH_MAX + 1;
    DWORD buf_bytes_size = sizeof(TCHAR) * buf_tchar_size;
    char *ptr = NULL;

    char *buf = malloc(buf_bytes_size);
    if(!buf)
      return CURLE_OUT_OF_MEMORY;
    buf[0] = '\0';

    res_len = SearchPathA(NULL, bundle_file, NULL, buf_tchar_size, buf, &ptr);
    if(res_len > 0) {
      Curl_safefree(config->cacert);
      config->cacert = strdup(buf);
      if(!config->cacert)
        result = CURLE_OUT_OF_MEMORY;
    }

    Curl_safefree(buf);
  }

  return result;
}

#endif /* WIN32 */

#endif /* MSDOS || WIN32 */

