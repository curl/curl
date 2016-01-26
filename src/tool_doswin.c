/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#if defined(MSDOS) || defined(WIN32)

#if defined(HAVE_LIBGEN_H) && defined(HAVE_BASENAME)
#  include <libgen.h>
#endif

#ifdef WIN32
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
#elif defined(__DJGPP__)
#  include <fcntl.h>                /* _use_lfn(f) prototype */
#endif

static char *msdosify(const char *file_name);
static char *rename_if_dos_device_name(const char *file_name);


/*
Sanitize *file_name.
Success: (CURLE_OK) *file_name points to a sanitized version of the original.
         This function takes ownership of the original *file_name and frees it.
Failure: (!= CURLE_OK) *file_name is unchanged.
*/
CURLcode sanitize_file_name(char **file_name)
{
  size_t len;
  char *p, *sanitized;

  /* Calculate the maximum length of a filename.
     FILENAME_MAX is often the same as PATH_MAX, in other words it does not
     discount the path information. PATH_MAX size is calculated based on:
     <drive-letter><colon><path-sep><max-filename-len><NULL> */
  const size_t max_filename_len = PATH_MAX - 3 - 1;

  if(!file_name || !*file_name)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  len = strlen(*file_name);

  if(len >= max_filename_len)
    len = max_filename_len - 1;

  sanitized = malloc(len + 1);

  if(!sanitized)
    return CURLE_OUT_OF_MEMORY;

  strncpy(sanitized, *file_name, len);
  sanitized[len] = '\0';

  for(p = sanitized; *p; ++p ) {
    const char *banned;
    if(1 <= *p && *p <= 31) {
      *p = '_';
      continue;
    }
    for(banned = "|<>/\\\":?*"; *banned; ++banned) {
      if(*p == *banned) {
        *p = '_';
        break;
      }
    }
  }

#ifdef MSDOS
  /* msdosify checks for more banned characters for MSDOS, however it allows
     for some path information to pass through. since we are sanitizing only a
     filename and cannot allow a path it's important this call be done in
     addition to and not instead of the banned character check above. */
  p = msdosify(sanitized);
  if(!p) {
    free(sanitized);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  sanitized = p;
  len = strlen(sanitized);
#endif

  p = rename_if_dos_device_name(sanitized);
  if(!p) {
    free(sanitized);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  sanitized = p;
  len = strlen(sanitized);

  /* dos_device_name rename will rename a device name, possibly changing the
     length. If the length is too long now we can't truncate it because we
     could end up with a device name. In practice this shouldn't be a problem
     because device names are short, but you never know. */
  if(len >= max_filename_len) {
    free(sanitized);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  *file_name = sanitized;
  return CURLE_OK;
}

/* The functions msdosify, rename_if_dos_device_name and __crt0_glob_function
 * were taken with modification from the DJGPP port of tar 1.12. They use
 * algorithms originally from DJTAR.
 */

/*
Extra sanitization MSDOS for file_name.
Returns a copy of file_name that is sanitized by MSDOS standards.
Warning: path information may pass through. For sanitizing a filename use
sanitize_file_name which calls this function after sanitizing path info.
*/
static char *msdosify(const char *file_name)
{
  char dos_name[PATH_MAX];
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
  return strdup(dos_name);
}

/*
Rename file_name if it's a representation of a device name.
Returns a copy of file_name, and the copy will have contents different from the
original if a device name was found.
*/
static char *rename_if_dos_device_name(const char *file_name)
{
  /* We could have a file whose name is a device on MS-DOS.  Trying to
   * retrieve such a file would fail at best and wedge us at worst.  We need
   * to rename such files. */
  char *p, *base;
  struct_stat st_buf;
  char fname[PATH_MAX];

  strncpy(fname, file_name, PATH_MAX-1);
  fname[PATH_MAX-1] = '\0';
  base = basename(fname);
  if(((stat(base, &st_buf)) == 0) && (S_ISCHR(st_buf.st_mode))) {
    size_t blen = strlen(base);

    if(strlen(fname) == PATH_MAX-1) {
      /* Make room for the '_' */
      blen--;
      base[blen] = '\0';
    }
    /* Prepend a '_'.  */
    memmove(base + 1, base, blen + 1);
    base[0] = '_';
  }

  /* The above stat check does not identify devices for me in Windows 7. For
     example a stat on COM1 returns a regular file S_IFREG. According to MSDN
     stat doc that is the correct behavior, so I assume the above code is
     legacy, maybe MSDOS or DJGPP specific? */

  /* Rename devices.
     Examples: CON => _CON, CON.EXT => CON_EXT, CON:ADS => CON_ADS */
  for(p = fname; p; p = (p == fname && fname != base ? base : NULL)) {
    size_t p_len;
    int x = (curl_strnequal(p, "CON", 3) ||
             curl_strnequal(p, "PRN", 3) ||
             curl_strnequal(p, "AUX", 3) ||
             curl_strnequal(p, "NUL", 3)) ? 3 :
            (curl_strnequal(p, "CLOCK$", 6)) ? 6 :
            (curl_strnequal(p, "COM", 3) || curl_strnequal(p, "LPT", 3)) ?
              (('1' <= p[3] && p[3] <= '9') ? 4 : 3) : 0;

    if(!x)
      continue;

    /* the devices may be accessible with an extension or ADS, for
       example CON.AIR and CON:AIR both access console */
    if(p[x] == '.' || p[x] == ':') {
      p[x] = '_';
      continue;
    }
    else if(p[x]) /* no match */
      continue;

    p_len = strlen(p);

    if(strlen(fname) == PATH_MAX-1) {
      /* Make room for the '_' */
      p_len--;
      p[p_len] = '\0';
    }
    /* Prepend a '_'.  */
    memmove(p + 1, p, p_len + 1);
    p[0] = '_';

    /* if fname was just modified then the basename pointer must be updated */
    if(p == fname)
      base = basename(fname);
  }

  return strdup(fname);
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

CURLcode FindWin32CACert(struct OperationConfig *config,
                         const char *bundle_file)
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
