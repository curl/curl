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
#include "../curl_setup.h"

#ifndef HAVE_BASENAME

#include "basename.h"

/*
  (Quote from The Open Group Base Specifications Issue 6 IEEE Std 1003.1, 2004
  Edition)

  The basename() function shall take the pathname pointed to by path and
  return a pointer to the final component of the pathname, deleting any
  trailing '/' characters.

  If the string pointed to by path consists entirely of the '/' character,
  basename() shall return a pointer to the string "/". If the string pointed
  to by path is exactly "//", it is implementation-defined whether '/' or "//"
  is returned.

  If path is a null pointer or points to an empty string, basename() shall
  return a pointer to the string ".".

  The basename() function may modify the string pointed to by path, and may
  return a pointer to static storage that may then be overwritten by a
  subsequent call to basename().

  The basename() function need not be reentrant. A function that is not
  required to be reentrant is not required to be thread-safe.

*/
char *curlx_basename(char *path)
{
  /* Ignore all the details above for now and make a quick and simple
     implementation here */
  char *s1;
  char *s2;

  s1 = strrchr(path, '/');
  s2 = strrchr(path, '\\');

  if(s1 && s2)
    path = ((s1 > s2) ? s1 : s2) + 1;
  else if(s1)
    path = s1 + 1;
  else if(s2)
    path = s2 + 1;

  return path;
}

#endif /* !HAVE_BASENAME */
