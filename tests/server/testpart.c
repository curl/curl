/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define CURL_NO_OLDIES

#include "setup.h"

#include "getpart.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* include memdebug.h last */
#include "memdebug.h"

int main(int argc, char **argv)
{
  int rc;
  char  *part;
  size_t partlen, i;

  if(argc< 3) {
    printf("./testpart main sub\n");
  }
  else {
    rc = getpart(&part, &partlen, argv[1], argv[2], stdin);
    if(rc)
      return(rc);
    for(i = 0; i < partlen; i++)
      printf("%c", part[i]);
    free(part);
  }
  return 0;
}

