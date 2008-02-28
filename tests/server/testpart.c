/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "getpart.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* include memdebug.h last */
#include "memdebug.h"

int main(int argc, char **argv)
{
  if(argc< 3) {
    printf("./testpart main sub\n");
  }
  else {
    size_t size;
    unsigned int i;
    const char *buffer = spitout(stdin, argv[1], argv[2], &size);
    for(i=0; i< size; i++)
      printf("%c", buffer[i]);
  }
  return 0;
}

