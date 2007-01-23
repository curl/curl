/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "getpart.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* just to please base64.h we create a fake struct */
struct SessionHandle {
  int fake;
};

#include "base64.h"

/* include memdebug.h last */
#include "memdebug.h"

#define EAT_SPACE(ptr) while( ptr && *ptr && ISSPACE(*ptr) ) ptr++
#define EAT_WORD(ptr) while( ptr && *ptr && !ISSPACE(*ptr) && \
                            ('>' != *ptr)) ptr++

#ifdef DEBUG
#define show(x) printf x
#else
#define show(x)
#endif

curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
curl_free_callback Curl_cfree = (curl_free_callback)free;
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)strdup;
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

static
char *appendstring(char *string, /* original string */
                   char *buffer, /* to append */
                   size_t *stringlen, /* length of string */
                   size_t *stralloc,  /* allocated size */
                   char base64) /* 1 if base64 encoded */
{
  size_t len = strlen(buffer);
  size_t needed_len = len + *stringlen + 1;
  char *buf64=NULL;

  if(base64) {
    /* decode the given buffer first */
    len = Curl_base64_decode(buffer, (unsigned char**)&buf64); /* updated len */
    buffer = buf64;
    needed_len = len + *stringlen + 1; /* recalculate */
  }

  if(needed_len >= *stralloc) {
    char *newptr;
    size_t newsize = needed_len*2; /* get twice the needed size */

    newptr = realloc(string, newsize);
    if(newptr) {
      string = newptr;
      *stralloc = newsize;
    }
    else {
      if(buf64)
        free(buf64);
      return NULL;
    }
  }
  /* memcpy to support binary blobs */
  memcpy(&string[*stringlen], buffer, len);
  *stringlen += len;
  string[*stringlen]=0;

  if(buf64)
    free(buf64);

  return string;
}

const char *spitout(FILE *stream,
                    const char *main,
                    const char *sub, size_t *size)
{
  char buffer[8192]; /* big enough for anything */
  char cmain[128]=""; /* current main section */
  char csub[128]="";  /* current sub section */
  char *ptr;
  char *end;
  char display = 0;

  char *string;
  size_t stringlen=0;
  size_t stralloc=256;
  char base64 = 0; /* set to 1 if true */

  enum {
    STATE_OUTSIDE,
    STATE_OUTER,
    STATE_INMAIN,
    STATE_INSUB,
    STATE_ILLEGAL
  } state = STATE_OUTSIDE;

  string = (char *)malloc(stralloc);
  if(!string)
    return NULL;

  string[0] = 0; /* zero first byte in case of no data */

  while(fgets(buffer, sizeof(buffer), stream)) {

    ptr = buffer;

    /* pass white spaces */
    EAT_SPACE(ptr);

    if('<' != *ptr) {
      if(display) {
        show(("=> %s", buffer));
        string = appendstring(string, buffer, &stringlen, &stralloc, base64);
        show(("* %s\n", buffer));
      }
      continue;
    }

    ptr++;
    EAT_SPACE(ptr);

    if('/' == *ptr) {
      /* end of a section */
      ptr++;
      EAT_SPACE(ptr);

      end = ptr;
      EAT_WORD(end);
      *end = 0;

      if((state == STATE_INSUB) &&
         !strcmp(csub, ptr)) {
        /* this is the end of the currently read sub section */
        state--;
        csub[0]=0; /* no sub anymore */
        display=0;
      }
      else if((state == STATE_INMAIN) &&
              !strcmp(cmain, ptr)) {
        /* this is the end of the currently read main section */
        state--;
        cmain[0]=0; /* no main anymore */
        display=0;
      }
      else if(state == STATE_OUTER) {
        /* this is the end of the outermost file section */
        state--;
      }
    }
    else if(!display) {
      /* this is the beginning of a section */
      end = ptr;
      EAT_WORD(end);

      *end = 0;
      switch(state) {
      case STATE_OUTSIDE:
        /* Ignore the outermost <testcase> element */
        state = STATE_OUTER;
        break;
      case STATE_OUTER:
        strcpy(cmain, ptr);
        state = STATE_INMAIN;
        break;
      case STATE_INMAIN:
        strcpy(csub, ptr);
        state = STATE_INSUB;
        break;
      default:
        break;
      }

      if(!end[1] != '>') {
        /* There might be attributes here. Check for those we know of and care
           about. */
        if(strstr(&end[1], "base64=")) {
          /* rought and dirty, but "mostly" functional */
          /* Treat all data as base64 encoded */
          base64 = 1;
        }
      }
    }
    if(display) {
      string = appendstring(string, buffer, &stringlen, &stralloc, base64);
      show(("* %s\n", buffer));
    }

    if((STATE_INSUB == state) &&
       !strcmp(cmain, main) &&
       !strcmp(csub, sub)) {
      show(("* (%d bytes) %s\n", stringlen, buffer));
      display = 1; /* start displaying */
    }
    else if ((*cmain == '!') || (*csub == '!')) {
        /* This is just a comment, not a new section */
        state--;
    }
    else {
      show(("%d (%s/%s): %s\n", state, cmain, csub, buffer));
      display = 0; /* no display */
    }
  }

  *size = stringlen;
  return string;
}

