#ifndef __FORMDATA_H
#define __FORMDATA_H

/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* plain and simple linked list with lines to send */
struct FormData {
  struct FormData *next;
  char *line;
  size_t length;
};

struct Form {
  struct FormData *data; /* current form line to send */
  unsigned int sent; /* number of bytes of the current line that has already
                        been sent in a previous invoke */
};

/* used by FormAdd for temporary storage */
typedef struct FormInfo {
  char *name;
  size_t namelength;
  char *value;
  size_t contentslength;
  char *contenttype;
  long flags;
  char *buffer;      /* pointer to existing buffer used for file upload */
  size_t bufferlength;
  char *showfilename; /* The file name to show. If not set, the actual
                         file name will be used */
  struct curl_slist* contentheader;
  struct FormInfo *more;
} FormInfo;

int Curl_FormInit(struct Form *form, struct FormData *formdata );

CURLcode
Curl_getFormData(struct FormData **,
                 struct curl_httppost *post,
                 curl_off_t *size);

/* fread() emulation */
size_t Curl_FormReader(char *buffer,
                       size_t size,
                       size_t nitems,
                       FILE *mydata);

/*
 * Curl_formpostheader() returns the first line of the formpost, the
 * request-header part (which is not part of the request-body like the rest of
 * the post).
 */
char *Curl_formpostheader(void *formp, size_t *len);

char *Curl_FormBoundary(void);

void Curl_formclean(struct FormData *);

#endif

