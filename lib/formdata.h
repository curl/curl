#ifndef HEADER_CURL_FORMDATA_H
#define HEADER_CURL_FORMDATA_H
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

enum formtype {
  FORM_DATA,    /* form metadata (convert to network encoding if necessary) */
  FORM_CONTENT, /* form content  (never convert) */
  FORM_CALLBACK, /* 'line' points to the custom pointer we pass to the callback
                  */
  FORM_FILE     /* 'line' points to a file name we should read from
                   to create the form data (never convert) */
};

/* plain and simple linked list with lines to send */
struct FormData {
  struct FormData *next;
  enum formtype type;
  char *line;
  size_t length;
};

struct Form {
  struct FormData *data; /* current form line to send */
  size_t sent;           /* number of bytes of the current line that has
                            already been sent in a previous invoke */
  FILE *fp;              /* file to read from */
  curl_read_callback fread_func; /* fread callback pointer */
};

/* used by FormAdd for temporary storage */
typedef struct FormInfo {
  char *name;
  bool name_alloc;
  size_t namelength;
  char *value;
  bool value_alloc;
  size_t contentslength;
  char *contenttype;
  bool contenttype_alloc;
  long flags;
  char *buffer;      /* pointer to existing buffer used for file upload */
  size_t bufferlength;
  char *showfilename; /* The file name to show. If not set, the actual
                         file name will be used */
  bool showfilename_alloc;
  char *userp;        /* pointer for the read callback */
  struct curl_slist* contentheader;
  struct FormInfo *more;
} FormInfo;

int Curl_FormInit(struct Form *form, struct FormData *formdata );

CURLcode Curl_getformdata(struct SessionHandle *data,
                          struct FormData **,
                          struct curl_httppost *post,
                          const char *custom_contenttype,
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

void Curl_formclean(struct FormData **);

CURLcode Curl_formconvert(struct SessionHandle *, struct FormData *);

#endif /* HEADER_CURL_FORMDATA_H */
