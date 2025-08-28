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
#include "first.h"

#define EAT_SPACE(p) while(*(p) && ISSPACE(*(p))) (p)++

#define EAT_WORD(p)  while(*(p) && !ISSPACE(*(p)) && ('>' != *(p))) (p)++

#ifdef DEBUG_GETPART
#define show(x) printf x
#else
#define show(x) Curl_nop_stmt
#endif

/*
 * line_length()
 *
 * Counts the number of characters in a line including a new line.
 * Unlike strlen() it does not stop at nul bytes.
 *
 */
static size_t line_length(const char *buffer, int bytestocheck)
{
  size_t length = 1;

  while(*buffer != '\n' && --bytestocheck) {
    length++;
    buffer++;
  }
  if(*buffer != '\n') {
    /*
     * We didn't find a new line so the last byte must be a
     * '\0' character inserted by fgets() which we should not
     * count.
     */
    length--;
  }

  return length;
}

/*
 * readline()
 *
 * Reads a complete line from a file into a dynamically allocated buffer.
 *
 * Calling function may call this multiple times with same 'buffer'
 * and 'bufsize' pointers to avoid multiple buffer allocations. Buffer
 * will be reallocated and 'bufsize' increased until whole line fits in
 * buffer before returning it.
 *
 * Calling function is responsible to free allocated buffer.
 *
 * This function may return:
 *   GPE_OUT_OF_MEMORY
 *   GPE_END_OF_FILE
 *   GPE_OK
 */
static int readline(char **buffer, size_t *bufsize, size_t *length,
                    FILE *stream)
{
  size_t offset = 0;
  char *newptr;

  if(!*buffer) {
    *buffer = calloc(1, 128);
    if(!*buffer)
      return GPE_OUT_OF_MEMORY;
    *bufsize = 128;
  }

  for(;;) {
    int bytestoread = curlx_uztosi(*bufsize - offset);

    if(!fgets(*buffer + offset, bytestoread, stream)) {
      *length = 0;
      return (offset != 0) ? GPE_OK : GPE_END_OF_FILE;
    }

    *length = offset + line_length(*buffer + offset, bytestoread);
    if(*(*buffer + *length - 1) == '\n')
      break;
    offset = *length;
    if(*length < *bufsize - 1)
      continue;

    newptr = realloc(*buffer, *bufsize * 2);
    if(!newptr)
      return GPE_OUT_OF_MEMORY;
    memset(&newptr[*bufsize], 0, *bufsize);
    *buffer = newptr;
    *bufsize *= 2;
  }

  return GPE_OK;
}

/*
 * appenddata()
 *
 * This appends data from a given source buffer to the end of the used part of
 * a destination buffer. Arguments relative to the destination buffer are, the
 * address of a pointer to the destination buffer 'dst_buf', the length of data
 * in destination buffer excluding potential null string termination 'dst_len',
 * the allocated size of destination buffer 'dst_alloc'. All three destination
 * buffer arguments may be modified by this function. Arguments relative to the
 * source buffer are, a pointer to the source buffer 'src_buf' and indication
 * whether the source buffer is base64 encoded or not 'src_b64'.
 *
 * If the source buffer is indicated to be base64 encoded, this appends the
 * decoded data, binary or whatever, to the destination. The source buffer
 * may not hold binary data, only a null-terminated string is valid content.
 *
 * Destination buffer will be enlarged and relocated as needed.
 *
 * Calling function is responsible to provide preallocated destination
 * buffer and also to deallocate it when no longer needed.
 *
 * This function may return:
 *   GPE_OUT_OF_MEMORY
 *   GPE_OK
 */
static int appenddata(char  **dst_buf,   /* dest buffer */
                      size_t *dst_len,   /* dest buffer data length */
                      size_t *dst_alloc, /* dest buffer allocated size */
                      char   *src_buf,   /* source buffer */
                      size_t  src_len,   /* source buffer length */
                      int     src_b64)   /* != 0 if source is base64 encoded */
{
  size_t need_alloc = 0;

  if(!src_len)
    return GPE_OK;

  need_alloc = src_len + *dst_len + 1;

  if(src_b64) {
    if(src_buf[src_len - 1] == '\r')
      src_len--;

    if(src_buf[src_len - 1] == '\n')
      src_len--;
  }

  /* enlarge destination buffer if required */
  if(need_alloc > *dst_alloc) {
    size_t newsize = need_alloc * 2;
    char *newptr = realloc(*dst_buf, newsize);
    if(!newptr) {
      return GPE_OUT_OF_MEMORY;
    }
    *dst_alloc = newsize;
    *dst_buf = newptr;
  }

  /* memcpy to support binary blobs */
  memcpy(*dst_buf + *dst_len, src_buf, src_len);
  *dst_len += src_len;
  *(*dst_buf + *dst_len) = '\0';

  return GPE_OK;
}

static int decodedata(char  **buf,   /* dest buffer */
                      size_t *len)   /* dest buffer data length */
{
  CURLcode error = CURLE_OK;
  unsigned char *buf64 = NULL;
  size_t src_len = 0;

  if(!*len)
    return GPE_OK;

  /* base64 decode the given buffer */
  error = curlx_base64_decode(*buf, &buf64, &src_len);
  if(error)
    return GPE_OUT_OF_MEMORY;

  if(!src_len) {
    /*
    ** currently there is no way to tell apart an OOM condition in
    ** curlx_base64_decode() from zero length decoded data. For now,
    ** let's just assume it is an OOM condition, currently we have
    ** no input for this function that decodes to zero length data.
    */
    free(buf64);

    return GPE_OUT_OF_MEMORY;
  }

  /* memcpy to support binary blobs */
  memcpy(*buf, buf64, src_len);
  *len = src_len;
  *(*buf + src_len) = '\0';

  free(buf64);

  return GPE_OK;
}

/*
 * getpart()
 *
 * This returns whole contents of specified XML-like section and subsection
 * from the given file. This is mostly used to retrieve a specific part from
 * a test definition file for consumption by test suite servers.
 *
 * Data is returned in a dynamically allocated buffer, a pointer to this data
 * and the size of the data is stored at the addresses that caller specifies.
 *
 * If the returned data is a string the returned size will be the length of
 * the string excluding null-termination. Otherwise it will just be the size
 * of the returned binary data.
 *
 * Calling function is responsible to free returned buffer.
 *
 * This function may return:
 *   GPE_NO_BUFFER_SPACE
 *   GPE_OUT_OF_MEMORY
 *   GPE_OK
 */
int getpart(char **outbuf, size_t *outlen,
            const char *main, const char *sub, FILE *stream)
{
# define MAX_TAG_LEN 200
  char curouter[MAX_TAG_LEN + 1]; /* current outermost section */
  char curmain[MAX_TAG_LEN + 1];  /* current main section */
  char cursub[MAX_TAG_LEN + 1];   /* current sub section */
  char ptag[MAX_TAG_LEN + 1];     /* potential tag */
  char patt[MAX_TAG_LEN + 1];     /* potential attributes */
  char *buffer = NULL;
  char *ptr;
  char *end;
  union {
    ssize_t sig;
     size_t uns;
  } len;
  size_t bufsize = 0;
  size_t outalloc = 256;
  size_t datalen;
  int in_wanted_part = 0;
  int base64 = 0;
  int nonewline = 0;
  int error;

  enum {
    STATE_OUTSIDE = 0,
    STATE_OUTER   = 1,
    STATE_INMAIN  = 2,
    STATE_INSUB   = 3,
    STATE_ILLEGAL = 4
  } state = STATE_OUTSIDE;

  *outlen = 0;
  *outbuf = malloc(outalloc);
  if(!*outbuf)
    return GPE_OUT_OF_MEMORY;
  *(*outbuf) = '\0';

  curouter[0] = curmain[0] = cursub[0] = ptag[0] = patt[0] = '\0';

  while((error = readline(&buffer, &bufsize, &datalen, stream)) == GPE_OK) {

    ptr = buffer;
    EAT_SPACE(ptr);

    if('<' != *ptr) {
      if(in_wanted_part) {
        show(("=> %s", buffer));
        error = appenddata(outbuf, outlen, &outalloc, buffer, datalen,
                           base64);
        if(error)
          break;
      }
      continue;
    }

    ptr++;

    if('/' == *ptr) {
      /*
      ** closing section tag
      */

      ptr++;
      end = ptr;
      EAT_WORD(end);
      len.sig = end - ptr;
      if(len.sig > MAX_TAG_LEN) {
        error = GPE_NO_BUFFER_SPACE;
        break;
      }
      memcpy(ptag, ptr, len.uns);
      ptag[len.uns] = '\0';

      if((STATE_INSUB == state) && !strcmp(cursub, ptag)) {
        /* end of current sub section */
        state = STATE_INMAIN;
        cursub[0] = '\0';
        if(in_wanted_part) {
          /* Do we need to base64 decode the data? */
          if(base64) {
            error = decodedata(outbuf, outlen);
            if(error)
              return error;
          }
          if(nonewline)
            (*outlen)--;
          break;
        }
      }
      else if((STATE_INMAIN == state) && !strcmp(curmain, ptag)) {
        /* end of current main section */
        state = STATE_OUTER;
        curmain[0] = '\0';
        if(in_wanted_part) {
          /* Do we need to base64 decode the data? */
          if(base64) {
            error = decodedata(outbuf, outlen);
            if(error)
              return error;
          }
          if(nonewline)
            (*outlen)--;
          break;
        }
      }
      else if((STATE_OUTER == state) && !strcmp(curouter, ptag)) {
        /* end of outermost file section */
        state = STATE_OUTSIDE;
        curouter[0] = '\0';
        if(in_wanted_part)
          break;
      }

    }
    else if(!in_wanted_part) {
      /*
      ** opening section tag
      */

      /* get potential tag */
      end = ptr;
      EAT_WORD(end);
      len.sig = end - ptr;
      if(len.sig > MAX_TAG_LEN) {
        error = GPE_NO_BUFFER_SPACE;
        break;
      }
      memcpy(ptag, ptr, len.uns);
      ptag[len.uns] = '\0';

      /* ignore comments, doctypes and xml declarations */
      if(('!' == ptag[0]) || ('?' == ptag[0])) {
        show(("* ignoring (%s)", buffer));
        continue;
      }

      /* get all potential attributes */
      ptr = end;
      EAT_SPACE(ptr);
      end = ptr;
      while(*end && ('>' != *end))
        end++;
      len.sig = end - ptr;
      if(len.sig > MAX_TAG_LEN) {
        error = GPE_NO_BUFFER_SPACE;
        break;
      }
      memcpy(patt, ptr, len.uns);
      patt[len.uns] = '\0';

      if(STATE_OUTSIDE == state) {
        /* outermost element (<testcase>) */
        strcpy(curouter, ptag);
        state = STATE_OUTER;
        continue;
      }
      else if(STATE_OUTER == state) {
        /* start of a main section */
        strcpy(curmain, ptag);
        state = STATE_INMAIN;
        continue;
      }
      else if(STATE_INMAIN == state) {
        /* start of a sub section */
        strcpy(cursub, ptag);
        state = STATE_INSUB;
        if(!strcmp(curmain, main) && !strcmp(cursub, sub)) {
          /* start of wanted part */
          in_wanted_part = 1;
          if(strstr(patt, "base64="))
              /* bit rough test, but "mostly" functional, */
              /* treat wanted part data as base64 encoded */
              base64 = 1;
          if(strstr(patt, "nonewline=")) {
            show(("* setting nonewline\n"));
            nonewline = 1;
          }
        }
        continue;
      }

    }

    if(in_wanted_part) {
      show(("=> %s", buffer));
      error = appenddata(outbuf, outlen, &outalloc, buffer, datalen, base64);
      if(error)
        break;
    }

  } /* while */

  free(buffer);

  if(error != GPE_OK) {
    if(error == GPE_END_OF_FILE)
      error = GPE_OK;
    else {
      free(*outbuf);
      *outbuf = NULL;
      *outlen = 0;
    }
  }

  return error;
}
