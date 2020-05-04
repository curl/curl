/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"
#include "strdup.h"
#include "dynbuf.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define MIN_FIRST_ALLOC 32

#define DYNINIT 0xbee51da /* random pattern */

/*
 * Init a dynbuf struct.
 */
void Curl_dyn_init(struct dynbuf *s, size_t toobig)
{
  DEBUGASSERT(s);
  DEBUGASSERT(toobig);
  s->bufr = NULL;
  s->leng = 0;
  s->allc = 0;
  s->toobig = toobig;
#ifdef DEBUGBUILD
  s->init = DYNINIT;
#endif
}

/*
 * free the buffer and re-init the necessary fields. It doesn't touch the
 * 'init' field and thus this buffer can be reused to add data to again.
 */
void Curl_dyn_free(struct dynbuf *s)
{
  DEBUGASSERT(s);
  Curl_safefree(s->bufr);
  s->leng = s->allc = 0;
}

/*
 * Store/append an chunk of memory to the dynbuf.
 */
static CURLcode dyn_nappend(struct dynbuf *s,
                            const unsigned char *mem, size_t len)
{
  size_t indx = s->leng;
  size_t a = s->allc;
  size_t fit = len + indx + 1; /* new string + old string + zero byte */

  /* try to detect if there's rubbish in the struct */
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(s->toobig);
  DEBUGASSERT(indx < s->toobig);
  DEBUGASSERT(!s->leng || s->bufr);

  if(fit > s->toobig) {
    Curl_dyn_free(s);
    return CURLE_OUT_OF_MEMORY;
  }
  else if(!a) {
    DEBUGASSERT(!indx);
    /* first invoke */
    if(fit < MIN_FIRST_ALLOC)
      a = MIN_FIRST_ALLOC;
    else
      a = fit;
  }
  else {
    while(a < fit)
      a *= 2;
  }

  if(a != s->allc) {
    s->bufr = Curl_saferealloc(s->bufr, a);
    if(!s->bufr) {
      s->leng = s->allc = 0;
      return CURLE_OUT_OF_MEMORY;
    }
    s->allc = a;
  }

  if(len)
    memcpy(&s->bufr[indx], mem, len);
  s->leng = indx + len;
  s->bufr[s->leng] = 0;
  return CURLE_OK;
}

/*
 * Clears the string, keeps the allocation. This can also be called on a
 * buffer that already was freed.
 */
void Curl_dyn_reset(struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  if(s->leng)
    s->bufr[0] = 0;
  s->leng = 0;
}

#ifdef USE_NGTCP2
/*
 * Specify the size of the tail to keep (number of bytes from the end of the
 * buffer). The rest will be dropped.
 */
CURLcode Curl_dyn_tail(struct dynbuf *s, size_t trail)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  if(trail > s->leng)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  else if(trail == s->leng)
    return CURLE_OK;
  else if(!trail) {
    Curl_dyn_reset(s);
  }
  else {
    memmove(&s->bufr[0], &s->bufr[s->leng - trail], trail);
    s->leng = trail;
  }
  return CURLE_OK;

}
#endif

/*
 * Appends a buffer with length.
 */
CURLcode Curl_dyn_addn(struct dynbuf *s, const void *mem, size_t len)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return dyn_nappend(s, mem, len);
}

/*
 * Append a zero terminated string at the end.
 */
CURLcode Curl_dyn_add(struct dynbuf *s, const char *str)
{
  size_t n = strlen(str);
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return dyn_nappend(s, (unsigned char *)str, n);
}

/*
 * Append a string printf()-style
 */
CURLcode Curl_dyn_addf(struct dynbuf *s, const char *fmt, ...)
{
  char *str;
  va_list ap;
  va_start(ap, fmt);
  str = vaprintf(fmt, ap); /* this allocs a new string to append */
  va_end(ap);

  if(str) {
    CURLcode result = dyn_nappend(s, (unsigned char *)str, strlen(str));
    free(str);
    return result;
  }
  /* If we failed, we cleanup the whole buffer and return error */
  Curl_dyn_free(s);
  return CURLE_OUT_OF_MEMORY;
}

/*
 * Returns a pointer to the buffer.
 */
char *Curl_dyn_ptr(const struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return s->leng ? s->bufr : (char *)"";
}

/*
 * Returns an unsigned pointer to the buffer.
 */
unsigned char *Curl_dyn_uptr(const struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return s->leng ? (unsigned char *)s->bufr : (unsigned char *)"";
}

/*
 * Returns the length of the buffer.
 */
size_t Curl_dyn_len(const struct dynbuf *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->init == DYNINIT);
  DEBUGASSERT(!s->leng || s->bufr);
  return s->leng;
}
