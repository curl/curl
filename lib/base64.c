/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* Base64 encoding/decoding
 *
 * Test harnesses down the bottom - compile with -DTEST_ENCODE for
 * a program that will read in raw data from stdin and write out
 * a base64-encoded version to stdout, and the length returned by the
 * encoding function to stderr. Compile with -DTEST_DECODE for a program that
 * will go the other way.
 *
 * This code will break if int is smaller than 32 bits
 */

#include "setup.h"

#include <stdlib.h>
#include <string.h>

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "base64.h"
#include "memory.h"

/* include memdebug.h last */
#include "memdebug.h"


static void decodeQuantum(unsigned char *dest, const char *src)
{
  unsigned int x = 0;
  int i;
  for(i = 0; i < 4; i++) {
    if(src[i] >= 'A' && src[i] <= 'Z')
      x = (x << 6) + (unsigned int)(src[i] - 'A' + 0);
    else if(src[i] >= 'a' && src[i] <= 'z')
      x = (x << 6) + (unsigned int)(src[i] - 'a' + 26);
    else if(src[i] >= '0' && src[i] <= '9')
      x = (x << 6) + (unsigned int)(src[i] - '0' + 52);
    else if(src[i] == '+')
      x = (x << 6) + 62;
    else if(src[i] == '/')
      x = (x << 6) + 63;
    else if(src[i] == '=')
      x = (x << 6);
  }

  dest[2] = (unsigned char)(x & 255);
  x >>= 8;
  dest[1] = (unsigned char)(x & 255);
  x >>= 8;
  dest[0] = (unsigned char)(x & 255);
}

/*
 * Curl_base64_decode()
 *
 * Given a base64 string at src, decode it and return an allocated memory in
 * the *outptr. Returns the length of the decoded data.
 */
size_t Curl_base64_decode(const char *src, unsigned char **outptr)
{
  int length = 0;
  int equalsTerm = 0;
  int i;
  int numQuantums;
  unsigned char lastQuantum[3];
  size_t rawlen=0;
  unsigned char *newstr;

  *outptr = NULL;

  while((src[length] != '=') && src[length])
    length++;
  /* A maximum of two = padding characters is allowed */
  if(src[length] == '=') {
    equalsTerm++;
    if(src[length+equalsTerm] == '=')
      equalsTerm++;
  }
  numQuantums = (length + equalsTerm) / 4;

  /* Don't allocate a buffer if the decoded length is 0 */
  if (numQuantums <= 0)
    return 0;

  rawlen = (numQuantums * 3) - equalsTerm;

  /* The buffer must be large enough to make room for the last quantum
  (which may be partially thrown out) and the zero terminator. */
  newstr = malloc(rawlen+4);
  if(!newstr)
    return 0;

  *outptr = newstr;

  /* Decode all but the last quantum (which may not decode to a
  multiple of 3 bytes) */
  for(i = 0; i < numQuantums - 1; i++) {
    decodeQuantum((unsigned char *)newstr, src);
    newstr += 3; src += 4;
  }

  /* This final decode may actually read slightly past the end of the buffer
  if the input string is missing pad bytes.  This will almost always be
  harmless. */
  decodeQuantum(lastQuantum, src);
  for(i = 0; i < 3 - equalsTerm; i++)
    newstr[i] = lastQuantum[i];

  newstr[i] = 0; /* zero terminate */
  return rawlen;
}

/* ---- Base64 Encoding --- */
static const char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Curl_base64_encode()
 *
 * Returns the length of the newly created base64 string. The third argument
 * is a pointer to an allocated area holding the base64 data. If something
 * went wrong, -1 is returned.
 *
 */
size_t Curl_base64_encode(const char *inp, size_t insize, char **outptr)
{
  unsigned char ibuf[3];
  unsigned char obuf[4];
  int i;
  int inputparts;
  char *output;
  char *base64data;

  char *indata = (char *)inp;

  *outptr = NULL; /* set to NULL in case of failure before we reach the end */

  if(0 == insize)
    insize = strlen(indata);

  base64data = output = (char*)malloc(insize*4/3+4);
  if(NULL == output)
    return 0;

  while(insize > 0) {
    for (i = inputparts = 0; i < 3; i++) {
      if(insize > 0) {
        inputparts++;
        ibuf[i] = *indata;
        indata++;
        insize--;
      }
      else
        ibuf[i] = 0;
    }

    obuf [0] = (ibuf [0] & 0xFC) >> 2;
    obuf [1] = ((ibuf [0] & 0x03) << 4) | ((ibuf [1] & 0xF0) >> 4);
    obuf [2] = ((ibuf [1] & 0x0F) << 2) | ((ibuf [2] & 0xC0) >> 6);
    obuf [3] = ibuf [2] & 0x3F;

    switch(inputparts) {
    case 1: /* only one byte read */
      snprintf(output, 5, "%c%c==",
               table64[obuf[0]],
               table64[obuf[1]]);
      break;
    case 2: /* two bytes read */
      snprintf(output, 5, "%c%c%c=",
               table64[obuf[0]],
               table64[obuf[1]],
               table64[obuf[2]]);
      break;
    default:
      snprintf(output, 5, "%c%c%c%c",
               table64[obuf[0]],
               table64[obuf[1]],
               table64[obuf[2]],
               table64[obuf[3]] );
      break;
    }
    output += 4;
  }
  *output=0;
  *outptr = base64data; /* make it return the actual data memory */

  return strlen(base64data); /* return the length of the new data */
}
/* ---- End of Base64 Encoding ---- */

/************* TEST HARNESS STUFF ****************/


#ifdef TEST_ENCODE
/* encoding test harness. Read in standard input and write out the length
 * returned by Curl_base64_encode, followed by the base64'd data itself
 */
#include <stdio.h>

#define TEST_NEED_SUCK
void *suck(int *);

int main(int argc, char **argv, char **envp)
{
  char *base64;
  size_t base64Len;
  unsigned char *data;
  int dataLen;

  data = (unsigned char *)suck(&dataLen);
  base64Len = Curl_base64_encode(data, dataLen, &base64);

  fprintf(stderr, "%d\n", base64Len);
  fprintf(stdout, "%s",   base64);

  free(base64); free(data);
  return 0;
}
#endif

#ifdef TEST_DECODE
/* decoding test harness. Read in a base64 string from stdin and write out the
 * length returned by Curl_base64_decode, followed by the decoded data itself
 *
 * gcc -DTEST_DECODE base64.c -o base64 mprintf.o memdebug.o
 */
#include <stdio.h>

#define TEST_NEED_SUCK
void *suck(int *);

int main(int argc, char **argv, char **envp)
{
  char *base64;
  int base64Len;
  unsigned char *data;
  int dataLen;
  int i, j;

  base64 = (char *)suck(&base64Len);
  data = (unsigned char *)malloc(base64Len * 3/4 + 8);
  dataLen = Curl_base64_decode(base64, data);

  fprintf(stderr, "%d\n", dataLen);

  for(i=0; i < dataLen; i+=0x10) {
    printf("0x%02x: ", i);
    for(j=0; j < 0x10; j++)
      if((j+i) < dataLen)
        printf("%02x ", data[i+j]);
      else
        printf("   ");

    printf(" | ");

    for(j=0; j < 0x10; j++)
      if((j+i) < dataLen)
        printf("%c", isgraph(data[i+j])?data[i+j]:'.');
      else
        break;
    puts("");
  }

  free(base64); free(data);
  return 0;
}
#endif

#ifdef TEST_NEED_SUCK
/* this function 'sucks' in as much as possible from stdin */
void *suck(int *lenptr)
{
  int cursize = 8192;
  unsigned char *buf = NULL;
  int lastread;
  int len = 0;

  do {
    cursize *= 2;
    buf = (unsigned char *)realloc(buf, cursize);
    memset(buf + len, 0, cursize - len);
    lastread = fread(buf + len, 1, cursize - len, stdin);
    len += lastread;
  } while(!feof(stdin));

  lenptr[0] = len;
  return (void *)buf;
}
#endif
