/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

static void decodeQuantum(unsigned char *dest, char *src)
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
  }

  dest[2] = (unsigned char)(x & 255); x >>= 8;
  dest[1] = (unsigned char)(x & 255); x >>= 8;
  dest[0] = (unsigned char)(x & 255); x >>= 8;
}

/* base64Decode
 * Given a base64 string at src, decode it into the memory pointed
 * to by dest. If rawLength points to a valid address (ie not NULL),
 * store the length of the decoded data to it.
 */
static void base64Decode(unsigned char *dest, char *src, int *rawLength)
{
  int length = 0;
  int equalsTerm = 0;
  int i;
  unsigned char lastQuantum[3];
	
  while((src[length] != '=') && src[length])
    length++;
  while(src[length+equalsTerm] == '=')
    equalsTerm++;
  
  if(rawLength)
    *rawLength = (length * 3 / 4) - equalsTerm;
  
  for(i = 0; i < length/4 - 1; i++) {
    decodeQuantum(dest, src);
    dest += 3; src += 4;
  }

  decodeQuantum(lastQuantum, src);
  for(i = 0; i < 3 - equalsTerm; i++) dest[i] = lastQuantum[i];
	
}

/* ---- Base64 Encoding --- */
static char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
/*
 * Curl_base64_encode()
 *
 * Returns the length of the newly created base64 string. The third argument
 * is a pointer to an allocated area holding the base64 data. If something
 * went wrong, -1 is returned.
 *
 */
int Curl_base64_encode(const void *inp, int insize, char **outptr)
{
  unsigned char ibuf[3];
  unsigned char obuf[4];
  int i;
  int inputparts;
  char *output;
  char *base64data;

  char *indata = (char *)inp;

  if(0 == insize)
    insize = strlen(indata);

  base64data = output = (char*)malloc(insize*4/3+4);
  if(NULL == output)
    return -1;

  while(insize > 0) {
    for (i = inputparts = 0; i < 3; i++) { 
      if(*indata) {
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
      sprintf(output, "%c%c==", 
              table64[obuf[0]],
              table64[obuf[1]]);
      break;
    case 2: /* two bytes read */
      sprintf(output, "%c%c%c=", 
              table64[obuf[0]],
              table64[obuf[1]],
              table64[obuf[2]]);
      break;
    default:
      sprintf(output, "%c%c%c%c", 
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

int Curl_base64_decode(const char *str, void *data)
{
  int ret;

  base64Decode((unsigned char *)data, (char *)str, &ret);
  return ret;
}

/************* TEST HARNESS STUFF ****************/


#ifdef TEST_ENCODE
/* encoding test harness. Read in standard input and write out the length
 * returned by Curl_base64_encode, followed by the base64'd data itself
 */
#include <stdio.h>

#define TEST_NEED_SUCK
void *suck(int *);

int main(int argc, char **argv, char **envp) {
	char *base64;
	int base64Len;
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
 */
#include <stdio.h>

#define TEST_NEED_SUCK
void *suck(int *);

int main(int argc, char **argv, char **envp) {
	char *base64;
	int base64Len;
	unsigned char *data;
	int dataLen;
	
	base64 = (char *)suck(&base64Len);
	data = (unsigned char *)malloc(base64Len * 3/4 + 8);
	dataLen = Curl_base64_decode(base64, data);

	fprintf(stderr, "%d\n", dataLen);
	fwrite(data,1,dataLen,stdout);
	

	free(base64); free(data);
	return 0;
}
#endif

#ifdef TEST_NEED_SUCK
/* this function 'sucks' in as much as possible from stdin */
void *suck(int *lenptr) {
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


/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
