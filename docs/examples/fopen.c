/*****************************************************************************
 *
 * This example source code introduces a c library buffered I/O interface to
 * URL reads it supports fopen(), fread(), fgets(), feof(), fclose(),
 * rewind(). Supported functions have identical prototypes to their normal c
 * lib namesakes and are preceaded by url_ .
 *
 * Using this code you can replace your program's fopen() with url_fopen()
 * and fread() with url_fread() and it become possible to read remote streams
 * instead of (only) local files. Local files (ie those that can be directly
 * fopened) will drop back to using the underlying clib implementations
 *
 * See the main() function at the bottom that shows an app that retrives from a
 * specified url using fgets() and fread() and saves as two output files.
 *
 * Copyright (c) 2003 Simtec Electronics
 *
 * Re-implemented by Vincent Sanders <vince@kyllikki.org> with extensive
 * reference to original curl example code
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This example requires libcurl 7.9.7 or later.
 */

#include <stdio.h>
#include <string.h>
#ifndef WIN32
#  include <sys/time.h>
#endif
#include <stdlib.h>
#include <errno.h>

#include <curl/curl.h>

enum fcurl_type_e {
  CFTYPE_NONE=0,
  CFTYPE_FILE=1,
  CFTYPE_CURL=2
};

struct fcurl_data
{
  enum fcurl_type_e type;     /* type of handle */
  union {
    CURL *curl;
    FILE *file;
  } handle;                   /* handle */

  char *buffer;               /* buffer to store cached data*/
  size_t buffer_len;          /* currently allocated buffers length */
  size_t buffer_pos;          /* end of data in buffer*/
  int still_running;          /* Is background url fetch still in progress */
};

typedef struct fcurl_data URL_FILE;

/* exported functions */
URL_FILE *url_fopen(const char *url,const char *operation);
int url_fclose(URL_FILE *file);
int url_feof(URL_FILE *file);
size_t url_fread(void *ptr, size_t size, size_t nmemb, URL_FILE *file);
char * url_fgets(char *ptr, size_t size, URL_FILE *file);
void url_rewind(URL_FILE *file);

/* we use a global one for convenience */
CURLM *multi_handle;

/* curl calls this routine to get more data */
static size_t write_callback(char *buffer,
                             size_t size,
                             size_t nitems,
                             void *userp)
{
  char *newbuff;
  size_t rembuff;

  URL_FILE *url = (URL_FILE *)userp;
  size *= nitems;

  rembuff=url->buffer_len - url->buffer_pos; /* remaining space in buffer */

  if(size > rembuff) {
    /* not enough space in buffer */
    newbuff=realloc(url->buffer,url->buffer_len + (size - rembuff));
    if(newbuff==NULL) {
      fprintf(stderr,"callback buffer grow failed\n");
      size=rembuff;
    }
    else {
      /* realloc suceeded increase buffer size*/
      url->buffer_len+=size - rembuff;
      url->buffer=newbuff;
    }
  }

  memcpy(&url->buffer[url->buffer_pos], buffer, size);
  url->buffer_pos += size;

  return size;
}

/* use to attempt to fill the read buffer up to requested number of bytes */
static int fill_buffer(URL_FILE *file, size_t want)
{
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  struct timeval timeout;
  int rc;
  CURLMcode mc; /* curl_multi_fdset() return code */

  /* only attempt to fill buffer if transactions still running and buffer
   * doesnt exceed required size already
   */
  if((!file->still_running) || (file->buffer_pos > want))
    return 0;

  /* attempt to fill buffer */
  do {
    int maxfd = -1;
    long curl_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* set a suitable timeout to fail on */
    timeout.tv_sec = 60; /* 1 minute */
    timeout.tv_usec = 0;

    curl_multi_timeout(multi_handle, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }

    /* get file descriptors from the transfers */
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    if(mc != CURLM_OK)
    {
      fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
      break;
    }

    /* On success the value of maxfd is guaranteed to be >= -1. We call
       select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
       no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
       to sleep 100ms, which is the minimum suggested value in the
       curl_multi_fdset() doc. */

    if(maxfd == -1) {
#ifdef _WIN32
      Sleep(100);
      rc = 0;
#else
      /* Portable sleep for platforms other than Windows. */
      struct timeval wait = { 0, 100 * 1000 }; /* 100ms */
      rc = select(0, NULL, NULL, NULL, &wait);
#endif
    }
    else {
      /* Note that on some platforms 'timeout' may be modified by select().
         If you need access to the original value save a copy beforehand. */
      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
    }

    switch(rc) {
    case -1:
      /* select error */
      break;

    case 0:
    default:
      /* timeout or readable/writable sockets */
      curl_multi_perform(multi_handle, &file->still_running);
      break;
    }
  } while(file->still_running && (file->buffer_pos < want));
  return 1;
}

/* use to remove want bytes from the front of a files buffer */
static int use_buffer(URL_FILE *file,int want)
{
  /* sort out buffer */
  if((file->buffer_pos - want) <=0) {
    /* ditch buffer - write will recreate */
    if(file->buffer)
      free(file->buffer);

    file->buffer=NULL;
    file->buffer_pos=0;
    file->buffer_len=0;
  }
  else {
    /* move rest down make it available for later */
    memmove(file->buffer,
            &file->buffer[want],
            (file->buffer_pos - want));

    file->buffer_pos -= want;
  }
  return 0;
}

URL_FILE *url_fopen(const char *url,const char *operation)
{
  /* this code could check for URLs or types in the 'url' and
     basicly use the real fopen() for standard files */

  URL_FILE *file;
  (void)operation;

  file = malloc(sizeof(URL_FILE));
  if(!file)
    return NULL;

  memset(file, 0, sizeof(URL_FILE));

  if((file->handle.file=fopen(url,operation)))
    file->type = CFTYPE_FILE; /* marked as URL */

  else {
    file->type = CFTYPE_CURL; /* marked as URL */
    file->handle.curl = curl_easy_init();

    curl_easy_setopt(file->handle.curl, CURLOPT_URL, url);
    curl_easy_setopt(file->handle.curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(file->handle.curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(file->handle.curl, CURLOPT_WRITEFUNCTION, write_callback);

    if(!multi_handle)
      multi_handle = curl_multi_init();

    curl_multi_add_handle(multi_handle, file->handle.curl);

    /* lets start the fetch */
    curl_multi_perform(multi_handle, &file->still_running);

    if((file->buffer_pos == 0) && (!file->still_running)) {
      /* if still_running is 0 now, we should return NULL */

      /* make sure the easy handle is not in the multi handle anymore */
      curl_multi_remove_handle(multi_handle, file->handle.curl);

      /* cleanup */
      curl_easy_cleanup(file->handle.curl);

      free(file);

      file = NULL;
    }
  }
  return file;
}

int url_fclose(URL_FILE *file)
{
  int ret=0;/* default is good return */

  switch(file->type) {
  case CFTYPE_FILE:
    ret=fclose(file->handle.file); /* passthrough */
    break;

  case CFTYPE_CURL:
    /* make sure the easy handle is not in the multi handle anymore */
    curl_multi_remove_handle(multi_handle, file->handle.curl);

    /* cleanup */
    curl_easy_cleanup(file->handle.curl);
    break;

  default: /* unknown or supported type - oh dear */
    ret=EOF;
    errno=EBADF;
    break;
  }

  if(file->buffer)
    free(file->buffer);/* free any allocated buffer space */

  free(file);

  return ret;
}

int url_feof(URL_FILE *file)
{
  int ret=0;

  switch(file->type) {
  case CFTYPE_FILE:
    ret=feof(file->handle.file);
    break;

  case CFTYPE_CURL:
    if((file->buffer_pos == 0) && (!file->still_running))
      ret = 1;
    break;

  default: /* unknown or supported type - oh dear */
    ret=-1;
    errno=EBADF;
    break;
  }
  return ret;
}

size_t url_fread(void *ptr, size_t size, size_t nmemb, URL_FILE *file)
{
  size_t want;

  switch(file->type) {
  case CFTYPE_FILE:
    want=fread(ptr,size,nmemb,file->handle.file);
    break;

  case CFTYPE_CURL:
    want = nmemb * size;

    fill_buffer(file,want);

    /* check if theres data in the buffer - if not fill_buffer()
     * either errored or EOF */
    if(!file->buffer_pos)
      return 0;

    /* ensure only available data is considered */
    if(file->buffer_pos < want)
      want = file->buffer_pos;

    /* xfer data to caller */
    memcpy(ptr, file->buffer, want);

    use_buffer(file,want);

    want = want / size;     /* number of items */
    break;

  default: /* unknown or supported type - oh dear */
    want=0;
    errno=EBADF;
    break;

  }
  return want;
}

char *url_fgets(char *ptr, size_t size, URL_FILE *file)
{
  size_t want = size - 1;/* always need to leave room for zero termination */
  size_t loop;

  switch(file->type) {
  case CFTYPE_FILE:
    ptr = fgets(ptr,size,file->handle.file);
    break;

  case CFTYPE_CURL:
    fill_buffer(file,want);

    /* check if theres data in the buffer - if not fill either errored or
     * EOF */
    if(!file->buffer_pos)
      return NULL;

    /* ensure only available data is considered */
    if(file->buffer_pos < want)
      want = file->buffer_pos;

    /*buffer contains data */
    /* look for newline or eof */
    for(loop=0;loop < want;loop++) {
      if(file->buffer[loop] == '\n') {
        want=loop+1;/* include newline */
        break;
      }
    }

    /* xfer data to caller */
    memcpy(ptr, file->buffer, want);
    ptr[want]=0;/* allways null terminate */

    use_buffer(file,want);

    break;

  default: /* unknown or supported type - oh dear */
    ptr=NULL;
    errno=EBADF;
    break;
  }

  return ptr;/*success */
}

void url_rewind(URL_FILE *file)
{
  switch(file->type) {
  case CFTYPE_FILE:
    rewind(file->handle.file); /* passthrough */
    break;

  case CFTYPE_CURL:
    /* halt transaction */
    curl_multi_remove_handle(multi_handle, file->handle.curl);

    /* restart */
    curl_multi_add_handle(multi_handle, file->handle.curl);

    /* ditch buffer - write will recreate - resets stream pos*/
    if(file->buffer)
      free(file->buffer);

    file->buffer=NULL;
    file->buffer_pos=0;
    file->buffer_len=0;

    break;

  default: /* unknown or supported type - oh dear */
    break;
  }
}

/* Small main program to retrive from a url using fgets and fread saving the
 * output to two test files (note the fgets method will corrupt binary files if
 * they contain 0 chars */
int main(int argc, char *argv[])
{
  URL_FILE *handle;
  FILE *outf;

  int nread;
  char buffer[256];
  const char *url;

  if(argc < 2)
    url="http://192.168.7.3/testfile";/* default to testurl */
  else
    url=argv[1];/* use passed url */

  /* copy from url line by line with fgets */
  outf=fopen("fgets.test","w+");
  if(!outf) {
    perror("couldn't open fgets output file\n");
    return 1;
  }

  handle = url_fopen(url, "r");
  if(!handle) {
    printf("couldn't url_fopen() %s\n", url);
    fclose(outf);
    return 2;
  }

  while(!url_feof(handle)) {
    url_fgets(buffer,sizeof(buffer),handle);
    fwrite(buffer,1,strlen(buffer),outf);
  }

  url_fclose(handle);

  fclose(outf);


  /* Copy from url with fread */
  outf=fopen("fread.test","w+");
  if(!outf) {
    perror("couldn't open fread output file\n");
    return 1;
  }

  handle = url_fopen("testfile", "r");
  if(!handle) {
    printf("couldn't url_fopen() testfile\n");
    fclose(outf);
    return 2;
  }

  do {
    nread = url_fread(buffer, 1,sizeof(buffer), handle);
    fwrite(buffer,1,nread,outf);
  } while(nread);

  url_fclose(handle);

  fclose(outf);


  /* Test rewind */
  outf=fopen("rewind.test","w+");
  if(!outf) {
    perror("couldn't open fread output file\n");
    return 1;
  }

  handle = url_fopen("testfile", "r");
  if(!handle) {
    printf("couldn't url_fopen() testfile\n");
    fclose(outf);
    return 2;
  }

  nread = url_fread(buffer, 1,sizeof(buffer), handle);
  fwrite(buffer,1,nread,outf);
  url_rewind(handle);

  buffer[0]='\n';
  fwrite(buffer,1,1,outf);

  nread = url_fread(buffer, 1,sizeof(buffer), handle);
  fwrite(buffer,1,nread,outf);


  url_fclose(handle);

  fclose(outf);


  return 0;/* all done */
}
