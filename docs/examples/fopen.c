/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * This example source code introduces an fopen()/fread()/fclose() emulation
 * for URL reads. Using an approach similar to this, you could replace your
 * program's fopen() with this url_fopen() and fread() with url_fread() and
 * it should be possible to read remote streams instead of (only) local files.
 *
 * See the main() function at the bottom that shows a tiny app in action.
 *
 * This source code is a proof of concept. It will need further attention to
 * become production-use useful and solid.
 *
 * This example requires libcurl 7.9.7 or later.
 */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

#include <curl/curl.h>

#if (LIBCURL_VERSION_NUM < 0x070907)
#error "too old libcurl version, get the latest!"
#endif

struct data {
  int type;
  union {
    CURL *curl;
    FILE *file;
  } handle;

  /* This is the documented biggest possible buffer chunk we can get from
     libcurl in one single callback! */
  char buffer[CURL_MAX_WRITE_SIZE];

  char *readptr; /* read from here */
  int bytes;     /* bytes available from read pointer */

  CURLMcode m;   /* stored from a previous url_fread() */
};

typedef struct data URL_FILE;

/* we use a global one for convenience */
CURLM *multi_handle;

static
size_t write_callback(char *buffer,
                      size_t size,
                      size_t nitems,
                      void *userp)
{
  URL_FILE *url = (URL_FILE *)userp;
  size *= nitems;

  memcpy(url->readptr, buffer, size);
  url->readptr += size;
  url->bytes += size;

  fprintf(stderr, "callback %d size bytes\n", size);

  return size;
}

URL_FILE *url_fopen(char *url, char *operation)
{
  /* this code could check for URLs or types in the 'url' and
     basicly use the real fopen() for standard files */

  URL_FILE *file;
  int still_running;
  (void)operation;

  file = (URL_FILE *)malloc(sizeof(URL_FILE));
  if(!file)
    return NULL;

  memset(file, 0, sizeof(URL_FILE));

  file->type = 1; /* marked as URL, use 0 for plain file */
  file->handle.curl = curl_easy_init();

  curl_easy_setopt(file->handle.curl, CURLOPT_URL, url);
  curl_easy_setopt(file->handle.curl, CURLOPT_FILE, file);
  curl_easy_setopt(file->handle.curl, CURLOPT_VERBOSE, FALSE);
  curl_easy_setopt(file->handle.curl, CURLOPT_WRITEFUNCTION, write_callback);

  if(!multi_handle)
    multi_handle = curl_multi_init();

  curl_multi_add_handle(multi_handle, file->handle.curl);

  while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(multi_handle, &still_running));

  /* if still_running would be 0 now, we should return NULL */

  return file;
}

void url_fclose(URL_FILE *file)
{
  /* make sure the easy handle is not in the multi handle anymore */
  curl_multi_remove_handle(multi_handle, file->handle.curl);

  /* cleanup */
  curl_easy_cleanup(file->handle.curl);
}



size_t url_fread(void *ptr, size_t size, size_t nmemb, URL_FILE *file)
{
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  int maxfd;
  struct timeval timeout;
  int rc;
  int still_running = 0;

  if(!file->bytes) { /* no data available at this point */

    file->readptr = file->buffer; /* reset read pointer */

    if(CURLM_CALL_MULTI_PERFORM == file->m) {
      while(CURLM_CALL_MULTI_PERFORM ==
            curl_multi_perform(multi_handle, &still_running)) {
        if(file->bytes) {
          printf("(fread) WOAH! THis happened!\n");
          break;        
        }
      }
      if(!still_running) {
        printf("DONE RUNNING AROUND!\n");
        return 0;
      }
    }

    do {

      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);
  
      /* set a suitable timeout to fail on */
      timeout.tv_sec = 500; /* 5 minutes */
      timeout.tv_usec = 0;

      /* get file descriptors from the transfers */
      curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

      switch(rc) {
      case -1:
        /* select error */
        break;
      case 0:
        break;
      default:
        /* timeout or readable/writable sockets */
        printf("select() returned %d!\n", rc);
        do {
          file->m = curl_multi_perform(multi_handle, &still_running);
          
          if(file->bytes)
            /* we have received data, return that now */
            break;
          
        } while(CURLM_CALL_MULTI_PERFORM == file->m);

        
        if(!still_running)
          printf("DONE RUNNING AROUND!\n");
        
        break;
      }
    } while(still_running && (file->bytes <= 0));
  }
  else
    printf("(fread) Skip network read\n");

  if(file->bytes) {
    /* data already available, return that */
    int want = size * nmemb;

    if(file->bytes < want)
      want = file->bytes;

    memcpy(ptr, file->readptr, want);
    file->readptr += want;
    file->bytes -= want;

    printf("(fread) return %d bytes\n", want);

    return want;
  }
  return 0; /* no data available to return */
}


int main(int argc, char *argv[])
{
  URL_FILE *handle;
  int nread;
  char buffer[256];

  (void)argc;
  (void)argv;

  handle = url_fopen("http://curl.haxx.se/", "r");

  if(!handle) {
    printf("couldn't url_fopen()\n");
  }

  do {
    nread = url_fread(buffer, sizeof(buffer), 1, handle);

    printf("We got: %d bytes\n", nread);
  } while(nread);

  url_fclose(handle);

  return 0;
}
