/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int test(char *URL)
{
  int res = 0;
  CURL *curl;
  FILE *hd_src ;
  int hd ;
  struct stat file_info;
  int running;
  char done=FALSE;
  CURLM *m;

  if (!arg2) {
    fprintf(stderr, "Usage: lib525 [url] [uploadfile]\n");
    return -1;
  }

  /* get the file size of the local file */
  hd = open(arg2, O_RDONLY) ;
  fstat(hd, &file_info);
  close(hd) ;

  /* get a FILE * of the same file, could also be made with
     fdopen() from the previous descriptor, but hey this is just
     an example! */
  hd_src = fopen(arg2, "rb");

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(!curl)
    return 100; /* major bad */


  /* enable uploading */
  curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE) ;

  /* specify target */
  curl_easy_setopt(curl,CURLOPT_URL, URL);

  /* go verbose */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

  /* use active FTP */
  curl_easy_setopt(curl, CURLOPT_FTPPORT, "-");

  /* now specify which file to upload */
  curl_easy_setopt(curl, CURLOPT_READDATA, hd_src);

  /* NOTE: if you want this code to work on Windows with libcurl as a DLL, you
     MUST also provide a read callback with CURLOPT_READFUNCTION. Failing to
     do so will give you a crash since a DLL may not use the variable's memory
     when passed in to it from an app like this. */

  /* Set the size of the file to upload (optional).  If you give a *_LARGE
     option you MUST make sure that the type of the passed-in argument is a
     curl_off_t. If you use CURLOPT_INFILESIZE (without _LARGE) you must
     make sure that to pass in a type 'long' argument. */
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                   (curl_off_t)file_info.st_size);

  m = curl_multi_init();

  res = (int)curl_multi_add_handle(m, curl);

  while(!done) {
    fd_set rd, wr, exc;
    int max_fd;
    struct timeval interval;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    while (res == CURLM_CALL_MULTI_PERFORM) {
      res = (int)curl_multi_perform(m, &running);
      if (running <= 0) {
        done = TRUE;
        break;
      }
    }
    if(done)
      break;

    if (res != CURLM_OK) {
      fprintf(stderr, "not okay???\n");
      break;
    }

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_ZERO(&exc);
    max_fd = 0;

    if (curl_multi_fdset(m, &rd, &wr, &exc, &max_fd) != CURLM_OK) {
      fprintf(stderr, "unexpected failured of fdset.\n");
      res = 189;
      break;
    }

    if (select_test(max_fd+1, &rd, &wr, &exc, &interval) == -1) {
      fprintf(stderr, "bad select??\n");
      res = 195;
      break;
    }

    res = CURLM_CALL_MULTI_PERFORM;
  }

  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);

  fclose(hd_src); /* close the local file */

  curl_global_cleanup();
  return res;
}
