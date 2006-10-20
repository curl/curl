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

#include "timeval.h"

#define MAIN_LOOP_HANG_TIMEOUT     30 * 1000
#define MULTI_PERFORM_HANG_TIMEOUT 20 * 1000

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
  struct timeval ml_start;
  struct timeval mp_start;
  char ml_timedout = FALSE;
  char mp_timedout = FALSE;

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
  if(!curl) {
    fclose(hd_src);
    curl_global_cleanup();
    return 100; /* major bad */
  }

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

  ml_timedout = FALSE;
  ml_start = curlx_tvnow();

  while (!done) {
    fd_set rd, wr, exc;
    int max_fd;
    struct timeval interval;

    interval.tv_sec = 1;
    interval.tv_usec = 0;

    if (curlx_tvdiff(curlx_tvnow(), ml_start) > 
        MAIN_LOOP_HANG_TIMEOUT) {
      ml_timedout = TRUE;
      break;
    }
    mp_timedout = FALSE;
    mp_start = curlx_tvnow();

    while (res == CURLM_CALL_MULTI_PERFORM) {
      res = (int)curl_multi_perform(m, &running);
      if (curlx_tvdiff(curlx_tvnow(), mp_start) > 
          MULTI_PERFORM_HANG_TIMEOUT) {
        mp_timedout = TRUE;
        break;
      }
      if (running <= 0) {
        done = TRUE;
        break;
      }
    }
    if (mp_timedout || done)
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

  if (ml_timedout || mp_timedout) {
    if (ml_timedout) fprintf(stderr, "ml_timedout\n");
    if (mp_timedout) fprintf(stderr, "mp_timedout\n");
    fprintf(stderr, "ABORTING TEST, since it seems "
            "that it would have run forever.\n");
    res = 77;
  }

#ifdef LIB529
  /* test 529 */
  curl_multi_remove_handle(m, curl);
  curl_multi_cleanup(m);
  curl_easy_cleanup(curl);
#else
  /* test 525 */
  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
#endif

  fclose(hd_src); /* close the local file */

  curl_global_cleanup();
  return res;
}
