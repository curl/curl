/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include "setup.h" /* struct_stat etc. */
#include "test.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/*
 * Two FTP uploads, the second with no content sent.
 */

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  FILE *hd_src ;
  int hd ;
  struct_stat file_info;
  int error;

  if (!arg2) {
    fprintf(stderr, "Usage: <url> <file-to-upload>\n");
    return -1;
  }

  /* get the file size of the local file */
  hd = stat(arg2, &file_info);
  if(hd == -1) {
    /* can't open file, bail out */
    error = ERRNO;
    fprintf(stderr, "stat() failed with error: %d %s\n",
            error, strerror(error));
    fprintf(stderr, "WARNING: cannot open file %s\n", arg2);
    return -1;
  }

  if(! file_info.st_size) {
    fprintf(stderr, "WARNING: file %s has no size!\n", arg2);
    return -4;
  }

  /* get a FILE * of the same file, could also be made with
     fdopen() from the previous descriptor, but hey this is just
     an example! */
  hd_src = fopen(arg2, "rb");
  if(NULL == hd_src) {
    error = ERRNO;
    fprintf(stderr, "fopen() failed with error: %d %s\n",
            error, strerror(error));
    fprintf(stderr, "Error opening file: %s\n", arg2);
    return -2; /* if this happens things are major weird */
  }

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  /* get a curl handle */
  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  /* enable uploading */
  curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE) ;

  /* enable verbose */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, TRUE) ;

  /* specify target */
  curl_easy_setopt(curl,CURLOPT_URL, URL);

  /* now specify which file to upload */
  curl_easy_setopt(curl, CURLOPT_INFILE, hd_src);

  /* Now run off and do what you've been told! */
  res = curl_easy_perform(curl);

  /* and now upload the exact same again, but without rewinding so it already
     is at end of file */
  res = curl_easy_perform(curl);

  /* close the local file */
  fclose(hd_src);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
