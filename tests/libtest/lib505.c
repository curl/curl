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
 * This example shows an FTP upload, with a rename of the file just after
 * a successful upload.
 *
 * Example based on source code provided by Erick Nuwendam. Thanks!
 */

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  FILE *hd_src ;
  int hd ;
  struct_stat file_info;

  struct curl_slist *headerlist=NULL;
  const char *buf_1 = "RNFR 505";
  const char *buf_2 = "RNTO 505-forreal";

  if (!arg2) {
    fprintf(stderr, "Usage: <url> <file-to-upload>\n");
    return -1;
  }

  /* get the file size of the local file */
  hd = stat(arg2, &file_info);
  if(hd == -1) {
    /* can't open file, bail out */
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
    return -2; /* if this happens things are major weird */
  }

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    struct curl_slist *hl;
    /* build a list of commands to pass to libcurl */
    hl = curl_slist_append(headerlist, buf_1);
    if(hl) {
      headerlist = curl_slist_append(hl, buf_2);
      if(hl)
        headerlist = hl;
    }

    /* enable uploading */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE) ;

    /* enable verbose */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, TRUE) ;

    /* specify target */
    curl_easy_setopt(curl,CURLOPT_URL, URL);

    /* pass in that last of FTP commands to run after the transfer */
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, headerlist);

    /* now specify which file to upload */
    curl_easy_setopt(curl, CURLOPT_INFILE, hd_src);

    /* and give the size of the upload (optional) */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)file_info.st_size);

    /* Now run off and do what you've been told! */
    res = curl_easy_perform(curl);

    /* clean up the FTP commands list */
    curl_slist_free_all (headerlist);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(hd_src); /* close the local file */

  curl_global_cleanup();
  return res;
}
