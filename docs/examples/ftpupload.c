/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include <stdio.h>

#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * This example shows an FTP upload, with a rename of the file just after
 * a successful upload.
 *
 * Example based on source code provided by Erick Nuwendam. Thanks!
 */

#define LOCAL_FILE      "/tmp/uploadthis.txt"
#define UPLOAD_FILE_AS  "while-uploading.txt"
#define REMOTE_URL      "ftp://localhost/"  UPLOAD_FILE_AS
#define RENAME_FILE_TO  "renamed-and-fine.txt"

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;
  FILE *ftpfile;
  FILE * hd_src ;
  int hd ;
  struct stat file_info;

  struct curl_slist *headerlist=NULL;
  char buf_1 [] = "RNFR " UPLOAD_FILE_AS;
  char buf_2 [] = "RNTO " RENAME_FILE_TO;

  /* get the file size of the local file */
  hd = open(LOCAL_FILE, O_RDONLY) ;
  fstat(hd, &file_info);
  close(hd) ;

  /* get a FILE * of the same file, could also be made with
     fdopen() from the previous descriptor, but hey this is just
     an example! */
  hd_src = fopen(LOCAL_FILE, "rb");

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* build a list of commands to pass to libcurl */
    headerlist = curl_slist_append(headerlist, buf_1);
    headerlist = curl_slist_append(headerlist, buf_2);

    /* enable uploading */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE) ;

    /* specify target */
    curl_easy_setopt(curl,CURLOPT_URL, REMOTE_URL);

    /* pass in that last of FTP commands to run after the transfer */
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, headerlist);

    /* now specify which file to upload */
    curl_easy_setopt(curl, CURLOPT_READDATA, hd_src);

    /* NOTE: if you want this example to work on Windows with libcurl as a
       DLL, you MUST also provide a read callback with
       CURLOPT_READFUNCTION. Failing to do so will give you a crash since a
       DLL may not use the variable's memory when passed in to it from an app
       like this. */

    /* and give the size of the upload (optional) */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, file_info.st_size);

    /* Now run off and do what you've been told! */
    res = curl_easy_perform(curl);

    /* clean up the FTP commands list */
    curl_slist_free_all (headerlist);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(hd_src); /* close the local file */

  curl_global_cleanup();
  return 0;
}
