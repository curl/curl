/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

/*
 * This is an example showing how to check a single file's size and mtime
 * from an FTP server.
 */

static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
  /* we are not interested in the headers itself,
     so we only return the size we would have saved ... */
  return (size_t)(size * nmemb);
}

int main(void)
{
  char ftpurl[] = "ftp://ftp.example.com/gnu/binutils/binutils-2.19.1.tar.bz2";
  CURL *curl;
  CURLcode res;
  const time_t filetime;
  const double filesize;
  const char *filename = strrchr(ftpurl, '/') + 1;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, ftpurl);
    /* No download if the file */
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    /* Ask for filetime */
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    /* No header output: TODO 14.1 http-style HEAD output for ftp */
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
    /* Switch on full protocol/debug output */
    /* curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */

    res = curl_easy_perform(curl);

    if(CURLE_OK == res) {
      /* http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html */
      res = curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if((CURLE_OK == res) && filetime)
        printf("filetime %s: %s", filename, ctime(&filetime));
      res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
      if((CURLE_OK == res) && filesize)
        printf("filesize %s: %0.0f bytes\n", filename, filesize);
    } else {
      /* we failed */
      fprintf(stderr, "curl told us %d\n", res);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
