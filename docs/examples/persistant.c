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
#include <unistd.h>

#include <curl/curl.h>

/* to make this work under windows, use the win32-functions from the
   docs/examples/win32socket.c file as well */

/* This example REQUIRES libcurl 7.7 or later */
#if (LIBCURL_VERSION_NUM < 0x070700)
#error Too old libcurl version, upgrade or stay away.
#endif

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;

#ifdef MALLOCDEBUG
  /* this sends all memory debug messages to a specified logfile */
  curl_memdebug("memdump");
#endif

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1);

    /* get the first document */
    curl_easy_setopt(curl, CURLOPT_URL, "http://curl.haxx.se/");
    res = curl_easy_perform(curl);

    /* get another document from the same server using the same
       connection */
    curl_easy_setopt(curl, CURLOPT_URL, "http://curl.haxx.se/docs/");
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  return 0;
}
