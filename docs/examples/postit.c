/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * Example code that uploads a file name 'foo' to a remote script that accepts
 * "HTML form based" (as described in RFC1738) uploads using HTTP POST.
 *
 * The imaginary form we'll fill in looks like:
 *
 * <form method="post" enctype="multipart/form-data" action="examplepost.cgi">
 * Enter file: <input type="file" name="sendfile" size="40">
 * Enter file name: <input type="text" name="filename" size="30">
 * <input type="submit" value="send" name="submit">
 * </form>
 *
 * This exact source code has not been verified to work.
 */

/* to make this work under windows, use the win32-functions from the
   win32socket.c file as well */

#include <stdio.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;

  struct HttpPost *formpost=NULL;
  struct HttpPost *lastptr=NULL;

  /* Fill in the file upload field */
  curl_formparse("sendfile=@foo",
                 &formpost,
                 &lastptr);

  /* Fill in the filename field */
  curl_formparse("filename=foo",
                 &formpost,
                 &lastptr);
  

  /* Fill in the submit field too, even if this is rarely needed */
  curl_formparse("submit=send",
                 &formpost,
                 &lastptr);

  curl = curl_easy_init();
  if(curl) {
    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL, "http://curl.haxx.se/examplepost.cgi");
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);
  }
  return 0;
}
