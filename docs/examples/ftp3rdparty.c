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
#include <curl/types.h>
#include <curl/easy.h>

/*
 * This is an example showing how to transfer a file between two remote hosts.
 * 7.13.0 or later required.
 */

int main(void)
{
  CURL *curl;
  CURLcode res;
  char source_url[] = "ftp://remotehost.com/path/to/source";
  char target_url[] = "ftp://aotherserver.com/path/to/dest";

  char sourceUserPass[] = "user:pass";
  char targetUserPass[] = "user:pass";
  char url[100];

  struct curl_slist *source_pre_cmd = NULL;
  struct curl_slist *target_pre_cmd = NULL;
  struct curl_slist *source_post_cmd = NULL;
  struct curl_slist *target_post_cmd = NULL;
  char cmd[] = "PWD";   /* just to test */

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if (curl) {
    /* The ordinary URL is the target when speaking 3rd party transfers */
    curl_easy_setopt(curl, CURLOPT_URL, target_url);

    /* Set a source URL */
    curl_easy_setopt(curl, CURLOPT_SOURCE_URL, source_url);

    /* Set target user and password */
    curl_easy_setopt(curl, CURLOPT_USERPWD, targetUserPass);

    /* Set source user and password */
    curl_easy_setopt(curl, CURLOPT_SOURCE_USERPWD, sourceUserPass);

#if 0
    /* FTPPORT enables PORT on the target side, instead of PASV. */
    curl_easy_setopt(curl, CURLOPT_FTPPORT, "");   /* optional */
#endif

    /* build a list of commands to pass to libcurl */
    source_pre_cmd = curl_slist_append(source_pre_cmd, cmd);
    /* Set a proxy pre-quote command */
    curl_easy_setopt(curl, CURLOPT_SOURCE_PREQUOTE, source_pre_cmd);

    /* build a list of commands to pass to libcurl */
    target_pre_cmd = curl_slist_append(target_pre_cmd, cmd);
    /* Set a pre-quote command */
    curl_easy_setopt(curl, CURLOPT_PREQUOTE, target_pre_cmd);

    /* build a list of commands to pass to libcurl */
    source_post_cmd = curl_slist_append(source_post_cmd, cmd);
    /* Set a proxy post-quote command */
    curl_easy_setopt(curl, CURLOPT_SOURCE_POSTQUOTE, source_post_cmd);

    /* build a list of commands to pass to libcurl */
    target_post_cmd = curl_slist_append(target_post_cmd, cmd);
    /* Set a post-quote command */
    curl_easy_setopt(curl, CURLOPT_POSTQUOTE, target_post_cmd);

    /* Switch on full protocol/debug output */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    res = curl_easy_perform(curl);

    /* clean up the FTP commands list */
    curl_slist_free_all(source_pre_cmd);
    curl_slist_free_all(target_pre_cmd);
    curl_slist_free_all(source_post_cmd);
    curl_slist_free_all(target_post_cmd);

    /* always cleanup */
    curl_easy_cleanup(curl);

    if(CURLE_OK != res) {
      /* we failed */
      fprintf(stderr, "curl told us %d\n", res);
    }
  }

  curl_global_cleanup();

  return 0;
}
