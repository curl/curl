/*****************************************************************************
 */

#include <stdio.h>

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

static size_t wrfu(void *ptr,  size_t  size,  size_t  nmemb,  void *stream)
{
  return size * nmemb;
}
int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.networking4all.com/");

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wrfu);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    res = curl_easy_perform(curl);

    if(!res) {
      struct curl_certinfo *ci = NULL;

      res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);

      if(!res && ci) {
        int i;
        printf("%d certs!\n", ci->num_of_certs);

        for(i=0; i<ci->num_of_certs; i++) {
          struct curl_slist *slist;

          for(slist = ci->certinfo[i]; slist; slist = slist->next)
            printf("%s\n", slist->data);

        }
      }

    }


    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
