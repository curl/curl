/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

/* A multi-threaded example that uses pthreads extensively to fetch
 * X remote files at once */

#include <stdio.h>
#include <pthread.h>
#include <curl/curl.h>

/* silly list of test-URLs */
char *urls[]= {
  "http://curl.haxx.se/",
  "ftp://cool.haxx.se/",
  "http://www.contactor.se/",
  "www.haxx.se"
};

void *pull_one_url(void *url)
{
  CURL *curl;

  curl = curl_easy_init();

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_perform(curl);

  curl_easy_cleanup(curl);

  return NULL;
}


/* 
   int pthread_create(pthread_t *new_thread_ID,
   const pthread_attr_t *attr,
   void * (*start_func)(void *), void *arg);
*/

int main(int argc, char **argv)
{
  pthread_t tid[4];
  int i;
  int error;
  for(i=0; i< 4; i++) {
    error = pthread_create(&tid[i],
                           NULL, /* default attributes please */
                           pull_one_url,
                           urls[i]);
    if(0 != error)
      fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
    else 
      fprintf(stderr, "Thread %d, gets %s\n", i, urls[i]);
  }

  /* now wait for all threads to terminate */
  for(i=0; i< 4; i++) {
    error = pthread_join(tid[i], NULL);
    fprintf(stderr, "Thread %d terminated\n", i);
  }

  return 0;
}
