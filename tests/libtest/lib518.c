#include "test.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <mprintf.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef FD_SETSIZE
#error "this test requires FD_SETSIZE"
#endif

#define NUM_OPEN (FD_SETSIZE + 10)

int test(char *URL)
{
  CURLcode res;
  CURL *curl;
  int fd[NUM_OPEN];
  int i;

  /* open a lot of file descriptors */
  for (i = 0; i < NUM_OPEN; i++) {
    fd[i] = open("/dev/null", O_RDONLY);
    if (fd[i] == -1) {
      fprintf(stderr, "open: attempt #%i: failed to open /dev/null\n", i);
      for (i--; i >= 0; i--)
        close(fd[i]);
      return CURLE_FAILED_INIT;
    }
  }

  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);

  for (i = 0; i < NUM_OPEN; i++)
    close(fd[i]);

  return (int)res;
}
