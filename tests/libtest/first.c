#include "test.h"

#ifdef CURLDEBUG
/* provide a proto for this debug function */
extern void curl_memdebug(const char *);
extern void curl_memlimit(int);
#endif

/* test is provided in the test code file */
int test(char *url);

char *arg2=NULL;

int main(int argc, char **argv)
{
  char *URL;

#ifdef CURLDEBUG
  /* this sends all memory debug messages to a logfile named memdump */
  char *env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    curl_free(env);
    curl_memdebug("memdump");
  }
  /* this enables the fail-on-alloc-number-N functionality */
  env = curl_getenv("CURL_MEMLIMIT");
  if(env) {
    curl_memlimit(atoi(env));
    curl_free(env);
  }
#endif
  if(argc< 2 ) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }
  if(argc>2)
    arg2=argv[2];

  URL = argv[1]; /* provide this to the rest */

  fprintf(stderr, "URL: %s\n", URL);

  return test(URL);
}
