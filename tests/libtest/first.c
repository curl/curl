#include "test.h"

#ifdef CURLDEBUG
/* provide a proto for this debug function */
extern void curl_memdebug(const char *);
#endif

/* test is provided in the test code file */
int test(char *url);

char *arg2=NULL;

int main(int argc, char **argv)
{
  char *URL;
  if(argc< 2 ) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }
  if(argc>2)
    arg2=argv[2];

  URL = argv[1]; /* provide this to the rest */

  fprintf(stderr, "URL: %s\n", URL);

#ifdef CURLDEBUG
  curl_memdebug("memdump");
#endif
  return test(URL);
}
