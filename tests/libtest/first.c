#include <curl/curl.h>

#ifdef MALLOCDEBUG
/* provide a proto for this debug function */
extern void curl_memdebug(const char *);
#endif

/* test is provided in the test code file */
CURLcode test(char *url);

int main(int argc, char **argv)
{
  char *URL;
  if(argc< 2 ) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }
  URL = argv[1]; /* provide this to the rest */

  fprintf(stderr, "URL: %s\n", URL);

#ifdef MALLOCDEBUG
  curl_memdebug("memdump");
#endif
  return test(URL);
}
