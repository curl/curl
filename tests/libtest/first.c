#include <curl/curl.h>

int main(int argc, char **argv)
{
  if(argc< 2 ) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }

  curl_memdebug("memdump");
