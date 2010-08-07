#include "setup.h"

#include "curl_gethostname.h"

#define HOSTNAME_MAX 1024

int main(int argc, char *argv[])
{
  char buff[HOSTNAME_MAX];
  if (argc != 2) {
    printf("Usage: %s EXPECTED_HOSTNAME\n", argv[0]);
    return 1;
  }

  if (Curl_gethostname(buff, HOSTNAME_MAX)) {
    printf("Curl_gethostname() failed\n");
    return 1;
  }

  /* compare the name returned by Curl_gethostname() with the expected one */
  if(strncmp(buff, argv[1], HOSTNAME_MAX)) {
    printf("got unexpected host name back, LD_PRELOAD failed\n");
    return 1;
  }
  return 0;
}
