/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GETHOSTNAME_ENV_VAR "CURL_GETHOSTNAME"

/*
 * we force our own host name, in order to make some tests machine independent
 */
int gethostname(char *name, size_t namelen) {
  const char *force_hostname = getenv(GETHOSTNAME_ENV_VAR);
  if(force_hostname) {
    strncpy(name, force_hostname, namelen);
    return 0;
  }

  /* LD_PRELOAD used, but no hostname set, we'll just return a failure */
  return -1;
}
