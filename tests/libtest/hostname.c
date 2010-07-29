/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include <string.h>
#include <unistd.h>

#define HOSTNAME "curlhost"
#define HOSTNAME_LEN sizeof(HOSTNAME)

/* 
 * we force our own host name, in order to make some tests machine independent
 */
int gethostname(char *name, size_t namelen) {
  char buff[HOSTNAME_LEN + /* terminating zero */ 1];
  size_t max = (namelen < HOSTNAME_LEN)
    ? namelen
    : HOSTNAME_LEN;

  if(!name || !namelen)
    return -1;

  strcpy(buff, HOSTNAME);
  buff[max - 1] = '\0';
  strcpy(name, buff);
  return 0;
};
