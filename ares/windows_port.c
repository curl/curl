#include "setup.h"

/* $Id$ */

/* only do the following on windows
 */
#if (defined(WIN32) || defined(WATT32)) && !defined(MSDOS)
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#ifdef WATT32
#include <sys/socket.h>
#else
#include "nameser.h"
#endif
#include "ares.h"
#include "ares_private.h"

#ifdef __WATCOMC__
/*
 * Watcom needs a DllMain() in order to initialise the clib startup code.
 */
BOOL
WINAPI DllMain (HINSTANCE hnd, DWORD reason, LPVOID reserved)
{
  (void) hnd;
  (void) reason;
  (void) reserved;
  return (TRUE);
}
#endif

int
ares_writev (ares_socket_t s, const struct iovec *vector, size_t count)
{
  char *buffer, *bp;
  size_t i, bytes = 0;

  /* Find the total number of bytes to write
   */
  for (i = 0; i < count; i++)
      bytes += vector[i].iov_len;

  if (bytes == 0)   /* not an error */
     return (0);

  /* Allocate a temporary buffer to hold the data
   */
  buffer = bp = (char*) alloca (bytes);
  if (!buffer)
  {
    SET_ERRNO(ENOMEM);
    return (-1);
  }

  /* Copy the data into buffer.
   */
  for (i = 0; i < count; ++i)
  {
    memcpy (bp, vector[i].iov_base, vector[i].iov_len);
    bp += vector[i].iov_len;
  }
  return (int)swrite(s, buffer, bytes);
}
#endif /* WIN32 builds only */
