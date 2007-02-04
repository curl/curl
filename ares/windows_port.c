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
/* Watcom needs a DlMain() in order to initialise the clib startup code.
 */
BOOL
DllMain (HINSTANCE hnd, DWORD reason, LPVOID reserved)
{
  (void) hnd;
  (void) reason;
  (void) reserved;
  return (TRUE);
}
#endif

#ifndef __MINGW32__
int
ares_strncasecmp(const char *a, const char *b, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        int c1 = isupper(a[i]) ? tolower(a[i]) : a[i];
        int c2 = isupper(b[i]) ? tolower(b[i]) : b[i];
        if (c1 != c2) return c1-c2;
    }
    return 0;
}

int
ares_strcasecmp(const char *a, const char *b)
{
    return strncasecmp(a, b, strlen(a)+1);
}
#endif

/*
 * Number of micro-seconds between the beginning of the Windows epoch
 * (Jan. 1, 1601) and the Unix epoch (Jan. 1, 1970).
 */
#if defined(_MSC_VER) || defined(__WATCOMC__)
#define EPOCH_FILETIME 11644473600000000Ui64
#else
#define EPOCH_FILETIME 11644473600000000ULL
#endif

int
ares_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME        ft;
    LARGE_INTEGER   li;
    __int64         t;

    if (tv)
    {
        GetSystemTimeAsFileTime(&ft);
        li.LowPart  = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        t  = li.QuadPart / 10;   /* In micro-second intervals */
        t -= EPOCH_FILETIME;     /* Offset to the Epoch time */
        tv->tv_sec  = (long)(t / 1000000);
        tv->tv_usec = (long)(t % 1000000);
    }
    (void) tz;
    return 0;
}

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
    errno = ENOMEM;
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
