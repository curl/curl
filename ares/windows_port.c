#include "setup.h"

#ifdef WIN32 /* only do the following on windows */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "nameser.h"

#ifndef __MINGW32__
int
ares_strncasecmp(const char *a, const char *b, size_t n)
{
    size_t i;

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

int
ares_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME        ft;
    LARGE_INTEGER   li;
    __int64         t;
    static int      tzflag;

    if (tv)
    {
        GetSystemTimeAsFileTime(&ft);
        li.LowPart  = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        t  = li.QuadPart;       /* In 100-nanosecond intervals */
        //t -= EPOCHFILETIME;     /* Offset to the Epoch time */
        t /= 10;                /* In microseconds */
        tv->tv_sec  = (long)(t / 1000000);
        tv->tv_usec = (long)(t % 1000000);
    }

    return 0;
}

#endif /* WIN32 builds only */
