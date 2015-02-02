#include "curl_setup.h"

#ifdef HAVE_WINDOWS_H
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_PC_APP)

int GetTickCount(void)
{
    LARGE_INTEGER t;
    return(int) (QueryPerformanceCounter(&t) ? t.QuadPart : 0);
}

#endif
#endif