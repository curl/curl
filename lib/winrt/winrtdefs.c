#include "curl_setup.h"

#ifdef HAVE_WINDOWS_H
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_PC_APP)

int GetTickCount(void)
{
  LARGE_INTEGER t;
  return(int) (QueryPerformanceCounter(&t) ? t.QuadPart : 0);
}

char* getenv (const char* name)
{
  return NULL;
}

DWORD WINAPI ExpandEnvironmentStringsA(
  _In_       LPCTSTR lpSrc,
  _Out_opt_  LPTSTR lpDst,
  _In_       DWORD nSize
)
{
  return strlen((const char*)lpSrc);
}

#endif
#endif