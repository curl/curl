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

HINSTANCE LoadLibrary(
  LPCTSTR lpLibFileName
)
{
  return NULL;
}

HANDLE WINAPI GetStdHandle(
  _In_  DWORD nStdHandle
)
{
  return INVALID_HANDLE_VALUE;
}

DWORD WINAPI GetFileType(
  _In_  HANDLE hFile
)
{
  return FILE_TYPE_UNKNOWN;
}

BOOL WINAPI PeekNamedPipe(
  _In_       HANDLE hNamedPipe,
  _Out_opt_  LPVOID lpBuffer,
  _In_       DWORD nBufferSize,
  _Out_opt_  LPDWORD lpBytesRead,
  _Out_opt_  LPDWORD lpTotalBytesAvail,
  _Out_opt_  LPDWORD lpBytesLeftThisMessage
)
{
  return FALSE;
}

void WINAPI InitializeCriticalSection(
  _Out_  LPCRITICAL_SECTION lpCriticalSection
)
{
  InitializeCriticalSectionEx(lpCriticalSection, 0, CRITICAL_SECTION_NO_DEBUG_INFO);
}

DWORD WaitForSingleObject(
  HANDLE hHandle,
  DWORD dwMilliseconds
)
{
  return WaitForSingleObjectEx(hHandle, dwMilliseconds, FALSE);
}

DWORD WINAPI WaitForMultipleObjects(
  _In_  DWORD nCount,
  _In_  const HANDLE *lpHandles,
  _In_  BOOL bWaitAll,
  _In_  DWORD dwMilliseconds
)
{
  return WaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, FALSE);
}

#endif
#endif