#ifndef HEADER_CURL_WINRTDEFS_H
#define HEADER_CURL_WINRTDEFS_H

#ifdef __cplusplus
extern "C" {
#endif

int GetTickCount(void);
char* getenv (const char* name);

DWORD WINAPI ExpandEnvironmentStringsA(
  _In_       const char* lpSrc,
  _Out_opt_  char* lpDst,
  _In_       DWORD nSize
);


HINSTANCE LoadLibrary(
  LPCTSTR lpLibFileName
);

HANDLE WINAPI GetStdHandle(
  _In_  DWORD nStdHandle
);

DWORD WINAPI GetFileType(
  _In_  HANDLE hFile
);

BOOL WINAPI PeekNamedPipe(
  _In_       HANDLE hNamedPipe,
  _Out_opt_  LPVOID lpBuffer,
  _In_       DWORD nBufferSize,
  _Out_opt_  LPDWORD lpBytesRead,
  _Out_opt_  LPDWORD lpTotalBytesAvail,
  _Out_opt_  LPDWORD lpBytesLeftThisMessage
);

void WINAPI InitializeCriticalSection(
  _Out_  LPCRITICAL_SECTION lpCriticalSection
);

DWORD WaitForSingleObject(
  HANDLE hHandle,
  DWORD dwMilliseconds
);

DWORD WINAPI WaitForMultipleObjects(
  _In_  DWORD nCount,
  _In_  const HANDLE *lpHandles,
  _In_  BOOL bWaitAll,
  _In_  DWORD dwMilliseconds
);

#ifdef __cplusplus
}
#endif

#endif