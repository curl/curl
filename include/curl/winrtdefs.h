#ifndef HEADER_CURL_WINRTDEFS_H
#define HEADER_CURL_WINRTDEFS_H

#ifdef __cplusplus
extern "C" {
#endif

int GetTickCount(void);
char* getenv (const char* name);

DWORD WINAPI ExpandEnvironmentStringsA(
  _In_       LPCTSTR lpSrc,
  _Out_opt_  LPTSTR lpDst,
  _In_       DWORD nSize
);

#ifdef __cplusplus
}
#endif

#endif