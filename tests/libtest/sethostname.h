/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#if (defined(WIN32) || defined(__SYMBIAN32__)) && !defined(CURL_STATICLIB)
#  if defined(BUILDING_LIBCURL)
#    define LIBHOSTNAME_EXTERN  __declspec(dllexport)
#  else
#    define LIBHOSTNAME_EXTERN  __declspec(dllimport)
#  endif
#else
#  ifdef CURL_HIDDEN_SYMBOLS
#    define LIBHOSTNAME_EXTERN CURL_EXTERN_SYMBOL
#  else
#    define LIBHOSTNAME_EXTERN
#  endif
#endif

#ifdef USE_WINSOCK
#  define FUNCALLCONV __stdcall
#else
#  define FUNCALLCONV
#endif

LIBHOSTNAME_EXTERN int FUNCALLCONV
  gethostname(char *name, GETHOSTNAME_TYPE_ARG2 namelen);

