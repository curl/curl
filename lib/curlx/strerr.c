/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "../curl_setup.h"

#ifdef HAVE_STRERROR_R
#  if (!defined(HAVE_POSIX_STRERROR_R) && \
       !defined(HAVE_GLIBC_STRERROR_R)) || \
      (defined(HAVE_POSIX_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R))
#    error "strerror_r MUST be either POSIX, glibc style"
#  endif
#endif

#include <curl/curl.h>

#ifndef WITHOUT_LIBCURL
#include <curl/mprintf.h>
#define SNPRINTF curl_msnprintf
#else
/* when built for the test servers */

/* adjust for old MSVC */
#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif
#endif /* !WITHOUT_LIBCURL */

#include "winapi.h"
#include "strerr.h"
/* The last 2 #include files should be in this order */
#include "../curl_memory.h"
#include "../memdebug.h"

#ifdef USE_WINSOCK
/* This is a helper function for curlx_strerror that converts Winsock error
 * codes (WSAGetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
static const char *
get_winsock_error(int err, char *buf, size_t len)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  const char *p;
  size_t alen;
#endif

  if(!len)
    return NULL;

  *buf = '\0';

#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)err;
  return NULL;
#else
  switch(err) {
  case WSAEINTR:
    p = "Call interrupted";
    break;
  case WSAEBADF:
    p = "Bad file";
    break;
  case WSAEACCES:
    p = "Bad access";
    break;
  case WSAEFAULT:
    p = "Bad argument";
    break;
  case WSAEINVAL:
    p = "Invalid arguments";
    break;
  case WSAEMFILE:
    p = "Out of file descriptors";
    break;
  case WSAEWOULDBLOCK:
    p = "Call would block";
    break;
  case WSAEINPROGRESS:
  case WSAEALREADY:
    p = "Blocking call in progress";
    break;
  case WSAENOTSOCK:
    p = "Descriptor is not a socket";
    break;
  case WSAEDESTADDRREQ:
    p = "Need destination address";
    break;
  case WSAEMSGSIZE:
    p = "Bad message size";
    break;
  case WSAEPROTOTYPE:
    p = "Bad protocol";
    break;
  case WSAENOPROTOOPT:
    p = "Protocol option is unsupported";
    break;
  case WSAEPROTONOSUPPORT:
    p = "Protocol is unsupported";
    break;
  case WSAESOCKTNOSUPPORT:
    p = "Socket is unsupported";
    break;
  case WSAEOPNOTSUPP:
    p = "Operation not supported";
    break;
  case WSAEAFNOSUPPORT:
    p = "Address family not supported";
    break;
  case WSAEPFNOSUPPORT:
    p = "Protocol family not supported";
    break;
  case WSAEADDRINUSE:
    p = "Address already in use";
    break;
  case WSAEADDRNOTAVAIL:
    p = "Address not available";
    break;
  case WSAENETDOWN:
    p = "Network down";
    break;
  case WSAENETUNREACH:
    p = "Network unreachable";
    break;
  case WSAENETRESET:
    p = "Network has been reset";
    break;
  case WSAECONNABORTED:
    p = "Connection was aborted";
    break;
  case WSAECONNRESET:
    p = "Connection was reset";
    break;
  case WSAENOBUFS:
    p = "No buffer space";
    break;
  case WSAEISCONN:
    p = "Socket is already connected";
    break;
  case WSAENOTCONN:
    p = "Socket is not connected";
    break;
  case WSAESHUTDOWN:
    p = "Socket has been shut down";
    break;
  case WSAETOOMANYREFS:
    p = "Too many references";
    break;
  case WSAETIMEDOUT:
    p = "Timed out";
    break;
  case WSAECONNREFUSED:
    p = "Connection refused";
    break;
  case WSAELOOP:
    p = "Loop??";
    break;
  case WSAENAMETOOLONG:
    p = "Name too long";
    break;
  case WSAEHOSTDOWN:
    p = "Host down";
    break;
  case WSAEHOSTUNREACH:
    p = "Host unreachable";
    break;
  case WSAENOTEMPTY:
    p = "Not empty";
    break;
  case WSAEPROCLIM:
    p = "Process limit reached";
    break;
  case WSAEUSERS:
    p = "Too many users";
    break;
  case WSAEDQUOT:
    p = "Bad quota";
    break;
  case WSAESTALE:
    p = "Something is stale";
    break;
  case WSAEREMOTE:
    p = "Remote error";
    break;
  case WSAEDISCON:
    p = "Disconnected";
    break;
    /* Extended Winsock errors */
  case WSASYSNOTREADY:
    p = "Winsock library is not ready";
    break;
  case WSANOTINITIALISED:
    p = "Winsock library not initialised";
    break;
  case WSAVERNOTSUPPORTED:
    p = "Winsock version not supported";
    break;

    /* getXbyY() errors (already handled in herrmsg):
     * Authoritative Answer: Host not found */
  case WSAHOST_NOT_FOUND:
    p = "Host not found";
    break;

    /* Non-Authoritative: Host not found, or SERVERFAIL */
  case WSATRY_AGAIN:
    p = "Host not found, try again";
    break;

    /* Non recoverable errors, FORMERR, REFUSED, NOTIMP */
  case WSANO_RECOVERY:
    p = "Unrecoverable error in call to nameserver";
    break;

    /* Valid name, no data record of requested type */
  case WSANO_DATA:
    p = "No data record of requested type";
    break;

  default:
    return NULL;
  }
  alen = strlen(p);
  if(alen < len)
    strcpy(buf, p);
  return buf;
#endif
}
#endif /* USE_WINSOCK */

/*
 * Our thread-safe and smart strerror() replacement.
 *
 * The 'err' argument passed in to this function MUST be a true errno number
 * as reported on this system. We do no range checking on the number before
 * we pass it to the "number-to-message" conversion function and there might
 * be systems that do not do proper range checking in there themselves.
 *
 * We do not do range checking (on systems other than Windows) since there is
 * no good reliable and portable way to do it.
 *
 * On Windows different types of error codes overlap. This function has an
 * order of preference when trying to match error codes:
 * CRT (errno), Winsock (WSAGetLastError), Windows API (GetLastError).
 *
 * It may be more correct to call one of the variant functions instead:
 * Call Curl_sspi_strerror if the error code is definitely Windows SSPI.
 * Call curlx_winapi_strerror if the error code is definitely Windows API.
 */
const char *curlx_strerror(int err, char *buf, size_t buflen)
{
#ifdef _WIN32
  DWORD old_win_err = GetLastError();
#endif
  int old_errno = errno;
  char *p;

  if(!buflen)
    return NULL;

#ifndef _WIN32
  DEBUGASSERT(err >= 0);
#endif

  *buf = '\0';

#ifdef _WIN32
#ifndef UNDER_CE
  /* 'sys_nerr' is the maximum errno number, it is not widely portable */
  if(err >= 0 && err < sys_nerr)
    SNPRINTF(buf, buflen, "%s", sys_errlist[err]);
  else
#endif
  {
    if(
#ifdef USE_WINSOCK
      !get_winsock_error(err, buf, buflen) &&
#endif
      !curlx_get_winapi_error((DWORD)err, buf, buflen))
      SNPRINTF(buf, buflen, "Unknown error %d (%#x)", err, err);
  }
#else /* !_WIN32 */

#if defined(HAVE_STRERROR_R) && defined(HAVE_POSIX_STRERROR_R)
  /*
   * The POSIX-style strerror_r() may set errno to ERANGE if insufficient
   * storage is supplied via 'strerrbuf' and 'buflen' to hold the generated
   * message string, or EINVAL if 'errnum' is not a valid error number.
   */
  if(strerror_r(err, buf, buflen) &&
     buflen > sizeof("Unknown error ") + 20) {
    if(buf[0] == '\0')
      SNPRINTF(buf, buflen, "Unknown error %d", err);
  }
#elif defined(HAVE_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R)
  /*
   * The glibc-style strerror_r() only *might* use the buffer we pass to
   * the function, but it always returns the error message as a pointer,
   * so we must copy that string unconditionally (if non-NULL).
   */
  {
    char buffer[256];
    char *msg = strerror_r(err, buffer, sizeof(buffer));
    if(msg && buflen > 1)
      SNPRINTF(buf, buflen, "%s", msg);
    else if(buflen > sizeof("Unknown error ") + 20)
      SNPRINTF(buf, buflen, "Unknown error %d", err);
  }
#else
  {
    /* !checksrc! disable BANNEDFUNC 1 */
    const char *msg = strerror(err);
    if(msg && buflen > 1)
      SNPRINTF(buf, buflen, "%s", msg);
    else if(buflen > sizeof("Unknown error ") + 20)
      SNPRINTF(buf, buflen, "Unknown error %d", err);
  }
#endif

#endif /* _WIN32 */

  /* strip trailing '\r\n' or '\n'. */
  p = strrchr(buf, '\n');
  if(p && (p - buf) >= 2)
    *p = '\0';
  p = strrchr(buf, '\r');
  if(p && (p - buf) >= 1)
    *p = '\0';

  if(errno != old_errno)
    CURL_SETERRNO(old_errno);

#ifdef _WIN32
  if(old_win_err != GetLastError())
    SetLastError(old_win_err);
#endif

  return buf;
}
