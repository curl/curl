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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef HAVE_STRERROR_R
#if (!defined(HAVE_POSIX_STRERROR_R) &&  \
     !defined(HAVE_GLIBC_STRERROR_R)) || \
    (defined(HAVE_POSIX_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R))
#error "strerror_r MUST be either POSIX, glibc style"
#endif
#endif

#include <fetch/fetch.h>

#ifdef USE_LIBIDN2
#include <idn2.h>
#endif

#ifdef USE_WINDOWS_SSPI
#include "fetch_sspi.h"
#endif

#include "strerror.h"
/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

#if defined(_WIN32) || defined(_WIN32_WCE)
#define PRESERVE_WINDOWS_ERROR_CODE
#endif

const char *
fetch_easy_strerror(FETCHcode error)
{
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  switch (error)
  {
  case FETCHE_OK:
    return "No error";

  case FETCHE_UNSUPPORTED_PROTOCOL:
    return "Unsupported protocol";

  case FETCHE_FAILED_INIT:
    return "Failed initialization";

  case FETCHE_URL_MALFORMAT:
    return "URL using bad/illegal format or missing URL";

  case FETCHE_NOT_BUILT_IN:
    return "A requested feature, protocol or option was not found built-in in"
           " this libfetch due to a build-time decision.";

  case FETCHE_COULDNT_RESOLVE_PROXY:
    return "Could not resolve proxy name";

  case FETCHE_COULDNT_RESOLVE_HOST:
    return "Could not resolve hostname";

  case FETCHE_COULDNT_CONNECT:
    return "Could not connect to server";

  case FETCHE_WEIRD_SERVER_REPLY:
    return "Weird server reply";

  case FETCHE_REMOTE_ACCESS_DENIED:
    return "Access denied to remote resource";

  case FETCHE_FTP_ACCEPT_FAILED:
    return "FTP: The server failed to connect to data port";

  case FETCHE_FTP_ACCEPT_TIMEOUT:
    return "FTP: Accepting server connect has timed out";

  case FETCHE_FTP_PRET_FAILED:
    return "FTP: The server did not accept the PRET command.";

  case FETCHE_FTP_WEIRD_PASS_REPLY:
    return "FTP: unknown PASS reply";

  case FETCHE_FTP_WEIRD_PASV_REPLY:
    return "FTP: unknown PASV reply";

  case FETCHE_FTP_WEIRD_227_FORMAT:
    return "FTP: unknown 227 response format";

  case FETCHE_FTP_CANT_GET_HOST:
    return "FTP: cannot figure out the host in the PASV response";

  case FETCHE_HTTP2:
    return "Error in the HTTP2 framing layer";

  case FETCHE_FTP_COULDNT_SET_TYPE:
    return "FTP: could not set file type";

  case FETCHE_PARTIAL_FILE:
    return "Transferred a partial file";

  case FETCHE_FTP_COULDNT_RETR_FILE:
    return "FTP: could not retrieve (RETR failed) the specified file";

  case FETCHE_QUOTE_ERROR:
    return "Quote command returned error";

  case FETCHE_HTTP_RETURNED_ERROR:
    return "HTTP response code said error";

  case FETCHE_WRITE_ERROR:
    return "Failed writing received data to disk/application";

  case FETCHE_UPLOAD_FAILED:
    return "Upload failed (at start/before it took off)";

  case FETCHE_READ_ERROR:
    return "Failed to open/read local data from file/application";

  case FETCHE_OUT_OF_MEMORY:
    return "Out of memory";

  case FETCHE_OPERATION_TIMEDOUT:
    return "Timeout was reached";

  case FETCHE_FTP_PORT_FAILED:
    return "FTP: command PORT failed";

  case FETCHE_FTP_COULDNT_USE_REST:
    return "FTP: command REST failed";

  case FETCHE_RANGE_ERROR:
    return "Requested range was not delivered by the server";

  case FETCHE_SSL_CONNECT_ERROR:
    return "SSL connect error";

  case FETCHE_BAD_DOWNLOAD_RESUME:
    return "Could not resume download";

  case FETCHE_FILE_COULDNT_READ_FILE:
    return "Could not read a file:// file";

  case FETCHE_LDAP_CANNOT_BIND:
    return "LDAP: cannot bind";

  case FETCHE_LDAP_SEARCH_FAILED:
    return "LDAP: search failed";

  case FETCHE_ABORTED_BY_CALLBACK:
    return "Operation was aborted by an application callback";

  case FETCHE_BAD_FUNCTION_ARGUMENT:
    return "A libfetch function was given a bad argument";

  case FETCHE_INTERFACE_FAILED:
    return "Failed binding local connection end";

  case FETCHE_TOO_MANY_REDIRECTS:
    return "Number of redirects hit maximum amount";

  case FETCHE_UNKNOWN_OPTION:
    return "An unknown option was passed in to libfetch";

  case FETCHE_SETOPT_OPTION_SYNTAX:
    return "Malformed option provided in a setopt";

  case FETCHE_GOT_NOTHING:
    return "Server returned nothing (no headers, no data)";

  case FETCHE_SSL_ENGINE_NOTFOUND:
    return "SSL crypto engine not found";

  case FETCHE_SSL_ENGINE_SETFAILED:
    return "Can not set SSL crypto engine as default";

  case FETCHE_SSL_ENGINE_INITFAILED:
    return "Failed to initialise SSL crypto engine";

  case FETCHE_SEND_ERROR:
    return "Failed sending data to the peer";

  case FETCHE_RECV_ERROR:
    return "Failure when receiving data from the peer";

  case FETCHE_SSL_CERTPROBLEM:
    return "Problem with the local SSL certificate";

  case FETCHE_SSL_CIPHER:
    return "Could not use specified SSL cipher";

  case FETCHE_PEER_FAILED_VERIFICATION:
    return "SSL peer certificate or SSH remote key was not OK";

  case FETCHE_SSL_CACERT_BADFILE:
    return "Problem with the SSL CA cert (path? access rights?)";

  case FETCHE_BAD_CONTENT_ENCODING:
    return "Unrecognized or bad HTTP Content or Transfer-Encoding";

  case FETCHE_FILESIZE_EXCEEDED:
    return "Maximum file size exceeded";

  case FETCHE_USE_SSL_FAILED:
    return "Requested SSL level failed";

  case FETCHE_SSL_SHUTDOWN_FAILED:
    return "Failed to shut down the SSL connection";

  case FETCHE_SSL_CRL_BADFILE:
    return "Failed to load CRL file (path? access rights?, format?)";

  case FETCHE_SSL_ISSUER_ERROR:
    return "Issuer check against peer certificate failed";

  case FETCHE_SEND_FAIL_REWIND:
    return "Send failed since rewinding of the data stream failed";

  case FETCHE_LOGIN_DENIED:
    return "Login denied";

  case FETCHE_TFTP_NOTFOUND:
    return "TFTP: File Not Found";

  case FETCHE_TFTP_PERM:
    return "TFTP: Access Violation";

  case FETCHE_REMOTE_DISK_FULL:
    return "Disk full or allocation exceeded";

  case FETCHE_TFTP_ILLEGAL:
    return "TFTP: Illegal operation";

  case FETCHE_TFTP_UNKNOWNID:
    return "TFTP: Unknown transfer ID";

  case FETCHE_REMOTE_FILE_EXISTS:
    return "Remote file already exists";

  case FETCHE_TFTP_NOSUCHUSER:
    return "TFTP: No such user";

  case FETCHE_REMOTE_FILE_NOT_FOUND:
    return "Remote file not found";

  case FETCHE_SSH:
    return "Error in the SSH layer";

  case FETCHE_AGAIN:
    return "Socket not ready for send/recv";

  case FETCHE_RTSP_CSEQ_ERROR:
    return "RTSP CSeq mismatch or invalid CSeq";

  case FETCHE_RTSP_SESSION_ERROR:
    return "RTSP session error";

  case FETCHE_FTP_BAD_FILE_LIST:
    return "Unable to parse FTP file list";

  case FETCHE_CHUNK_FAILED:
    return "Chunk callback failed";

  case FETCHE_NO_CONNECTION_AVAILABLE:
    return "The max connection limit is reached";

  case FETCHE_SSL_PINNEDPUBKEYNOTMATCH:
    return "SSL public key does not match pinned public key";

  case FETCHE_SSL_INVALIDCERTSTATUS:
    return "SSL server certificate status verification FAILED";

  case FETCHE_HTTP2_STREAM:
    return "Stream error in the HTTP/2 framing layer";

  case FETCHE_RECURSIVE_API_CALL:
    return "API function called from within callback";

  case FETCHE_AUTH_ERROR:
    return "An authentication function returned an error";

  case FETCHE_HTTP3:
    return "HTTP/3 error";

  case FETCHE_QUIC_CONNECT_ERROR:
    return "QUIC connection error";

  case FETCHE_PROXY:
    return "proxy handshake error";

  case FETCHE_SSL_CLIENTCERT:
    return "SSL Client Certificate required";

  case FETCHE_UNRECOVERABLE_POLL:
    return "Unrecoverable error in select/poll";

  case FETCHE_TOO_LARGE:
    return "A value or data field grew larger than allowed";

  case FETCHE_ECH_REQUIRED:
    return "ECH attempted but failed";

    /* error codes not used by current libfetch */
  case FETCHE_OBSOLETE20:
  case FETCHE_OBSOLETE24:
  case FETCHE_OBSOLETE29:
  case FETCHE_OBSOLETE32:
  case FETCHE_OBSOLETE34:
  case FETCHE_OBSOLETE40:
  case FETCHE_OBSOLETE41:
  case FETCHE_OBSOLETE44:
  case FETCHE_OBSOLETE46:
  case FETCHE_OBSOLETE50:
  case FETCHE_OBSOLETE51:
  case FETCHE_OBSOLETE57:
  case FETCHE_OBSOLETE62:
  case FETCHE_OBSOLETE75:
  case FETCHE_OBSOLETE76:
  case FETCH_LAST:
    break;
  }
  /*
   * By using a switch, gcc -Wall will complain about enum values
   * which do not appear, helping keep this function up-to-date.
   * By using gcc -Wall -Werror, you cannot forget.
   *
   * A table would not have the same benefit. Most compilers will generate
   * code similar to a table in any case, so there is little performance gain
   * from a table. Something is broken for the user's application, anyways, so
   * does it matter how fast it _does not_ work?
   *
   * The line number for the error will be near this comment, which is why it
   * is here, and not at the start of the switch.
   */
  return "Unknown error";
#else
  if (!error)
    return "No error";
  else
    return "Error";
#endif
}

const char *
fetch_multi_strerror(FETCHMcode error)
{
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  switch (error)
  {
  case FETCHM_CALL_MULTI_PERFORM:
    return "Please call fetch_multi_perform() soon";

  case FETCHM_OK:
    return "No error";

  case FETCHM_BAD_HANDLE:
    return "Invalid multi handle";

  case FETCHM_BAD_EASY_HANDLE:
    return "Invalid easy handle";

  case FETCHM_OUT_OF_MEMORY:
    return "Out of memory";

  case FETCHM_INTERNAL_ERROR:
    return "Internal error";

  case FETCHM_BAD_SOCKET:
    return "Invalid socket argument";

  case FETCHM_UNKNOWN_OPTION:
    return "Unknown option";

  case FETCHM_ADDED_ALREADY:
    return "The easy handle is already added to a multi handle";

  case FETCHM_RECURSIVE_API_CALL:
    return "API function called from within callback";

  case FETCHM_WAKEUP_FAILURE:
    return "Wakeup is unavailable or failed";

  case FETCHM_BAD_FUNCTION_ARGUMENT:
    return "A libfetch function was given a bad argument";

  case FETCHM_ABORTED_BY_CALLBACK:
    return "Operation was aborted by an application callback";

  case FETCHM_UNRECOVERABLE_POLL:
    return "Unrecoverable error in select/poll";

  case FETCHM_LAST:
    break;
  }

  return "Unknown error";
#else
  if (error == FETCHM_OK)
    return "No error";
  else
    return "Error";
#endif
}

const char *
fetch_share_strerror(FETCHSHcode error)
{
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  switch (error)
  {
  case FETCHSHE_OK:
    return "No error";

  case FETCHSHE_BAD_OPTION:
    return "Unknown share option";

  case FETCHSHE_IN_USE:
    return "Share currently in use";

  case FETCHSHE_INVALID:
    return "Invalid share handle";

  case FETCHSHE_NOMEM:
    return "Out of memory";

  case FETCHSHE_NOT_BUILT_IN:
    return "Feature not enabled in this library";

  case FETCHSHE_LAST:
    break;
  }

  return "FETCHSHcode unknown";
#else
  if (error == FETCHSHE_OK)
    return "No error";
  else
    return "Error";
#endif
}

const char *
fetch_url_strerror(FETCHUcode error)
{
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  switch (error)
  {
  case FETCHUE_OK:
    return "No error";

  case FETCHUE_BAD_HANDLE:
    return "An invalid FETCHU pointer was passed as argument";

  case FETCHUE_BAD_PARTPOINTER:
    return "An invalid 'part' argument was passed as argument";

  case FETCHUE_MALFORMED_INPUT:
    return "Malformed input to a URL function";

  case FETCHUE_BAD_PORT_NUMBER:
    return "Port number was not a decimal number between 0 and 65535";

  case FETCHUE_UNSUPPORTED_SCHEME:
    return "Unsupported URL scheme";

  case FETCHUE_URLDECODE:
    return "URL decode error, most likely because of rubbish in the input";

  case FETCHUE_OUT_OF_MEMORY:
    return "A memory function failed";

  case FETCHUE_USER_NOT_ALLOWED:
    return "Credentials was passed in the URL when prohibited";

  case FETCHUE_UNKNOWN_PART:
    return "An unknown part ID was passed to a URL API function";

  case FETCHUE_NO_SCHEME:
    return "No scheme part in the URL";

  case FETCHUE_NO_USER:
    return "No user part in the URL";

  case FETCHUE_NO_PASSWORD:
    return "No password part in the URL";

  case FETCHUE_NO_OPTIONS:
    return "No options part in the URL";

  case FETCHUE_NO_HOST:
    return "No host part in the URL";

  case FETCHUE_NO_PORT:
    return "No port part in the URL";

  case FETCHUE_NO_QUERY:
    return "No query part in the URL";

  case FETCHUE_NO_FRAGMENT:
    return "No fragment part in the URL";

  case FETCHUE_NO_ZONEID:
    return "No zoneid part in the URL";

  case FETCHUE_BAD_LOGIN:
    return "Bad login part";

  case FETCHUE_BAD_IPV6:
    return "Bad IPv6 address";

  case FETCHUE_BAD_HOSTNAME:
    return "Bad hostname";

  case FETCHUE_BAD_FILE_URL:
    return "Bad file:// URL";

  case FETCHUE_BAD_SLASHES:
    return "Unsupported number of slashes following scheme";

  case FETCHUE_BAD_SCHEME:
    return "Bad scheme";

  case FETCHUE_BAD_PATH:
    return "Bad path";

  case FETCHUE_BAD_FRAGMENT:
    return "Bad fragment";

  case FETCHUE_BAD_QUERY:
    return "Bad query";

  case FETCHUE_BAD_PASSWORD:
    return "Bad password";

  case FETCHUE_BAD_USER:
    return "Bad user";

  case FETCHUE_LACKS_IDN:
    return "libfetch lacks IDN support";

  case FETCHUE_TOO_LARGE:
    return "A value or data field is larger than allowed";

  case FETCHUE_LAST:
    break;
  }

  return "FETCHUcode unknown";
#else
  if (error == FETCHUE_OK)
    return "No error";
  else
    return "Error";
#endif
}

#ifdef USE_WINSOCK
/* This is a helper function for Fetch_strerror that converts Winsock error
 * codes (WSAGetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
static const char *
get_winsock_error(int err, char *buf, size_t len)
{
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  const char *p;
  size_t alen;
#endif

  if (!len)
    return NULL;

  *buf = '\0';

#ifdef FETCH_DISABLE_VERBOSE_STRINGS
  (void)err;
  return NULL;
#else
  switch (err)
  {
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
#ifdef WSAEDISCON /* missing in SalfordC! */
  case WSAEDISCON:
    p = "Disconnected";
    break;
#endif
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
  if (alen < len)
    strcpy(buf, p);
  return buf;
#endif
}
#endif /* USE_WINSOCK */

#if defined(_WIN32) || defined(_WIN32_WCE)
/* This is a helper function for Fetch_strerror that converts Windows API error
 * codes (GetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
static const char *
get_winapi_error(int err, char *buf, size_t buflen)
{
  char *p;
  wchar_t wbuf[256];

  if (!buflen)
    return NULL;

  *buf = '\0';
  *wbuf = L'\0';

  /* We return the local codepage version of the error string because if it is
     output to the user's terminal it will likely be with functions which
     expect the local codepage (eg fprintf, failf, infof).
     FormatMessageW -> wcstombs is used for Windows CE compatibility. */
  if (FormatMessageW((FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS),
                     NULL, (DWORD)err,
                     LANG_NEUTRAL, wbuf, sizeof(wbuf) / sizeof(wchar_t), NULL))
  {
    size_t written = wcstombs(buf, wbuf, buflen - 1);
    if (written != (size_t)-1)
      buf[written] = '\0';
    else
      *buf = '\0';
  }

  /* Truncate multiple lines */
  p = strchr(buf, '\n');
  if (p)
  {
    if (p > buf && *(p - 1) == '\r')
      *(p - 1) = '\0';
    else
      *p = '\0';
  }

  return *buf ? buf : NULL;
}
#endif /* _WIN32 || _WIN32_WCE */

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
 * Call Fetch_sspi_strerror if the error code is definitely Windows SSPI.
 * Call Fetch_winapi_strerror if the error code is definitely Windows API.
 */
const char *Fetch_strerror(int err, char *buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
  DWORD old_win_err = GetLastError();
#endif
  int old_errno = errno;
  char *p;

  if (!buflen)
    return NULL;

#ifndef _WIN32
  DEBUGASSERT(err >= 0);
#endif

  *buf = '\0';

#if defined(_WIN32) || defined(_WIN32_WCE)
#if defined(_WIN32)
  /* 'sys_nerr' is the maximum errno number, it is not widely portable */
  if (err >= 0 && err < sys_nerr)
    msnprintf(buf, buflen, "%s", sys_errlist[err]);
  else
#endif
  {
    if (
#ifdef USE_WINSOCK
        !get_winsock_error(err, buf, buflen) &&
#endif
        !get_winapi_error(err, buf, buflen))
      msnprintf(buf, buflen, "Unknown error %d (%#x)", err, err);
  }
#else /* not Windows coming up */

#if defined(HAVE_STRERROR_R) && defined(HAVE_POSIX_STRERROR_R)
  /*
   * The POSIX-style strerror_r() may set errno to ERANGE if insufficient
   * storage is supplied via 'strerrbuf' and 'buflen' to hold the generated
   * message string, or EINVAL if 'errnum' is not a valid error number.
   */
  if (0 != strerror_r(err, buf, buflen))
  {
    if ('\0' == buf[0])
      msnprintf(buf, buflen, "Unknown error %d", err);
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
    if (msg)
      msnprintf(buf, buflen, "%s", msg);
    else
      msnprintf(buf, buflen, "Unknown error %d", err);
  }
#else
  {
    /* !checksrc! disable BANNEDFUNC 1 */
    const char *msg = strerror(err);
    if (msg)
      msnprintf(buf, buflen, "%s", msg);
    else
      msnprintf(buf, buflen, "Unknown error %d", err);
  }
#endif

#endif /* end of not Windows */

  /* strip trailing '\r\n' or '\n'. */
  p = strrchr(buf, '\n');
  if (p && (p - buf) >= 2)
    *p = '\0';
  p = strrchr(buf, '\r');
  if (p && (p - buf) >= 1)
    *p = '\0';

  if (errno != old_errno)
    errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
  if (old_win_err != GetLastError())
    SetLastError(old_win_err);
#endif

  return buf;
}

/*
 * Fetch_winapi_strerror:
 * Variant of Fetch_strerror if the error code is definitely Windows API.
 */
#if defined(_WIN32) || defined(_WIN32_WCE)
const char *Fetch_winapi_strerror(DWORD err, char *buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
  DWORD old_win_err = GetLastError();
#endif
  int old_errno = errno;

  if (!buflen)
    return NULL;

  *buf = '\0';

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  if (!get_winapi_error((int)err, buf, buflen))
  {
    msnprintf(buf, buflen, "Unknown error %lu (0x%08lX)", err, err);
  }
#else
  {
    const char *txt = (err == ERROR_SUCCESS) ? "No error" : "Error";
    if (strlen(txt) < buflen)
      strcpy(buf, txt);
  }
#endif

  if (errno != old_errno)
    errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
  if (old_win_err != GetLastError())
    SetLastError(old_win_err);
#endif

  return buf;
}
#endif /* _WIN32 || _WIN32_WCE */

#ifdef USE_WINDOWS_SSPI
/*
 * Fetch_sspi_strerror:
 * Variant of Fetch_strerror if the error code is definitely Windows SSPI.
 */
const char *Fetch_sspi_strerror(int err, char *buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
  DWORD old_win_err = GetLastError();
#endif
  int old_errno = errno;
  const char *txt;

  if (!buflen)
    return NULL;

  *buf = '\0';

#ifndef FETCH_DISABLE_VERBOSE_STRINGS

  switch (err)
  {
  case SEC_E_OK:
    txt = "No error";
    break;
#define SEC2TXT(sec) \
  case sec:          \
    txt = #sec;      \
    break
    SEC2TXT(CRYPT_E_REVOKED);
    SEC2TXT(CRYPT_E_NO_REVOCATION_DLL);
    SEC2TXT(CRYPT_E_NO_REVOCATION_CHECK);
    SEC2TXT(CRYPT_E_REVOCATION_OFFLINE);
    SEC2TXT(CRYPT_E_NOT_IN_REVOCATION_DATABASE);
    SEC2TXT(SEC_E_ALGORITHM_MISMATCH);
    SEC2TXT(SEC_E_BAD_BINDINGS);
    SEC2TXT(SEC_E_BAD_PKGID);
    SEC2TXT(SEC_E_BUFFER_TOO_SMALL);
    SEC2TXT(SEC_E_CANNOT_INSTALL);
    SEC2TXT(SEC_E_CANNOT_PACK);
    SEC2TXT(SEC_E_CERT_EXPIRED);
    SEC2TXT(SEC_E_CERT_UNKNOWN);
    SEC2TXT(SEC_E_CERT_WRONG_USAGE);
    SEC2TXT(SEC_E_CONTEXT_EXPIRED);
    SEC2TXT(SEC_E_CROSSREALM_DELEGATION_FAILURE);
    SEC2TXT(SEC_E_CRYPTO_SYSTEM_INVALID);
    SEC2TXT(SEC_E_DECRYPT_FAILURE);
    SEC2TXT(SEC_E_DELEGATION_POLICY);
    SEC2TXT(SEC_E_DELEGATION_REQUIRED);
    SEC2TXT(SEC_E_DOWNGRADE_DETECTED);
    SEC2TXT(SEC_E_ENCRYPT_FAILURE);
    SEC2TXT(SEC_E_ILLEGAL_MESSAGE);
    SEC2TXT(SEC_E_INCOMPLETE_CREDENTIALS);
    SEC2TXT(SEC_E_INCOMPLETE_MESSAGE);
    SEC2TXT(SEC_E_INSUFFICIENT_MEMORY);
    SEC2TXT(SEC_E_INTERNAL_ERROR);
    SEC2TXT(SEC_E_INVALID_HANDLE);
    SEC2TXT(SEC_E_INVALID_PARAMETER);
    SEC2TXT(SEC_E_INVALID_TOKEN);
    SEC2TXT(SEC_E_ISSUING_CA_UNTRUSTED);
    SEC2TXT(SEC_E_ISSUING_CA_UNTRUSTED_KDC);
    SEC2TXT(SEC_E_KDC_CERT_EXPIRED);
    SEC2TXT(SEC_E_KDC_CERT_REVOKED);
    SEC2TXT(SEC_E_KDC_INVALID_REQUEST);
    SEC2TXT(SEC_E_KDC_UNABLE_TO_REFER);
    SEC2TXT(SEC_E_KDC_UNKNOWN_ETYPE);
    SEC2TXT(SEC_E_LOGON_DENIED);
    SEC2TXT(SEC_E_MAX_REFERRALS_EXCEEDED);
    SEC2TXT(SEC_E_MESSAGE_ALTERED);
    SEC2TXT(SEC_E_MULTIPLE_ACCOUNTS);
    SEC2TXT(SEC_E_MUST_BE_KDC);
    SEC2TXT(SEC_E_NOT_OWNER);
    SEC2TXT(SEC_E_NO_AUTHENTICATING_AUTHORITY);
    SEC2TXT(SEC_E_NO_CREDENTIALS);
    SEC2TXT(SEC_E_NO_IMPERSONATION);
    SEC2TXT(SEC_E_NO_IP_ADDRESSES);
    SEC2TXT(SEC_E_NO_KERB_KEY);
    SEC2TXT(SEC_E_NO_PA_DATA);
    SEC2TXT(SEC_E_NO_S4U_PROT_SUPPORT);
    SEC2TXT(SEC_E_NO_TGT_REPLY);
    SEC2TXT(SEC_E_OUT_OF_SEQUENCE);
    SEC2TXT(SEC_E_PKINIT_CLIENT_FAILURE);
    SEC2TXT(SEC_E_PKINIT_NAME_MISMATCH);
    SEC2TXT(SEC_E_POLICY_NLTM_ONLY);
    SEC2TXT(SEC_E_QOP_NOT_SUPPORTED);
    SEC2TXT(SEC_E_REVOCATION_OFFLINE_C);
    SEC2TXT(SEC_E_REVOCATION_OFFLINE_KDC);
    SEC2TXT(SEC_E_SECPKG_NOT_FOUND);
    SEC2TXT(SEC_E_SECURITY_QOS_FAILED);
    SEC2TXT(SEC_E_SHUTDOWN_IN_PROGRESS);
    SEC2TXT(SEC_E_SMARTCARD_CERT_EXPIRED);
    SEC2TXT(SEC_E_SMARTCARD_CERT_REVOKED);
    SEC2TXT(SEC_E_SMARTCARD_LOGON_REQUIRED);
    SEC2TXT(SEC_E_STRONG_CRYPTO_NOT_SUPPORTED);
    SEC2TXT(SEC_E_TARGET_UNKNOWN);
    SEC2TXT(SEC_E_TIME_SKEW);
    SEC2TXT(SEC_E_TOO_MANY_PRINCIPALS);
    SEC2TXT(SEC_E_UNFINISHED_CONTEXT_DELETED);
    SEC2TXT(SEC_E_UNKNOWN_CREDENTIALS);
    SEC2TXT(SEC_E_UNSUPPORTED_FUNCTION);
    SEC2TXT(SEC_E_UNSUPPORTED_PREAUTH);
    SEC2TXT(SEC_E_UNTRUSTED_ROOT);
    SEC2TXT(SEC_E_WRONG_CREDENTIAL_HANDLE);
    SEC2TXT(SEC_E_WRONG_PRINCIPAL);
    SEC2TXT(SEC_I_COMPLETE_AND_CONTINUE);
    SEC2TXT(SEC_I_COMPLETE_NEEDED);
    SEC2TXT(SEC_I_CONTEXT_EXPIRED);
    SEC2TXT(SEC_I_CONTINUE_NEEDED);
    SEC2TXT(SEC_I_INCOMPLETE_CREDENTIALS);
    SEC2TXT(SEC_I_LOCAL_LOGON);
    SEC2TXT(SEC_I_NO_LSA_CONTEXT);
    SEC2TXT(SEC_I_RENEGOTIATE);
    SEC2TXT(SEC_I_SIGNATURE_NEEDED);
  default:
    txt = "Unknown error";
  }

  if (err == SEC_E_ILLEGAL_MESSAGE)
  {
    msnprintf(buf, buflen,
              "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs "
              "when a fatal SSL/TLS alert is received (e.g. handshake failed)."
              " More detail may be available in the Windows System event log.",
              err);
  }
  else
  {
    char msgbuf[256];
    if (get_winapi_error(err, msgbuf, sizeof(msgbuf)))
      msnprintf(buf, buflen, "%s (0x%08X) - %s", txt, err, msgbuf);
    else
      msnprintf(buf, buflen, "%s (0x%08X)", txt, err);
  }

#else
  if (err == SEC_E_OK)
    txt = "No error";
  else
    txt = "Error";
  if (buflen > strlen(txt))
    strcpy(buf, txt);
#endif

  if (errno != old_errno)
    errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
  if (old_win_err != GetLastError())
    SetLastError(old_win_err);
#endif

  return buf;
}
#endif /* USE_WINDOWS_SSPI */
