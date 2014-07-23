/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2004 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef HAVE_STRERROR_R
#  if (!defined(HAVE_POSIX_STRERROR_R) && \
       !defined(HAVE_GLIBC_STRERROR_R) && \
       !defined(HAVE_VXWORKS_STRERROR_R)) || \
      (defined(HAVE_POSIX_STRERROR_R) && defined(HAVE_VXWORKS_STRERROR_R)) || \
      (defined(HAVE_GLIBC_STRERROR_R) && defined(HAVE_VXWORKS_STRERROR_R)) || \
      (defined(HAVE_POSIX_STRERROR_R) && defined(HAVE_GLIBC_STRERROR_R))
#    error "strerror_r MUST be either POSIX, glibc or vxworks-style"
#  endif
#endif

#include <curl/curl.h>

#ifdef USE_LIBIDN
#include <idna.h>
#endif

#include "strerror.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

const char *
curl_easy_strerror(CURLcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (error) {
  case CURLE_OK:
    return "No error";

  case CURLE_UNSUPPORTED_PROTOCOL:
    return "Unsupported protocol";

  case CURLE_FAILED_INIT:
    return "Failed initialization";

  case CURLE_URL_MALFORMAT:
    return "URL using bad/illegal format or missing URL";

  case CURLE_NOT_BUILT_IN:
    return "A requested feature, protocol or option was not found built-in in"
      " this libcurl due to a build-time decision.";

  case CURLE_COULDNT_RESOLVE_PROXY:
    return "Couldn't resolve proxy name";

  case CURLE_COULDNT_RESOLVE_HOST:
    return "Couldn't resolve host name";

  case CURLE_COULDNT_CONNECT:
    return "Couldn't connect to server";

  case CURLE_FTP_WEIRD_SERVER_REPLY:
    return "FTP: weird server reply";

  case CURLE_REMOTE_ACCESS_DENIED:
    return "Access denied to remote resource";

  case CURLE_FTP_ACCEPT_FAILED:
    return "FTP: The server failed to connect to data port";

  case CURLE_FTP_ACCEPT_TIMEOUT:
    return "FTP: Accepting server connect has timed out";

  case CURLE_FTP_PRET_FAILED:
    return "FTP: The server did not accept the PRET command.";

  case CURLE_FTP_WEIRD_PASS_REPLY:
    return "FTP: unknown PASS reply";

  case CURLE_FTP_WEIRD_PASV_REPLY:
    return "FTP: unknown PASV reply";

  case CURLE_FTP_WEIRD_227_FORMAT:
    return "FTP: unknown 227 response format";

  case CURLE_FTP_CANT_GET_HOST:
    return "FTP: can't figure out the host in the PASV response";

  case CURLE_HTTP2:
    return "Error in the HTTP2 framing layer";

  case CURLE_FTP_COULDNT_SET_TYPE:
    return "FTP: couldn't set file type";

  case CURLE_PARTIAL_FILE:
    return "Transferred a partial file";

  case CURLE_FTP_COULDNT_RETR_FILE:
    return "FTP: couldn't retrieve (RETR failed) the specified file";

  case CURLE_QUOTE_ERROR:
    return "Quote command returned error";

  case CURLE_HTTP_RETURNED_ERROR:
    return "HTTP response code said error";

  case CURLE_WRITE_ERROR:
    return "Failed writing received data to disk/application";

  case CURLE_UPLOAD_FAILED:
    return "Upload failed (at start/before it took off)";

  case CURLE_READ_ERROR:
    return "Failed to open/read local data from file/application";

  case CURLE_OUT_OF_MEMORY:
    return "Out of memory";

  case CURLE_OPERATION_TIMEDOUT:
    return "Timeout was reached";

  case CURLE_FTP_PORT_FAILED:
    return "FTP: command PORT failed";

  case CURLE_FTP_COULDNT_USE_REST:
    return "FTP: command REST failed";

  case CURLE_RANGE_ERROR:
    return "Requested range was not delivered by the server";

  case CURLE_HTTP_POST_ERROR:
    return "Internal problem setting up the POST";

  case CURLE_SSL_CONNECT_ERROR:
    return "SSL connect error";

  case CURLE_BAD_DOWNLOAD_RESUME:
    return "Couldn't resume download";

  case CURLE_FILE_COULDNT_READ_FILE:
    return "Couldn't read a file:// file";

  case CURLE_LDAP_CANNOT_BIND:
    return "LDAP: cannot bind";

  case CURLE_LDAP_SEARCH_FAILED:
    return "LDAP: search failed";

  case CURLE_FUNCTION_NOT_FOUND:
    return "A required function in the library was not found";

  case CURLE_ABORTED_BY_CALLBACK:
    return "Operation was aborted by an application callback";

  case CURLE_BAD_FUNCTION_ARGUMENT:
    return "A libcurl function was given a bad argument";

  case CURLE_INTERFACE_FAILED:
    return "Failed binding local connection end";

  case CURLE_TOO_MANY_REDIRECTS :
    return "Number of redirects hit maximum amount";

  case CURLE_UNKNOWN_OPTION:
    return "An unknown option was passed in to libcurl";

  case CURLE_TELNET_OPTION_SYNTAX :
    return "Malformed telnet option";

  case CURLE_PEER_FAILED_VERIFICATION:
    return "SSL peer certificate or SSH remote key was not OK";

  case CURLE_GOT_NOTHING:
    return "Server returned nothing (no headers, no data)";

  case CURLE_SSL_ENGINE_NOTFOUND:
    return "SSL crypto engine not found";

  case CURLE_SSL_ENGINE_SETFAILED:
    return "Can not set SSL crypto engine as default";

  case CURLE_SSL_ENGINE_INITFAILED:
    return "Failed to initialise SSL crypto engine";

  case CURLE_SEND_ERROR:
    return "Failed sending data to the peer";

  case CURLE_RECV_ERROR:
    return "Failure when receiving data from the peer";

  case CURLE_SSL_CERTPROBLEM:
    return "Problem with the local SSL certificate";

  case CURLE_SSL_CIPHER:
    return "Couldn't use specified SSL cipher";

  case CURLE_SSL_CACERT:
    return "Peer certificate cannot be authenticated with given CA "
      "certificates";

  case CURLE_SSL_CACERT_BADFILE:
    return "Problem with the SSL CA cert (path? access rights?)";

  case CURLE_BAD_CONTENT_ENCODING:
    return "Unrecognized or bad HTTP Content or Transfer-Encoding";

  case CURLE_LDAP_INVALID_URL:
    return "Invalid LDAP URL";

  case CURLE_FILESIZE_EXCEEDED:
    return "Maximum file size exceeded";

  case CURLE_USE_SSL_FAILED:
    return "Requested SSL level failed";

  case CURLE_SSL_SHUTDOWN_FAILED:
    return "Failed to shut down the SSL connection";

  case CURLE_SSL_CRL_BADFILE:
    return "Failed to load CRL file (path? access rights?, format?)";

  case CURLE_SSL_ISSUER_ERROR:
    return "Issuer check against peer certificate failed";

  case CURLE_SEND_FAIL_REWIND:
    return "Send failed since rewinding of the data stream failed";

  case CURLE_LOGIN_DENIED:
    return "Login denied";

  case CURLE_TFTP_NOTFOUND:
    return "TFTP: File Not Found";

  case CURLE_TFTP_PERM:
    return "TFTP: Access Violation";

  case CURLE_REMOTE_DISK_FULL:
    return "Disk full or allocation exceeded";

  case CURLE_TFTP_ILLEGAL:
    return "TFTP: Illegal operation";

  case CURLE_TFTP_UNKNOWNID:
    return "TFTP: Unknown transfer ID";

  case CURLE_REMOTE_FILE_EXISTS:
    return "Remote file already exists";

  case CURLE_TFTP_NOSUCHUSER:
    return "TFTP: No such user";

  case CURLE_CONV_FAILED:
    return "Conversion failed";

  case CURLE_CONV_REQD:
    return "Caller must register CURLOPT_CONV_ callback options";

  case CURLE_REMOTE_FILE_NOT_FOUND:
    return "Remote file not found";

  case CURLE_SSH:
    return "Error in the SSH layer";

  case CURLE_AGAIN:
    return "Socket not ready for send/recv";

  case CURLE_RTSP_CSEQ_ERROR:
    return "RTSP CSeq mismatch or invalid CSeq";

  case CURLE_RTSP_SESSION_ERROR:
    return "RTSP session error";

  case CURLE_FTP_BAD_FILE_LIST:
    return "Unable to parse FTP file list";

  case CURLE_CHUNK_FAILED:
    return "Chunk callback failed";

  case CURLE_NO_CONNECTION_AVAILABLE:
    return "The max connection limit is reached";

    /* error codes not used by current libcurl */
  case CURLE_OBSOLETE20:
  case CURLE_OBSOLETE24:
  case CURLE_OBSOLETE29:
  case CURLE_OBSOLETE32:
  case CURLE_OBSOLETE40:
  case CURLE_OBSOLETE44:
  case CURLE_OBSOLETE46:
  case CURLE_OBSOLETE50:
  case CURLE_OBSOLETE57:
  case CURL_LAST:
    break;
  }
  /*
   * By using a switch, gcc -Wall will complain about enum values
   * which do not appear, helping keep this function up-to-date.
   * By using gcc -Wall -Werror, you can't forget.
   *
   * A table would not have the same benefit.  Most compilers will
   * generate code very similar to a table in any case, so there
   * is little performance gain from a table.  And something is broken
   * for the user's application, anyways, so does it matter how fast
   * it _doesn't_ work?
   *
   * The line number for the error will be near this comment, which
   * is why it is here, and not at the start of the switch.
   */
  return "Unknown error";
#else
  if(error == CURLE_OK)
    return "No error";
  else
    return "Error";
#endif
}

const char *
curl_multi_strerror(CURLMcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (error) {
  case CURLM_CALL_MULTI_PERFORM:
    return "Please call curl_multi_perform() soon";

  case CURLM_OK:
    return "No error";

  case CURLM_BAD_HANDLE:
    return "Invalid multi handle";

  case CURLM_BAD_EASY_HANDLE:
    return "Invalid easy handle";

  case CURLM_OUT_OF_MEMORY:
    return "Out of memory";

  case CURLM_INTERNAL_ERROR:
    return "Internal error";

  case CURLM_BAD_SOCKET:
    return "Invalid socket argument";

  case CURLM_UNKNOWN_OPTION:
    return "Unknown option";

  case CURLM_ADDED_ALREADY:
    return "The easy handle is already added to a multi handle";

  case CURLM_LAST:
    break;
  }

  return "Unknown error";
#else
  if(error == CURLM_OK)
    return "No error";
  else
    return "Error";
#endif
}

const char *
curl_share_strerror(CURLSHcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (error) {
  case CURLSHE_OK:
    return "No error";

  case CURLSHE_BAD_OPTION:
    return "Unknown share option";

  case CURLSHE_IN_USE:
    return "Share currently in use";

  case CURLSHE_INVALID:
    return "Invalid share handle";

  case CURLSHE_NOMEM:
    return "Out of memory";

  case CURLSHE_NOT_BUILT_IN:
    return "Feature not enabled in this library";

  case CURLSHE_LAST:
    break;
  }

  return "CURLSHcode unknown";
#else
  if(error == CURLSHE_OK)
    return "No error";
  else
    return "Error";
#endif
}

#ifdef USE_WINSOCK

/* This function handles most / all (?) Winsock errors cURL is able to produce.
 */
static const char *
get_winsock_error (int err, char *buf, size_t len)
{
  const char *p;

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (err) {
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
#ifdef WSAEDISCON  /* missing in SalfordC! */
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
#else
  if(err == CURLE_OK)
    return NULL;
  else
    p = "error";
#endif
  strncpy (buf, p, len);
  buf [len-1] = '\0';
  return buf;
}
#endif   /* USE_WINSOCK */

/*
 * Our thread-safe and smart strerror() replacement.
 *
 * The 'err' argument passed in to this function MUST be a true errno number
 * as reported on this system. We do no range checking on the number before
 * we pass it to the "number-to-message" conversion function and there might
 * be systems that don't do proper range checking in there themselves.
 *
 * We don't do range checking (on systems other than Windows) since there is
 * no good reliable and portable way to do it.
 */
const char *Curl_strerror(struct connectdata *conn, int err)
{
  char *buf, *p;
  size_t max;
  int old_errno = ERRNO;

  DEBUGASSERT(conn);
  DEBUGASSERT(err >= 0);

  buf = conn->syserr_buf;
  max = sizeof(conn->syserr_buf)-1;
  *buf = '\0';

#ifdef USE_WINSOCK

#ifdef _WIN32_WCE
  {
    wchar_t wbuf[256];
    wbuf[0] = L'\0';

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                  LANG_NEUTRAL, wbuf, sizeof(wbuf)/sizeof(wchar_t), NULL);
    wcstombs(buf,wbuf,max);
  }
#else
  /* 'sys_nerr' is the maximum errno number, it is not widely portable */
  if(err >= 0 && err < sys_nerr)
    strncpy(buf, strerror(err), max);
  else {
    if(!get_winsock_error(err, buf, max) &&
       !FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                       LANG_NEUTRAL, buf, (DWORD)max, NULL))
      snprintf(buf, max, "Unknown error %d (%#x)", err, err);
  }
#endif

#else /* not USE_WINSOCK coming up */

#if defined(HAVE_STRERROR_R) && defined(HAVE_POSIX_STRERROR_R)
 /*
  * The POSIX-style strerror_r() may set errno to ERANGE if insufficient
  * storage is supplied via 'strerrbuf' and 'buflen' to hold the generated
  * message string, or EINVAL if 'errnum' is not a valid error number.
  */
  if(0 != strerror_r(err, buf, max)) {
    if('\0' == buf[0])
      snprintf(buf, max, "Unknown error %d", err);
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
    if(msg)
      strncpy(buf, msg, max);
    else
      snprintf(buf, max, "Unknown error %d", err);
  }
#elif defined(HAVE_STRERROR_R) && defined(HAVE_VXWORKS_STRERROR_R)
 /*
  * The vxworks-style strerror_r() does use the buffer we pass to the function.
  * The buffer size should be at least NAME_MAX (256)
  */
  {
    char buffer[256];
    if(OK == strerror_r(err, buffer))
      strncpy(buf, buffer, max);
    else
      snprintf(buf, max, "Unknown error %d", err);
  }
#else
  {
    char *msg = strerror(err);
    if(msg)
      strncpy(buf, msg, max);
    else
      snprintf(buf, max, "Unknown error %d", err);
  }
#endif

#endif /* end of ! USE_WINSOCK */

  buf[max] = '\0'; /* make sure the string is zero terminated */

  /* strip trailing '\r\n' or '\n'. */
  if((p = strrchr(buf,'\n')) != NULL && (p - buf) >= 2)
     *p = '\0';
  if((p = strrchr(buf,'\r')) != NULL && (p - buf) >= 1)
     *p = '\0';

  if(old_errno != ERRNO)
    SET_ERRNO(old_errno);

  return buf;
}

#ifdef USE_LIBIDN
/*
 * Return error-string for libidn status as returned from idna_to_ascii_lz().
 */
const char *Curl_idn_strerror (struct connectdata *conn, int err)
{
#ifdef HAVE_IDNA_STRERROR
  (void)conn;
  return idna_strerror((Idna_rc) err);
#else
  const char *str;
  char *buf;
  size_t max;

  DEBUGASSERT(conn);

  buf = conn->syserr_buf;
  max = sizeof(conn->syserr_buf)-1;
  *buf = '\0';

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch ((Idna_rc)err) {
    case IDNA_SUCCESS:
      str = "No error";
      break;
    case IDNA_STRINGPREP_ERROR:
      str = "Error in string preparation";
      break;
    case IDNA_PUNYCODE_ERROR:
      str = "Error in Punycode operation";
      break;
    case IDNA_CONTAINS_NON_LDH:
      str = "Illegal ASCII characters";
      break;
    case IDNA_CONTAINS_MINUS:
      str = "Contains minus";
      break;
    case IDNA_INVALID_LENGTH:
      str = "Invalid output length";
      break;
    case IDNA_NO_ACE_PREFIX:
      str = "No ACE prefix (\"xn--\")";
      break;
    case IDNA_ROUNDTRIP_VERIFY_ERROR:
      str = "Round trip verify error";
      break;
    case IDNA_CONTAINS_ACE_PREFIX:
      str = "Already have ACE prefix (\"xn--\")";
      break;
    case IDNA_ICONV_ERROR:
      str = "Locale conversion failed";
      break;
    case IDNA_MALLOC_ERROR:
      str = "Allocation failed";
      break;
    case IDNA_DLOPEN_ERROR:
      str = "dlopen() error";
      break;
    default:
      snprintf(buf, max, "error %d", err);
      str = NULL;
      break;
  }
#else
  if((Idna_rc)err == IDNA_SUCCESS)
    str = "No error";
  else
    str = "Error";
#endif
  if(str)
    strncpy(buf, str, max);
  buf[max] = '\0';
  return (buf);
#endif
}
#endif  /* USE_LIBIDN */

#ifdef USE_WINDOWS_SSPI
const char *Curl_sspi_strerror (struct connectdata *conn, int err)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  char txtbuf[80];
  char msgbuf[sizeof(conn->syserr_buf)];
  char *p, *str, *msg = NULL;
  bool msg_formatted = FALSE;
  int old_errno;
#endif
  const char *txt;
  char *outbuf;
  size_t outmax;

  DEBUGASSERT(conn);

  outbuf = conn->syserr_buf;
  outmax = sizeof(conn->syserr_buf)-1;
  *outbuf = '\0';

#ifndef CURL_DISABLE_VERBOSE_STRINGS

  old_errno = ERRNO;

  switch (err) {
    case SEC_E_OK:
      txt = "No error";
      break;
    case SEC_E_ALGORITHM_MISMATCH:
      txt = "SEC_E_ALGORITHM_MISMATCH";
      break;
    case SEC_E_BAD_BINDINGS:
      txt = "SEC_E_BAD_BINDINGS";
      break;
    case SEC_E_BAD_PKGID:
      txt = "SEC_E_BAD_PKGID";
      break;
    case SEC_E_BUFFER_TOO_SMALL:
      txt = "SEC_E_BUFFER_TOO_SMALL";
      break;
    case SEC_E_CANNOT_INSTALL:
      txt = "SEC_E_CANNOT_INSTALL";
      break;
    case SEC_E_CANNOT_PACK:
      txt = "SEC_E_CANNOT_PACK";
      break;
    case SEC_E_CERT_EXPIRED:
      txt = "SEC_E_CERT_EXPIRED";
      break;
    case SEC_E_CERT_UNKNOWN:
      txt = "SEC_E_CERT_UNKNOWN";
      break;
    case SEC_E_CERT_WRONG_USAGE:
      txt = "SEC_E_CERT_WRONG_USAGE";
      break;
    case SEC_E_CONTEXT_EXPIRED:
      txt = "SEC_E_CONTEXT_EXPIRED";
      break;
    case SEC_E_CROSSREALM_DELEGATION_FAILURE:
      txt = "SEC_E_CROSSREALM_DELEGATION_FAILURE";
      break;
    case SEC_E_CRYPTO_SYSTEM_INVALID:
      txt = "SEC_E_CRYPTO_SYSTEM_INVALID";
      break;
    case SEC_E_DECRYPT_FAILURE:
      txt = "SEC_E_DECRYPT_FAILURE";
      break;
    case SEC_E_DELEGATION_POLICY:
      txt = "SEC_E_DELEGATION_POLICY";
      break;
    case SEC_E_DELEGATION_REQUIRED:
      txt = "SEC_E_DELEGATION_REQUIRED";
      break;
    case SEC_E_DOWNGRADE_DETECTED:
      txt = "SEC_E_DOWNGRADE_DETECTED";
      break;
    case SEC_E_ENCRYPT_FAILURE:
      txt = "SEC_E_ENCRYPT_FAILURE";
      break;
    case SEC_E_ILLEGAL_MESSAGE:
      txt = "SEC_E_ILLEGAL_MESSAGE";
      break;
    case SEC_E_INCOMPLETE_CREDENTIALS:
      txt = "SEC_E_INCOMPLETE_CREDENTIALS";
      break;
    case SEC_E_INCOMPLETE_MESSAGE:
      txt = "SEC_E_INCOMPLETE_MESSAGE";
      break;
    case SEC_E_INSUFFICIENT_MEMORY:
      txt = "SEC_E_INSUFFICIENT_MEMORY";
      break;
    case SEC_E_INTERNAL_ERROR:
      txt = "SEC_E_INTERNAL_ERROR";
      break;
    case SEC_E_INVALID_HANDLE:
      txt = "SEC_E_INVALID_HANDLE";
      break;
    case SEC_E_INVALID_PARAMETER:
      txt = "SEC_E_INVALID_PARAMETER";
      break;
    case SEC_E_INVALID_TOKEN:
      txt = "SEC_E_INVALID_TOKEN";
      break;
    case SEC_E_ISSUING_CA_UNTRUSTED:
      txt = "SEC_E_ISSUING_CA_UNTRUSTED";
      break;
    case SEC_E_ISSUING_CA_UNTRUSTED_KDC:
      txt = "SEC_E_ISSUING_CA_UNTRUSTED_KDC";
      break;
    case SEC_E_KDC_CERT_EXPIRED:
      txt = "SEC_E_KDC_CERT_EXPIRED";
      break;
    case SEC_E_KDC_CERT_REVOKED:
      txt = "SEC_E_KDC_CERT_REVOKED";
      break;
    case SEC_E_KDC_INVALID_REQUEST:
      txt = "SEC_E_KDC_INVALID_REQUEST";
      break;
    case SEC_E_KDC_UNABLE_TO_REFER:
      txt = "SEC_E_KDC_UNABLE_TO_REFER";
      break;
    case SEC_E_KDC_UNKNOWN_ETYPE:
      txt = "SEC_E_KDC_UNKNOWN_ETYPE";
      break;
    case SEC_E_LOGON_DENIED:
      txt = "SEC_E_LOGON_DENIED";
      break;
    case SEC_E_MAX_REFERRALS_EXCEEDED:
      txt = "SEC_E_MAX_REFERRALS_EXCEEDED";
      break;
    case SEC_E_MESSAGE_ALTERED:
      txt = "SEC_E_MESSAGE_ALTERED";
      break;
    case SEC_E_MULTIPLE_ACCOUNTS:
      txt = "SEC_E_MULTIPLE_ACCOUNTS";
      break;
    case SEC_E_MUST_BE_KDC:
      txt = "SEC_E_MUST_BE_KDC";
      break;
    case SEC_E_NOT_OWNER:
      txt = "SEC_E_NOT_OWNER";
      break;
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
      txt = "SEC_E_NO_AUTHENTICATING_AUTHORITY";
      break;
    case SEC_E_NO_CREDENTIALS:
      txt = "SEC_E_NO_CREDENTIALS";
      break;
    case SEC_E_NO_IMPERSONATION:
      txt = "SEC_E_NO_IMPERSONATION";
      break;
    case SEC_E_NO_IP_ADDRESSES:
      txt = "SEC_E_NO_IP_ADDRESSES";
      break;
    case SEC_E_NO_KERB_KEY:
      txt = "SEC_E_NO_KERB_KEY";
      break;
    case SEC_E_NO_PA_DATA:
      txt = "SEC_E_NO_PA_DATA";
      break;
    case SEC_E_NO_S4U_PROT_SUPPORT:
      txt = "SEC_E_NO_S4U_PROT_SUPPORT";
      break;
    case SEC_E_NO_TGT_REPLY:
      txt = "SEC_E_NO_TGT_REPLY";
      break;
    case SEC_E_OUT_OF_SEQUENCE:
      txt = "SEC_E_OUT_OF_SEQUENCE";
      break;
    case SEC_E_PKINIT_CLIENT_FAILURE:
      txt = "SEC_E_PKINIT_CLIENT_FAILURE";
      break;
    case SEC_E_PKINIT_NAME_MISMATCH:
      txt = "SEC_E_PKINIT_NAME_MISMATCH";
      break;
    case SEC_E_POLICY_NLTM_ONLY:
      txt = "SEC_E_POLICY_NLTM_ONLY";
      break;
    case SEC_E_QOP_NOT_SUPPORTED:
      txt = "SEC_E_QOP_NOT_SUPPORTED";
      break;
    case SEC_E_REVOCATION_OFFLINE_C:
      txt = "SEC_E_REVOCATION_OFFLINE_C";
      break;
    case SEC_E_REVOCATION_OFFLINE_KDC:
      txt = "SEC_E_REVOCATION_OFFLINE_KDC";
      break;
    case SEC_E_SECPKG_NOT_FOUND:
      txt = "SEC_E_SECPKG_NOT_FOUND";
      break;
    case SEC_E_SECURITY_QOS_FAILED:
      txt = "SEC_E_SECURITY_QOS_FAILED";
      break;
    case SEC_E_SHUTDOWN_IN_PROGRESS:
      txt = "SEC_E_SHUTDOWN_IN_PROGRESS";
      break;
    case SEC_E_SMARTCARD_CERT_EXPIRED:
      txt = "SEC_E_SMARTCARD_CERT_EXPIRED";
      break;
    case SEC_E_SMARTCARD_CERT_REVOKED:
      txt = "SEC_E_SMARTCARD_CERT_REVOKED";
      break;
    case SEC_E_SMARTCARD_LOGON_REQUIRED:
      txt = "SEC_E_SMARTCARD_LOGON_REQUIRED";
      break;
    case SEC_E_STRONG_CRYPTO_NOT_SUPPORTED:
      txt = "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED";
      break;
    case SEC_E_TARGET_UNKNOWN:
      txt = "SEC_E_TARGET_UNKNOWN";
      break;
    case SEC_E_TIME_SKEW:
      txt = "SEC_E_TIME_SKEW";
      break;
    case SEC_E_TOO_MANY_PRINCIPALS:
      txt = "SEC_E_TOO_MANY_PRINCIPALS";
      break;
    case SEC_E_UNFINISHED_CONTEXT_DELETED:
      txt = "SEC_E_UNFINISHED_CONTEXT_DELETED";
      break;
    case SEC_E_UNKNOWN_CREDENTIALS:
      txt = "SEC_E_UNKNOWN_CREDENTIALS";
      break;
    case SEC_E_UNSUPPORTED_FUNCTION:
      txt = "SEC_E_UNSUPPORTED_FUNCTION";
      break;
    case SEC_E_UNSUPPORTED_PREAUTH:
      txt = "SEC_E_UNSUPPORTED_PREAUTH";
      break;
    case SEC_E_UNTRUSTED_ROOT:
      txt = "SEC_E_UNTRUSTED_ROOT";
      break;
    case SEC_E_WRONG_CREDENTIAL_HANDLE:
      txt = "SEC_E_WRONG_CREDENTIAL_HANDLE";
      break;
    case SEC_E_WRONG_PRINCIPAL:
      txt = "SEC_E_WRONG_PRINCIPAL";
      break;
    case SEC_I_COMPLETE_AND_CONTINUE:
      txt = "SEC_I_COMPLETE_AND_CONTINUE";
      break;
    case SEC_I_COMPLETE_NEEDED:
      txt = "SEC_I_COMPLETE_NEEDED";
      break;
    case SEC_I_CONTEXT_EXPIRED:
      txt = "SEC_I_CONTEXT_EXPIRED";
      break;
    case SEC_I_CONTINUE_NEEDED:
      txt = "SEC_I_CONTINUE_NEEDED";
      break;
    case SEC_I_INCOMPLETE_CREDENTIALS:
      txt = "SEC_I_INCOMPLETE_CREDENTIALS";
      break;
    case SEC_I_LOCAL_LOGON:
      txt = "SEC_I_LOCAL_LOGON";
      break;
    case SEC_I_NO_LSA_CONTEXT:
      txt = "SEC_I_NO_LSA_CONTEXT";
      break;
    case SEC_I_RENEGOTIATE:
      txt = "SEC_I_RENEGOTIATE";
      break;
    case SEC_I_SIGNATURE_NEEDED:
      txt = "SEC_I_SIGNATURE_NEEDED";
      break;
    default:
      txt = "Unknown error";
  }

  if(err == SEC_E_OK)
    strncpy(outbuf, txt, outmax);
  else {
    str = txtbuf;
    snprintf(txtbuf, sizeof(txtbuf), "%s (0x%04X%04X)",
             txt, (err >> 16) & 0xffff, err & 0xffff);
    txtbuf[sizeof(txtbuf)-1] = '\0';

#ifdef _WIN32_WCE
    {
      wchar_t wbuf[256];
      wbuf[0] = L'\0';

      if(FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, err, LANG_NEUTRAL,
                       wbuf, sizeof(wbuf)/sizeof(wchar_t), NULL)) {
        wcstombs(msgbuf,wbuf,sizeof(msgbuf)-1);
        msg_formatted = TRUE;
      }
    }
#else
    if(FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, LANG_NEUTRAL,
                      msgbuf, sizeof(msgbuf)-1, NULL)) {
      msg_formatted = TRUE;
    }
#endif
    if(msg_formatted) {
      msgbuf[sizeof(msgbuf)-1] = '\0';
      /* strip trailing '\r\n' or '\n' */
      if((p = strrchr(msgbuf,'\n')) != NULL && (p - msgbuf) >= 2)
         *p = '\0';
      if((p = strrchr(msgbuf,'\r')) != NULL && (p - msgbuf) >= 1)
         *p = '\0';
      msg = msgbuf;
    }
    if(msg)
      snprintf(outbuf, outmax, "%s - %s", str, msg);
    else
      strncpy(outbuf, str, outmax);
  }

  if(old_errno != ERRNO)
    SET_ERRNO(old_errno);

#else

  if(err == SEC_E_OK)
    txt = "No error";
  else
    txt = "Error";

  strncpy(outbuf, txt, outmax);

#endif

  outbuf[outmax] = '\0';

  return outbuf;
}
#endif /* USE_WINDOWS_SSPI */
