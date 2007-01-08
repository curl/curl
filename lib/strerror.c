/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2004 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#ifdef HAVE_STRERROR_R
#if !defined(HAVE_POSIX_STRERROR_R) && !defined(HAVE_GLIBC_STRERROR_R)
#error "you MUST have either POSIX or glibc strerror_r if strerror_r is found"
#endif /* !POSIX && !glibc */
#endif /* HAVE_STRERROR_R */

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef USE_LIBIDN
#include <idna.h>
#endif

#include "strerror.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(HAVE_STRERROR_R) && defined(HAVE_NO_STRERROR_R_DECL)
#ifdef HAVE_POSIX_STRERROR_R
/* seen on AIX 5100-02 gcc 2.9 */
extern int strerror_r(int errnum, char *strerrbuf, size_t buflen);
#else
extern char *strerror_r(int errnum, char *buf, size_t buflen);
#endif
#endif

const char *
curl_easy_strerror(CURLcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (error) {
  case CURLE_OK:
    return "no error";

  case CURLE_UNSUPPORTED_PROTOCOL:
    return "unsupported protocol";

  case CURLE_FAILED_INIT:
    return "failed init";

  case CURLE_URL_MALFORMAT:
    return "URL using bad/illegal format or missing URL";

  case CURLE_COULDNT_RESOLVE_PROXY:
    return "couldn't resolve proxy name";

  case CURLE_COULDNT_RESOLVE_HOST:
    return "couldn't resolve host name";

  case CURLE_COULDNT_CONNECT:
    return "couldn't connect to server";

  case CURLE_FTP_WEIRD_SERVER_REPLY:
    return "FTP: weird server reply";

  case CURLE_FTP_ACCESS_DENIED:
    return "FTP: access denied";

  case CURLE_FTP_WEIRD_PASS_REPLY:
    return "FTP: unknown PASS reply";

  case CURLE_FTP_WEIRD_USER_REPLY:
    return "FTP: unknown USER reply";

  case CURLE_FTP_WEIRD_PASV_REPLY:
    return "FTP: unknown PASV reply";

  case CURLE_FTP_WEIRD_227_FORMAT:
    return "FTP: unknown 227 response format";

  case CURLE_FTP_CANT_GET_HOST:
    return "FTP: can't figure out the host in the PASV response";

  case CURLE_FTP_CANT_RECONNECT:
    return "FTP: can't connect to server the response code is unknown";

  case CURLE_FTP_COULDNT_SET_BINARY:
    return "FTP: couldn't set binary mode";

  case CURLE_PARTIAL_FILE:
    return "Transferred a partial file";

  case CURLE_FTP_COULDNT_RETR_FILE:
    return "FTP: couldn't retrieve (RETR failed) the specified file";

  case CURLE_FTP_WRITE_ERROR:
    return "FTP: the post-transfer acknowledge response was not OK";

  case CURLE_FTP_QUOTE_ERROR:
    return "FTP: a quote command returned error";

  case CURLE_HTTP_RETURNED_ERROR:
    return "HTTP response code said error";

  case CURLE_WRITE_ERROR:
    return "failed writing received data to disk/application";

  case CURLE_FTP_COULDNT_STOR_FILE:
    return "failed FTP upload (the STOR command)";

  case CURLE_READ_ERROR:
    return "failed to open/read local data from file/application";

  case CURLE_OUT_OF_MEMORY:
#ifdef CURL_DOES_CONVERSIONS
    return "conversion failed -or- out of memory";
#else
    return "out of memory";
#endif /* CURL_DOES_CONVERSIONS */

  case CURLE_OPERATION_TIMEOUTED:
    return "a timeout was reached";

  case CURLE_FTP_COULDNT_SET_ASCII:
    return "FTP could not set ASCII mode (TYPE A)";

  case CURLE_FTP_PORT_FAILED:
    return "FTP command PORT failed";

  case CURLE_FTP_COULDNT_USE_REST:
    return "FTP command REST failed";

  case CURLE_FTP_COULDNT_GET_SIZE:
    return "FTP command SIZE failed";

  case CURLE_HTTP_RANGE_ERROR:
    return "a range was requested but the server did not deliver it";

  case CURLE_HTTP_POST_ERROR:
    return "internal problem setting up the POST";

  case CURLE_SSL_CONNECT_ERROR:
    return "SSL connect error";

  case CURLE_BAD_DOWNLOAD_RESUME:
    return "couldn't resume download";

  case CURLE_FILE_COULDNT_READ_FILE:
    return "couldn't read a file:// file";

  case CURLE_LDAP_CANNOT_BIND:
    return "LDAP: cannot bind";

  case CURLE_LDAP_SEARCH_FAILED:
    return "LDAP: search failed";

  case CURLE_LIBRARY_NOT_FOUND:
    return "a required shared library was not found";

  case CURLE_FUNCTION_NOT_FOUND:
    return "a required function in the shared library was not found";

  case CURLE_ABORTED_BY_CALLBACK:
    return "the operation was aborted by an application callback";

  case CURLE_BAD_FUNCTION_ARGUMENT:
    return "a libcurl function was given a bad argument";

  case CURLE_INTERFACE_FAILED:
    return "failed binding local connection end";

  case CURLE_TOO_MANY_REDIRECTS :
    return "number of redirects hit maximum amount";

  case CURLE_UNKNOWN_TELNET_OPTION:
    return "User specified an unknown option";

  case CURLE_TELNET_OPTION_SYNTAX :
    return "Malformed telnet option";

  case CURLE_SSL_PEER_CERTIFICATE:
    return "SSL peer certificate was not ok";

  case CURLE_GOT_NOTHING:
    return "server returned nothing (no headers, no data)";

  case CURLE_SSL_ENGINE_NOTFOUND:
    return "SSL crypto engine not found";

  case CURLE_SSL_ENGINE_SETFAILED:
    return "can not set SSL crypto engine as default";

  case CURLE_SSL_ENGINE_INITFAILED:
    return "failed to initialise SSL crypto engine";

  case CURLE_SEND_ERROR:
    return "failed sending data to the peer";

  case CURLE_RECV_ERROR:
    return "failure when receiving data from the peer";

  case CURLE_SHARE_IN_USE:
    return "share is already in use";

  case CURLE_SSL_CERTPROBLEM:
    return "problem with the local SSL certificate";

  case CURLE_SSL_CIPHER:
    return "couldn't use specified SSL cipher";

  case CURLE_SSL_CACERT:
    return "peer certificate cannot be authenticated with known CA certificates";

  case CURLE_SSL_CACERT_BADFILE:
    return "problem with the SSL CA cert (path? access rights?)";

  case CURLE_BAD_CONTENT_ENCODING:
    return "Unrecognized HTTP Content-Encoding";

  case CURLE_LDAP_INVALID_URL:
    return "Invalid LDAP URL";

  case CURLE_FILESIZE_EXCEEDED:
    return "Maximum file size exceeded";

  case CURLE_FTP_SSL_FAILED:
    return "Requested FTP SSL level failed";

  case CURLE_SSL_SHUTDOWN_FAILED:
    return "Failed to shut down the SSL connection";

  case CURLE_SEND_FAIL_REWIND:
    return "Send failed since rewinding of the data stream failed";

  case CURLE_LOGIN_DENIED:
    return "FTP: login denied";

  case CURLE_TFTP_NOTFOUND:
    return "TFTP: File Not Found";

  case CURLE_TFTP_PERM:
    return "TFTP: Access Violation";

  case CURLE_TFTP_DISKFULL:
    return "TFTP: Disk full or allocation exceeded";

  case CURLE_TFTP_ILLEGAL:
    return "TFTP: Illegal operation";

  case CURLE_TFTP_UNKNOWNID:
    return "TFTP: Unknown transfer ID";

  case CURLE_TFTP_EXISTS:
    return "TFTP: File already exists";

  case CURLE_TFTP_NOSUCHUSER:
    return "TFTP: No such user";

  case CURLE_CONV_FAILED:
    return "conversion failed";

  case CURLE_CONV_REQD:
    return "caller must register CURLOPT_CONV_ callback options";

  case CURLE_REMOTE_FILE_NOT_FOUND:
    return "Remote file not found";

  case CURLE_SSH:
    return "Error in the SSH layer";

    /* error codes not used by current libcurl */
  case CURLE_URL_MALFORMAT_USER:
  case CURLE_FTP_USER_PASSWORD_INCORRECT:
  case CURLE_MALFORMAT_USER:
  case CURLE_BAD_CALLING_ORDER:
  case CURLE_BAD_PASSWORD_ENTERED:
  case CURLE_OBSOLETE:
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
  return "unknown error";
#else
  if (error == CURLE_OK)
    return "no error";
  else
    return "error";
#endif
}

const char *
curl_multi_strerror(CURLMcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (error) {
  case CURLM_CALL_MULTI_PERFORM:
    return "please call curl_multi_perform() soon";

  case CURLM_OK:
    return "no error";

  case CURLM_BAD_HANDLE:
    return "invalid multi handle";

  case CURLM_BAD_EASY_HANDLE:
    return "invalid easy handle";

  case CURLM_OUT_OF_MEMORY:
    return "out of memory";

  case CURLM_INTERNAL_ERROR:
    return "internal error";

  case CURLM_BAD_SOCKET:
    return "invalid socket argument";

  case CURLM_UNKNOWN_OPTION:
    return "unknown option";

  case CURLM_LAST:
    break;
  }

  return "unknown error";
#else
  if (error == CURLM_OK)
    return "no error";
  else
    return "error";
#endif
}

const char *
curl_share_strerror(CURLSHcode error)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  switch (error) {
  case CURLSHE_OK:
    return "no error";

  case CURLSHE_BAD_OPTION:
    return "unknown share option";

  case CURLSHE_IN_USE:
    return "share currently in use";

  case CURLSHE_INVALID:
    return "invalid share handle";

  case CURLSHE_NOMEM:
    return "out of memory";

  case CURLSHE_LAST:
    break;
  }

  return "CURLSH unknown";
#else
  if (error == CURLSHE_OK)
    return "no error";
  else
    return "error";
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
    p = "Call interrupted.";
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
    p = "Descriptor is not a socket.";
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
    p = "Winsock version not supported.";
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
  if (error == CURLE_OK)
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
 * we pass it to the "number-to-message" convertion function and there might
 * be systems that don't do proper range checking in there themselves.
 *
 * We don't do range checking (on systems other than Windows) since there is
 * no good reliable and portable way to do it.
 */
const char *Curl_strerror(struct connectdata *conn, int err)
{
  char *buf, *p;
  size_t max;

  curlassert(conn);
  curlassert(err >= 0);

  buf = conn->syserr_buf;
  max = sizeof(conn->syserr_buf)-1;
  *buf = '\0';

#ifdef USE_WINSOCK

#ifdef _WIN32_WCE
  buf[0]=0;
  {
    wchar_t wbuf[256];

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                  LANG_NEUTRAL, wbuf, sizeof(wbuf)/sizeof(wchar_t), NULL);
    wcstombs(buf,wbuf,max);
  }

#else

  /* 'sys_nerr' is the maximum errno number, it is not widely portable */
  if (err >= 0 && err < sys_nerr)
    strncpy(buf, strerror(err), max);
  else {
    if (!get_winsock_error(err, buf, max) &&
        !FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                       LANG_NEUTRAL, buf, (DWORD)max, NULL))
      snprintf(buf, max, "Unknown error %d (%#x)", err, err);
  }
#endif
#else /* not USE_WINSOCK coming up */

  /* These should be atomic and hopefully thread-safe */
#ifdef HAVE_STRERROR_R
  /* There are two different APIs for strerror_r(). The POSIX and the GLIBC
     versions. */
#ifdef HAVE_POSIX_STRERROR_R
  strerror_r(err, buf, max);
  /* this may set errno to ERANGE if insufficient storage was supplied via
     'strerrbuf' and 'buflen' to contain the generated message string, or
     EINVAL if the value of 'errnum' is not a valid error number.*/
#else
  {
    /* HAVE_GLIBC_STRERROR_R */
    char buffer[256];
    char *msg = strerror_r(err, buffer, sizeof(buffer));
    /* this version of strerror_r() only *might* use the buffer we pass to
       the function, but it always returns the error message as a pointer,
       so we must copy that string unconditionally (if non-NULL) */
    if(msg)
      strncpy(buf, msg, max);
    else
      snprintf(buf, max, "Unknown error %d", err);
  }
#endif /* end of HAVE_GLIBC_STRERROR_R */
#else /* HAVE_STRERROR_R */
  strncpy(buf, strerror(err), max);
#endif /* end of HAVE_STRERROR_R */
#endif /* end of ! USE_WINSOCK */

  buf[max] = '\0'; /* make sure the string is zero terminated */

  /* strip trailing '\r\n' or '\n'. */
  if ((p = strrchr(buf,'\n')) != NULL && (p - buf) >= 2)
     *p = '\0';
  if ((p = strrchr(buf,'\r')) != NULL && (p - buf) >= 1)
     *p = '\0';
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

  curlassert(conn);

  buf = conn->syserr_buf;
  max = sizeof(conn->syserr_buf)-1;

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
      str = "Roundtrip verify error";
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
      snprintf(buf, max, "error %d", (int)err);
      str = NULL;
      break;
  }
#else
  if ((Idna_rc)err == IDNA_SUCCESS)
    str = "No error";
  else
    str = "error";
#endif
  if (str)
    strncpy(buf, str, max);
  buf[max] = '\0';
  return (buf);
#endif
}
#endif  /* USE_LIBIDN */
