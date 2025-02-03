---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_getinfo
Section: 3
Source: libfetch
See-also:
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

fetch_easy_getinfo - extract information from a fetch handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *fetch, FETCHINFO info, ... );
~~~

# DESCRIPTION

Get the *info* kept in the *fetch* handle. The third argument **MUST** be
pointing to the specific type of the used option which is documented in each
man page of the *info* option. The data is stored accordingly and can be
relied upon only if this function returns FETCHE_OK. Use this function after a
performed transfer if you want to get transfer related data.

You should not free the memory returned by this function unless it is
explicitly mentioned below.

# OPTIONS

The following information can be extracted:

## FETCHINFO_ACTIVESOCKET

The session's active socket. See FETCHINFO_ACTIVESOCKET(3)

## FETCHINFO_APPCONNECT_TIME

The time it took from the start until the SSL connect/handshake with the
remote host was completed as a double in number of seconds. (Added in 7.19.0)

## FETCHINFO_APPCONNECT_TIME_T

The time it took from the start until the SSL connect/handshake with the
remote host was completed in number of microseconds. (Added in 7.60.0) See
FETCHINFO_APPCONNECT_TIME_T(3)

## FETCHINFO_CAINFO

Get the default value for FETCHOPT_CAINFO(3). See FETCHINFO_CAINFO(3)

## FETCHINFO_CAPATH

Get the default value for FETCHOPT_CAPATH(3). See FETCHINFO_CAPATH(3)

## FETCHINFO_CERTINFO

Certificate chain. See FETCHINFO_CERTINFO(3)

## FETCHINFO_CONDITION_UNMET

Whether or not a time conditional was met or 304 HTTP response.
See FETCHINFO_CONDITION_UNMET(3)

## FETCHINFO_CONNECT_TIME

The time it took from the start until the connect to the remote host (or
proxy) was completed. As a double. See FETCHINFO_CONNECT_TIME(3)

## FETCHINFO_CONNECT_TIME_T

The time it took from the start until the connect to the remote host (or
proxy) was completed. In microseconds. See FETCHINFO_CONNECT_TIME_T(3).

## FETCHINFO_CONN_ID

The ID of the last connection used by the transfer. (Added in 8.2.0)
See FETCHINFO_CONN_ID(3)

## FETCHINFO_CONTENT_LENGTH_DOWNLOAD

(**Deprecated**) Content length from the Content-Length header.
See FETCHINFO_CONTENT_LENGTH_DOWNLOAD(3)

## FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T

Content length from the Content-Length header.
See FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T(3)

## FETCHINFO_CONTENT_LENGTH_UPLOAD

(**Deprecated**) Upload size. See FETCHINFO_CONTENT_LENGTH_UPLOAD(3)

## FETCHINFO_CONTENT_LENGTH_UPLOAD_T

Upload size. See FETCHINFO_CONTENT_LENGTH_UPLOAD_T(3)

## FETCHINFO_CONTENT_TYPE

Content type from the `Content-Type:` header. We recommend using
fetch_easy_header(3) instead. See FETCHINFO_CONTENT_TYPE(3)

## FETCHINFO_COOKIELIST

List of all known cookies. See FETCHINFO_COOKIELIST(3)

## FETCHINFO_EARLYDATA_SENT_T

Amount of TLS early data sent (in number of bytes) when
FETCHSSLOPT_EARLYDATA is enabled.

## FETCHINFO_EFFECTIVE_METHOD

Last used HTTP method. See FETCHINFO_EFFECTIVE_METHOD(3)

## FETCHINFO_EFFECTIVE_URL

Last used URL. See FETCHINFO_EFFECTIVE_URL(3)

## FETCHINFO_FILETIME

Remote time of the retrieved document. See FETCHINFO_FILETIME(3)

## FETCHINFO_FILETIME_T

Remote time of the retrieved document. See FETCHINFO_FILETIME_T(3)

## FETCHINFO_FTP_ENTRY_PATH

The entry path after logging in to an FTP server. See
FETCHINFO_FTP_ENTRY_PATH(3)

## FETCHINFO_HEADER_SIZE

Number of bytes of all headers received. See FETCHINFO_HEADER_SIZE(3)

## FETCHINFO_HTTPAUTH_AVAIL

Available HTTP authentication methods. See FETCHINFO_HTTPAUTH_AVAIL(3)

## FETCHINFO_HTTPAUTH_USED

Used HTTP authentication method. See FETCHINFO_HTTPAUTH_USED(3)

## FETCHINFO_HTTP_CONNECTCODE

Last proxy CONNECT response code. See FETCHINFO_HTTP_CONNECTCODE(3)

## FETCHINFO_HTTP_VERSION

The http version used in the connection. See FETCHINFO_HTTP_VERSION(3)

## FETCHINFO_LASTSOCKET

(**Deprecated**) Last socket used. See FETCHINFO_LASTSOCKET(3)

## FETCHINFO_LOCAL_IP

Source IP address of the last connection. See FETCHINFO_LOCAL_IP(3)

## FETCHINFO_LOCAL_PORT

Source port number of the last connection. See FETCHINFO_LOCAL_PORT(3)

## FETCHINFO_NAMELOOKUP_TIME

Time from start until name resolving completed as a double. See
FETCHINFO_NAMELOOKUP_TIME(3)

## FETCHINFO_NAMELOOKUP_TIME_T

Time from start until name resolving completed in number of microseconds. See
FETCHINFO_NAMELOOKUP_TIME_T(3)

## FETCHINFO_NUM_CONNECTS

Number of new successful connections used for previous transfer.
See FETCHINFO_NUM_CONNECTS(3)

## FETCHINFO_OS_ERRNO

The errno from the last failure to connect. See FETCHINFO_OS_ERRNO(3)

## FETCHINFO_POSTTRANSFER_TIME_T

The time it took from the start until the last byte is sent by libfetch.
In microseconds. (Added in 8.10.0) See FETCHINFO_POSTTRANSFER_TIME_T(3)

## FETCHINFO_PRETRANSFER_TIME

The time it took from the start until the file transfer is just about to
begin. This includes all pre-transfer commands and negotiations that are
specific to the particular protocol(s) involved. See
FETCHINFO_PRETRANSFER_TIME(3)

## FETCHINFO_PRETRANSFER_TIME_T

The time it took from the start until the file transfer is just about to
begin. This includes all pre-transfer commands and negotiations that are
specific to the particular protocol(s) involved. In microseconds. See
FETCHINFO_PRETRANSFER_TIME_T(3)

## FETCHINFO_PRIMARY_IP

Destination IP address of the last connection. See FETCHINFO_PRIMARY_IP(3)

## FETCHINFO_PRIMARY_PORT

Destination port of the last connection. See FETCHINFO_PRIMARY_PORT(3)

## FETCHINFO_PRIVATE

User's private data pointer. See FETCHINFO_PRIVATE(3)

## FETCHINFO_PROTOCOL

(**Deprecated**) The protocol used for the connection. (Added in 7.52.0) See
FETCHINFO_PROTOCOL(3)

## FETCHINFO_PROXYAUTH_AVAIL

Available HTTP proxy authentication methods. See FETCHINFO_PROXYAUTH_AVAIL(3)

## FETCHINFO_PROXYAUTH_USED

Used HTTP proxy authentication methods. See FETCHINFO_PROXYAUTH_USED(3)

## FETCHINFO_PROXY_ERROR

Detailed proxy error. See FETCHINFO_PROXY_ERROR(3)

## FETCHINFO_PROXY_SSL_VERIFYRESULT

Proxy certificate verification result. See FETCHINFO_PROXY_SSL_VERIFYRESULT(3)

## FETCHINFO_QUEUE_TIME_T

The time during which the transfer was held in a waiting queue before it could
start for real in number of microseconds. (Added in 8.6.0) See
FETCHINFO_QUEUE_TIME_T(3)

## FETCHINFO_REDIRECT_COUNT

Total number of redirects that were followed. See FETCHINFO_REDIRECT_COUNT(3)

## FETCHINFO_REDIRECT_TIME

The time it took for all redirection steps include name lookup, connect,
pretransfer and transfer before final transaction was started. So, this is
zero if no redirection took place. As a double. See FETCHINFO_REDIRECT_TIME(3)

## FETCHINFO_REDIRECT_TIME_T

The time it took for all redirection steps include name lookup, connect,
pretransfer and transfer before final transaction was started. So, this is
zero if no redirection took place. In number of microseconds. See
FETCHINFO_REDIRECT_TIME_T(3)

## FETCHINFO_REDIRECT_URL

URL a redirect would take you to, had you enabled redirects. See
FETCHINFO_REDIRECT_URL(3)

## FETCHINFO_REFERER

Referrer header. See FETCHINFO_REFERER(3)

## FETCHINFO_REQUEST_SIZE

Number of bytes sent in the issued HTTP requests. See FETCHINFO_REQUEST_SIZE(3)

## FETCHINFO_RESPONSE_CODE

Last received response code. See FETCHINFO_RESPONSE_CODE(3)

## FETCHINFO_RETRY_AFTER

The value from the Retry-After header. See FETCHINFO_RETRY_AFTER(3)

## FETCHINFO_RTSP_CLIENT_CSEQ

The RTSP client CSeq that is expected next. See FETCHINFO_RTSP_CLIENT_CSEQ(3)

## FETCHINFO_RTSP_CSEQ_RECV

RTSP CSeq last received. See FETCHINFO_RTSP_CSEQ_RECV(3)

## FETCHINFO_RTSP_SERVER_CSEQ

The RTSP server CSeq that is expected next. See FETCHINFO_RTSP_SERVER_CSEQ(3)

## FETCHINFO_RTSP_SESSION_ID

RTSP session ID. See FETCHINFO_RTSP_SESSION_ID(3)

## FETCHINFO_SCHEME

The scheme used for the connection. (Added in 7.52.0) See FETCHINFO_SCHEME(3)

## FETCHINFO_SIZE_DOWNLOAD

(**Deprecated**) Number of bytes downloaded. See FETCHINFO_SIZE_DOWNLOAD(3)

## FETCHINFO_SIZE_DOWNLOAD_T

Number of bytes downloaded. See FETCHINFO_SIZE_DOWNLOAD_T(3)

## FETCHINFO_SIZE_UPLOAD

(**Deprecated**) Number of bytes uploaded. See FETCHINFO_SIZE_UPLOAD(3)

## FETCHINFO_SIZE_UPLOAD_T

Number of bytes uploaded. See FETCHINFO_SIZE_UPLOAD_T(3)

## FETCHINFO_SPEED_DOWNLOAD

(**Deprecated**) Average download speed. See FETCHINFO_SPEED_DOWNLOAD(3)

## FETCHINFO_SPEED_DOWNLOAD_T

Average download speed. See FETCHINFO_SPEED_DOWNLOAD_T(3)

## FETCHINFO_SPEED_UPLOAD

(**Deprecated**) Average upload speed. See FETCHINFO_SPEED_UPLOAD(3)

## FETCHINFO_SPEED_UPLOAD_T

Average upload speed in number of bytes per second. See
FETCHINFO_SPEED_UPLOAD_T(3)

## FETCHINFO_SSL_ENGINES

A list of OpenSSL crypto engines. See FETCHINFO_SSL_ENGINES(3)

## FETCHINFO_SSL_VERIFYRESULT

Certificate verification result. See FETCHINFO_SSL_VERIFYRESULT(3)

## FETCHINFO_STARTTRANSFER_TIME

The time it took from the start until the first byte is received by libfetch.
As a double. See FETCHINFO_STARTTRANSFER_TIME(3)

## FETCHINFO_STARTTRANSFER_TIME_T

The time it took from the start until the first byte is received by libfetch.
In microseconds. See FETCHINFO_STARTTRANSFER_TIME_T(3)

## FETCHINFO_TLS_SESSION

(**Deprecated**) TLS session info that can be used for further processing. See
FETCHINFO_TLS_SESSION(3). Use FETCHINFO_TLS_SSL_PTR(3) instead.

## FETCHINFO_TLS_SSL_PTR

TLS session info that can be used for further processing. See
FETCHINFO_TLS_SSL_PTR(3)

## FETCHINFO_TOTAL_TIME

Total time of previous transfer. See FETCHINFO_TOTAL_TIME(3)

## FETCHINFO_TOTAL_TIME_T

Total time of previous transfer. See FETCHINFO_TOTAL_TIME_T(3)

## FETCHINFO_USED_PROXY

Whether the proxy was used (Added in 8.7.0). See FETCHINFO_USED_PROXY(3)

## FETCHINFO_XFER_ID

The ID of the transfer. (Added in 8.2.0) See FETCHINFO_XFER_ID(3)

# TIMES

An overview of the time values available from fetch_easy_getinfo(3)

    fetch_easy_perform()
        |
        |--QUEUE
        |--|--NAMELOOKUP
        |--|--|--CONNECT
        |--|--|--|--APPCONNECT
        |--|--|--|--|--PRETRANSFER
        |--|--|--|--|--|--POSTTRANSFER
        |--|--|--|--|--|--|--STARTTRANSFER
        |--|--|--|--|--|--|--|--TOTAL
        |--|--|--|--|--|--|--|--REDIRECT


 FETCHINFO_QUEUE_TIME_T(3), FETCHINFO_NAMELOOKUP_TIME_T(3),
 FETCHINFO_CONNECT_TIME_T(3), FETCHINFO_APPCONNECT_TIME_T(3),
 FETCHINFO_PRETRANSFER_TIME_T(3), FETCHINFO_POSTTRANSFER_TIME_T(3),
 FETCHINFO_STARTTRANSFER_TIME_T(3), FETCHINFO_TOTAL_TIME_T(3),
 FETCHINFO_REDIRECT_TIME_T(3)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://www.example.com/");
    res = fetch_easy_perform(fetch);

    if(FETCHE_OK == res) {
      char *ct;
      /* ask for the content-type */
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONTENT_TYPE, &ct);

      if((FETCHE_OK == res) && ct)
        printf("We received Content-Type: %s\n", ct);
    }

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
