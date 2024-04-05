---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: libcurl-env-dbg
Section: 3
Source: libcurl
See-also:
  - libcurl-env (3)
Protocol:
  - All
---

# NAME

libcurl-env-dbg - environment variables libcurl DEBUGBUILD understands

# DESCRIPTION

This is a set of variables only recognized and used if libcurl was built
"debug enabled", which should never be true for a library used in production.
These variables are intended for internal use only, subject to change and have
many effects on the behavior of libcurl. Refer to the source code to determine
how exactly they are being used.

## CURL_ALTSVC_HTTP

Bypass the AltSvc HTTPS protocol restriction if this variable exists.

## CURL_DBG_SOCK_RBLOCK

The percentage of recv() calls that should be answered with a EAGAIN at random.
For TCP/UNIX sockets.

## CURL_DBG_SOCK_RMAX

The maximum data that shall be received from the network in one recv() call.
For TCP/UNIX sockets. This is applied to every recv.

Example: **CURL_DBG_SOCK_RMAX=400** means recv buffer size is limited to a
maximum of 400 bytes.

## CURL_DBG_SOCK_WBLOCK

The percentage of send() calls that should be answered with a EAGAIN at random.
For TCP/UNIX sockets.

## CURL_DBG_SOCK_WPARTIAL

The percentage of data that shall be written to the network. For TCP/UNIX
sockets. This is applied to every send.

Example: **CURL_DBG_SOCK_WPARTIAL=80** means a send with 1000 bytes would
only send 800.

## CURL_DBG_QUIC_WBLOCK

The percentage of send() calls that should be answered with EAGAIN at random.
QUIC only.

## CURL_DEBUG

Trace logging behavior as an alternative to calling curl_global_trace(3).

Example: **CURL_DEBUG=http/2** means trace details about HTTP/2 handling.

## CURL_DEBUG_SIZE

Fake the size returned by CURLINFO_HEADER_SIZE and CURLINFO_REQUEST_SIZE.

## CURL_GETHOSTNAME

Fake the local machine's unqualified hostname for NTLM and SMTP.

## CURL_HSTS_HTTP

Bypass the HSTS HTTPS protocol restriction if this variable exists.

## CURL_FORCETIME

A time of 0 is used for AWS signatures and NTLM if this variable exists.

## CURL_ENTROPY

A fixed faked value to use instead of a proper random number so that functions
in libcurl that are otherwise getting random outputs can be tested for what
they generate.

## CURL_SMALLREQSEND

An alternative size of HTTP data to be sent at a time only if smaller than the
current.

## CURL_SMALLSENDS

An alternative size of socket data to be sent at a time only if smaller than
the current.

## CURL_TIME

Fake unix timestamp to use for AltSvc, HSTS and CURLINFO variables that are
time related.

This variable can also be used to fake the data returned by some CURLINFO
variables that are not time-related (such as CURLINFO_LOCAL_PORT), and in that
case the value is not a timestamp.

## CURL_TRACE

LDAP tracing is enabled if this variable exists and its value is 1 or greater.

OpenLDAP tracing is separate. Refer to CURL_OPENLDAP_TRACE.

## CURL_NTLM_WB_FILE

Debug-version of the *ntlm-wb* executable.

## CURL_OPENLDAP_TRACE

OpenLDAP tracing is enabled if this variable exists and its value is 1 or
greater. There is a number of debug levels, refer to *openldap.c* comments.

## CURL_WS_CHUNK_SIZE

Used to influence the buffer chunk size used for WebSocket encoding and
decoding.
