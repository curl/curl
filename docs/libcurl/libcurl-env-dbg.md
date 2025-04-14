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
Added-in: n/a
---

# NAME

libcurl-env-dbg - environment variables libcurl DEBUGBUILD understands

# DESCRIPTION

This is a set of variables only recognized and used if libcurl was built
"debug enabled", which should never be true for a library used in production.
These variables are intended for internal use only, subject to change and have
many effects on the behavior of libcurl. Refer to the source code to determine
how exactly they are being used.

## `CURL_ALTSVC_HTTP`

Bypass the AltSvc HTTPS protocol restriction if this variable exists.

## `CURL_DBG_SOCK_RBLOCK`

The percentage of recv() calls that should be answered with an EAGAIN at
random. For TCP/UNIX sockets.

## `CURL_DBG_SOCK_RMAX`

The maximum data that shall be received from the network in one recv() call.
For TCP/UNIX sockets. This is applied to every recv.

Example: **CURL_DBG_SOCK_RMAX=400** means recv buffer size is limited to a
maximum of 400 bytes.

## `CURL_DBG_SOCK_WBLOCK`

The percentage of send() calls that should be answered with an EAGAIN at
random. For TCP/UNIX sockets.

## `CURL_DBG_SOCK_WPARTIAL`

The percentage of data that shall be written to the network. For TCP/UNIX
sockets. This is applied to every send.

Example: **CURL_DBG_SOCK_WPARTIAL=80** means a send with 1000 bytes would
only send 800.

## `CURL_DBG_QUIC_WBLOCK`

The percentage of send() calls that should be answered with EAGAIN at random.
QUIC only.

## `CURL_DEBUG`

Trace logging behavior as an alternative to calling curl_global_trace(3).

Example: **CURL_DEBUG=http/2** means trace details about HTTP/2 handling.

In the curl command line tool, built with `--enable-debug`, this environment
variable adds to arguments like `--verbose`, `-vvv`. At least a single `-v`
is needed to make the run emit trace output, but when it does, the contents
of `CURL_DEBUG` are added and can override existing options.

Example: **CURL_DEBUG=tcp,-http/2 curl -vv url** means trace protocol details,
triggered by `-vv`, add tracing of TCP in addition and remove tracing of
HTTP/2.

## `CURL_DEBUG_SIZE`

Fake the size returned by CURLINFO_HEADER_SIZE and CURLINFO_REQUEST_SIZE.

## `CURL_DNS_SERVER`

When built with c-ares for name resolving, setting this environment variable
to `[IP:port]` makes libcurl use that DNS server instead of the system
default. This is used by the curl test suite.

## `CURL_GETHOSTNAME`

Fake the local machine's unqualified hostname for NTLM and SMTP.

## `CURL_HSTS_HTTP`

Bypass the HSTS HTTPS protocol restriction if this variable exists.

## `CURL_FORCETIME`

A time of 0 is used for AWS signatures and NTLM if this variable exists.

## `CURL_ENTROPY`

A fixed faked value to use instead of a proper random number so that functions
in libcurl that are otherwise getting random outputs can be tested for what
they generate.

## `CURL_SMALLREQSEND`

An alternative size of HTTP data to be sent at a time only if smaller than the
current.

## `CURL_SMALLSENDS`

An alternative size of socket data to be sent at a time only if smaller than
the current.

## `CURL_TIME`

Fake Unix timestamp to use for AltSvc, HSTS and CURLINFO variables that are
time related.

This variable can also be used to fake the data returned by some CURLINFO
variables that are not time-related (such as CURLINFO_LOCAL_PORT), and in that
case the value is not a timestamp.

## `CURL_TRACE`

LDAP tracing is enabled if this variable exists and its value is 1 or greater.

OpenLDAP tracing is separate. Refer to CURL_OPENLDAP_TRACE.

## `CURL_OPENLDAP_TRACE`

OpenLDAP tracing is enabled if this variable exists and its value is 1 or
greater. There is a number of debug levels, refer to *openldap.c* comments.

## `CURL_WS_CHUNK_SIZE`

Used to influence the buffer chunk size used for WebSocket encoding and
decoding.

## `CURL_WS_CHUNK_EAGAIN`

Used to simulate blocking sends after this chunk size for WebSocket
connections.

## `CURL_WS_FORCE_ZERO_MASK`

Used to set the bitmask of all sent WebSocket frames to zero. The value of the
environment variable does not matter.

## `CURL_FORBID_REUSE`

Used to set the CURLOPT_FORBID_REUSE flag on each transfer initiated
by the curl command line tool. The value of the environment variable
does not matter.

## `CURL_GRACEFUL_SHUTDOWN`

Make a blocking, graceful shutdown of all remaining connections when
a multi handle is destroyed. This implicitly triggers for easy handles
that are run via easy_perform. The value of the environment variable
gives the shutdown timeout in milliseconds.

## `CURL_H2_STREAM_WIN_MAX`

Set to a positive 32-bit number to override the HTTP/2 stream window's
default of 10MB. Used in testing to verify correct window update handling.
