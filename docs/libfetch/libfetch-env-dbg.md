---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: libfetch-env-dbg
Section: 3
Source: libfetch
See-also:
  - libfetch-env (3)
Protocol:
  - All
Added-in: n/a
---

# NAME

libfetch-env-dbg - environment variables libfetch DEBUGBUILD understands

# DESCRIPTION

This is a set of variables only recognized and used if libfetch was built
"debug enabled", which should never be true for a library used in production.
These variables are intended for internal use only, subject to change and have
many effects on the behavior of libfetch. Refer to the source code to determine
how exactly they are being used.

## FETCH_ALTSVC_HTTP

Bypass the AltSvc HTTPS protocol restriction if this variable exists.

## FETCH_DBG_SOCK_RBLOCK

The percentage of recv() calls that should be answered with a EAGAIN at random.
For TCP/UNIX sockets.

## FETCH_DBG_SOCK_RMAX

The maximum data that shall be received from the network in one recv() call.
For TCP/UNIX sockets. This is applied to every recv.

Example: **FETCH_DBG_SOCK_RMAX=400** means recv buffer size is limited to a
maximum of 400 bytes.

## FETCH_DBG_SOCK_WBLOCK

The percentage of send() calls that should be answered with a EAGAIN at random.
For TCP/UNIX sockets.

## FETCH_DBG_SOCK_WPARTIAL

The percentage of data that shall be written to the network. For TCP/UNIX
sockets. This is applied to every send.

Example: **FETCH_DBG_SOCK_WPARTIAL=80** means a send with 1000 bytes would
only send 800.

## FETCH_DBG_QUIC_WBLOCK

The percentage of send() calls that should be answered with EAGAIN at random.
QUIC only.

## FETCH_DEBUG

Trace logging behavior as an alternative to calling fetch_global_trace(3).

Example: **FETCH_DEBUG=http/2** means trace details about HTTP/2 handling.

In the fetch command line tool, built with `--enable-debug`, this environment
variable adds to arguments like `--verbose`, `-vvv`. At least a single `-v`
is needed to make the run emit trace output, but when it does, the contents
of `FETCH_DEBUG` are added and can override existing options.

Example: **FETCH_DEBUG=tcp,-http/2 fetch -vv url** means trace protocol details,
triggered by `-vv`, add tracing of TCP in addition and remove tracing of
HTTP/2.

## FETCH_DEBUG_SIZE

Fake the size returned by FETCHINFO_HEADER_SIZE and FETCHINFO_REQUEST_SIZE.

## FETCH_GETHOSTNAME

Fake the local machine's unqualified hostname for NTLM and SMTP.

## FETCH_HSTS_HTTP

Bypass the HSTS HTTPS protocol restriction if this variable exists.

## FETCH_FORCETIME

A time of 0 is used for AWS signatures and NTLM if this variable exists.

## FETCH_ENTROPY

A fixed faked value to use instead of a proper random number so that functions
in libfetch that are otherwise getting random outputs can be tested for what
they generate.

## FETCH_SMALLREQSEND

An alternative size of HTTP data to be sent at a time only if smaller than the
current.

## FETCH_SMALLSENDS

An alternative size of socket data to be sent at a time only if smaller than
the current.

## FETCH_TIME

Fake Unix timestamp to use for AltSvc, HSTS and FETCHINFO variables that are
time related.

This variable can also be used to fake the data returned by some FETCHINFO
variables that are not time-related (such as FETCHINFO_LOCAL_PORT), and in that
case the value is not a timestamp.

## FETCH_TRACE

LDAP tracing is enabled if this variable exists and its value is 1 or greater.

OpenLDAP tracing is separate. Refer to FETCH_OPENLDAP_TRACE.

## FETCH_OPENLDAP_TRACE

OpenLDAP tracing is enabled if this variable exists and its value is 1 or
greater. There is a number of debug levels, refer to *openldap.c* comments.

## FETCH_WS_CHUNK_SIZE

Used to influence the buffer chunk size used for WebSocket encoding and
decoding.

## FETCH_WS_CHUNK_EAGAIN

Used to simulate blocking sends after this chunk size for WebSocket
connections.

## FETCH_FORBID_REUSE

Used to set the FETCHOPT_FORBID_REUSE flag on each transfer initiated
by the fetch command line tool. The value of the environment variable
does not matter.

## FETCH_GRACEFUL_SHUTDOWN

Make a blocking, graceful shutdown of all remaining connections when
a multi handle is destroyed. This implicitly triggers for easy handles
that are run via easy_perform. The value of the environment variable
gives the shutdown timeout in milliseconds.
