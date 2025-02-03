---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RTSP_REQUEST
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_RTSP_SESSION_ID (3)
  - FETCHOPT_RTSP_STREAM_URI (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

FETCHOPT_RTSP_REQUEST - RTSP request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RTSP_REQUEST, long request);
~~~

# DESCRIPTION

Tell libfetch what kind of RTSP request to make. Pass one of the following RTSP
enum values as a long in the *request* argument. Unless noted otherwise,
commands require the Session ID to be initialized.

## FETCH_RTSPREQ_OPTIONS

Used to retrieve the available methods of the server. The application is
responsible for parsing and obeying the response. The session ID is not needed
for this method.

## FETCH_RTSPREQ_DESCRIBE

Used to get the low level description of a stream. The application should note
what formats it understands in the *'Accept:'* header. Unless set manually,
libfetch automatically adds in *'Accept: application/sdp'*. Time-condition
headers are added to Describe requests if the FETCHOPT_TIMECONDITION(3)
option is used. (The session ID is not needed for this method)

## FETCH_RTSPREQ_ANNOUNCE

When sent by a client, this method changes the description of the session. For
example, if a client is using the server to record a meeting, the client can
use Announce to inform the server of all the meta-information about the
session. ANNOUNCE acts like an HTTP PUT or POST just like
*FETCH_RTSPREQ_SET_PARAMETER*

## FETCH_RTSPREQ_SETUP

Setup is used to initialize the transport layer for the session. The
application must set the desired Transport options for a session by using the
FETCHOPT_RTSP_TRANSPORT(3) option prior to calling setup. If no session
ID is currently set with FETCHOPT_RTSP_SESSION_ID(3), libfetch extracts
and uses the session ID in the response to this request. The session ID is not
needed for this method.

## FETCH_RTSPREQ_PLAY

Send a Play command to the server. Use the FETCHOPT_RANGE(3) option to
modify the playback time (e.g. *npt=10-15*).

## FETCH_RTSPREQ_PAUSE

Send a Pause command to the server. Use the FETCHOPT_RANGE(3) option with
a single value to indicate when the stream should be
halted. (e.g. *npt=25*)

## FETCH_RTSPREQ_TEARDOWN

This command terminates an RTSP session. Simply closing a connection does not
terminate the RTSP session since it is valid to control an RTSP session over
different connections.

## FETCH_RTSPREQ_GET_PARAMETER

Retrieve a parameter from the server. By default, libfetch adds a
*Content-Type: text/parameters* header on all non-empty requests unless a
custom one is set. GET_PARAMETER acts just like an HTTP PUT or POST (see
*FETCH_RTSPREQ_SET_PARAMETER*). Applications wishing to send a heartbeat
message (e.g. in the presence of a server-specified timeout) should send use
an empty GET_PARAMETER request.

## FETCH_RTSPREQ_SET_PARAMETER

Set a parameter on the server. By default, libfetch uses a *Content-Type:
text/parameters* header unless a custom one is set. The interaction with
SET_PARAMETER is much like an HTTP PUT or POST. An application may either use
FETCHOPT_UPLOAD(3) with FETCHOPT_READDATA(3) like an HTTP PUT, or it may use
FETCHOPT_POSTFIELDS(3) like an HTTP POST. No chunked transfers are allowed, so
the application must set the FETCHOPT_INFILESIZE(3) in the former and
FETCHOPT_POSTFIELDSIZE(3) in the latter. Also, there is no use of multi-part
POSTs within RTSP.

## FETCH_RTSPREQ_RECORD

Used to tell the server to record a session. Use the FETCHOPT_RANGE(3)
option to modify the record time.

## FETCH_RTSPREQ_RECEIVE

This is a special request because it does not send any data to the server. The
application may call this function in order to receive interleaved RTP
data. It returns after processing one read buffer of data in order to give the
application a chance to run.

# DEFAULT

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "rtsp://example.com/");
    /* ask for options */
    fetch_easy_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_OPTIONS);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
