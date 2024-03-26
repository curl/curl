<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# WebSocket in curl

## URL

WebSocket communication with libcurl is done by setting up a transfer to a URL
using the `ws://` or `wss://` URL schemes. The latter one being the secure
version done over HTTPS.

When using `wss://` to do WebSocket over HTTPS, the standard TLS and HTTPS
options are acknowledged for the CA, verification of server certificate etc.

WebSocket communication is done by upgrading a connection from either HTTP or
HTTPS. When given a WebSocket URL to work with, libcurl considers it a
transfer failure if the upgrade procedure fails. This means that a plain HTTP
200 response code is considered an error for this work.

## API

The WebSocket API is described in the individual man pages for the new API.

WebSocket with libcurl can be done two ways.

1. Get the WebSocket frames from the server sent to the write callback. You
   can then respond with `curl_ws_send()` from within the callback (or outside
   of it).

2. Set `CURLOPT_CONNECT_ONLY` to 2L (new for WebSocket), which makes libcurl
   do an HTTP GET + `Upgrade:` request plus response in the
   `curl_easy_perform()` call before it returns and then you can use
   `curl_ws_recv()` and `curl_ws_send()` to receive and send WebSocket frames
   from and to the server.

The new options to `curl_easy_setopt()`:

 `CURLOPT_WS_OPTIONS` - to control specific behavior. `CURLWS_RAW_MODE` makes
 libcurl provide all WebSocket traffic raw in the callback.

The new function calls:

 `curl_ws_recv()` - receive a WebSocket frame

 `curl_ws_send()` - send a WebSocket frame

 `curl_ws_meta()` - return WebSocket metadata within a write callback

## Max frame size

The current implementation only supports frame sizes up to a max (64K right
now). This is because the API delivers full frames and it then cannot manage
the full 2^63 bytes size.

If we decide we need to support (much) larger frames than 64K, we need to
adjust the API accordingly to be able to deliver partial frames in both
directions.

## Errors

If the given WebSocket URL (using `ws://` or `wss://`) fails to get upgraded
via a 101 response code and instead gets another response code back from the
HTTP server - the transfer returns `CURLE_HTTP_RETURNED_ERROR` for that
transfer. Note then that even 2xx response codes are then considered error
since it failed to provide a WebSocket transfer.

## Test suite

I looked for an existing small WebSocket server implementation with maximum
flexibility to dissect and cram into the test suite but I ended up deciding
that extending the existing test suite server sws to deal with WebSocket
might be the better way.

- This server is already integrated and working in the test suite

- We want maximum control and ability to generate broken protocol and negative
  tests as well. A dumber and simpler TCP server could then be easier to
  massage into this than a "proper" WebSocket server.

## Command line tool WebSocket

The plan is to make curl do WebSocket similar to telnet/nc. That part of the
work has not been started.

Ideas:

 - Read stdin and send off as messages. Consider newline as end of fragment.
   (default to text? offer option to set binary)
 - Respond to PINGs automatically
 - Issue PINGs at some default interval (option to switch off/change interval?)
 - Allow `-d` to specify (initial) data to send (should the format allow for
   multiple separate frames?)
 - Exit after N messages received, where N can be zero.

## Future work

- Verify the Sec-WebSocket-Accept response. It requires a sha-1 function.
- Verify Sec-WebSocket-Extensions and Sec-WebSocket-Protocol in the response
- Make WebSocket work with hyper
- Consider a `curl_ws_poll()`
- Make sure WebSocket code paths are fuzzed
- Add client-side PING interval
- Provide option to disable PING-PONG automation
- Support compression (`CURLWS_COMPRESS`)

## Why not libWebSocket

libWebSocket is said to be a solid, fast and efficient WebSocket library with
a vast amount of users. My plan was originally to build upon it to skip having
to implement the low level parts of WebSocket myself.

Here are the reasons why I have decided to move forward with WebSocket in
curl **without using libWebSocket**:

- doxygen generated docs only makes them hard to navigate. No tutorial, no
  clearly written explanatory pages for specific functions.

- seems (too) tightly integrated with a specific TLS library, while we want to
  support WebSocket with whatever TLS library libcurl was already made to
  work with.

- seems (too) tightly integrated with event libraries

- the references to threads and thread-pools in code and APIs indicate too
  much logic for our purposes

- "bloated" - it is a *huge* library that is actually more lines of code than
  libcurl itself

- WebSocket is a fairly simple protocol on the network/framing layer so
  making a homegrown handling of it should be fine
