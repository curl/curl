<!--
Copyright (C) 2000 - 2022 Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# WebSockets in curl

## API

The Websockets API is described in the individual man pages for the new API.

Websockets with libcurl can be done two ways.

1. Get the websockets frames from the server sent to the write callback. You
   can then respond with `curl_ws_send()` from within the callback (or outside
   of it).

2. Set `CURLOPT_CONNECT_ONLY` to 2L (new for websockets), which makes libcurl
   do a HTTP GET + `Upgrade:` request plus response in the
   `curl_easy_perform()` call before it returns and then you can use
   `curl_ws_recv()` and `curl_ws_send()` to receive and send websocket frames
   from and to the server.

The new options to `curl_easy_setopt()`:

 `CURLOPT_WS_OPTIONS` - to control specific behavior. `CURLWS_RAW_MODE` makes
 libcurl provide all websocket traffic raw in the callback.

The new function calls:

 `curl_ws_recv()` - receive a websockets frame

 `curl_ws_send()` - send a websockets frame

 `curl_ws_meta()` - return websockets metadata within a write callback

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
HTTP server - the transfer will return `CURLE_HTTP_RETURNED_ERROR` for that
transfer. Note then that even 2xx response codes are then considered error
since it failed to provide a WebSocket transfer.

## Test suite

I looked for an existing small WebSockets server implementation with maximum
flexibility to dissect and cram into the test suite but I ended up deciding
that extending the existing test suite server sws to deal with WebSockets
might be the better way.

- This server is already integrated and working in the test suite

- We want maximum control and ability to generate broken protocol and negative
  tests as well. A dumber and simpler TCP server could then be easier to
  massage into this than a "proper" websockets server.

## Command line tool websockets

The plan is to make curl do websockets similar to telnet/nc. That part of the
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
- Verify Sec-Websocket-Extensions and Sec-Websocket-Protocol in the response
- Make websockets work with hyper
- Consider a `curl_ws_poll()`
- Make sure Websockets code paths are fuzzed
- Add client-side PING interval
- Provide option to disable PING-PONG automation
- Support compression (`CURLWS_COMPRESS`)

## Why not libwebsockets

[libwebsockets](https://libwebsockets.org/) is said to be a solid, fast and
efficient WebSockets library with a vast amount of users. My plan was
originally to build upon it to skip having to implement the lowlevel parts of
WebSockets myself.

Here are the reasons why I have decided to move forward with WebSockets in
curl **without using libwebsockets**:

- doxygen generated docs only makes them very hard to navigate. No tutorial,
  no clearly written explanatory pages for specific functions.

- seems (too) tightly integrated with a specific TLS library, while we want to
  support websockets with whatever TLS library libcurl was already made to
  work with.

- seems (too) tightly integrated with event libraries

- the references to threads and thread-pools in code and APIs indicate too
  much logic for our purposes

- "bloated" - it is a *huge* library that is actually more lines of code than
  libcurl itself

- websockets is a fairly simple protocol on the network/framing layer so
  making a homegrown handling of it should be fine
