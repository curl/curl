---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: libcurl-ws
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONNECT_ONLY (3)
  - CURLOPT_WRITEFUNCTION (3)
  - CURLOPT_WS_OPTIONS (3)
  - curl_easy_init (3)
  - curl_ws_meta (3)
  - curl_ws_recv (3)
  - curl_ws_send (3)
Protocol:
  - All
Added-in: 7.86.0
---

# NAME

libcurl-ws - WebSocket interface overview

# DESCRIPTION

The WebSocket interface provides functions for receiving and sending WebSocket
data.

# INCLUDE

You still only include \<curl/curl.h\> in your code.

# SETUP

WebSocket is also often known as *WebSockets*, in plural. It is done by
upgrading a regular HTTP(S) GET request to a WebSocket connection.

WebSocket is a TCP-like message-based communication protocol done over HTTP,
specified in RFC 6455.

To initiate a WebSocket session with libcurl, setup an easy handle to use a
URL with a "WS://" or "WSS://" scheme. "WS" is for cleartext communication
over HTTP and "WSS" is for doing WebSocket securely over HTTPS.

A WebSocket request is done as an HTTP/1 GET request with an "Upgrade
WebSocket" request header field. When the upgrade is accepted by the server,
it responds with a 101 Switching and then the client can speak WebSocket with
the server. The communication can happen in both directions at the same time.

# EXTENSIONS

The WebSocket protocol allows the client to request and negotiate *extensions*
can add additional features and restrictions to the protocol.

libcurl does not support the use of extensions and always sets up a connection
without them.

# MESSAGES

WebSocket communication is message based. That means that both ends send and
receive entire messages, not streams like TCP. A WebSocket message is sent
over the wire in one or more frames. A message which is split into several
frames is referred to as a *fragmented* message and the individual frames are
called *fragments*. Each frame (or fragment) in a message can have a size of
up to 2^63 bytes and declares the frame size in the header. The total size of
a message that is fragmented into multiple frames is not limited by the
protocol and the number of fragments is not known until the final fragment is
received.

Transmission of a frame must not be interrupted by any other data transfers and
transmission of the different fragments of a message must not be interrupted by
other user data frames. Control frames - PING, PONG and CLOSE - may be
transmitted in between any other two frames, even in between two fragments of
the same user data message. The control frames themselves on the other hand
must never be fragmented and are limited to a size of 125 bytes.

libcurl delivers WebSocket data as chunks of frames. It might deliver a whole
frame as a single chunk, but it might also deliver it in several pieces
depending on size and network patterns. See the individual API documentations
for further information.

# PING

WebSocket is designed to allow long-lived sessions and in order to keep the
connections alive, both ends can send PING messages for the other end to
respond with a PONG. Both ends may also send unsolicited PONG messages as
unidirectional heartbeat.

libcurl automatically responds to server PING messages with a PONG that echoes
the payload of the PING message. libcurl does neither send any PING messages
nor any unsolicited PONG messages automatically. The automatic reply to PING
messages can be disabled through CURLOPT_WS_OPTIONS(3).

# MODELS

Because of the many different ways WebSocket can be used, which is much more
flexible than limited to plain downloads or uploads, libcurl offers two
different API models to use it:

1. CURLOPT_WRITEFUNCTION/CURLOPT_READFUNCTION model:
Using a write callback with CURLOPT_WRITEFUNCTION(3) much like other
downloads for when the traffic is download oriented.

Using a read callback with CURLOPT_READFUNCTION(3) much like other
uploads for sending WebSocket frames to the server.

2. CURLOPT_CONNECT_ONLY model:
Using curl_ws_recv(3) and curl_ws_send(3) functions.

## CURLOPT_WRITEFUNCTION/CURLOPT_READFUNCTION MODEL

CURLOPT_CONNECT_ONLY(3) must be unset or **0L** for this model to take effect.

curl_easy_perform(3) establishes and sets up the WebSocket communication and
then blocks for the whole duration of the connection. libcurl calls the
callback configured in CURLOPT_WRITEFUNCTION(3), whenever an incoming chunk
of WebSocket data is received. The callback is handed a pointer to the payload
data as an argument and can call curl_ws_meta(3) to get relevant metadata.

With libcurl 8.16.0 or later, sending of WebSocket frames via a
CURLOPT_READFUNCTION(3) is supported. To use that on such a connection,
register a callback via CURLOPT_READFUNCTION(3) and set CURLOPT_UPLOAD(3)
as well. Once, the WebSocket connection is established, your callback is
invoked to get data to send. That data is sent in a *CURLWS_BINARY* frame with
length of exactly the data returned.

To send other frame types or longer frames, use curl_ws_start_frame(3)
in the read callback. See the *websocket-updown* example.

When using curl_multi_perform(3) to drive transfers, more possibilities
exist. The CURLOPT_READFUNCTION(3) may return *CURL_READFUNC_PAUSE* when
it has no more data to send. Calling curl_easy_pause(3) afterwards
resumes the upload and the read callback is invoked again.

## CURLOPT_CONNECT_ONLY MODEL

CURLOPT_CONNECT_ONLY(3) must be **2L** for this model to take effect.

curl_easy_perform(3) only establishes and sets up the WebSocket communication
and then returns control back to the application. The application can then use
curl_ws_recv(3) and curl_ws_send(3) to exchange WebSocket messages with the
server.

# RAW MODE

libcurl can be told to speak WebSocket in "raw mode" by setting the
**CURLWS_RAW_MODE** bit of the CURLOPT_WS_OPTIONS(3) option.

Raw WebSocket means that libcurl passes on the data from the network without
parsing it, leaving that entirely to the application.

This mode is intended for applications that already have a WebSocket
parser/engine and want to switch over to use libcurl for enabling WebSocket,
and keep parts of the existing software architecture.
