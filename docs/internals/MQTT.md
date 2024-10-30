<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# MQTT in curl

## Usage

A plain "GET" subscribes to the topic and prints all published messages.

Doing a "POST" publishes the post data to the topic and exits.


### Subscribing

Command usage:

    curl mqtt://host/topic

Example subscribe:

    curl mqtt://host.home/bedroom/temp

This will send an MQTT SUBSCRIBE packet for the topic `bedroom/temp` and listen in for incoming PUBLISH packets.

### Publishing

Command usage:

    curl -d payload mqtt://host/topic

Example publish:

    curl -d 75 mqtt://host.home/bedroom/dimmer

This will send an MQTT PUBLISH packet to the topic `bedroom/dimmer` with the payload `75`.

## What does curl deliver as a response to a subscribe

Whenever a PUBLISH packet is received, curl outputs two bytes topic length (MSB | LSB), the topic followed by the
payload.

## Caveats

Remaining limitations:
 - Only QoS level 0 is implemented for publish
 - No way to set retain flag for publish
 - No TLS (mqtts) support
 - Naive EAGAIN handling does not handle split messages
