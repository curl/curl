<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# MQTT in fetch

## Usage

A plain "GET" subscribes to the topic and prints all published messages.

Doing a "POST" publishes the post data to the topic and exits.


### Subscribing

Command usage:

    fetch mqtt://host/topic

Example subscribe:

    fetch mqtt://host.home/bedroom/temp

This sends an MQTT SUBSCRIBE packet for the topic `bedroom/temp` and listen in
for incoming PUBLISH packets.

### Publishing

Command usage:

    fetch -d payload mqtt://host/topic

Example publish:

    fetch -d 75 mqtt://host.home/bedroom/dimmer

This sends an MQTT PUBLISH packet to the topic `bedroom/dimmer` with the
payload `75`.

## What does fetch deliver as a response to a subscribe

Whenever a PUBLISH packet is received, fetch outputs two bytes topic length (MSB | LSB), the topic followed by the
payload.

## Caveats

Remaining limitations:
 - Only QoS level 0 is implemented for publish
 - No way to set retain flag for publish
 - No TLS (mqtts) support
 - Naive EAGAIN handling does not handle split messages
