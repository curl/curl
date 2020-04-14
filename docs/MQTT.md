# MQTT in curl

## Experimental!

MQTT support in curl is considered **EXPERIMENTAL** until further notice. It
needs to be enabled at build-time. See below.

After the initial merge, further development and tweaking of the MQTT support
in curl will happen in the master branch using pull-requests, just like
ordinary changes.

Experimental support for MQTT means that we **do not guarantee** that the
current protocol functionality will remain or remain this way going forward.
There are no API or ABI promises for experimental features as for regular curl
features.

Do not ship anything with this enabled.

## Build

    ./configure --enable-mqtt

## Usage

A plain "GET" subscribes to the topic and prints all published messages.
Doing a "POST" publishes the post data to the topic and exits.

Example subscribe:

    curl mqtt://host/home/bedroom/temp

Example publish:

    curl -d 75 mqtt://host/home/bedroom/dimmer

## What does curl deliver as a response to a subscribe

It outputs two bytes topic length (MSB | LSB), the topic followed by the
payload.

## Caveats

Remaining limitations:
 - No username support
 - Only QoS level 0 is implemented for publish
 - No way to set retain flag for publish
 - No username/password support
 - No TLS (mqtts) support
 - Naive EAGAIN handling won't handle split messages

## Work

1. Write a mqtt server for the test suite
2. Create a few tests verifying the existing mqtt functionality
3. Work on fixing some of the worst limitations - with accompanying tests
4. Consider replacing the client-side MQTT code with wolfMQTT

## Credits

The initial MQTT patch was authored by Björn Stenberg. This work is built upon
that patch and has been expanded since.
