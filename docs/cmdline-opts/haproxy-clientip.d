c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: haproxy-clientip
Help: Sets client IP in HAProxy PROXY protocol v1 header
Protocols: HTTP
Added: 8.2.0
Category: http proxy
Example: --haproxy-clientip $IP
See-also: proxy
Multi: single
---
Sets a client IP in HAProxy PROXY protocol v1 header at the beginning of the
connection.

For valid requests, IPv4 addresses must be indicated as a series of exactly
4 integers in the range [0..255] inclusive written in decimal representation
separated by exactly one dot between each other. Heading zeroes are not
permitted in front of numbers in order to avoid any possible confusion
with octal numbers. IPv6 addresses must be indicated as series of 4 hexadecimal
digits (upper or lower case) delimited by colons between each other, with the
acceptance of one double colon sequence to replace the largest acceptable range
of consecutive zeroes. The total number of decoded bits must exactly be 128.

Otherwise, any string can be accepted for the client IP and will be sent.

It replaces `--haproxy-protocol` if used, it is not necessary to specify both flags.

This option is primarily useful when sending test requests to
verify a service is working as intended.
