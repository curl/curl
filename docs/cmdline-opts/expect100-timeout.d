c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: expect100-timeout
Arg: <seconds>
Help: How long to wait for 100-continue
Protocols: HTTP
Added: 7.47.0
See-also: connect-timeout
Category: http
Example: --expect100-timeout 2.5 -T file $URL
Multi: single
---
Maximum time in seconds that you allow curl to wait for a 100-continue
response when curl emits an Expects: 100-continue header in its request. By
default curl will wait one second. This option accepts decimal values! When
curl stops waiting, it will continue as if the response has been received.

The decimal value needs to provided using a dot (.) as decimal separator - not
the local version even if it might be using another separator.
