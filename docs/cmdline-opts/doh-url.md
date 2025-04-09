---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: doh-url
Arg: <URL>
Help: Resolve hostnames over DoH
Added: 7.62.0
Category: dns
Multi: single
See-also:
  - doh-insecure
Example:
  - --doh-url https://doh.example $URL
  - --doh-url https://doh.example --resolve doh.example:443:192.0.2.1 $URL
---

# `--doh-url`

Specify which DNS-over-HTTPS (DoH) server to use to resolve hostnames, instead
of using the default name resolver mechanism. The URL must be HTTPS.

Some SSL options that you set for your transfer also applies to DoH since the
name lookups take place over SSL. However, the certificate verification
settings are not inherited but are controlled separately via --doh-insecure
and --doh-cert-status.

By default, DoH is bypassed when initially looking up DNS records of the DoH server. You can specify the IP address(es) of the DoH server with --resolve to avoid this.

This option is unset if an empty string "" is used as the URL.
(Added in 7.85.0)
