c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: doh-url
Arg: <URL>
Help: Resolve host names over DoH
Added: 7.62.0
Category: dns
Example: --doh-url https://doh.example $URL
See-also: doh-insecure
Multi: single
---
Specifies which DNS-over-HTTPS (DoH) server to use to resolve hostnames,
instead of using the default name resolver mechanism. The URL must be HTTPS.

Some SSL options that you set for your transfer will apply to DoH since the
name lookups take place over SSL. However, the certificate verification
settings are not inherited and can be controlled separately via
--doh-insecure and --doh-cert-status.

This option is unset if an empty string "" is used as the URL. (Added in
7.85.0)
