<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# HSTS support

HTTP Strict-Transport-Security. Added as experimental in curl
7.74.0. Supported "for real" since 7.77.0.

## Standard

[HTTP Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc6797)

## Behavior

libcurl features an in-memory cache for HSTS hosts, so that subsequent
HTTP-only requests to a hostname present in the cache gets internally
"redirected" to the HTTPS version.

## `curl_easy_setopt()` options:

 - `CURLOPT_HSTS_CTRL` - enable HSTS for this easy handle
 - `CURLOPT_HSTS` - specify filename where to store the HSTS cache on close
  (and possibly read from at startup)

## curl command line options

 - `--hsts [filename]` - enable HSTS, use the file as HSTS cache. If filename
   is `""` (no length) then no file is used, only in-memory cache.

## HSTS cache file format

Lines starting with `#` are ignored.

For each hsts entry:

    [host name] "YYYYMMDD HH:MM:SS"

The `[host name]` is dot-prefixed if it includes subdomains.

The time stamp is when the entry expires.

## Possible future additions

 - `CURLOPT_HSTS_PRELOAD` - provide a set of HSTS hostnames to load first
 - ability to save to something else than a file
