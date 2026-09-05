<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Performance tests

This directory contains small stand-alone libcurl-using programs that each
test specific aspects of the library's performance.

The idea is to have a set of tests here that can be used to verify various
libcurl functions' performance when we have no other good means of doing so.
Performance is best tested relatively. Does it run slower or faster than
before?

Ideally these tests run without using any servers.

## `urlparser`

Provide this test with a list of many URLs and it times how fast it can parse
them: `./perf urlparser URLs.txt [loops]`

A test sample of 100K URLs can be found
[here](https://raw.githubusercontent.com/ada-url/url-various-datasets/refs/heads/main/top100/top100.txt)

## `base64enc`

This test base64 encodes a 256-byte buffer that has every different byte octet
represented. Repeatedly in a loop the provided number of times:

    ./perf base64enc [loops]

## `base64dec`

This test base64 decodes a big encoded string. Repeatedly in a loop the
provided number of times:

    ./perf base64dec [loops]

## `snprintf`

This test repeatedly formats a representative string and measures the time per
call:

    ./perf snprintf [loops]

## `maprintf`

This test repeatedly formats a request header block with `curl_maprintf()`,
which allocates the result, and measures the time per call. It exercises the
allocating output path and a `curl_off_t` conversion, which the `snprintf`
test does not:

    ./perf maprintf [loops]

## `simpleformat`

This test repeatedly formats a commonly used simple message with
`curl_msnprintf()`: literal text plus `%s`, a `size_t` and a `curl_off_t`,
with no width or precision. Where `snprintf` measures an elaborate format,
this measures the common one:

    ./perf simpleformat [loops]

## `urlencode`

This test URL (percent) encodes a 256-byte buffer that has every different
byte octet represented. Repeatedly in a loop the provided number of times:

    ./perf urlencode [loops]

## `urldecode`

This test URL (percent) decodes a 600+ byte buffer. Repeatedly in a loop the
provided number of times:

    ./perf urldecode [loops]
