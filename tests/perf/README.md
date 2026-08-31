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

## `base64`

This test first base64 encodes a 256-byte buffer that has every different
byte octet represented. It then decodes that string. Repeatedly in a loop the
provided number of times: `./perf base64 [loops]`

## `snprintf`

This test repeatedly formats a representative string and measures the time per
call: `./perf snprintf [loops]`
