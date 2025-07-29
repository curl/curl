<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# `curlx`

Functions that are prefixed with `curlx_` are internal global functions that
are written in a way to allow them to be "borrowed" and used outside of the
library: in the curl tool and in the curl test suite.

The `curlx` functions are not part of the libcurl API, but are stand-alone
functions whose sources can be built and used outside of libcurl. There are
not API or ABI guarantees. The functions are not written or meant to be used
outside of the curl project.

Only functions actually used by the library are provided here.

## Ways to success

- Do not use `struct Curl_easy` in these files
- Do not use the printf defines in these files
- Make them as stand-alone as possible
