<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

## TLS libraries without 1.3 support

curl drops support for TLS libraries without TLS 1.3 capability after May
2025.

It requires that a curl build using the library should be able to negotiate
and use TLS 1.3, or else it is not good enough.

As of May 2024, the libraries that need to get fixed to remain supported after
May 2025 are: BearSSL and Secure Transport.

## Hyper

Hyper is an alternative HTTP backend for curl. It uses the hyper library and
could in theory be used for HTTP/1, HTTP/2 and even HTTP/3 in the future with
curl.

The original plan and goal was that we would add this HTTP alternative (using
a memory-safe library) and that users could eventually build and use libcurl
exactly as previously but with parts of the core being more memory-safe.

The hyper implementation ran into some snags and 10-15 tests and HTTP/2
support have remained disabled with hyper. For these reasons, hyper support
has remained tagged EXPERIMENTAL.

It is undoubtedly hard work to fix these remaining problems, as they typically
require both rust and C knowledge in addition to deep HTTP familiarity. There
does not seem to be that many persons interested or available for this
challenge. Meanwhile, there is little if any demand for hyper from existing
(lib)curl users.

Finally: having support for hyper in curl has a significant cost: we need to
maintain and develop a lot of functionality and tests twice to make sure
libcurl works identically using either HTTP backend.

The only way to keep hyper support in curl is to give it a good polish by
someone with time, skill and energy to spend on this task.

Unless a significant overhaul has proven to be in progress, hyper support is
removed from curl in January 2025.

## Past removals

 - Pipelining
 - axTLS
 - PolarSSL
 - NPN
 - Support for systems without 64-bit data types
 - NSS
 - gskit
 - MinGW v1
 - NTLM_WB
 - space-separated `NOPROXY` patterns
