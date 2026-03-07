<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Experimental

Some features and functionality in curl and libcurl are considered
**EXPERIMENTAL**.

Experimental support in curl means:

1. Experimental features are provided to allow users to try them out and
   provide feedback on functionality and API etc before they ship and get
   "carved in stone".
2. You must enable the feature when invoking configure as otherwise curl is
   not built with the feature present.
3. We strongly advise against using this feature in production.
4. **We reserve the right to change behavior** of the feature without sticking
   to our API/ABI rules as we do for regular features, as long as it is marked
   experimental.
5. Experimental features are clearly marked so in documentation. Beware.

## Graduation

1. Each experimental feature should have a set of documented requirements of
   what is needed for that feature to graduate. Graduation means being removed
   from the list of experiments.
2. An experiment should NOT graduate if it needs test cases to be disabled,
   unless they are for minor features that are clearly documented as not
   provided by the experiment and then the disabling should be managed inside
   each affected test case.

## Experimental features right now

###  HTTP/3 support (non-ngtcp2 backends)

Graduation requirements:

- The used libraries should be considered out-of-beta with a reasonable
  expectation of a stable API going forward.

- Using HTTP/3 with the given build should perform without risking busy-loops

### The Rustls backend

Graduation requirements:

- a reasonable expectation of a stable API going forward.

## ECH

Use of the HTTPS resource record and Encrypted Client Hello (ECH) when using
DoH

Graduation requirements:

- ECH support exists in at least one widely used TLS library apart from
  BoringSSL and wolfSSL.

- feedback from users saying that ECH works for their use cases

- it has been given time to mature, so no earlier than April 2025 (twelve
  months after being added here)

## SSL session import/export

Import/Export of SSL sessions tickets in libcurl and curl command line
option '--ssl-session <filename>' for faster TLS handshakes and use
of TLSv1.3/QUIC Early Data (0-RTT).

Graduation requirements:

- the implementation is considered safe

- feedback from users saying that session export works for their use cases

## HTTPS RR

HTTPS records support is a requirement for ECH but is provided as a
stand-alone feature that is itself considered EXPERIMENTAL.

Graduation requirements:

- HTTPS records work for DoH, c-ares and the threaded resolver

- HTTPS records can control ALPN and port number, at least

- There are options to control HTTPS use
