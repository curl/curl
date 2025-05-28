---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tls-max
Arg: <VERSION>
Tags: Versions
Protocols: TLS
Added: 7.54.0
Requires: TLS
Help: Maximum allowed TLS version
Category: tls
Multi: single
See-also:
  - tlsv1.0
  - tlsv1.1
  - tlsv1.2
  - tlsv1.3
Example:
  - --tls-max 1.2 $URL
  - --tls-max 1.3 --tlsv1.2 $URL
---

# `--tls-max`

Set the maximum allowed TLS version. The minimum acceptable version is set by
tlsv1.0, tlsv1.1, tlsv1.2 or tlsv1.3.

If the connection is done without TLS, this option has no effect. This
includes QUIC-using (HTTP/3) transfers.

## default
Use up to the recommended TLS version.

## 1.0
Use up to TLSv1.0.

## 1.1
Use up to TLSv1.1.

## 1.2
Use up to TLSv1.2.

## 1.3
Use up to TLSv1.3.
