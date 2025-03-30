---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ech
Arg: <config>
Help: Configure ECH
Added: 8.8.0
Category: tls
Protocols: HTTPS
Multi: single
See-also:
  - doh-url
Example:
  - --ech true $URL
---

# `--ech`

Specify how to do ECH (Encrypted Client Hello).

The values allowed for \<config\> can be:

## `false`

Do not attempt ECH. The is the default.

## `grease`

Send a GREASE ECH extension

## `true`

Attempt ECH if possible, but do not fail if ECH is not attempted.
(The connection fails if ECH is attempted but fails.)

## `hard`

Attempt ECH and fail if that is not possible. ECH only works with TLS 1.3 and
also requires using DoH or providing an ECHConfigList on the command line.

## `ecl:<b64val>`

A base64 encoded ECHConfigList that is used for ECH.

## `pn:<name>`

A name to use to over-ride the `public_name` field of an ECHConfigList (only
available with OpenSSL TLS support)

##

Most ECH related errors cause error *CURLE_ECH_REQUIRED* (101).
