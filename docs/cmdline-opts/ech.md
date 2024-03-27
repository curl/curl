---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ech
Arg: <config>
Help: Configure Encrypted Client Hello (ECH) for use with the TLS session
Added: 8.6.1
Category: tls ECH
Multi: single
See-also:
  - doh-url
Example:
  - --ech true $URL
---

# `--ech`

When multiple ``--ech`` options are supplied then the most-recent value for
true/false/hard/grease value will be used, as will the most-recent
``ecl:<b64string>`` value, and ``pn:<name>`` value, if either of those were
provided.

The values allowed for <config> can be:

## "false"
Do not attempt ECH

## "grease"

Send a GREASE ECH extension

## "true"

Attempt ECH if possible, but don't fail if ECH is not attempted.
(The connection will fail if ECH is attempted but fails.)

## "hard"

Attempt ECH and fail if that's not possible.
ECH only works with TLS 1.3 and also requires using
DoH or providing an ECHConfigList on the command line.

## "ecl:<b64val>"

A base64 encoded ECHConfigList that will be used for ECH.

## "pn:<name>"

A name to use to over-ride the `public_name` field of an ECHConfigList
(only available with OpenSSL TLS support)

## Errors

Most errors cause error
*CURLE_ECH_REQUIRED* (101).

