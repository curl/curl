---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: version-all
Help: Show version number, disabled features, and quit
Category: curl
Added: 8.13.0
Multi: custom
See-also:
  - help
  - manual
  - version
Example:
  - --version-all
---

# `--version-all`

Displays information about curl and the libcurl version it uses.

Same as `--version`, with an additional fifth line (starts with `Disabled:`)
that shows specific features explicitly disabled.

## `aws`
Disabled **aws-sigv4**.

## `basic-auth`
Disabled Basic authentication.

## `bearer-auth`
Disabled Bearer authentication.

## `bindlocal`
Disabled local binding support.

## `cookies`
Disabled cookies support.

## `DoH`
Disabled DNS-over-HTTPS.

## `digest-auth`
Disabled Digest authentication.

## `form-api`
Disabled **form-api**.

## `HTTP-auth`
Disabled all HTTP authentication methods.

## `headers-api`
Disabled **headers-api** support.

## `large-size`
Missing large size support.

## `large-time`
Missing large time support.

## `Mime`
Disabled MIME support.

## `negotiate-auth`
Disabled negotiate authentication.

## `netrc`
Disabled netrc parser.

## `parsedate`
Disabled date parsing.

## `proxy`
Disabled proxy support.

## `sha512-256`
Disabled SHA-512/256 hash algorithm.

## `shuffle-dns`
Disabled shuffle DNS feature.

## `typecheck`
Disabled GCC type-checker.

## `verbose-strings`
Disabled verbose strings.

## `wakeup`
Disabled wakeup support.

## `win32-ca-search-safe`
Disabled unsafe CA bundle search in PATH on Windows.

## `win32-ca-searchpath`
Disabled CA bundle search on disk on Windows.

## `xattr`
Disabled xattr support.
