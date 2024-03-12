---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proto
Arg: <protocols>
Help: Enable/disable PROTOCOLS
Added: 7.20.2
Category: connection curl
Multi: single
See-also:
  - proto-redir
  - proto-default
Example:
  - --proto =http,https,sftp $URL
---

# `--proto`

Limit what protocols to allow for transfers. Protocols are evaluated left to
right, are comma separated, and are each a protocol name or 'all', optionally
prefixed by zero or more modifiers. Available modifiers are:

## +
Permit this protocol in addition to protocols already permitted (this is
the default if no modifier is used).

## -
Deny this protocol, removing it from the list of protocols already permitted.

## =
Permit only this protocol (ignoring the list already permitted), though
subject to later modification by subsequent entries in the comma separated
list.

##

For example: --proto -ftps uses the default protocols, but disables ftps

--proto -all,https,+http only enables http and https

--proto =http,https also only enables http and https

Unknown and disabled protocols produce a warning. This allows scripts to
safely rely on being able to disable potentially dangerous protocols, without
relying upon support for that protocol being built into curl to avoid an error.

This option can be used multiple times, in which case the effect is the same
as concatenating the protocols into one instance of the option.
