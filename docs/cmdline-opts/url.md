---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: url
Arg: <url>
Help: URL to work with
Category: curl
Added: 7.5
Multi: append
See-also:
  - next
  - config
Example:
  - --url $URL
---

# `--url`

Specify a URL to fetch.

If the given URL is missing a scheme name (such as `http://` or `ftp://` etc)
then curl makes a guess based on the host. If the outermost subdomain name
matches DICT, FTP, IMAP, LDAP, POP3 or SMTP then that protocol is used,
otherwise HTTP is used. Guessing can be avoided by providing a full URL
including the scheme, or disabled by setting a default protocol, see
--proto-default for details.

To control where this URL is written, use the --output or the --remote-name
options.

**WARNING**: On Windows, particular `file://` accesses can be converted to
network accesses by the operating system. Beware!
