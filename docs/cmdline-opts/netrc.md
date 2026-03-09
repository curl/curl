---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc
Short: n
Help: Must read .netrc for username and password
Category: auth
Added: 4.6
Mutexed: netrc-file netrc-optional
Multi: boolean
See-also:
  - netrc-file
  - config
  - user
Example:
  - --netrc $URL
---

# `--netrc`

Make curl scan the *.netrc* file in the user's home directory for login name
and password. This is typically used for FTP on Unix. If used with HTTP, curl
enables user authentication. See *netrc(5)* and *ftp(1)* for details on the
file format. curl does not complain if that file does not have the right
permissions (it should be neither world- nor group-readable). The environment
variable `HOME` is used to find the home directory. If the `NETRC` environment
variable is set, that filename is used as the netrc file. (Added in 8.16.0)

If --netrc-file is used, that overrides all other ways to figure out the file.

The netrc file provides credentials for a hostname independent of which
protocol and port number that are used.

On Windows two filenames in the home directory are checked: *.netrc* and
*_netrc*, preferring the former. Older versions on Windows checked for
*_netrc* only.

A quick and simple example of how to setup a *.netrc* to allow curl to access
the machine host.example.com with username `myself` and password `secret`
could look similar to:

    machine host.example.com
    login myself
    password secret

curl also supports the `default` keyword. This is the same as machine name
except that default matches any name. There can be only one `default` token,
and it must be after all machine tokens.

When providing a username in the URL and a *.netrc* file, curl looks for the
password for that specific user for the given host if such an entry appears in
the file before a "generic" `machine` entry without `login` specified.
