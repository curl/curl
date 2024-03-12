---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc
Short: n
Help: Must read .netrc for username and password
Category: curl
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
file format. Curl does not complain if that file does not have the right
permissions (it should be neither world- nor group-readable). The environment
variable "HOME" is used to find the home directory.

On Windows two filenames in the home directory are checked: *.netrc* and
*_netrc*, preferring the former. Older versions on Windows checked for *_netrc*
only.

A quick and simple example of how to setup a *.netrc* to allow curl to FTP to
the machine host.domain.com with username 'myself' and password 'secret' could
look similar to:

    machine host.domain.com
    login myself
    password secret
