---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: knownhosts
Arg: <file>
Protocols: SCP SFTP
Help: Specify knownhosts path
Category: ssh
Added: 8.17.0
Multi: single
See-also:
  - hostpubsha256
  - hostpubmd5
  - insecure
  - key
Example:
  - --knownhosts filename --key here $URL
---

# `--knownhosts`

When doing SCP and SFTP transfers, curl automatically checks a database
containing identification for all hosts it has ever been used with to verify
that the host it connects to is the same as previously. Host keys are stored
in such a known hosts file. curl uses the ~/.ssh/known_hosts in the user's
home directory by default.

This option lets a user specify a specific file to check the host against.

The known hosts check can be disabled with --insecure, but that makes the
transfer insecure and is strongly discouraged.
