c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: alt-svc
Arg: <file name>
Protocols: HTTPS
Help: Enable alt-svc with this cache file
Added: 7.64.1
Category: http
See-also: resolve connect-to
Example: --alt-svc svc.txt $URL
Multi: append
---
This option enables the alt-svc parser in curl. If the file name points to an
existing alt-svc cache file, that will be used. After a completed transfer,
the cache will be saved to the file name again if it has been modified.

Specify a "" file name (zero length) to avoid loading/saving and make curl
just handle the cache in memory.

If this option is used several times, curl will load contents from all the
files but the last one will be used for saving.
