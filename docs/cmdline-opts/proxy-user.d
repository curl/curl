c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-user
Short: U
Arg: <user:password>
Help: Proxy user and password
Category: proxy auth
Example: --proxy-user name:pwd -x proxy $URL
Added: 4.0
See-also: proxy-pass
Multi: single
---
Specify the user name and password to use for proxy authentication.

If you use a Windows SSPI-enabled curl binary and do either Negotiate or NTLM
authentication then you can tell curl to select the user name and password
from your environment by specifying a single colon with this option: "-U :".

On systems where it works, curl hides the given option argument from process
listings. This is not enough to protect credentials from possibly getting seen
by other users on the same system as they still are visible for a moment
before cleared. Such sensitive data should be retrieved from a file instead or
similar and never used in clear text in a command line.
