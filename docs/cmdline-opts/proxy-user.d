Long: proxy-user
Short: U
Arg: <user:password>
Help: Proxy user and password
Category: proxy auth
Example: --proxy-user name:pwd -x proxy $URL
Added: 4.0
---
Specify the user name and password to use for proxy authentication.

If you use a Windows SSPI-enabled curl binary and do either Negotiate or NTLM
authentication then you can tell curl to select the user name and password
from your environment by specifying a single colon with this option: "-U :".

On systems where it works, curl will hide the given option argument from
process listings. This is not enough to protect credentials from possibly
getting seen by other users on the same system as they will still be visible
for a brief moment before cleared. Such sensitive data should be retrieved
from a file instead or similar and never used in clear text in a command line.

If this option is used several times, the last one will be used.
