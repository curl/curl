Long: proxy-user
Short: U
Arg: <user:password>
Help: Proxy user and password
---
Specify the user name and password to use for proxy authentication.

If you use a Windows SSPI-enabled curl binary and do either Negotiate or NTLM
authentication then you can tell curl to select the user name and password
from your environment by specifying a single colon with this option: "-U :".

If this option is used several times, the last one will be used.
