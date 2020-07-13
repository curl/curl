Long: max-redirs
Arg: <num>
Help: Maximum number of redirects allowed
Protocols: HTTP
Category: http
---
Set maximum number of redirection-followings allowed. When --location is used,
is used to prevent curl from following redirections too much. By default, the
limit is set to 50 redirections. Set this option to -1 to make it unlimited.

If this option is used several times, the last one will be used.
