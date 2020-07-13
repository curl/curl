Long: location-trusted
Help: Like --location, and send auth to other hosts
Protocols: HTTP
See-also: user
Category: http auth
---
Like --location, but will allow sending the name + password to all hosts that
the site may redirect to. This may or may not introduce a security breach if
the site redirects you to a site to which you'll send your authentication info
(which is plaintext in the case of HTTP Basic authentication).
