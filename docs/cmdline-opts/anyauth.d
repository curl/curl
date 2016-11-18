Long: anyauth
Help: Pick any authentication method
Protocols: HTTP
See-also: proxy-anyauth basic digest
---
Tells curl to figure out authentication method by itself, and use the most
secure one the remote site claims to support. This is done by first doing a
request and checking the response-headers, thus possibly inducing an extra
network round-trip. This is used instead of setting a specific authentication
method, which you can do with --basic, --digest, --ntlm, and --negotiate.

Using --anyauth is not recommended if you do uploads from stdin, since it may
require data to be sent twice and then the client must be able to rewind. If
the need should arise when uploading from stdin, the upload operation will
fail.

Used together with --user.
