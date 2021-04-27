Long: fail-with-body
Protocols: HTTP
Help: Fail on HTTP errors but save the body
Category: http output
Added: 7.76.0
See-also: fail
---

Return an error on server errors where the HTTP response code is 400 or
greater). In normal cases when an HTTP server fails to deliver a document, it
returns an HTML document stating so (which often also describes why and
more). This flag will still allow curl to output and save that content but
also to return error 22.

This is an alternative option to --fail which makes curl fail for the same
circumstances but without saving the content.
