Long: fail
Short: f
Protocols: HTTP
Help: Fail silently (no output at all) on HTTP errors
See-also: fail-with-body
Category: important http
---
Fail silently (no output at all) on server errors. This is mostly done to
enable scripts etc to better deal with failed attempts. In normal cases
when an HTTP server fails to deliver a document, it returns an HTML document
stating so (which often also describes why and more). This flag will prevent
curl from outputting that and return error 22.

This method is not fail-safe and there are occasions where non-successful
response codes will slip through, especially when authentication is involved
(response codes 401 and 407).
