Long: http0.9
Tags: Versions
Protocols: HTTP
Added:
Help: Allow HTTP 0.9 responses
---
Tells curl to be fine with HTTP version 0.9 response.

HTTP/0.9 is a completely headerless response and therefore you can also
connect with this to non-HTTP servers and still get a response since curl will
simply transparently downgrade - if allowed.

A future curl version will deny continuing if the response isn't at least
HTTP/1.0 unless this option is used.
