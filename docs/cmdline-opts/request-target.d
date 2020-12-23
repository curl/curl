Long: request-target
Help: Specify the target for this request
Protocols: HTTP
Added: 7.55.0
Category: http
---
Tells curl to use an alternative "target" (path) instead of using the path as
provided in the URL. Particularly useful when wanting to issue HTTP requests
without leading slash or other data that doesn't follow the regular URL
pattern, like "OPTIONS *".
