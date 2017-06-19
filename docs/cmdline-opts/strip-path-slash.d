Long: strip-path-slash
Help: Strip off the first slash of the path
Protocols: HTTP
---
Tells curl to strip the leading slash from the path when it sends the path to
the server. Useful when wanting to issue HTTP requests without leading slash,
like "OPTIONS *".
