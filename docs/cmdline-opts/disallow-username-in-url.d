Long: disallow-username-in-url
Help: Disallow username in url
Protocols: HTTP
Added: 7.61.0
See-also: proto
Category: curl http
Example: --disallow-username-in-url $URL
---
This tells curl to exit if passed a url containing a username. This is probably
most useful when the URL is being provided at run-time or similar.
