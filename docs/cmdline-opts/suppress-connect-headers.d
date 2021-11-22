Long: suppress-connect-headers
Help: Suppress proxy CONNECT response headers
See-also: dump-header include proxytunnel
Category: proxy
Example: --suppress-connect-headers --include -x proxy $URL
Added: 7.54.0
---
When --proxytunnel is used and a CONNECT request is made do not output proxy
CONNECT response headers. This option is meant to be used with --dump-header or
--include which are used to show protocol headers in the output. It has no
effect on debug options such as --verbose or --trace, or any statistics.
