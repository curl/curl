Long: ssl-no-implied-proxytunnel
Help: Disable implied --proxytunnel for HTTPS URL
Added: 7.58.0
---
This option tells curl to disable implied --proxytunnel for HTTPS URL.
If this option is enabled, and --connect-to is not enabled, and --proxytunnel
is not enabled, and the user has set an HTTP/HTTPS proxy then libcurl will
request HTTPS URLs from the proxy instead of attempting to tunnel the request
through the proxy. WARNING: this option loosens the SSL security, and by using
this flag you ask for exactly that.
