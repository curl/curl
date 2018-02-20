Long: ssl-trust-proxy
Help: Disable implied --proxytunnel for HTTPS URL
Added: 7.58.0
---
This option tells curl to disable implied --proxytunnel for SSL.
If this option is enabled, and --connect-to is not enabled, and --proxytunnel
is not enabled, and the user has set an HTTP/HTTPS proxy then libcurl will
request HTTPS URLs from the proxy instead of attempting to tunnel the request
through the proxy.

INSECURE: This option basically exposes the SSL transfer to the proxy, whereas
if it were tunneled the proxy would not be able to tamper with the connection.
Furthermore if it is an HTTP proxy then from libcurl to the proxy would be
unencrypted.
