Long: proto-default
Help: Use PROTOCOL for any URL missing a scheme
Arg: <protocol>
Added: 7.45.0
Category: connection curl
---
Tells curl to use \fIprotocol\fP for any URL missing a scheme name.

Example:

 curl --proto-default https ftp.mozilla.org

An unknown or unsupported protocol causes error
\fICURLE_UNSUPPORTED_PROTOCOL\fP (1).

This option does not change the default proxy protocol (http).

Without this option curl would make a guess based on the host, see --url for
details.
