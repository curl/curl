Long: resolve
Arg: <host:port:address>
Help: Resolve the host+port to this address
Added: 7.21.3
---
Provide a custom address for a specific host and port pair. Using this, you
can make the curl requests(s) use a specified address and prevent the
otherwise normally resolved address to be used. Consider it a sort of
/etc/hosts alternative provided on the command line. The port number should be
the number used for the specific protocol the host will be used for. It means
you need several entries if you want to provide address for the same host but
different ports.

The provided address set by this option will be used even if --ipv4 or --ipv6
is set to make curl use another IP version.

Support for providing the IP address within [brackets] was added in 7.57.0.

This option can be used many times to add many host names to resolve.
