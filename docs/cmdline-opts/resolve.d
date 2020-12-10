Long: resolve
Arg: <[+]host:port:addr[,addr]...>
Help: Resolve the host+port to this address
Added: 7.21.3
Category: connection
---
Provide a custom address for a specific host and port pair. Using this, you
can make the curl requests(s) use a specified address and prevent the
otherwise normally resolved address to be used. Consider it a sort of
/etc/hosts alternative provided on the command line. The port number should be
the number used for the specific protocol the host will be used for. It means
you need several entries if you want to provide address for the same host but
different ports.

By specifying '*' as host you can tell curl to resolve any host and specific
port pair to the specified address. Wildcard is resolved last so any --resolve
with a specific host and port will be used first.

The provided address set by this option will be used even if --ipv4 or --ipv6
is set to make curl use another IP version.

By prefixing the host with a '+' you can make the entry time out after curl's
default timeout (1 minute). Note that this will only make sense for long
running parallel transfers with a lot of files. In such cases, if this option
is used curl will try to resolve the host as it normally would once the
timeout has expired.

Support for providing the IP address within [brackets] was added in 7.57.0.

Support for providing multiple IP addresses per entry was added in 7.59.0.

Support for resolving with wildcard was added in 7.64.0.

Support for the '+' prefix was was added in 7.75.0.

This option can be used many times to add many host names to resolve.
