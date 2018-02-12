Long: interface
Arg: <name>
Help: Use network INTERFACE (or address)
See-also: dns-interface
---

Perform an operation using a specified interface. You can enter interface
name, IP address or host name. An example could look like:

 curl --interface eth0:1 https://www.example.com/

If this option is used several times, the last one will be used.

On Linux it can be used to specify a VRF, but the binary needs to either
have CAP_NET_RAW or to be ran as root. More information about Linux VRF:
https://www.kernel.org/doc/Documentation/networking/vrf.txt
