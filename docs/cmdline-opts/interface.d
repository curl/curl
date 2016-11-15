Long: interface
Arg: <name>
Help: Use network INTERFACE (or address)
See-also: dns-interface
---

Perform an operation using a specified interface. You can enter interface
name, IP address or host name. An example could look like:

 curl --interface eth0:1 https://www.example.com/

If this option is used several times, the last one will be used.
