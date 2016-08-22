Long: localaddr
Arg: <IP Address>
Help: Use a specific local IP Address
See-also: interface
---

Perform an operation using a specified local IP address.

The IP Address can already be set with the
CURLOPT_INTERFACE, but if you want to set both the Interface and the IP
address, then you can set the Interface with CURLOPT_INTERFACE and the
address with CURLOPT_LOCALADDR.  These two options together are also
needed in cases where you are using VRF (on Linux) and have the same
IP Address on multiple different Interfaces.
name, IP address or host name. An example could look like:

 curl --interface if!eth0 --localaddr 192.168.100.1 https://www.example.com/

If this option is used several times, the last one will be used.
