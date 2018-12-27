Long: tls13-middlebox
Arg: <boolean>
Help: TLS 1.3 middlebox compatibility mode
Added: 7.65.0
---
This option tells curl to enable or disable middlebox compatibility mode for
TLS 1.3. Middlebox compatibility is on by default. This option only applies
to the OpenSSL backend, no other backend can turn off middlebox for TLS 1.3.
