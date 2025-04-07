---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: engine
Arg: <name>
Help: Crypto engine to use
Protocols: TLS
Category: tls
Added: 7.9.3
Multi: single
See-also:
  - ciphers
  - curves
Example:
  - --engine flavor $URL
---

# `--engine`

Select the OpenSSL crypto engine to use for cipher operations. Use --engine
list to print a list of build-time supported engines. Note that not all (and
possibly none) of the engines may be available at runtime.

OpenSSL 1.x used engines, whereas starting from OpenSSL 3.x providers should
be used and engines are deprecated. curl does not provide an command line
option to explicitly load a certain OpenSSL providers. However, an OpenSSL
config can be used to achieve this. Either adjust the system-wide config,
usually present under `/etc/ssl/openssl.cnf` or point to one via the
environment variable before calling curl
`export OPENSSL_CONF=/your/path/to/openssl.cnf`. A minimum config file that
loads the `tpm2` and the default provider would look the following:

```dosini
openssl_conf = default_conf_section

[default_conf_section]
providers = provider_sect
alg_section = evp_properties

[provider_sect]
default = default_sect
tpm2 = tpm2_sect

[default_sect]
activate = 1

[tpm2_sect]
activate = 1

[evp_properties]
default_properties = ?provider!=tpm2
```
