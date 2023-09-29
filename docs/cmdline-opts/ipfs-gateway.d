c: Copyright (C) 2023, Mark Gaiser, <markg85@gmail.com>
SPDX-License-Identifier: curl
Long: ipfs-gateway
Arg: <URL>
Help: Gateway for IPFS
Added: 8.4.0
See-also: help manual
Category: ipfs
Example: --ipfs-gateway $URL ipfs://
Multi: single
---
Specifies which gateway to use for IPFS and IPNS URLs.
Not specifying this argument will let cURL try to automatically
check if IPFS_GATEWAY environment variable is set,
or if ~/.ipfs/gateway plain text file exists.

If you run a local IPFS node, this gateway is by default
available under http://localhost:8080. A full example URL would
look like:

 curl --ipfs-gateway http://localhost:8080 ipfs://bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi


You can also specify publicly available gateways. One such
gateway is https://ipfs.io. A full example url would look like:

 curl --ipfs-gateway https://ipfs.io ipfs://bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi


There are many public IPFS gateways. As a starting point to find
one that works for your case, consult this page:

 https://ipfs.github.io/public-gateway-checker/


A word of caution! When you opt to go for a remote gateway you should
be aware that you completely trust the gateway. This is fine in local gateways
as you host it yourself. With remote gateways there could potentially be
a malicious actor returning you data that does not match the request you made,
inspect or even interfere with the request. You won't notice this when using cURL.
A mitigation could be to go for a "trustless" gateway. This means you
locally verify that the data. Consult the docs page on trusted vs trustless:
https://docs.ipfs.tech/reference/http/gateway/#trusted-vs-trustless

