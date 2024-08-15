---
c: Copyright (C) Mark Gaiser, <markg85@gmail.com>
SPDX-License-Identifier: curl
Long: ipfs-gateway
Arg: <URL>
Help: Gateway for IPFS
Protocols: IPFS
Added: 8.4.0
Category: curl
Multi: single
See-also:
  - help
  - manual
Example:
  - --ipfs-gateway $URL ipfs://
---

# `--ipfs-gateway`

Specify which gateway to use for IPFS and IPNS URLs. Not specifying this
instead makes curl check if the IPFS_GATEWAY environment variable is set, or
if a `~/.ipfs/gateway` file holding the gateway URL exists.

If you run a local IPFS node, this gateway is by default available under
`http://localhost:8080`. A full example URL would look like:

    curl --ipfs-gateway http://localhost:8080 \
       ipfs://bafybeigagd5nmnn2iys2f3

There are many public IPFS gateways. See for example:
https://ipfs.github.io/public-gateway-checker/

If you opt to go for a remote gateway you need to be aware that you completely
trust the gateway. This might be fine in local gateways that you host
yourself. With remote gateways there could potentially be malicious actors
returning you data that does not match the request you made, inspect or even
interfere with the request. You may not notice this when using curl. A
mitigation could be to go for a "trustless" gateway. This means you locally
verify that the data. Consult the docs page on trusted vs trustless:
https://docs.ipfs.tech/reference/http/gateway/#trusted-vs-trustless
