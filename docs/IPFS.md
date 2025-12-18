<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# IPFS
For an overview about IPFS, visit the [IPFS project site](https://ipfs.tech/).

In IPFS there are two protocols. IPFS and IPNS (their workings are explained in detail [here](https://docs.ipfs.tech/concepts/)). The ideal way to access data on the IPFS network is through those protocols. For example to access the Big Buck Bunny video the ideal way to access it is like: `ipfs://bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi`

## IPFS Gateways

IPFS Gateway acts as a bridge between traditional HTTP clients and IPFS.
IPFS Gateway specifications of HTTP semantics can be found [here](https://specs.ipfs.tech/http-gateways/).

### Deserialized responses

By default, a gateway acts as a bridge between traditional HTTP clients and IPFS and performs necessary hash verification and deserialization. Through such gateway, users can download files, directories, and other content-addressed data stored with IPFS or IPNS as if they were stored in a traditional web server.

### Verifiable responses

By explicitly requesting [application/vnd.ipld.raw](https://www.iana.org/assignments/media-types/application/vnd.ipld.raw) or [application/vnd.ipld.car](https://www.iana.org/assignments/media-types/application/vnd.ipld.car) responses, by means defined in [Trustless Gateway Specification](https://specs.ipfs.tech/http-gateways/trustless-gateway/), the user is able to fetch raw content-addressed data and [perform hash verification themselves](https://docs.ipfs.tech/reference/http/gateway/#trustless-verifiable-retrieval).

This enables users to use untrusted, public gateways without worrying they might return invalid/malicious bytes.

## IPFS and IPNS protocol handling

There are various ways to access data from the IPFS network. One such way is
through the concept of public
"[gateways](https://docs.ipfs.tech/concepts/ipfs-gateway/#overview)". The
short version is that entities can offer gateway services. An example here
that is hosted by Protocol Labs (who also makes IPFS) is `dweb.link` and
`ipfs.io`. Both sites expose gateway functionality. Getting a file through
`ipfs.io` looks like this:
`https://ipfs.io/ipfs/bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi`

If you were to be [running your own IPFS
node](https://docs.ipfs.tech/how-to/command-line-quick-start/) then you, by
default, also have a [local gateway](https://specs.ipfs.tech/http-gateways/)
running. In its default configuration the earlier example would then also work
in this link:

`http://127.0.0.1:8080/ipfs/bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi`

## cURL handling of the IPFS protocols

The IPFS integration in cURL hides this gateway logic for you. Instead of
providing a full URL to a file on IPFS like this:

```
curl http://127.0.0.1:8080/ipfs/bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi
```

You can provide it with the IPFS protocol instead:
```
curl ipfs://bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi
```

With the IPFS protocol way of asking a file, cURL still needs to know the
gateway. curl essentially just rewrites the IPFS based URL to a gateway URL.

### IPFS_GATEWAY environment variable

If the `IPFS_GATEWAY` environment variable is found, its value is used as
gateway.

### Automatic gateway detection

When you provide no additional details to cURL then it:

1. First looks for the `IPFS_GATEWAY` environment variable and use that if it
   is set.
2. Looks for the file: `~/.ipfs/gateway`. If it can find that file then it
   means that you have a local gateway running and that file contains the URL
   to your local gateway.

If cURL fails, you are presented with an error message and a link to this page
to the option most applicable to solving the issue.

### `--ipfs-gateway` argument

You can also provide a `--ipfs-gateway` argument to cURL. This overrules any
other gateway setting. curl does not fallback to the other options if the
provided gateway did not work.

## Gateway redirects

A gateway could redirect to another place. For example, `dweb.link` redirects
[path based](https://docs.ipfs.tech/how-to/address-ipfs-on-web/#path-gateway)
requests to [subdomain
based](https://docs.ipfs.tech/how-to/address-ipfs-on-web/#subdomain-gateway)
ones. A request using:

    curl ipfs://bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi --ipfs-gateway https://dweb.link

Which would be translated to:

    https://dweb.link/ipfs/bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi

redirects to:

    https://bafybeigagd5nmnn2iys2f3doro7ydrevyr2mzarwidgadawmamiteydbzi.ipfs.dweb.link

If you trust this behavior from your gateway of choice then passing the `-L`
option follows the redirect.

## Error messages and hints

Depending on the arguments, cURL could present the user with an error.

### Gateway file and environment variable

cURL tried to look for the file: `~/.ipfs/gateway` but could not find it. It
also tried to look for the `IPFS_GATEWAY` environment variable but could not
find that either. This happens when no extra arguments are passed to cURL and
letting it try to figure it out [automatically](#automatic-gateway-detection).

Any IPFS implementation that has gateway support should expose its URL in
`~/.ipfs/gateway`. If you are already running a gateway, make sure it exposes
the file where cURL expects to find it.

Alternatively you could set the `IPFS_GATEWAY` environment variable or pass
the `--ipfs-gateway` flag to the cURL command.

### Malformed gateway URL

The command executed evaluates in an invalid URL. This could be anywhere in
the URL, but a likely point is a wrong gateway URL.

Inspect the URL set via the `IPFS_GATEWAY` environment variable or passed with
the `--ipfs-gateway` flag. Alternatively opt to go for the
[automatic](#automatic-gateway-detection) gateway detection.
