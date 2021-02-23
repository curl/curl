# Alt-Svc

curl features support for the Alt-Svc: HTTP header.

## Enable Alt-Svc in build

`./configure --enable-alt-svc`

(enabled by default since 7.73.0)

## Standard

[RFC 7838](https://tools.ietf.org/html/rfc7838)

# Alt-Svc cache file format

This a text based file with one line per entry and each line consists of nine
space separated fields.

## Example

    h2 quic.tech 8443 h3-22 quic.tech 8443 "20190808 06:18:37" 0 0

## Fields

1. The ALPN id for the source origin
2. The host name for the source origin
3. The port number for the source origin
4. The ALPN id for the destination host
5. The host name for the destination host
6. The host number for the destination host
7. The expiration date and time of this entry within double quotes. The date format is "YYYYMMDD HH:MM:SS" and the time zone is GMT.
8. Boolean (1 or 0) if "persist" was set for this entry
9. Integer priority value (not currently used)

# TODO

- handle multiple response headers, when one of them says `clear` (should
  override them all)
- using `Age:` value for caching age as per spec
- `CURLALTSVC_IMMEDIATELY` support
