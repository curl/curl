# Alt-Svc

curl features **EXPERIMENTAL** support for the Alt-Svc: HTTP header.

## Experimental

Experimental support in curl means:

1. Experimental features are provided to allow users to try them out and
   provide feedback on functionality and API etc before they ship and get
   "carved in stone".
2. You must enable the feature when invoking configure as otherwise curl will
   not be built with the feature present.
3. We strongly advice against using this feature in production.
4. **We reserve the right to change behavior** of the feature without sticking
   to our API/ABI rules as we do for regular features, as long as it is marked
   experimental.
5. Experimental features are clearly marked so in documentation. Beware.

## Enable Alt-Svc in build

`./configure --enable-alt-svc`

## Standard

[RFC 7838](https://tools.ietf.org/html/rfc7838)

## What works

- read alt-svc file from disk
- write alt-svc file from disk
- parse `Alt-Svc:` response headers, including `ma`, `clear` and `persist`.
- replaces old entries when new alternatives are received
- unit tests to verify most of this functionality (test 1654)
- act on `Alt-Svc:` response headers
- build conditionally on `configure --enable-alt-svc` only, feature marked as
  **EXPERIMENTAL**
- implement `CURLOPT_ALTSVC_CTRL`
- implement `CURLOPT_ALTSVC`
- document  `CURLOPT_ALTSVC_CTRL`
- document `CURLOPT_ALTSVC`
- document `--alt-svc`
- add `CURL_VERSION_ALTSVC`
- make `curl -V` show 'alt-svc' as a feature if built-in
- support `curl --alt-svc [file]` to enable caching, using that file
- make `tests/runtests.pl` able to filter tests on the feature `alt-svc`
- actually use the existing in-memory alt-svc cache for outgoing connections
- alt-svc cache expiry
- test 355 and 356 verify curl acting on Alt-Svc, received from header and
  loaded from cache. The latter needs a debug build since it enables Alt-Svc
  for plain HTTP.

## What is left

- handle multiple response headers, when one of them says `clear` (should
  override them all)
- using `Age:` value for caching age as per spec
- `CURLALTSVC_IMMEDIATELY` support
- `CURLALTSVC_ALTUSED` support
