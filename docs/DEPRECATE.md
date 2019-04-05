# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the curl-library mailing list as soon as possible and explain to us why
this is a problem for you and how your use case can't be satisfied properly
using a work around.

## `CURLOPT_DNS_USE_GLOBAL_CACHE`

This option makes libcurl use a global non-thread-safe cache for DNS if
enabled. The option has been marked as "obsolete" in the header file and in
documentation for several years already.

There's proper and safe method alternative provided since many years: the
share API.

### State

In curl 7.62.0 setting this option to TRUE will not have any effect. The
global cache will not be enabled. The code still remains so it is easy to
revert if need be.

### Removal

Remove all global-cache related code from curl around April 2019 (might be
7.66.0).

## HTTP/0.9

Supporting this is non-obvious and might even come as a surprise to some
users. Potentially even being a security risk in some cases.

### State

curl 7.64.0 introduces options to disable/enable support for this protocol
version. The default remains supported for now.

### Removal

The support for HTTP/0.9 will be switched to disabled by default in 6 months,
in the September 2019 release (possibly called curl 7.68.0).
