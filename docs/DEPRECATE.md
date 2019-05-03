# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the curl-library mailing list as soon as possible and explain to us why
this is a problem for you and how your use case can't be satisfied properly
using a work around.

## HTTP/0.9

Supporting this is non-obvious and might even come as a surprise to some
users. Potentially even being a security risk in some cases.

### State

curl 7.64.0 introduces options to disable/enable support for this protocol
version. The default remains supported for now.

### Removal

The support for HTTP/0.9 will be switched to disabled by default in 6 months,
in the September 2019 release (possibly called curl 7.68.0).
