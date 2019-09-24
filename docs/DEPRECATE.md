# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the curl-library mailing list as soon as possible and explain to us why
this is a problem for you and how your use case can't be satisfied properly
using a work around.

## PolarSSL

The polarssl TLS library has not had an update in over three years. The last
release was done on [January 7
2016](https://tls.mbed.org/tech-updates/releases). This library has been
superseded by the mbedTLS library, which is the current incarnation of
PolarSSL. curl has supported mbedTLS since 2015.

It seems unlikely that this library is a good choice for users to get proper
TLS security and support today and at the same time there are plenty of good
and updated alternatives.

I consider it likely that the existing users of curl + polarssl out there are
stuck on old curl versions and when they eventually manage to update curl they
should also be able to update their TLS library.

### State

In the curl 7.65.2 release (July 17, 2019) the ability to build with this TLS
backend is removed from the configure script. The code remains and can be
built and used going forward, but it has to be manually enabled in a build (or
the configure removal reverted).

### Removal

The support for PolarSSL and all code for it will be completely removed from
the curl code base six months after it ships disabled in configure in a
release. In the release on or near February 27, 2020. (possibly called curl
7.70.0).
