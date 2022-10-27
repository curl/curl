# curl the next few years - perhaps

Roadmap of things Daniel Stenberg wants to work on next. It is intended to
serve as a guideline for others for information, feedback and possible
participation.

## "Complete" the HTTP/3 support

curl has experimental support for HTTP/3 since a good while back. There are
some functionality missing and once the final specs are published we want to
eventually remove the "experimental" label from this functionality.

## HTTPS DNS records

As a DNS version of alt-svc and also a pre-requisite for ECH (see below).

See: https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-02

## ECH (Encrypted Client Hello - formerly known as ESNI)

 See Daniel's post on [Support of Encrypted
 SNI](https://curl.se/mail/lib-2019-03/0000.html) on the mailing list.

 Initial work exists in [PR 4011](https://github.com/curl/curl/pull/4011)
