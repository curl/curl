curl the next few years - perhaps
=================================

Roadmap of things Daniel Stenberg wants to work on next. It is intended to
serve as a guideline for others for information, feedback and possible
participation.

QUIC
----

 See the [QUIC wiki page](https://github.com/curl/curl/wiki/QUIC).

HTTP cookies
------------

Two cookie drafts have been adopted by the httpwg in IETF and we should
support them as the popular browsers will as well:

[Deprecate modification of 'secure' cookies from non-secure
origins](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone-00)

[Cookie Prefixes](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-prefixes-00)

[Firefox bug report about secure cookies](https://bugzilla.mozilla.org/show_bug.cgi?id=976073)

SRV records
-----------

How to find services for specific domains/hosts.

Improve
-------

1. curl -h output (considered overwhelming to users).

2. We have > 200 command line options, is there a way to redo things to
   simplify or improve the situation as we are likely to keep adding
   features/options in the future too.

3. Perform some of the clean up from the TODO document, removing old
   definitions and such like that are currently earmarked to be removed years
   ago.
