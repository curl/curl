curl the next few years - perhaps
=================================

Roadmap of things Daniel Stenberg and Steve Holme want to work on next. It is
intended to serve as a guideline for others for information, feedback and
possible participation.

HTTP/2
------

Improve performance. Measurements and tests have shown that in several cases
doing transfers over HTTP/2 can be notably slower than the same transfer done
over HTTP/1. Some of that difference can be attributed the inefficient window
size handling currently in use but there are probably more to be learned and
worked on to optimize this.

QUIC
----

The standardization process of QUIC has been taken to the IETF and can be
followed on the [IETF QUIC Mailing
list](https://www.ietf.org/mailman/listinfo/quic). I'd like us to get on the
bandwagon. Ideally, this would be done with a separate library/project to
handle the binary/framing layer in a similar fashion to how HTTP/2 is
implemented. This, to allow other projects to benefit from the work and to
thus broaden the interest and chance of others to participate.

TLS 1.3
-------

The new version of the TLS protocol is in the pipeline and will soon start to
get used out in the wild. It offers some new interesting features and will
need the TLS libraries to adapt and quite likely provide additional or
modified APIs. libcurl needs to adapt accordingly.


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

HTTPS to proxy
--------------

To avoid network traffic to/from the proxy getting snooped on. There's a git
branch in the public git repository for this that we need to make sure works
for all TLS backends and then merge!

curl_formadd()
--------------

make sure there's an easy handle passed in to `curl_formadd()`,
`curl_formget()` and `curl_formfree()` by adding replacement functions and
deprecating the old ones to allow custom mallocs and more

Third-party SASL
----------------

Add support for third-party SASL libraries such as Cyrus SASL.

SASL authentication in LDAP
---------------------------

...

Simplify the SMTP email
-----------------------

Simplify the SMTP email interface so that programmers don't have to
construct the body of an email that contains all the headers, alternative
content, images and attachments - maintain raw interface so that
programmers that want to do this can

email capabilities
------------------

Allow the email protocols to return the capabilities before
authenticating. This will allow an application to decide on the best
authentication mechanism

Win32 pthreads
--------------

Allow Windows threading model to be replaced by Win32 pthreads port

dynamic buffer size
-------------------

Implement a dynamic buffer size to allow SFTP to use much larger buffers and
possibly allow the size to be customizable by applications. Use less memory
when handles are not in use?

New stuff - curl
----------------

1. Embed a language interpreter (lua?). For that middle ground where curl
   isn’t enough and a libcurl binding feels “too much”. Build-time conditional
   of course.

2. Simplify the SMTP command line so that the headers and multi-part content
   don't have to be constructed before calling curl

Improve
-------

1. build for windows (considered hard by many users)

2. curl -h output (considered overwhelming to users)

3. we have > 170 command line options, is there a way to redo things to
   simplify or improve the situation as we are likely to keep adding
   features/options in the future too

4. docs (considered "bad" by users but how do we make it better?)

  - split up curl.1

5. authentication framework (consider merging HTTP and SASL authentication to
   give one API for protocols to call)

6. Perform some of the clean up from the TODO document, removing old
   definitions and such like that are currently earmarked to be removed years
   ago

Remove
------

1. makefile.vc files as there is no point in maintaining two sets of Windows
   makefiles. Note: These are currently being used by the Windows autobuilds
