curl the next few years - perhaps
=================================

Roadmap of things Daniel Stenberg and Steve Holme want to work on next. It is
intended to serve as a guideline for others for information, feedback and
possible participation.

HTTP/2
------

- test suite

   Base this on existing nghttp2 server to start with to make functional
   tests. Later on we can adopt that code or work with nghttp2 to provide ways
   to have the http2 server respond with broken responses to make sure we deal
   with that nicely as well.

   To decide: if we need to bundle parts of the nghttp2 stuff that probably
   won't be shipped by many distros.

- provide option for HTTP/2 "prior knowledge" over clear text

   As it would avoid the roundtrip-heavy Upgrade: procedures when you _know_
   it speaks HTTP/2.

- provide option to allow curl to default to HTTP/2 only when using HTTPS

   We could switch on HTTP/2 by-default for HTTPS quite easily and it
   shouldn't hurt anyone, while HTTP/2 for HTTP by default could introduce
   lots of Upgrade: roundtrips that users won't like. So a separated option
   alternative makes sense.

SRV records
-----------

How to find services for specific domains/hosts.

HTTPS to proxy
--------------

To avoid network traffic to/from the proxy getting snooped on.

curl_formadd()
--------------

make sure there's an easy handle passed in to `curl_formadd()`,
`curl_formget()` and `curl_formfree()` by adding replacement functions and
deprecating the old ones to allow custom mallocs and more

third-party SASL
----------------

add support for third-party SASL libraries such as Cyrus SASL - may need to
move existing native and SSPI based authentication into vsasl folder after
reworking HTTP and SASL code

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
