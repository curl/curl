curl the next few years - perhaps
=================================

Roadmap of things Daniel Stenberg and Steve Holme want to work on next. It is
intended to serve as a guideline for others for information, feedback and
possible participation.

New stuff - libcurl
-------------------

1. HTTP/2

 - test suite
 - http2 multiplexing/pipelining
 - provide option for HTTP/2 "prior knowledge" over clear text
 - provide option to allow curl to default to HTTP/2 only when using HTTPS

2. SRV records

3. HTTPS to proxy

4. make sure there's an easy handle passed in to `curl_formadd()`,
   `curl_formget()` and `curl_formfree()` by adding replacement functions and
   deprecating the old ones to allow custom mallocs and more

5. add support for third-party SASL libraries such as Cyrus SASL - may need to
   move existing native and SSPI based authentication into vsasl folder after
   reworking HTTP and SASL code

6. SASL authentication in LDAP

7. Simplify the SMTP email interface so that programmers don't have to
   construct the body of an email that contains all the headers, alternative
   content, images and attachments - maintain raw interface so that
   programmers that want to do this can

8. Allow the email protocols to return the capabilities before
    authenticating. This will allow an application to decide on the best
    authentication mechanism

9. Allow Windows threading model to be replaced by Win32 pthreads port

10. Implement a dynamic buffer size to allow SFTP to use much larger buffers
    and possibly allow the size to be customizable by applications. Use less
    memory when handles are not in use?

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

3. we have > 160 command line options, is there a way to redo things to
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
