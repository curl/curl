# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the curl-library mailing list as soon as possible and explain to us why
this is a problem for you and how your use case can't be satisfied properly
using a work around.

## axTLS backend

Here are some complaints on axTLS.

 - home page without HTTPS
 - [doesn't support modern TLS features like SNI](https://github.com/dsheets/axtls/issues/2)
 - [lacks support for modern ciphers](https://github.com/micropython/micropython/issues/3198)
 - [doesn't allow for outside bug report submissions](https://sourceforge.net/p/axtls/bugs/)
 - there's virtually no discussion about it in its [forum](https://sourceforge.net/p/axtls/discussion/)
   nor [mailing list](https://sourceforge.net/p/axtls/mailman/axtls-general/)

Combined, this list hints that this is not a library and project we should
recommend to users.

### State

Since June 1st, 2018 (curl 7.61.0) axTLS support is disabled in code and
requires a small code change to build without errors. [See
PR](https://github.com/curl/curl/pull/2628)

### Removal

Remove all axTLS related code from curl on December 1st, exactly six months
after previously mentioned commit. To be shipped on December 26, 2018
(possibly called version 7.64.0)

## HTTP pipelining

HTTP pipelining is badly supported by curl in the sense that we have bugs and
it is a fragile feature without enough tests. Also, when something turns out
to have problems it is really tricky to debug due to the timing sensitivity so
very often enabling debug outputs or similar completely changes the nature of
the behavior and things are not reproducing anymore!

HTTP pipelining was never enabled by default by the large desktop browsers due
to all the issues with it. Both Firefox and Chrome have also dropped
pipelining support entirely since a long time back now. We are in fact over
time becoming more and more lonely in supporting pipelining.

The bad state of HTTP pipelining was a primary driving factor behind HTTP/2
and its multiplexing feature. HTTP/2 multiplexing is truly and really
"pipelining done right". It is way more solid, practical and solves the use
case in a better way with better performance and fewer downsides and problems.

In 2018, pipelining *should* be abandoned and HTTP/2 should be used instead.

### State

In 7.62.0, we will add code that ignores the "enable pipeline" option
setting). The *setopt() function would still return "OK" though so the
application couldn't tell that this is happening.

Users who truly need pipelining from that version will need to modify the code
(ever so slightly) and rebuild.

### Removal

Six months later, in sync with the planned release happen in April 2019,
(might be 7.66.0), assuming no major riots have occurred due to this in the
mean time, we rip out the pipelining code. It is in the order of 1000 lines of
libcurl code.

Left to answer: should the *setopt() function start to return error when these
options are set to be able to tell when they're trying to use options that are
no longer around or should we maintain behavior as much as possible?

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
