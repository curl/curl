curl the next few years - perhaps
=================================

Roadmap of things Daniel Stenberg wants to work on next. It is intended to
serve as a guideline for others for information, feedback and possible
participation.

HSTS
----

 Complete and merge [the existing PR](https://github.com/curl/curl/pull/2682).

 Loading a huge preload file is probably not too interesting to most people,
 but using a custom file and reacting to HSTS response header probably are
 good features.

DNS-over-TLS
------------

 Similar to DNS-over-HTTPS. Could share quite a lot of generic code.

ESNI (Encrypted SNI)
--------------------

 See Daniel's post on [Support of Encrypted
 SNI](https://curl.haxx.se/mail/lib-2019-03/0000.html) on the mailing list.

 Initial work exists in https://github.com/curl/curl/pull/4011

thread-safe `curl_global_init()`
--------------------------------

 Fix the libcurl specific parts of the function to be thread-safe. Make sure
 it can be thread-safe if built with thread-safe 3rd party libraries.
 (probably can't include `curl_global_init_mem()` for obvious reasons)

tiny-curl
---------

 There's no immediate action for this but users seem keen on being able to
 building custom minimized versions of libcurl for their products. Make sure
 new features that are "niche" can still be disabled at build-time.

MQTT
----

 Support receiving and sending MQTT messages. Initial work exists in
 https://github.com/curl/curl/pull/3514

Hardcode “localhost”
--------------------

 No need to resolve it. Avoid a risk where this is resolved over the network
 and actually responds with something else than a local address. Some
 operating systems already do this. Also:
 https://tools.ietf.org/html/draft-ietf-dnsop-let-localhost-be-localhost-02

"menu config"-style build feature selection
-------------------------------------------

 Allow easier building of custom libcurl versions with only a selected feature
 where the available features are easily browsable and toggle-able ON/OFF or
 similar.
