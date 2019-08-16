curl the next few years - perhaps
=================================

Roadmap of things Daniel Stenberg wants to work on next. It is intended to
serve as a guideline for others for information, feedback and possible
participation.

ESNI (Encrypted SNI)
--------------------

 See Daniel's post on [Support of Encrypted
 SNI](https://curl.haxx.se/mail/lib-2019-03/0000.html) on the mailing list.

HSTS
----

Complete and merge [the existing PR](https://github.com/curl/curl/pull/2682).

Option to let CURLOPT_CUSTOMREQUEST be overridden on redirect
-------------------------------------------------------------

(This is a common problem for people using `-X` and `-L` together.)

Possibly as a new bit to `CURLOPT_FOLLOWLOCATION` ?

Hardcode “localhost”
--------------------

No need to resolve it. Avoid a risk where this is resolved over the network
and actually responds with something else than a local address. Some operating
systems already do this. Also:
https://tools.ietf.org/html/draft-ietf-dnsop-let-localhost-be-localhost-02

Consider "menu config"-style build feature selection
----------------------------------------------------

Allow easier building of custom libcurl versions with only a selected feature
where the available features are easily browsable and toggle-able ON/OFF or
similar.
