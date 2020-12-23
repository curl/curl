Long: no-sessionid
Help: Disable SSL session-ID reusing
Protocols: TLS
Added: 7.16.0
Category: tls
---
Disable curl's use of SSL session-ID caching.  By default all transfers are
done using the cache. Note that while nothing should ever get hurt by
attempting to reuse SSL session-IDs, there seem to be broken SSL
implementations in the wild that may require you to disable this in order for
you to succeed.

Note that this is the negated option name documented. You can thus use
--sessionid to enforce session-ID caching.
