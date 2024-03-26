# Experimental

Some features and functionality in curl and libcurl are considered
**EXPERIMENTAL**.

Experimental support in curl means:

1. Experimental features are provided to allow users to try them out and
   provide feedback on functionality and API etc before they ship and get
   "carved in stone".
2. You must enable the feature when invoking configure as otherwise curl is
   not built with the feature present.
3. We strongly advise against using this feature in production.
4. **We reserve the right to change behavior** of the feature without sticking
   to our API/ABI rules as we do for regular features, as long as it is marked
   experimental.
5. Experimental features are clearly marked so in documentation. Beware.

## Experimental features right now

 - The Hyper HTTP backend
 - HTTP/3 support (using the quiche or msh3 backends)
 - The rustls backend
 - WebSocket
