<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Adding a new protocol?

Every once in a while, someone comes up with the idea of adding support for yet
another protocol to curl. After all, curl already supports 25 something
protocols and it is the Internet transfer machine for the world.

In the curl project we love protocols and we love supporting many protocols
and doing it well.

How do you proceed to add a new protocol and what are the requirements?

## No fixed set of requirements

This document is an attempt to describe things to consider. There is no
checklist of the twenty-seven things you need to cross off. We view the entire
effort as a whole and then judge if it seems to be the right thing - for now.
The more things that look right, fit our patterns and are done in ways that
align with our thinking, the better are the chances that we agree that
supporting this protocol is a grand idea.

## Mutual benefit is preferred

curl is not here for your protocol. Your protocol is not here for curl. The
best cooperation and end result occur when all involved parties mutually see
and agree that supporting this protocol in curl would be good for everyone.
Heck, for the world.

Consider "selling us" the idea that we need an implementation merged in curl,
to be fairly important. *Why* do we want curl to support this new protocol?

## Protocol requirements

### Client-side

The protocol implementation is for a client's side of a "communication
session".

### Transfer oriented

The protocol itself should be focused on *transfers*. Be it uploads or
downloads or both. It should at least be possible to view the transfers as
such, like we can view reading emails over POP3 as a download and sending
emails over SMTP as an upload.

If you cannot even shoehorn the protocol into a transfer focused view, then
you are up for a tough argument.

### URL

There should be a documented URL format. If there is an RFC for it there is no
question about it but the syntax does not have to be a published RFC. It could
be enough if it is already in use by other implementations.

If you make up the syntax just in order to be able to propose it to curl, then
you are in a bad place. URLs are designed and defined for interoperability.
There should at least be a good chance that other clients and servers can be
implemented supporting the same URL syntax and work the same or similar way.

URLs work on registered 'schemes'. There is a register of [all officially
recognized
schemes](https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml). If
your protocol is not in there, is it really a protocol we want?

### Wide and public use

The protocol shall already be used or have an expectation of getting used
widely. Experimental protocols are better off worked on in experiments first,
to prove themselves before they are adopted by curl.

## Code

Of course the code needs to be written, provided, licensed agreeably and it
should follow our code guidelines and review comments have to be dealt with.
If the implementation needs third party code, that third party code should not
have noticeably lesser standards than the curl project itself.

## Tests

As much of the protocol implementation as possible needs to be verified by
curl test cases. We must have the implementation get tested by CI jobs,
torture tests and more.

We have experienced many times in the past how new implementations were brought
to curl and immediately once the code had been merged, the originator vanished
from the face of the earth. That is fine, but we need to take the necessary
precautions so when it happens we are still fine.

Our test infrastructure is powerful enough to test just about every possible
protocol - but it might require a bit of an effort to make it happen.

## Documentation

We cannot assume that users are particularly familiar with details and
peculiarities of the protocol. It needs documentation.

Maybe it even needs some internal documentation so that the developers who try
to debug something five years from now can figure out functionality a little
easier.

The protocol specification itself should be freely available without requiring
a non-disclosure agreement or similar.

## Do not compare

We are constantly raising the bar and we are constantly improving the project.
A lot of things we did in the past would not be acceptable if done today.
Therefore, you might be tempted to use shortcuts or "hacks" you can spot
other - existing - protocol implementations have used, but there is nothing to
gain from that. The bar has been raised. Former "cheats" may not tolerated
anymore.
