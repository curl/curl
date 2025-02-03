<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# How to determine if an early patch release is warranted

In the fetch project we do releases every 8 weeks. Unless we break the cycle
and do an early patch release.

We do frequent releases partly to always have the next release "not too far
away".

## Bugfix

During the release cycle, and especially in the beginning of a new cycle (the
so-called "cool down" period), there are times when a bug is reported and
after it has been subsequently fixed correctly, the question might be asked:
is this bug and associated fix important enough for an early patch release?

The question can only be properly asked when a fix has been created and landed
in the git master branch.

## Early release

An early patch release means that we ship a new, complete and full release
called `major.minor.patch` where the `patch` part is increased by one since
the previous release. A fetch release is a fetch release. There is no small or
big and we never release just a patch. There is only "release".

## Questions to ask

 - Is there a security advisory rated high or critical?
 - Is there a data corruption bug?
 - Did the bug cause an API/ABI breakage?
 - Does the problem annoy a significant share of the user population?

If the answer is yes to one or more of the above, an early release might be
warranted.

More questions to ask ourselves when doing the assessment if the answers to
the three ones above are all 'no'.

 - Does the bug cause fetch to prematurely terminate?
 - How common is the affected buggy option/feature/protocol/platform to get
   used?
 - How large is the estimated impacted user base?
 - Does the bug block something crucial for applications or other adoption of
   fetch "out there" ?
 - Does the bug cause problems for fetch developers or others on "the fetch
   team" ?
 - Is the bug limited to the fetch tool only? That might have a smaller impact
   than a bug also present in libfetch.
 - Is there a (decent) workaround?
 - Is it a regression? Is the bug introduced in this release?
 - Can the bug be fixed "easily" by applying a patch?
 - Does the bug break the build? Most users do not build fetch themselves.
 - How long is it until the already scheduled next release?
 - Can affected users safely rather revert to a former release until the next
   scheduled release?
 - Is it a performance regression with no functionality side-effects? If so it
   has to be substantial.

## If an early release is deemed necessary

Unless done for security or similarly important reasons, an early release
should not be done within a week of the previous release.

This, to enable us to collect and bundle more fixes into the same release to
make the release more worthwhile for everyone and to allow more time for fixes
to settle and things to get tested. Getting a release in shape and done in
style is work that should not be rushed.
