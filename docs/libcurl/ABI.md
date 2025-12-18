<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

ABI - Application Binary Interface
==================================

 "ABI" describes the low-level interface between an application program and a
 library. Calling conventions, function arguments, return values, struct
 sizes/defines and more.

 [Wikipedia has a longer description](https://en.wikipedia.org/wiki/Application_binary_interface)

## Upgrades

 A libcurl upgrade does not break the ABI or change established and documented
 behavior. Your application can remain using libcurl just as before, only with
 fewer bugs and possibly with added new features.

## Version Numbers

 In libcurl land, you cannot tell by the libcurl version number if that
 libcurl is binary compatible or not with another libcurl version. As a rule,
 we do not break the ABI so you can *always* upgrade to a later version without
 any loss or change in functionality.

## SONAME Bumps

 Whenever there are changes done to the library that causes an ABI breakage,
 that may require your application to get attention or possibly be changed to
 adhere to new things, we bump the SONAME. Then the library gets a different
 output name and thus can in fact be installed in parallel with an older
 installed lib (on most systems). Thus, old applications built against the
 previous ABI version remains working and using the older lib, while newer
 applications build and use the newer one.

 During the first seven years of libcurl releases, there have only been four
 ABI breakages.

 We are determined to bump the SONAME as rarely as possible. Ideally, we never
 do it again.

## Downgrades

 Going to an older libcurl version from one you are currently using can be a
 tricky thing. Mostly we add features and options to newer libcurls as that
 does not break ABI or hamper existing applications. This has the implication
 that going backwards may get you in a situation where you pick a libcurl that
 does not support the options your application needs. Or possibly you even
 downgrade so far so you cross an ABI break border and thus a different
 SONAME, and then your application may need to adapt to the modified ABI.

## History

 The previous major library SONAME number bumps (breaking backwards
 compatibility) happened the following times:

 0 - libcurl 7.1,   August 2000

 1 - libcurl 7.5    December 2000

 2 - libcurl 7.7    March 2001

 3 - libcurl 7.12.0 June 2004

 4 - libcurl 7.16.0 October 2006
