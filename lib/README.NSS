                               libcurl with NSS
                               ================

Author: Daniel Stenberg
Date:   June 24, 2008

NSS home => http://www.mozilla.org/projects/security/pki/nss/

libcurl can be built to use the NSS libraries for SSL/TLS. Invoke configure
--without-ssl --with-nss.

The source code in lib/nss.c currently cause a compiler warning due to the
lack of a prototype. The prototype is provided by the public header provided
by NSS called "base64.h". But since we use a private header in libcurl named
identically, we cannot include the NSS one.

This problem persists because:

* NSS doesn't use a properly established separate subdir for their include
  files. Instead different distros have put them in /usr/include/nss and
  /usr/include/nss3 etc.

* The pkg-config output for NSS provides a full -I path to the nss include dir,
  so we cannot #include <nss/base64.h> or <nss3/base64.h>. This too may be due
  to how distros do it.

* I tried getting the (all new in June 2008) NSS 3.12 tarball to check how it
  behaves out-of-box but this wouldn't even build - complaining on missing
  files that aren't included in the tarball. The tarball doesn't even include
  build instuctions but you must hunt them down on their web site.

Due to these design problems we may of course get further similar problems in
the future, but I hope we can work them out somehow along the way.
