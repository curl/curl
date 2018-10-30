License Mixing
==============

libcurl can be built to use a fair amount of various third party libraries,
libraries that are written and provided by other parties that are distributed
using their own licenses. Even libcurl itself contains code that may cause
problems to some. This document attempts to describe what licenses libcurl and
the other libraries use and what possible dilemmas linking and mixing them all
can lead to for end users.

I am not a lawyer and this is not legal advice!

One common dilemma is that [GPL](https://www.gnu.org/licenses/gpl.html)
licensed code is not allowed to be linked with code licensed under the
[Original BSD license](https://spdx.org/licenses/BSD-4-Clause.html) (with the
announcement clause). You may still build your own copies that use them all,
but distributing them as binaries would be to violate the GPL license - unless
you accompany your license with an
[exception](https://www.gnu.org/licenses/gpl-faq.html#GPLIncompatibleLibs). This
particular problem was addressed when the [Modified BSD
license](https://opensource.org/licenses/BSD-3-Clause) was created, which does
not have the announcement clause that collides with GPL.

## libcurl

 Uses an [MIT style license](https://curl.haxx.se/docs/copyright.html) that is
 very liberal.

## OpenSSL

 (May be used for SSL/TLS support) Uses an Original BSD-style license with an
 announcement clause that makes it "incompatible" with GPL. You are not
 allowed to ship binaries that link with OpenSSL that includes GPL code
 (unless that specific GPL code includes an exception for OpenSSL - a habit
 that is growing more and more common). If OpenSSL's licensing is a problem
 for you, consider using another TLS library.

## GnuTLS

 (May be used for SSL/TLS support) Uses the
 [LGPL](https://www.gnu.org/licenses/lgpl.html) license. If this is a problem
 for you, consider using another TLS library. Also note that GnuTLS itself
 depends on and uses other libs (libgcrypt and libgpg-error) and they too are
 LGPL- or GPL-licensed.

## WolfSSL

 (May be used for SSL/TLS support) Uses the GPL license or a proprietary
 license. If this is a problem for you, consider using another TLS library.

## NSS

 (May be used for SSL/TLS support) Is covered by the
 [MPL](https://www.mozilla.org/MPL/) license, the GPL license and the LGPL
 license. You may choose to license the code under MPL terms, GPL terms, or
 LGPL terms. These licenses grant you different permissions and impose
 different obligations. You should select the license that best meets your
 needs.

## mbedTLS

 (May be used for SSL/TLS support) Uses the [Apache 2.0
 license](https://opensource.org/licenses/Apache-2.0) or the GPL license.
 You may choose to license the code under Apache 2.0 terms or GPL terms.
 These licenses grant you different permissions and impose different
 obligations. You should select the license that best meets your needs.

## BoringSSL

 (May be used for SSL/TLS support) As an OpenSSL fork, it has the same
 license as that.

## libressl

 (May be used for SSL/TLS support) As an OpenSSL fork, it has the same
 license as that.

## c-ares

 (Used for asynchronous name resolves) Uses an MIT license that is very
 liberal and imposes no restrictions on any other library or part you may link
 with.

## zlib

 (Used for compressed Transfer-Encoding support) Uses an MIT-style license
 that shouldn't collide with any other library.

## MIT Kerberos

 (May be used for GSS support) MIT licensed, that shouldn't collide with any
 other parts.

## Heimdal

 (May be used for GSS support) Heimdal is Original BSD licensed with the
 announcement clause.

## GNU GSS

 (May be used for GSS support) GNU GSS is GPL licensed. Note that you may not
 distribute binary curl packages that uses this if you build curl to also link
 and use any Original BSD licensed libraries!

## libidn

 (Used for IDNA support) Uses the GNU Lesser General Public License [3]. LGPL
 is a variation of GPL with slightly less aggressive "copyleft". This license
 requires more requirements to be met when distributing binaries, see the
 license for details. Also note that if you distribute a binary that includes
 this library, you must also include the full LGPL license text. Please
 properly point out what parts of the distributed package that the license
 addresses.

## OpenLDAP

 (Used for LDAP support) Uses a Modified BSD-style license. Since libcurl uses
 OpenLDAP as a shared library only, I have not heard of anyone that ships
 OpenLDAP linked with libcurl in an app.

## libssh2

 (Used for scp and sftp support) libssh2 uses a Modified BSD-style license.
