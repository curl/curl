#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts

CERTCONFIGS = \
  EdelCurlRoot-ca.prm \
  EdelCurlRoot-ca.cnf \
  Server-localhost-sv.prm \
  Server-localhost.nn-sv.prm \
  Server-localhost0h-sv.prm

GENERATEDCERTS = \
  EdelCurlRoot-ca.cacert \
  EdelCurlRoot-ca.crt \
  EdelCurlRoot-ca.csr \
  EdelCurlRoot-ca.der \
  EdelCurlRoot-ca.key \
  Server-localhost-sv.crl \
  Server-localhost-sv.crt \
  Server-localhost-sv.csr \
  Server-localhost-sv.der \
  Server-localhost-sv.dhp \
  Server-localhost-sv.key \
  Server-localhost-sv.pem \
  Server-localhost-sv.pub.der \
  Server-localhost-sv.pub.pem \
  Server-localhost.nn-sv.crl \
  Server-localhost.nn-sv.crt \
  Server-localhost.nn-sv.csr \
  Server-localhost.nn-sv.der \
  Server-localhost.nn-sv.dhp \
  Server-localhost.nn-sv.key \
  Server-localhost.nn-sv.pem \
  Server-localhost.nn-sv.pub.der \
  Server-localhost.nn-sv.pub.pem \
  Server-localhost0h-sv.crl \
  Server-localhost0h-sv.crt \
  Server-localhost0h-sv.csr \
  Server-localhost0h-sv.der \
  Server-localhost0h-sv.dhp \
  Server-localhost0h-sv.key \
  Server-localhost0h-sv.pem \
  Server-localhost0h-sv.pub.der \
  Server-localhost0h-sv.pub.pem \
  Server-localhost-firstSAN-sv.crl \
  Server-localhost-firstSAN-sv.crt \
  Server-localhost-firstSAN-sv.csr \
  Server-localhost-firstSAN-sv.der \
  Server-localhost-firstSAN-sv.dhp \
  Server-localhost-firstSAN-sv.key \
  Server-localhost-firstSAN-sv.pem \
  Server-localhost-firstSAN-sv.pub.der \
  Server-localhost-firstSAN-sv.pub.pem \
  Server-localhost-lastSAN-sv.crl \
  Server-localhost-lastSAN-sv.crt \
  Server-localhost-lastSAN-sv.csr \
  Server-localhost-lastSAN-sv.der \
  Server-localhost-lastSAN-sv.dhp \
  Server-localhost-lastSAN-sv.key \
  Server-localhost-lastSAN-sv.pem \
  Server-localhost-lastSAN-sv.pub.der \
  Server-localhost-lastSAN-sv.pub.pem

SRPFILES = \
  srp-verifier-conf \
  srp-verifier-db

EXTRA_DIST = $(CERTCONFIGS) $(GENERATEDCERTS) $(SRPFILES)

# Rebuild the certificates

clean-certs:
	cd $(srcdir); rm -f $(GENERATEDCERTS)

build-certs: $(srcdir)/EdelCurlRoot-ca.cacert $(srcdir)/Server-localhost-sv.pem \
	$(srcdir)/Server-localhost.nn-sv.pem $(srcdir)/Server-localhost0h-sv.pem \
	$(srcdir)/Server-localhost-firstSAN-sv.pem $(srcdir)/Server-localhost-lastSAN-sv.pem

$(srcdir)/EdelCurlRoot-ca.cacert:
	cd $(srcdir); scripts/genroot.sh EdelCurlRoot

$(srcdir)/Server-localhost-sv.pem: $(srcdir)/EdelCurlRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost EdelCurlRoot

$(srcdir)/Server-localhost.nn-sv.pem: $(srcdir)/EdelCurlRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost.nn EdelCurlRoot

$(srcdir)/Server-localhost0h-sv.pem: $(srcdir)/EdelCurlRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost0h EdelCurlRoot

$(srcdir)/Server-localhost-firstSAN-sv.pem: $(srcdir)/EdelCurlRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost-firstSAN EdelCurlRoot

$(srcdir)/Server-localhost-lastSAN-sv.pem: $(srcdir)/EdelCurlRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost-firstSAN EdelCurlRoot
