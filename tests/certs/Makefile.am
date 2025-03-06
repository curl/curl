#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts

include Makefile.inc

EXTRA_DIST = $(CERTCONFIGS) $(GENERATEDCERTS) $(SRPFILES) CMakeLists.txt

# Rebuild the certificates

clean-certs:
	cd $(srcdir); rm -f $(GENERATEDCERTS)

build-certs: $(srcdir)/test-ca.cacert $(srcdir)/Server-localhost-sv.pem \
	$(srcdir)/Server-localhost.nn-sv.pem $(srcdir)/Server-localhost0h-sv.pem \
	$(srcdir)/Server-localhost-firstSAN-sv.pem $(srcdir)/Server-localhost-lastSAN-sv.pem \
	$(srcdir)/stunnel-sv.pem $(srcdir)/../stunnel.pem

$(srcdir)/test-ca.cacert:
	cd $(srcdir); scripts/genroot.sh test

$(srcdir)/Server-localhost-sv.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost test

$(srcdir)/Server-localhost.nn-sv.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost.nn test

$(srcdir)/Server-localhost0h-sv.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost0h test

$(srcdir)/Server-localhost-firstSAN-sv.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost-firstSAN test

$(srcdir)/Server-localhost-lastSAN-sv.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost-lastSAN test

$(srcdir)/stunnel-sv.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh stunnel test

 $(srcdir)/../stunnel.pem: $(srcdir)/stunnel-sv.pem
	cp $< $@
