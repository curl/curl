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

build-certs: $(srcdir)/test-ca.cacert $(srcdir)/test-localhost.pem \
	$(srcdir)/test-localhost.nn.pem $(srcdir)/test-localhost0h.pem \
	$(srcdir)/test-localhost-san-first.pem $(srcdir)/test-localhost-san-last.pem

$(srcdir)/test-ca.cacert:
	cd $(srcdir); scripts/genroot.sh test

$(srcdir)/test-localhost.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh test-localhost test

$(srcdir)/test-localhost.nn.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh test-localhost.nn test

$(srcdir)/test-localhost0h.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh test-localhost0h test

$(srcdir)/test-localhost-san-first.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh test-localhost-san-first test

$(srcdir)/test-localhost-san-last.pem: $(srcdir)/test-ca.cacert
	cd $(srcdir); scripts/genserv.sh test-localhost-san-last test
