#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
###########################################################################
AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts

include Makefile.inc

EXTRA_DIST = $(CERTCONFIGS) $(GENERATEDCERTS) $(SRPFILES) CMakeLists.txt

# Rebuild the certificates

clean-certs:
	cd $(srcdir); rm -f $(GENERATEDCERTS)

build-certs: $(srcdir)/EdelFetchRoot-ca.cacert $(srcdir)/Server-localhost-sv.pem \
	$(srcdir)/Server-localhost.nn-sv.pem $(srcdir)/Server-localhost0h-sv.pem \
	$(srcdir)/Server-localhost-firstSAN-sv.pem $(srcdir)/Server-localhost-lastSAN-sv.pem \
	$(srcdir)/stunnel-sv.pem $(srcdir)/../stunnel.pem

$(srcdir)/EdelFetchRoot-ca.cacert:
	cd $(srcdir); scripts/genroot.sh EdelFetchRoot

$(srcdir)/Server-localhost-sv.pem: $(srcdir)/EdelFetchRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost EdelFetchRoot

$(srcdir)/Server-localhost.nn-sv.pem: $(srcdir)/EdelFetchRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost.nn EdelFetchRoot

$(srcdir)/Server-localhost0h-sv.pem: $(srcdir)/EdelFetchRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost0h EdelFetchRoot

$(srcdir)/Server-localhost-firstSAN-sv.pem: $(srcdir)/EdelFetchRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost-firstSAN EdelFetchRoot

$(srcdir)/Server-localhost-lastSAN-sv.pem: $(srcdir)/EdelFetchRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh Server-localhost-lastSAN EdelFetchRoot

$(srcdir)/stunnel-sv.pem: $(srcdir)/EdelFetchRoot-ca.cacert
	cd $(srcdir); scripts/genserv.sh stunnel EdelFetchRoot

 $(srcdir)/../stunnel.pem: $(srcdir)/stunnel-sv.pem
	cp $< $@
