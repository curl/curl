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

# Get CERTCONFIG_CA, CERTCONFIGS, GENERATEDCERTS, SRPFILES variables
include Makefile.inc

EXTRA_DIST = $(CERTCONFIG_CA) $(CERTCONFIGS) $(SRPFILES) CMakeLists.txt \
  genserv.pl

DISTCLEANFILES = $(GENERATEDCERTS)

all-am: test-ca.cacert

# Rebuild the certificates

# Generate all certs in a single shot, but declare just a single target file
# to support GNU Make <4.3 without the "grouped explicit targets" feature.
test-ca.cacert: $(CERTCONFIG_CA) $(CERTCONFIGS) genserv.pl
	@PERL@ $(srcdir)/genserv.pl test $(CERTCONFIGS)

clean-local:
	rm -f $(GENERATEDCERTS) \
	  test-*.csr \
	  test-*.der \
	  test-*.keyenc \
	  test-ca.cnt* \
	  test-ca.db* \
	  test-ca.raw* \
	  test-ca.srl
