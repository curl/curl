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

all:
	./configure
	make

ssl:
	./configure --with-openssl
	make

vc:
	cd winbuild
	nmake /f Makefile.vc MACHINE=x86

vc-x64:
	cd winbuild
	nmake /f Makefile.vc MACHINE=x64

djgpp%:
	$(MAKE) -C lib -f Makefile.mk CFG=$@ CROSSPREFIX=i586-pc-msdosdjgpp-
	$(MAKE) -C src -f Makefile.mk CFG=$@ CROSSPREFIX=i586-pc-msdosdjgpp-

cygwin:
	./configure
	make

cygwin-ssl:
	./configure --with-openssl
	make

amiga%:
	$(MAKE) -C lib -f Makefile.mk CFG=$@ CROSSPREFIX=m68k-amigaos-
	$(MAKE) -C src -f Makefile.mk CFG=$@ CROSSPREFIX=m68k-amigaos-

unix: all

unix-ssl: ssl

linux: all

linux-ssl: ssl

ca-bundle: scripts/mk-ca-bundle.pl
	@echo "generate a fresh ca-bundle.crt"
	@perl $< -b -l -u lib/ca-bundle.crt

ca-firefox: lib/firefox-db2pem.sh
	@echo "generate a fresh ca-bundle.crt"
	./lib/firefox-db2pem.sh lib/ca-bundle.crt
