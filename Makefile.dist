#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################

all:
	./configure
	make

ssl:
	./configure --with-openssl
	make

mingw32:
	$(MAKE) -C lib -f Makefile.m32
	$(MAKE) -C src -f Makefile.m32

mingw32-clean:
	$(MAKE) -C lib -f Makefile.m32 clean
	$(MAKE) -C src -f Makefile.m32 clean
	$(MAKE) -C docs/examples -f Makefile.m32 clean

mingw32-vclean mingw32-distclean:
	$(MAKE) -C lib -f Makefile.m32 vclean
	$(MAKE) -C src -f Makefile.m32 vclean
	$(MAKE) -C docs/examples -f Makefile.m32 vclean

mingw32-examples%:
	$(MAKE) -C docs/examples -f Makefile.m32 CFG=$@

mingw32%:
	$(MAKE) -C lib -f Makefile.m32 CFG=$@
	$(MAKE) -C src -f Makefile.m32 CFG=$@

vc:
	cd winbuild
	nmake /f Makefile.vc MACHINE=x86

vc-x64:
	cd winbuild
	nmake /f Makefile.vc MACHINE=x64

djgpp:
	$(MAKE) -C lib -f Makefile.dj
	$(MAKE) -C src -f Makefile.dj

cygwin:
	./configure
	make

cygwin-ssl:
	./configure --with-openssl
	make

amiga:
	cd ./lib && make -f makefile.amiga
	cd ./src && make -f makefile.amiga

netware:
	$(MAKE) -C lib -f Makefile.netware
	$(MAKE) -C src -f Makefile.netware

netware-clean:
	$(MAKE) -C lib -f Makefile.netware clean
	$(MAKE) -C src -f Makefile.netware clean
	$(MAKE) -C docs/examples -f Makefile.netware clean

netware-vclean netware-distclean:
	$(MAKE) -C lib -f Makefile.netware vclean
	$(MAKE) -C src -f Makefile.netware vclean
	$(MAKE) -C docs/examples -f Makefile.netware vclean

netware-install:
	$(MAKE) -C lib -f Makefile.netware install
	$(MAKE) -C src -f Makefile.netware install

netware-examples-%:
	$(MAKE) -C docs/examples -f Makefile.netware CFG=$@

netware-%:
	$(MAKE) -C lib -f Makefile.netware CFG=$@
	$(MAKE) -C src -f Makefile.netware CFG=$@

unix: all

unix-ssl: ssl

linux: all

linux-ssl: ssl

ca-bundle: lib/mk-ca-bundle.pl
	@echo "generate a fresh ca-bundle.crt"
	@perl $< -b -l -u lib/ca-bundle.crt

ca-firefox: lib/firefox-db2pem.sh
	@echo "generate a fresh ca-bundle.crt"
	./lib/firefox-db2pem.sh lib/ca-bundle.crt
