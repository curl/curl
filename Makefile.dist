#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

VC=vc6

all:
	./configure
	make

ssl:
	./configure --with-ssl
	make

borland:
	cd lib
	make -f Makefile.b32
	cd ..\src
	make -f Makefile.b32

borland-ssl:
	cd lib
	make -f Makefile.b32 WITH_SSL=1
	cd ..\src
	make -f Makefile.b32 WITH_SSL=1

borland-ssl-zlib:
	cd lib
	make -f Makefile.b32 WITH_SSL=1 WITH_ZLIB=1
	cd ..\src
	make -f Makefile.b32 WITH_SSL=1 WITH_ZLIB=1

borland-clean:
	cd lib
	make -f Makefile.b32 clean
	cd ..\src
	make -f Makefile.b32 clean

watcom: .SYMBOLIC
	cd lib
	wmake -u -f Makefile.Watcom
	cd ..\src
	wmake -u -f Makefile.Watcom

watcom-clean: .SYMBOLIC
	cd lib
	wmake -u -f Makefile.Watcom clean
	cd ..\src
	wmake -u -f Makefile.Watcom clean

watcom-vclean: .SYMBOLIC
	cd lib
	wmake -u -f Makefile.Watcom vclean
	cd ..\src
	wmake -u -f Makefile.Watcom vclean

mingw32:
	$(MAKE) -C lib -f Makefile.m32
	$(MAKE) -C src -f Makefile.m32

mingw32-zlib:
	$(MAKE) -C lib -f Makefile.m32 ZLIB=1
	$(MAKE) -C src -f Makefile.m32 ZLIB=1

mingw32-ssl-zlib:
	$(MAKE) -C lib -f Makefile.m32 SSL=1 ZLIB=1
	$(MAKE) -C src -f Makefile.m32 SSL=1 ZLIB=1

mingw32-ssh2-ssl-zlib:
	$(MAKE) -C lib -f Makefile.m32 SSH2=1 SSL=1 ZLIB=1
	$(MAKE) -C src -f Makefile.m32 SSH2=1 SSL=1 ZLIB=1

mingw32-ssh2-ssl-sspi-zlib:
	$(MAKE) -C lib -f Makefile.m32 SSH2=1 SSL=1 SSPI=1 ZLIB=1
	$(MAKE) -C src -f Makefile.m32 SSH2=1 SSL=1 SSPI=1 ZLIB=1

mingw32-clean:
	$(MAKE) -C lib -f Makefile.m32 clean
	$(MAKE) -C src -f Makefile.m32 clean

vc-clean: $(VC)
	cd lib
	nmake -f Makefile.$(VC) clean
	cd ..\src
	nmake -f Makefile.$(VC) clean

vc-all: $(VC)
	cd lib
	nmake -f Makefile.$(VC) cfg=release
	nmake -f Makefile.$(VC) cfg=release-ssl
	nmake -f Makefile.$(VC) cfg=release-zlib
	nmake -f Makefile.$(VC) cfg=release-ssl-zlib
	nmake -f Makefile.$(VC) cfg=release-ssl-dll
	nmake -f Makefile.$(VC) cfg=release-zlib-dll
	nmake -f Makefile.$(VC) cfg=release-ssl-dll-zlib-dll
	nmake -f Makefile.$(VC) cfg=release-dll
	nmake -f Makefile.$(VC) cfg=release-dll-ssl-dll
	nmake -f Makefile.$(VC) cfg=release-dll-zlib-dll
	nmake -f Makefile.$(VC) cfg=release-dll-ssl-dll-zlib-dll
	nmake -f Makefile.$(VC) cfg=debug
	nmake -f Makefile.$(VC) cfg=debug-ssl
	nmake -f Makefile.$(VC) cfg=debug-zlib
	nmake -f Makefile.$(VC) cfg=debug-ssl-zlib
	nmake -f Makefile.$(VC) cfg=debug-ssl-dll
	nmake -f Makefile.$(VC) cfg=debug-zlib-dll
	nmake -f Makefile.$(VC) cfg=debug-ssl-dll-zlib-dll
	nmake -f Makefile.$(VC) cfg=debug-dll
	nmake -f Makefile.$(VC) cfg=debug-dll-ssl-dll
	nmake -f Makefile.$(VC) cfg=debug-dll-zlib-dll
	nmake -f Makefile.$(VC) cfg=debug-dll-ssl-dll-zlib-dll

vc: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release
	cd ..\src
	nmake /f Makefile.$(VC)

vc-x64: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release

vc-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-zlib
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-zlib

vc-ssl: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl

vc-ssl-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib

vc-x64-ssl-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib

vc-ssl-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-dll

vc-dll-ssl-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-dll-ssl-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-dll-ssl-dll

vc-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-dll

vc-dll-zlib-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-dll-zlib-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-dll-zlib-dll

vc-dll-ssl-dll-zlib-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-dll-ssl-dll-zlib-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-dll-ssl-dll-zlib-dll

vc-ssl-dll-zlib-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-dll-zlib-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-dll-zlib-dll

vc-zlib-dll: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-zlib-dll
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-zlib-dll

vc-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release WINDOWS_SSPI=1

djgpp:
	$(MAKE) -C lib -f Makefile.dj
	$(MAKE) -C src -f Makefile.dj

cygwin:
	./configure
	make

cygwin-ssl:
	./configure --with-ssl
	make

amiga:
	cd ./lib && make -f makefile.amiga
	cd ./src && make -f makefile.amiga

netware:
	$(MAKE) -C lib -f Makefile.netware
	$(MAKE) -C src -f Makefile.netware

netware-ares:
	$(MAKE) -C lib -f Makefile.netware WITH_ARES=1
	$(MAKE) -C src -f Makefile.netware WITH_ARES=1

netware-ssl:
	$(MAKE) -C lib -f Makefile.netware WITH_SSL=1
	$(MAKE) -C src -f Makefile.netware WITH_SSL=1

netware-ssl-zlib:
	$(MAKE) -C lib -f Makefile.netware WITH_SSL=1 WITH_ZLIB=1
	$(MAKE) -C src -f Makefile.netware WITH_SSL=1 WITH_ZLIB=1

netware-ssh2-ssl-zlib:
	$(MAKE) -C lib -f Makefile.netware WITH_SSH2=1 WITH_SSL=1 WITH_ZLIB=1
	$(MAKE) -C src -f Makefile.netware WITH_SSH2=1 WITH_SSL=1 WITH_ZLIB=1

netware-zlib:
	$(MAKE) -C lib -f Makefile.netware WITH_ZLIB=1
	$(MAKE) -C src -f Makefile.netware WITH_ZLIB=1

netware-clean:
	$(MAKE) -C lib -f Makefile.netware clean
	$(MAKE) -C src -f Makefile.netware clean

netware-install:
	$(MAKE) -C lib -f Makefile.netware install
	$(MAKE) -C src -f Makefile.netware install

unix: all

unix-ssl: ssl

linux: all

linux-ssl: ssl

# We don't need to do anything for vc6.
vc6:

vc8: lib/Makefile.vc8 src/Makefile.vc8

lib/Makefile.vc8: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib bufferoverflowu.lib/g" -e "s/VC6/VC8/g" lib/Makefile.vc6 > lib/Makefile.vc8

src/Makefile.vc8: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib bufferoverflowu.lib/g" -e "s/VC6/VC8/g" src/Makefile.vc6 > src/Makefile.vc8

# VC9 makefiles are for use with VS2008
vc9: lib/Makefile.vc9 src/Makefile.vc9

lib/Makefile.vc9: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc9/g" -e "s/VC6/VC9/g" lib/Makefile.vc6 > lib/Makefile.vc9

src/Makefile.vc9: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc9/g" -e "s/VC6/VC9/g" src/Makefile.vc6 > src/Makefile.vc9

# VC10 makefiles are for use with VS2010
vc10: lib/Makefile.vc10 src/Makefile.vc10

lib/Makefile.vc10: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc10/g" -e "s/VC6/VC10/g" lib/Makefile.vc6 > lib/Makefile.vc10

src/Makefile.vc10: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc10/g" -e "s/VC6/VC10/g" src/Makefile.vc6 > src/Makefile.vc10

ca-bundle: lib/mk-ca-bundle.pl
	@echo "generate a fresh ca-bundle.crt"
	@perl $< -b -l -u lib/ca-bundle.crt

ca-firefox: lib/firefox-db2pem.sh
	@echo "generate a fresh ca-bundle.crt"
	./lib/firefox-db2pem.sh lib/ca-bundle.crt
