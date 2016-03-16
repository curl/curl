#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

VC=vc6

all:
	./configure
	make

ssl:
	./configure --with-ssl
	make

borland:
	cd lib
	$(MAKE) -f Makefile.b32
	cd ..\src
	$(MAKE) -f Makefile.b32

borland-ssl:
	cd lib
	$(MAKE) -f Makefile.b32 WITH_SSL=1
	cd ..\src
	$(MAKE) -f Makefile.b32 WITH_SSL=1

borland-ssl-zlib:
	cd lib
	$(MAKE) -f Makefile.b32 WITH_SSL=1 WITH_ZLIB=1
	cd ..\src
	$(MAKE) -f Makefile.b32 WITH_SSL=1 WITH_ZLIB=1

borland-clean:
	cd lib
	$(MAKE) -f Makefile.b32 clean
	cd ..\src
	$(MAKE) -f Makefile.b32 clean

watcom: .SYMBOLIC
	cd lib && $(MAKE) -u -f Makefile.Watcom
	cd src && $(MAKE) -u -f Makefile.Watcom

watcom-clean: .SYMBOLIC
	cd lib && $(MAKE) -u -f Makefile.Watcom clean
	cd src && $(MAKE) -u -f Makefile.Watcom clean

watcom-vclean: .SYMBOLIC
	cd lib && $(MAKE) -u -f Makefile.Watcom vclean
	cd src && $(MAKE) -u -f Makefile.Watcom vclean

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

vc-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release WINDOWS_SSPI=1

vc-x64-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release WINDOWS_SSPI=1

vc-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release USE_IDN=1

vc-x64-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release USE_IDN=1

vc-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release USE_IDN=1 WINDOWS_SSPI=1

vc-x64-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release USE_IDN=1 WINDOWS_SSPI=1

vc-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-zlib
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-zlib

vc-x64-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib

vc-zlib-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-zlib WINDOWS_SSPI=1

vc-x64-zlib-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib WINDOWS_SSPI=1

vc-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-zlib USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-zlib USE_IDN=1

vc-x64-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib USE_IDN=1

vc-zlib-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-x64-zlib-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-ssl: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl

vc-x64-ssl: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl

vc-ssl-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl WINDOWS_SSPI=1

vc-x64-ssl-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl WINDOWS_SSPI=1

vc-ssl-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl USE_IDN=1

vc-x64-ssl-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl USE_IDN=1

vc-ssl-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl USE_IDN=1 WINDOWS_SSPI=1

vc-x64-ssl-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl USE_IDN=1 WINDOWS_SSPI=1

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

vc-ssl-zlib-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib WINDOWS_SSPI=1

vc-x64-ssl-zlib-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib WINDOWS_SSPI=1

vc-ssl-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib USE_IDN=1

vc-x64-ssl-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib USE_IDN=1

vc-ssl-zlib-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-x64-ssl-zlib-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-ssl-ssh2-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib

vc-x64-ssl-ssh2-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib

vc-ssl-ssh2-zlib-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib WINDOWS_SSPI=1

vc-x64-ssl-ssh2-zlib-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib WINDOWS_SSPI=1

vc-ssl-ssh2-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib USE_IDN=1

vc-x64-ssl-ssh2-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib USE_IDN=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib USE_IDN=1

vc-ssl-ssh2-zlib-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-ssl-ssh2-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-x64-ssl-ssh2-zlib-idn-sspi: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-ssl-ssh2-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-winssl: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-winssl WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-winssl WINDOWS_SSPI=1

vc-x64-winssl: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl WINDOWS_SSPI=1

vc-winssl-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-winssl USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-winssl USE_IDN=1 WINDOWS_SSPI=1

vc-x64-winssl-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl USE_IDN=1 WINDOWS_SSPI=1

vc-winssl-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-winssl-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-winssl-zlib WINDOWS_SSPI=1

vc-x64-winssl-zlib: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl-zlib WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl-zlib WINDOWS_SSPI=1

vc-winssl-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) cfg=release-winssl-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) cfg=release-winssl-zlib USE_IDN=1 WINDOWS_SSPI=1

vc-x64-winssl-zlib-idn: $(VC)
	cd lib
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl-zlib USE_IDN=1 WINDOWS_SSPI=1
	cd ..\src
	nmake /f Makefile.$(VC) MACHINE=x64 cfg=release-winssl-zlib USE_IDN=1 WINDOWS_SSPI=1

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

# We don't need to do anything for vc6.
vc6:

# VC7 makefiles are for use with VS.NET and VS.NET 2003
vc7: lib/Makefile.vc7 src/Makefile.vc7

lib/Makefile.vc7: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s/VC6/VC7/g" lib/Makefile.vc6 > lib/Makefile.vc7

src/Makefile.vc7: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s/VC6/VC7/g" src/Makefile.vc6 > src/Makefile.vc7

# VC8 makefiles are for use with VS2005
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

# VC11 makefiles are for use with VS2012
vc11: lib/Makefile.vc11 src/Makefile.vc11

lib/Makefile.vc11: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc11/g" -e "s/VC6/VC11/g" lib/Makefile.vc6 > lib/Makefile.vc11

src/Makefile.vc11: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc11/g" -e "s/VC6/VC11/g" src/Makefile.vc6 > src/Makefile.vc11

# VC12 makefiles are for use with VS2013
vc12: lib/Makefile.vc12 src/Makefile.vc12

lib/Makefile.vc12: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc12/g" -e "s/VC6/VC12/g" lib/Makefile.vc6 > lib/Makefile.vc12

src/Makefile.vc12: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc12/g" -e "s/VC6/VC12/g" src/Makefile.vc6 > src/Makefile.vc12

# VC14 makefiles are for use with VS2015
vc14: lib/Makefile.vc14 src/Makefile.vc14

lib/Makefile.vc14: lib/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc14/g" -e "s/VC6/VC14/g" lib/Makefile.vc6 > lib/Makefile.vc14

src/Makefile.vc14: src/Makefile.vc6
	@echo "generate $@"
	@sed -e "s#/GX /DWIN32 /YX#/EHsc /DWIN32#" -e "s#/GZ#/RTC1#" -e "s/ws2_32.lib/ws2_32.lib/g" -e "s/vc6/vc14/g" -e "s/VC6/VC14/g" src/Makefile.vc6 > src/Makefile.vc14

ca-bundle: lib/mk-ca-bundle.pl
	@echo "generate a fresh ca-bundle.crt"
	@perl $< -b -l -u lib/ca-bundle.crt

ca-firefox: lib/firefox-db2pem.sh
	@echo "generate a fresh ca-bundle.crt"
	./lib/firefox-db2pem.sh lib/ca-bundle.crt
