# Building curl with Visual C++

 This document describes how to compile, build and install curl and libcurl
 from sources using the Visual C++ build tool. To build with VC++, you will of
 course have to first install VC++. The minimum required version of VC is 6
 (part of Visual Studio 6). However using a more recent version is strongly
 recommended.

 VC++ is also part of the Windows Platform SDK. You do not have to install the
 full Visual Studio or Visual C++ if all you want is to build curl.

 The latest Platform SDK can be downloaded freely from [Windows SDK and
 emulator
 archive](https://developer.microsoft.com/en-us/windows/downloads/sdk-archive)

## Prerequisites

 If you wish to support zlib, openssl, c-ares, ssh2, you will have to download
 them separately and copy them to the deps directory as shown below:

    somedirectory\
     |_curl-src
     | |_winbuild
     |
     |_deps
       |_ lib
       |_ include
       |_ bin

 It is also possible to create the deps directory in some other random places
 and tell the Makefile its location using the WITH_DEVEL option.

## Building straight from git

 When you check out code git and build it, as opposed from a released source
 code archive, you need to first run the `buildconf.bat` batch file (present
 in the source code root directory) to set things up.

## Open a command prompt

Open a Visual Studio Command prompt:

 Using the **'Developer Command Prompt for VS [version]'** menu entry: where
 [version} is the Visual Studio version. The developer prompt at default uses
 the x86 mode. It is required to call `Vcvarsall.bat` to setup the prompt for
 the machine type you want. This type of command prompt may not exist in all
 Visual Studio versions.

 See also: [Developer Command Prompt for Visual
 Studio](https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs)
 and [How to: Enable a 64-Bit, x64 hosted MSVC toolset on the command
 line](https://docs.microsoft.com/en-us/cpp/build/how-to-enable-a-64-bit-visual-cpp-toolset-on-the-command-line)

 Using the **'VS [version] [platform] [type] Command Prompt'** menu entry:
 where [version] is the Visual Studio version, [platform] is e.g. x64 and
 [type] Native of Cross platform build.  This type of command prompt may not
 exist in all Visual Studio versions.

 See also: [Set the Path and Environment Variables for Command-Line Builds](https://msdn.microsoft.com/en-us/library/f2ccy3wt.aspx)

## Build in the console

 Once you are in the console, go to the winbuild directory in the Curl
 sources:

    cd curl-src\winbuild

 Then you can call `nmake /f Makefile.vc` with the desired options (see
 below). The builds will be in the top src directory, `builds\` directory, in
 a directory named using the options given to the nmake call.

    nmake /f Makefile.vc mode=<static or dll> <options>

where `<options>` is one or many of:

 - `VC=<num>`                    - VC version. 6 or later.
 - `WITH_DEVEL=<path>`           - Paths for the development files (SSL, zlib, etc.)
                                   Defaults to sibbling directory deps: ../deps
                                   Libraries can be fetched at https://windows.php.net/downloads/php-sdk/deps/
                                   Uncompress them into the deps folder.
 - `WITH_SSL=<dll/static>`       - Enable OpenSSL support, DLL or static
 - `WITH_NGHTTP2=<dll/static>`   - Enable HTTP/2 support, DLL or static
 - `WITH_MBEDTLS=<dll/static>`   - Enable mbedTLS support, DLL or static
 - `WITH_CARES=<dll/static>`     - Enable c-ares support, DLL or static
 - `WITH_ZLIB=<dll/static>`      - Enable zlib support, DLL or static
 - `WITH_SSH2=<dll/static>`      - Enable libSSH2 support, DLL or static
 - `WITH_PREFIX=<dir>`           - Where to install the build
 - `ENABLE_SSPI=<yes/no>`        - Enable SSPI support, defaults to yes
 - `ENABLE_IPV6=<yes/no>`        - Enable IPv6, defaults to yes
 - `ENABLE_IDN=<yes or no>`      - Enable use of Windows IDN APIs, defaults to yes
                                   Requires Windows Vista or later
 - `ENABLE_SCHANNEL=<yes/no>`    - Enable native Windows SSL support, defaults
                                   to yes if SSPI and no other SSL library
 - `ENABLE_OPENSSL_AUTO_LOAD_CONFIG=<yes/no>`
                                 - Enable loading OpenSSL configuration
                                   automatically, defaults to yes
 - `ENABLE_UNICODE=<yes/no>`     - Enable UNICODE support, defaults to no
 - `GEN_PDB=<yes/no>`            - Generate Program Database (debug symbols for release build)
 - `DEBUG=<yes/no>`              - Debug builds
 - `MACHINE=<x86/x64>`           - Target architecture (default is x86)
 - `CARES_PATH=<path>`           - Custom path for c-ares
 - `MBEDTLS_PATH=<path>`         - Custom path for mbedTLS
 - `NGHTTP2_PATH=<path>`         - Custom path for nghttp2
 - `SSH2_PATH=<path>`            - Custom path for libSSH2
 - `SSL_PATH=<path>`             - Custom path for OpenSSL
 - `ZLIB_PATH=<path>`            - Custom path for zlib

## Static linking of Microsoft's C RunTime (CRT):

 If you are using mode=static nmake will create and link to the static build
 of libcurl but *not* the static CRT. If you must you can force nmake to link
 in the static CRT by passing RTLIBCFG=static. Typically you shouldn't use
 that option, and nmake will default to the DLL CRT. RTLIBCFG is rarely used
 and therefore rarely tested. When passing RTLIBCFG for a configuration that
 was already built but not with that option, or if the option was specified
 differently, you must destroy the build directory containing the
 configuration so that nmake can build it from scratch.

## Building your own application with a static libcurl

 When building an application that uses the static libcurl library on Windows,
 you must define CURL_STATICLIB. Otherwise the linker will look for dynamic
 import symbols.

## Legacy Windows and SSL

 When you build curl using the build files in this directory the default SSL
 backend will be Schannel (Windows SSPI), the native SSL library that comes
 with the Windows OS. Schannel in Windows <= XP is not able to connect to
 servers that no longer support the legacy handshakes and algorithms used by
 those versions. If you will be using curl in one of those earlier versions of
 Windows you should choose another SSL backend like OpenSSL.
