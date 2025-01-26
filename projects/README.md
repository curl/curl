<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

Building via IDE Project Files
==============================

This document describes how to compile, build and install curl and libcurl
from sources using legacy versions of Visual Studio 2010 - 2013.

You need to generate the project files before using them. Please run "generate
-help" for usage details.

To generate project files for recent versions of Visual Studio instead, use
cmake. Refer to INSTALL-CMAKE.md in the docs directory.

Another way to build curl using Visual Studio is without project files. Refer
to README in the winbuild directory.

## Directory Structure

The following directory structure is used for the legacy project files:

    somedirectory\
     |_curl
       |_projects
         |_<platform>
           |_<ide>
             |_lib
             |_src

This structure allows for side-by-side compilation of curl on the same machine
using different versions of a given compiler (for example VC10 and VC12) and
allows for your own application or product to be compiled against those
variants of libcurl for example.

Note: Typically this side-by-side compilation is generally only required when
a library is being compiled against dynamic runtime libraries.

## Dependencies

The projects files also support build configurations that require third party
dependencies such as OpenSSL and libssh2. If you wish to support these, you
also need to download and compile those libraries as well.

To support compilation of these libraries using different versions of
compilers, the following directory structure has been used for both the output
of curl and libcurl as well as these dependencies.

    somedirectory\
     |_curl
     | |_ build
     |    |_<architecture>
     |      |_<ide>
     |        |_<configuration>
     |          |_lib
     |          |_src
     |
     |_openssl
     | |_ build
     |    |_<architecture>
     |      |_VC <version>
     |        |_<configuration>
     |
     |_libssh2
       |_ build
          |_<architecture>
            |_VC <version>
              |_<configuration>

As OpenSSL does not support side-by-side compilation when using different
versions of Visual Studio, a helper batch file has been provided to assist
with this. Please run `build-openssl -help` for usage details.

## Building with Visual C++

To build with VC++, you have to first install VC++ which is part of Visual
Studio.

Once you have VC++ installed you should launch the application and open one of
the solution or workspace files. The VC directory names are based on the
version of Visual C++ that you use. Each version of Visual Studio has a
default version of Visual C++. We offer these versions:

 - VC10      (Visual Studio 2010 Version 10.0)
 - VC11      (Visual Studio 2012 Version 11.0)
 - VC12      (Visual Studio 2013 Version 12.0)

Separate solutions are provided for both libcurl and the curl command line
tool as well as a solution that includes both projects. libcurl.sln, curl.sln
and curl-all.sln, respectively. We recommend using curl-all.sln to build both
projects.

For example, if you are using Visual Studio 2010 then you should be able to
use `VC10\curl-all.sln` to build curl and libcurl.

## Running DLL based configurations

If you are a developer and plan to run the curl tool from Visual Studio with
any third-party libraries (such as OpenSSL or libssh2) then you need to add
the search path of these DLLs to the configuration's PATH environment. To do
that:

 1. Open the 'curl-all.sln' or 'curl.sln' solutions
 2. Right-click on the 'curl' project and select Properties
 3. Navigate to 'Configuration Properties > Debugging > Environment'
 4. Add `PATH='Path to DLL';C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem`

... where 'Path to DLL` is the configuration specific path. For example the
following configurations in Visual Studio 2010 might be:

DLL Debug - DLL OpenSSL (Win32):

    PATH=..\..\..\..\..\openssl\build\Win32\VC10\DLL Debug;C:\Windows\System32;
    C:\Windows;C:\Windows\System32\Wbem

DLL Debug - DLL OpenSSL (x64):

    PATH=..\..\..\..\..\openssl\build\Win64\VC10\DLL Debug;C:\Windows\System32;
    C:\Windows;C:\Windows\System32\Wbem

If you are using a configuration that uses multiple third-party library DLLs
(such as DLL Debug - DLL OpenSSL - DLL libssh2) then 'Path to DLL' need to
contain the path to both of these.

## Notes

The following keywords have been used in the directory hierarchy:

 - `<platform>`      - The platform (For example: Windows)
 - `<ide>`           - The IDE (For example: VC10)
 - `<architecture>`  - The platform architecture (For example: Win32, Win64)
 - `<configuration>` - The target configuration (For example: DLL Debug, LIB
   Release - LIB OpenSSL)

Should you wish to help out with some of the items on the TODO list, or find
bugs in the project files that need correcting, and would like to submit
updated files back then please note that, whilst the solution files can be
edited directly, the templates for the project files (which are stored in the
git repository) need to be modified rather than the generated project files
that Visual Studio uses.

## Legacy Windows and SSL

Some of the project configurations use Schannel (Windows SSPI), the native SSL
library that comes with the Windows OS. Schannel in Windows 8 and earlier is
not able to connect to servers that no longer support the legacy handshakes
and algorithms used by those versions. If you are using curl in one of those
earlier versions of Windows you should choose another SSL backend like
OpenSSL.
