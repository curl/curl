IMPORTANT
=========
CyaSSL has changed its name to wolfSSL. Although the information in this file
is accurate for now, many things in their repo may change in name to wolfSSL.
Also note CyaSSL/wolfSSL is licensed GPLv2 unless you apply for a commercial
license from them. Please visit their website wolfssl.com for more information.

BUILDING FOR WINDOWS
====================
Visual Studio 2010+ project files for libcurl and the curl tool have
'DLL wolfSSL' and 'LIB wolfSSL' configurations available for both x86 and x64
platforms.

Building automatically
----------------------
Use the build-wolfssl.bat script to build wolfSSL automatically using preferred
settings for maximum compatibility (refer to wolfssl_options.h for details).

Run build-wolfssl.bat without any parameters for usage information.

By default the script expects both curl and wolfSSL source folders to be at the
same directory level:

|-curl
|-wolfssl

If you have your wolfSSL repo or release source at some other location you may
specify a different directory, however the curl and libcurl project files
depend on the folder containing curl source and the folder containing wolfSSL
source to be at the same directory level. If you specify a different location
you'll have to modify the curl and libcurl project files to point to that
location so that it will find the wolfSSL lib files. Therefore it's recommended
you have curl and wolfSSL source folders at the same directory level.

Building manually
-----------------
The wolfSSL project has two Visual Studio solutions in its repo, both of which
can be used to build the wolfSSL static library (LIB) for Visual Studio.

wolfssl.sln - Visual Studio 2008
wolfssl64.sln - Visual Studio 2012

wolfssl.sln has not been tested and the curl and libcurl project files
currently only support wolfSSL for Visual Studio 2010+.

Use wolfssl64.sln to build wolfSSL. It can build x86 as well despite the suffix
64. Additionally, wolfssl64.sln and project files can be used by any Visual
Studio 2010+ although you must change the platform toolset to match your
version of Visual Studio if you're not using Visual Studio 2012.

Also, after you build wolfSSL you'll have to modify the curl and libcurl
project files to point to where the wolfSSL lib files are located.

DLL specific, Developer specific
--------------------------------
If you are a developer and plan to run the curl tool from Visual Studio (eg you
are debugging) you will need to add the path of the right wolfSSL DLL to the
PATH environment. To do that:

- Open curl-all.sln
- Right-click on curl-src and select Properties
- Navigate to Configuration Properties > Debugging > Environment
- PATH=`wolfssl-path`;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

... where `wolfssl-path` is the configuration specific path. For example both
my curl repo and my wolfSSL repo are at the same directory level,  and here's
what my PATH settings look like for Visual Studio 2010 (VC10):

```
DLL Debug - DLL wolfSSL (Win32):
PATH=..\..\..\..\..\wolfssl\build\Win32\VC10\DLL Debug;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

DLL Debug - DLL wolfSSL (x64):
PATH=..\..\..\..\..\wolfssl\build\Win64\VC10\DLL Debug;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

DLL Release - DLL wolfSSL (Win32):
PATH=..\..\..\..\..\wolfssl\build\Win32\VC10\DLL Release;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

DLL Release - DLL wolfSSL (x64):
PATH=..\..\..\..\..\wolfssl\build\Win64\VC10\DLL Release;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem
```
