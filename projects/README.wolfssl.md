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
platforms. We don't offer a script to automate building the wolfSSL code, you
must do it manually before building libcurl/curl.

The wolfSSL project has two Visual Studio solutions in its repo, both of which
can be used to build the wolfSSL static library (LIB) for Visual Studio.

wolfssl.sln - Visual Studio 2008
wolfssl64.sln - Visual Studio 2012

Use wolfssl64.sln to build wolfSSL. It can build x86 as well despite the suffix
64. Additionally, wolfssl64.sln and project files can be used by any Visual
Studio 2010+ although you must change the platform toolset to match your
version of Visual Studio if you're not using Visual Studio 2012.

To change the platform toolset in wolfssl64.sln, for every project in the
solution right-click and choose properties. A property pages window will
appear. Change 'Configuration' to 'All Configurations' and change 'Platform' to
'All Platforms'. Change the platform toolset via:

Configuration Properties > General > Platform Toolset

These are the most common toolset mappings:
Visual Studio 2010: v100
Visual Studio 2012: v110
Visual Studio 2013: v120

DLL specific, Developer specific
--------------------------------
wolfSSL can be built as a DLL but their Visual Studio projects currently do not
have the DLL configurations to do that. I've added them and submitted a pull
request. As part of that changeset I changed platform toolset to default to the
current version of Visual Studio, so the above toolset changes aren't
necessary for either DLL or LIB if you're building based off of my work.

https://github.com/wolfSSL/wolfssl/pull/46

If you are a developer and plan to run the curl tool from Visual Studio (eg you
are debugging) you will need to add the path to the right wolfSSL DLL to the
PATH environment. To do that:

- Open curl-all.sln
- Right-click on curl-src and select Properties
- Navigate to Configuration Properties > Debugging > Environment
- PATH=`wolfssl-path`;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

... where `wolfssl-path` is the configuration specific path. For example both
my curl repo and my wolfssl repo are in the same folder and here's what my PATH
settings look like:

```
DLL Debug - DLL wolfSSL (Win32):
PATH=..\..\..\..\..\wolfSSL\DLL Debug;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

DLL Debug - DLL wolfSSL (x64):
PATH=..\..\..\..\..\wolfSSL\x64\DLL Debug;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

DLL Release - DLL wolfSSL (Win32):
PATH=..\..\..\..\..\wolfSSL\DLL Release;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem

DLL Release - DLL wolfSSL (x64):
PATH=..\..\..\..\..\wolfSSL\x64\DLL Release;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem
```
