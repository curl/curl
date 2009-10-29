# Microsoft Developer Studio Project File - Name="cares" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102
# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=cares - Win32 LIB Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vc6cares.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vc6cares.mak" CFG="cares - Win32 LIB Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cares - Win32 DLL Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "cares - Win32 DLL Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "cares - Win32 LIB Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "cares - Win32 LIB Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "cares - Win32 DLL Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "DLL-Debug"
# PROP BASE Intermediate_Dir "DLL-Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "DLL-Debug"
# PROP Intermediate_Dir "DLL-Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "..\.." /D "WIN32" /D "DEBUGBUILD" /D "CARES_BUILDING_LIBRARY" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /D "WIN32" /D "DEBUGBUILD" /D "CARES_BUILDING_LIBRARY" /FD /GZ /c
MTL=midl.exe
# ADD BASE MTL /nologo /D "DEBUGBUILD" /mktyplib203 /win32
# ADD MTL /nologo /D "DEBUGBUILD" /mktyplib203 /win32
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "DEBUGBUILD"
# ADD RSC /l 0x409 /d "DEBUGBUILD"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib advapi32.lib /nologo /dll /incremental:no /map /debug /machine:I386 /out:"DLL-Debug/caresd.dll" /implib:"DLL-Debug/caresd_imp.lib" /pdbtype:sept
# ADD LINK32 ws2_32.lib advapi32.lib /nologo /dll /incremental:no /map /debug /machine:I386 /out:"DLL-Debug/caresd.dll" /implib:"DLL-Debug/caresd_imp.lib" /pdbtype:sept

!ELSEIF  "$(CFG)" == "cares - Win32 DLL Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "DLL-Release"
# PROP BASE Intermediate_Dir "DLL-Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "DLL-Release"
# PROP Intermediate_Dir "DLL-Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "CARES_BUILDING_LIBRARY" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "CARES_BUILDING_LIBRARY" /FD /c
MTL=midl.exe
# ADD BASE MTL /nologo /mktyplib203 /win32
# ADD MTL /nologo /mktyplib203 /win32
RSC=rc.exe
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib advapi32.lib /nologo /dll /pdb:none /machine:I386 /out:"DLL-Release/cares.dll" /implib:"DLL-Release/cares_imp.lib"
# ADD LINK32 ws2_32.lib advapi32.lib /nologo /dll /pdb:none /machine:I386 /out:"DLL-Release/cares.dll" /implib:"DLL-Release/cares_imp.lib"

!ELSEIF  "$(CFG)" == "cares - Win32 LIB Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "LIB-Debug"
# PROP BASE Intermediate_Dir "LIB-Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LIB-Debug"
# PROP Intermediate_Dir "LIB-Debug"
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "..\.." /D "WIN32" /D "DEBUGBUILD" /D "CARES_BUILDING_LIBRARY" /D "CARES_STATICLIB" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /D "WIN32" /D "DEBUGBUILD" /D "CARES_BUILDING_LIBRARY" /D "CARES_STATICLIB" /FD /GZ /c
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "DEBUGBUILD"
# ADD RSC /l 0x409 /d "DEBUGBUILD"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"LIB-Debug/caresd.lib" /machine:I386
# ADD LIB32 /nologo /out:"LIB-Debug/caresd.lib" /machine:I386

!ELSEIF  "$(CFG)" == "cares - Win32 LIB Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "LIB-Release"
# PROP BASE Intermediate_Dir "LIB-Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LIB-Release"
# PROP Intermediate_Dir "LIB-Release"
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "CARES_BUILDING_LIBRARY" /D "CARES_STATICLIB" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "CARES_BUILDING_LIBRARY" /D "CARES_STATICLIB" /FD /c
RSC=rc.exe
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"LIB-Release/cares.lib" /machine:I386
# ADD LIB32 /nologo /out:"LIB-Release/cares.lib" /machine:I386

!ENDIF 

# Begin Target

# Name "cares - Win32 DLL Debug"
# Name "cares - Win32 DLL Release"
# Name "cares - Win32 LIB Debug"
# Name "cares - Win32 LIB Release"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\ares__close_sockets.c
# End Source File
# Begin Source File

SOURCE=..\..\ares__get_hostent.c
# End Source File
# Begin Source File

SOURCE=..\..\ares__read_line.c
# End Source File
# Begin Source File

SOURCE=..\..\ares__timeval.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_cancel.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_destroy.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_expand_name.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_expand_string.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_fds.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_free_hostent.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_free_string.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_gethostbyaddr.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_gethostbyname.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_getsock.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_init.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_library_init.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_llist.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_mkquery.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_parse_a_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_parse_aaaa_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_parse_ns_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_parse_ptr_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_parse_srv_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_parse_txt_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_process.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_query.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_search.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_send.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_strcasecmp.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_strerror.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_timeout.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_version.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_writev.c
# End Source File
# Begin Source File

SOURCE=..\..\bitncmp.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.c
# End Source File
# Begin Source File

SOURCE=..\..\windows_port.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\ares.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_build.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_dns.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_ipv6.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_library_init.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_llist.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_private.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_rules.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_strcasecmp.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_version.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_writev.h
# End Source File
# Begin Source File

SOURCE=..\..\bitncmp.h
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.h
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.h
# End Source File
# Begin Source File

SOURCE=..\..\nameser.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\cares.rc
# End Source File
# End Group
# End Target
# End Project
