# Microsoft Developer Studio Project File - Name="curltool" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=curltool - Win32 using libcurl LIB Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vc6curltool.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vc6curltool.mak" CFG="curltool - Win32 using libcurl LIB Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "curltool - Win32 using libcurl DLL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "curltool - Win32 using libcurl DLL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "curltool - Win32 using libcurl LIB Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "curltool - Win32 using libcurl LIB Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "curltool - Win32 using libcurl DLL Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "dll-debug"
# PROP BASE Intermediate_Dir "dll-debug/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "dll-debug"
# PROP Intermediate_Dir "dll-debug/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "_DEBUG" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "_DEBUG" /FD /GZ /c
# ADD BASE RSC /l 0x409 /i "..\..\..\include" /d "_DEBUG"
# ADD RSC /l 0x409 /i "..\..\..\include" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurld_imp.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"dll-debug/curl.exe" /pdbtype:con /libpath:"..\lib\dll-debug" /fixed:no
# ADD LINK32 libcurld_imp.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"dll-debug/curl.exe" /pdbtype:con /libpath:"..\lib\dll-debug" /fixed:no

!ELSEIF  "$(CFG)" == "curltool - Win32 using libcurl DLL Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "dll-release"
# PROP BASE Intermediate_Dir "dll-release/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "dll-release"
# PROP Intermediate_Dir "dll-release/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /EHsc /O2 /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "NDEBUG" /FD /c
# ADD CPP /nologo /MD /W3 /EHsc /O2 /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "NDEBUG" /FD /c
# ADD BASE RSC /l 0x409 /i "..\..\..\include" /d "NDEBUG"
# ADD RSC /l 0x409 /i "..\..\..\include" /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurl_imp.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"dll-release/curl.exe" /libpath:"..\lib\dll-release" /fixed:no
# ADD LINK32 libcurl_imp.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"dll-release/curl.exe" /libpath:"..\lib\dll-release" /fixed:no

!ELSEIF  "$(CFG)" == "curltool - Win32 using libcurl LIB Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "lib-debug"
# PROP BASE Intermediate_Dir "lib-debug/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "lib-debug"
# PROP Intermediate_Dir "lib-debug/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "_DEBUG" /D "CURL_STATICLIB" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "_DEBUG" /D "CURL_STATICLIB" /FD /GZ /c
# ADD BASE RSC /l 0x409 /i "..\..\..\include" /d "_DEBUG"
# ADD RSC /l 0x409 /i "..\..\..\include" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurld.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"lib-debug/curl.exe" /pdbtype:con /libpath:"..\lib\lib-debug" /fixed:no
# ADD LINK32 libcurld.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"lib-debug/curl.exe" /pdbtype:con /libpath:"..\lib\lib-debug" /fixed:no

!ELSEIF  "$(CFG)" == "curltool - Win32 using libcurl LIB Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "lib-release"
# PROP BASE Intermediate_Dir "lib-release/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "lib-release"
# PROP Intermediate_Dir "lib-release/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /EHsc /O2 /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "NDEBUG" /D "CURL_STATICLIB" /FD /c
# ADD CPP /nologo /MD /W3 /EHsc /O2 /I "..\..\..\lib" /I "..\..\..\include" /I "..\..\..\src" /D "_CONSOLE" /D "WIN32" /D "NDEBUG" /D "CURL_STATICLIB" /FD /c
# ADD BASE RSC /l 0x409 /i "..\..\..\include" /d "NDEBUG"
# ADD RSC /l 0x409 /i "..\..\..\include" /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurl.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"lib-release/curl.exe" /libpath:"..\lib\lib-release" /fixed:no
# ADD LINK32 libcurl.lib wldap32.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"lib-release/curl.exe" /libpath:"..\lib\lib-release" /fixed:no

!ENDIF 

# Begin Target

# Name "curltool - Win32 using libcurl DLL Debug"
# Name "curltool - Win32 using libcurl DLL Release"
# Name "curltool - Win32 using libcurl LIB Debug"
# Name "curltool - Win32 using libcurl LIB Release"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\lib\nonblock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\lib\rawstr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\lib\strtoofft.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_binmode.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_bname.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_dbg.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_hdr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_prg.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_rea.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_see.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_wrt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cfgable.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_convert.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_dirhie.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_doswin.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_easysrc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_formparse.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_getparam.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_getpass.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_help.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_helpers.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_homedir.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_hugehelp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_libinfo.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_main.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_metalink.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_mfiles.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_msgs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_operate.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_operhlp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_panykey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_paramhlp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_parsecfg.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_setopt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_sleep.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_urlglob.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_util.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_vms.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_writeenv.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_writeout.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_xattr.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\..\..\lib\config-win32.h"
# End Source File
# Begin Source File

SOURCE=..\..\..\lib\nonblock.h
# End Source File
# Begin Source File

SOURCE=..\..\..\lib\rawstr.h
# End Source File
# Begin Source File

SOURCE=..\..\..\lib\strtoofft.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_binmode.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_bname.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_dbg.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_hdr.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_prg.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_rea.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_see.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cb_wrt.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_cfgable.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_convert.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_dirhie.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_doswin.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_easysrc.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_formparse.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_getparam.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_getpass.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_help.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_helpers.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_homedir.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_hugehelp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_libinfo.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_main.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_metalink.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_mfiles.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_msgs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_operate.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_operhlp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_panykey.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_paramhlp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_parsecfg.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_sdecls.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_setopt.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_setup.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_sleep.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_urlglob.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_util.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_version.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_vms.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_writeenv.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_writeout.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\tool_xattr.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\src\curl.rc
# End Source File
# End Group
# End Target
# End Project
