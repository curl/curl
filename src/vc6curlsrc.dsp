# Microsoft Developer Studio Project File - Name="curlsrc" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=curlsrc - Win32 using libcurl LIB Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "curlsrc.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "curlsrc.mak" CFG="curlsrc - Win32 using libcurl LIB Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "curlsrc - Win32 using libcurl DLL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "curlsrc - Win32 using libcurl DLL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "curlsrc - Win32 using libcurl LIB Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "curlsrc - Win32 using libcurl LIB Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "curlsrc - Win32 using libcurl DLL Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_CONSOLE" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_CONSOLE" /FD /GZ /c
# ADD BASE RSC /l 0x409 /i "..\include" /d "_DEBUG"
# ADD RSC /l 0x409 /i "..\include" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurld_imp.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"DLL-Debug/curl.exe" /pdbtype:sept /libpath:"..\lib\DLL-Debug"
# ADD LINK32 libcurld_imp.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"DLL-Debug/curl.exe" /pdbtype:sept /libpath:"..\lib\DLL-Debug"

!ELSEIF  "$(CFG)" == "curlsrc - Win32 using libcurl DLL Release"

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
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_CONSOLE" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_CONSOLE" /FD /c
# ADD BASE RSC /l 0x409 /i "..\include" /d "NDEBUG"
# ADD RSC /l 0x409 /i "..\include" /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurl_imp.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"DLL-Release/curl.exe" /libpath:"..\lib\DLL-Release"
# ADD LINK32 libcurl_imp.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"DLL-Release/curl.exe" /libpath:"..\lib\DLL-Release"

!ELSEIF  "$(CFG)" == "curlsrc - Win32 using libcurl LIB Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "LIB-Debug"
# PROP BASE Intermediate_Dir "LIB-Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LIB-Debug"
# PROP Intermediate_Dir "LIB-Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_CONSOLE" /D "CURL_STATICLIB" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_CONSOLE" /D "CURL_STATICLIB" /FD /GZ /c
# ADD BASE RSC /l 0x409 /i "..\include" /d "_DEBUG"
# ADD RSC /l 0x409 /i "..\include" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurld.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"LIB-Debug/curl.exe" /pdbtype:sept /libpath:"..\lib\LIB-Debug"
# ADD LINK32 libcurld.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"LIB-Debug/curl.exe" /pdbtype:sept /libpath:"..\lib\LIB-Debug"

!ELSEIF  "$(CFG)" == "curlsrc - Win32 using libcurl LIB Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "LIB-Release"
# PROP BASE Intermediate_Dir "LIB-Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LIB-Release"
# PROP Intermediate_Dir "LIB-Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_CONSOLE" /D "CURL_STATICLIB" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\lib" /I "..\include" /I "." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_CONSOLE" /D "CURL_STATICLIB" /FD /c
# ADD BASE RSC /l 0x409 /i "..\include" /d "NDEBUG"
# ADD RSC /l 0x409 /i "..\include" /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libcurl.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"LIB-Release/curl.exe" /libpath:"..\lib\LIB-Release"
# ADD LINK32 libcurl.lib kernel32.lib ws2_32.lib wldap32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"LIB-Release/curl.exe" /libpath:"..\lib\LIB-Release"

!ENDIF 

# Begin Target

# Name "curlsrc - Win32 using libcurl DLL Debug"
# Name "curlsrc - Win32 using libcurl DLL Release"
# Name "curlsrc - Win32 using libcurl LIB Debug"
# Name "curlsrc - Win32 using libcurl LIB Release"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\hugehelp.c
# End Source File
# Begin Source File

SOURCE=..\lib\nonblock.c
# End Source File
# Begin Source File

SOURCE=..\lib\rawstr.c
# End Source File
# Begin Source File

SOURCE=..\lib\strtoofft.c
# End Source File
# Begin Source File

SOURCE=.\tool_binmode.c
# End Source File
# Begin Source File

SOURCE=.\tool_bname.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_dbg.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_hdr.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_prg.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_rea.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_see.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_skt.c
# End Source File
# Begin Source File

SOURCE=.\tool_cb_wrt.c
# End Source File
# Begin Source File

SOURCE=.\tool_cfgable.c
# End Source File
# Begin Source File

SOURCE=.\tool_convert.c
# End Source File
# Begin Source File

SOURCE=.\tool_dirhie.c
# End Source File
# Begin Source File

SOURCE=.\tool_doswin.c
# End Source File
# Begin Source File

SOURCE=.\tool_easysrc.c
# End Source File
# Begin Source File

SOURCE=.\tool_formparse.c
# End Source File
# Begin Source File

SOURCE=.\tool_getparam.c
# End Source File
# Begin Source File

SOURCE=.\tool_getpass.c
# End Source File
# Begin Source File

SOURCE=.\tool_help.c
# End Source File
# Begin Source File

SOURCE=.\tool_helpers.c
# End Source File
# Begin Source File

SOURCE=.\tool_homedir.c
# End Source File
# Begin Source File

SOURCE=.\tool_libinfo.c
# End Source File
# Begin Source File

SOURCE=.\tool_main.c
# End Source File
# Begin Source File

SOURCE=.\tool_mfiles.c
# End Source File
# Begin Source File

SOURCE=.\tool_msgs.c
# End Source File
# Begin Source File

SOURCE=.\tool_operate.c
# End Source File
# Begin Source File

SOURCE=.\tool_operhlp.c
# End Source File
# Begin Source File

SOURCE=.\tool_panykey.c
# End Source File
# Begin Source File

SOURCE=.\tool_paramhlp.c
# End Source File
# Begin Source File

SOURCE=.\tool_parsecfg.c
# End Source File
# Begin Source File

SOURCE=.\tool_setopt.c
# End Source File
# Begin Source File

SOURCE=.\tool_sleep.c
# End Source File
# Begin Source File

SOURCE=.\tool_urlglob.c
# End Source File
# Begin Source File

SOURCE=.\tool_util.c
# End Source File
# Begin Source File

SOURCE=.\tool_vms.c
# End Source File
# Begin Source File

SOURCE=.\tool_writeenv.c
# End Source File
# Begin Source File

SOURCE=.\tool_writeout.c
# End Source File
# Begin Source File

SOURCE=.\tool_xattr.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\config-win32.h"
# End Source File
# Begin Source File

SOURCE=.\hugehelp.h
# End Source File
# Begin Source File

SOURCE=.\setup.h
# End Source File
# Begin Source File

SOURCE=..\lib\nonblock.h
# End Source File
# Begin Source File

SOURCE=..\lib\rawstr.h
# End Source File
# Begin Source File

SOURCE=..\lib\strtoofft.h
# End Source File
# Begin Source File

SOURCE=.\tool_binmode.h
# End Source File
# Begin Source File

SOURCE=.\tool_bname.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_dbg.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_hdr.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_prg.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_rea.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_see.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_skt.h
# End Source File
# Begin Source File

SOURCE=.\tool_cb_wrt.h
# End Source File
# Begin Source File

SOURCE=.\tool_cfgable.h
# End Source File
# Begin Source File

SOURCE=.\tool_convert.h
# End Source File
# Begin Source File

SOURCE=.\tool_dirhie.h
# End Source File
# Begin Source File

SOURCE=.\tool_doswin.h
# End Source File
# Begin Source File

SOURCE=.\tool_easysrc.h
# End Source File
# Begin Source File

SOURCE=.\tool_formparse.h
# End Source File
# Begin Source File

SOURCE=.\tool_getparam.h
# End Source File
# Begin Source File

SOURCE=.\tool_getpass.h
# End Source File
# Begin Source File

SOURCE=.\tool_help.h
# End Source File
# Begin Source File

SOURCE=.\tool_helpers.h
# End Source File
# Begin Source File

SOURCE=.\tool_homedir.h
# End Source File
# Begin Source File

SOURCE=.\tool_libinfo.h
# End Source File
# Begin Source File

SOURCE=.\tool_main.h
# End Source File
# Begin Source File

SOURCE=.\tool_mfiles.h
# End Source File
# Begin Source File

SOURCE=.\tool_msgs.h
# End Source File
# Begin Source File

SOURCE=.\tool_operate.h
# End Source File
# Begin Source File

SOURCE=.\tool_operhlp.h
# End Source File
# Begin Source File

SOURCE=.\tool_panykey.h
# End Source File
# Begin Source File

SOURCE=.\tool_paramhlp.h
# End Source File
# Begin Source File

SOURCE=.\tool_parsecfg.h
# End Source File
# Begin Source File

SOURCE=.\tool_sdecls.h
# End Source File
# Begin Source File

SOURCE=.\tool_setopt.h
# End Source File
# Begin Source File

SOURCE=.\tool_sleep.h
# End Source File
# Begin Source File

SOURCE=.\tool_urlglob.h
# End Source File
# Begin Source File

SOURCE=.\tool_util.h
# End Source File
# Begin Source File

SOURCE=.\tool_version.h
# End Source File
# Begin Source File

SOURCE=.\tool_vms.h
# End Source File
# Begin Source File

SOURCE=.\tool_writeenv.h
# End Source File
# Begin Source File

SOURCE=.\tool_writeout.h
# End Source File
# Begin Source File

SOURCE=.\tool_xattr.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\curl.rc
# End Source File
# End Group
# End Target
# End Project
