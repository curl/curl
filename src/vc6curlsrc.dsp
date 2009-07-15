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

SOURCE=.\curlutil.c
# End Source File
# Begin Source File

SOURCE=.\getpass.c
# End Source File
# Begin Source File

SOURCE=.\homedir.c
# End Source File
# Begin Source File

SOURCE=.\hugehelp.c
# End Source File
# Begin Source File

SOURCE=.\main.c
# End Source File
# Begin Source File

SOURCE=.\os-specific.c
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

SOURCE=.\urlglob.c
# End Source File
# Begin Source File

SOURCE=.\writeenv.c
# End Source File
# Begin Source File

SOURCE=.\writeout.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\config-win32.h"
# End Source File
# Begin Source File

SOURCE=.\curlutil.h
# End Source File
# Begin Source File

SOURCE=.\getpass.h
# End Source File
# Begin Source File

SOURCE=.\homedir.h
# End Source File
# Begin Source File

SOURCE=.\hugehelp.h
# End Source File
# Begin Source File

SOURCE=.\os-specific.h
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

SOURCE=.\urlglob.h
# End Source File
# Begin Source File

SOURCE=.\version.h
# End Source File
# Begin Source File

SOURCE=.\writeenv.h
# End Source File
# Begin Source File

SOURCE=.\writeout.h
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
