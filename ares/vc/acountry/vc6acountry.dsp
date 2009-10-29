# Microsoft Developer Studio Project File - Name="acountry" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=acountry - Win32 using cares LIB Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vc6acountry.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vc6acountry.mak" CFG="acountry - Win32 using cares LIB Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "acountry - Win32 using cares DLL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "acountry - Win32 using cares DLL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "acountry - Win32 using cares LIB Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "acountry - Win32 using cares LIB Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "acountry - Win32 using cares DLL Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /D "WIN32" /D "_CONSOLE" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /D "WIN32" /D "_CONSOLE" /FD /GZ /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 caresd_imp.lib ws2_32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"DLL-Debug/acountry.exe" /pdbtype:sept /libpath:"..\cares\DLL-Debug"
# ADD LINK32 caresd_imp.lib ws2_32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"DLL-Debug/acountry.exe" /pdbtype:sept /libpath:"..\cares\DLL-Debug"

!ELSEIF  "$(CFG)" == "acountry - Win32 using cares DLL Release"

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
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "_CONSOLE" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "_CONSOLE" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 cares_imp.lib ws2_32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"DLL-Release/acountry.exe" /libpath:"..\cares\DLL-Release"
# ADD LINK32 cares_imp.lib ws2_32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"DLL-Release/acountry.exe" /libpath:"..\cares\DLL-Release"

!ELSEIF  "$(CFG)" == "acountry - Win32 using cares LIB Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /D "WIN32" /D "_CONSOLE" /D "CARES_STATICLIB" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /D "WIN32" /D "_CONSOLE" /D "CARES_STATICLIB" /FD /GZ /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 caresd.lib ws2_32.lib advapi32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"LIB-Debug/acountry.exe" /pdbtype:sept /libpath:"..\cares\LIB-Debug"
# ADD LINK32 caresd.lib ws2_32.lib advapi32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"LIB-Debug/acountry.exe" /pdbtype:sept /libpath:"..\cares\LIB-Debug"

!ELSEIF  "$(CFG)" == "acountry - Win32 using cares LIB Release"

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
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "_CONSOLE" /D "CARES_STATICLIB" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "_CONSOLE" /D "CARES_STATICLIB" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 cares.lib ws2_32.lib advapi32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"LIB-Release/acountry.exe" /libpath:"..\cares\LIB-Release"
# ADD LINK32 cares.lib ws2_32.lib advapi32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"LIB-Release/acountry.exe" /libpath:"..\cares\LIB-Release"

!ENDIF 

# Begin Target

# Name "acountry - Win32 using cares DLL Debug"
# Name "acountry - Win32 using cares DLL Release"
# Name "acountry - Win32 using cares LIB Debug"
# Name "acountry - Win32 using cares LIB Release"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\acountry.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_getopt.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_strcasecmp.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\ares_getopt.h
# End Source File
# End Group
# End Target
# End Project
