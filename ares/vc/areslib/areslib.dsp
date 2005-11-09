# Microsoft Developer Studio Project File - Name="areslib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=areslib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "areslib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "areslib.mak" CFG="areslib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "areslib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "areslib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "areslib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "HAVE_IOCTLSOCKET" /D "HAVE_STRUCT_IN6_ADDR" /D "HAVE_AF_INET6" /D "HAVE_STRUCT_SOCKADDR_IN6" /D "HAVE_STRUCT_ADDRINFO" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "areslib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /I "..\.." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "HAVE_IOCTLSOCKET" /D "HAVE_STRUCT_IN6_ADDR" /D "HAVE_AF_INET6" /D "HAVE_STRUCT_SOCKADDR_IN6" /D "HAVE_STRUCT_ADDRINFO" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "areslib - Win32 Release"
# Name "areslib - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
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

SOURCE=..\..\ares_cancel.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_destroy.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_expand_name.c
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

SOURCE=..\..\ares_init.c
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

SOURCE=..\..\ares_parse_ptr_reply.c
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

SOURCE=..\..\ares_strerror.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_timeout.c
# End Source File
# Begin Source File

SOURCE=..\..\ares_version.c
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

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\ares.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_dns.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_ipv6.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_private.h
# End Source File
# Begin Source File

SOURCE=..\..\ares_version.h
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
# End Target
# End Project
