# Microsoft Developer Studio Generated NMAKE File, Based on areslib.dsp
!IF "$(CFG)" == ""
CFG=areslib - Win32 Debug
!MESSAGE No configuration specified. Defaulting to areslib - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "areslib - Win32 Release" && "$(CFG)" != "areslib - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
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
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "areslib - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\areslib.lib"


CLEAN :
	-@erase "$(INTDIR)\ares__close_sockets.obj"
	-@erase "$(INTDIR)\ares__get_hostent.obj"
	-@erase "$(INTDIR)\ares__read_line.obj"
	-@erase "$(INTDIR)\ares_cancel.obj"
	-@erase "$(INTDIR)\ares_destroy.obj"
	-@erase "$(INTDIR)\ares_expand_name.obj"
	-@erase "$(INTDIR)\ares_fds.obj"
	-@erase "$(INTDIR)\ares_free_hostent.obj"
	-@erase "$(INTDIR)\ares_free_string.obj"
	-@erase "$(INTDIR)\ares_gethostbyaddr.obj"
	-@erase "$(INTDIR)\ares_gethostbyname.obj"
	-@erase "$(INTDIR)\ares_init.obj"
	-@erase "$(INTDIR)\ares_mkquery.obj"
	-@erase "$(INTDIR)\ares_parse_a_reply.obj"
	-@erase "$(INTDIR)\ares_parse_aaaa_reply.obj"
	-@erase "$(INTDIR)\ares_parse_ptr_reply.obj"
	-@erase "$(INTDIR)\ares_process.obj"
	-@erase "$(INTDIR)\ares_query.obj"
	-@erase "$(INTDIR)\ares_search.obj"
	-@erase "$(INTDIR)\ares_send.obj"
	-@erase "$(INTDIR)\ares_strerror.obj"
	-@erase "$(INTDIR)\ares_timeout.obj"
	-@erase "$(INTDIR)\ares_version.obj"
	-@erase "$(INTDIR)\bitncmp.obj"
	-@erase "$(INTDIR)\inet_net_pton.obj"
	-@erase "$(INTDIR)\inet_ntop.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\windows_port.obj"
	-@erase "$(OUTDIR)\areslib.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\.." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "HAVE_IOCTLSOCKET" /D "HAVE_STRUCT_IN6_ADDR" /D "HAVE_AF_INET6" /D "HAVE_STRUCT_SOCKADDR_IN6" /D "HAVE_STRUCT_ADDRINFO" /Fp"$(INTDIR)\areslib.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\areslib.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\areslib.lib" 
LIB32_OBJS= \
	"$(INTDIR)\ares__close_sockets.obj" \
	"$(INTDIR)\ares__get_hostent.obj" \
	"$(INTDIR)\ares__read_line.obj" \
	"$(INTDIR)\ares_destroy.obj" \
	"$(INTDIR)\ares_expand_name.obj" \
	"$(INTDIR)\ares_fds.obj" \
	"$(INTDIR)\ares_free_hostent.obj" \
	"$(INTDIR)\ares_free_string.obj" \
	"$(INTDIR)\ares_gethostbyaddr.obj" \
	"$(INTDIR)\ares_gethostbyname.obj" \
	"$(INTDIR)\ares_init.obj" \
	"$(INTDIR)\ares_mkquery.obj" \
	"$(INTDIR)\ares_parse_a_reply.obj" \
	"$(INTDIR)\ares_parse_ptr_reply.obj" \
	"$(INTDIR)\ares_process.obj" \
	"$(INTDIR)\ares_query.obj" \
	"$(INTDIR)\ares_search.obj" \
	"$(INTDIR)\ares_cancel.obj" \
	"$(INTDIR)\ares_version.obj" \
	"$(INTDIR)\ares_send.obj" \
	"$(INTDIR)\ares_strerror.obj" \
	"$(INTDIR)\ares_timeout.obj" \
	"$(INTDIR)\windows_port.obj" \
	"$(INTDIR)\inet_ntop.obj" \
	"$(INTDIR)\inet_net_pton.obj" \
	"$(INTDIR)\bitncmp.obj" \
	"$(INTDIR)\ares_parse_aaaa_reply.obj"

"$(OUTDIR)\areslib.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "areslib - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\areslib.lib"


CLEAN :
	-@erase "$(INTDIR)\ares__close_sockets.obj"
	-@erase "$(INTDIR)\ares__get_hostent.obj"
	-@erase "$(INTDIR)\ares__read_line.obj"
	-@erase "$(INTDIR)\ares_cancel.obj"
	-@erase "$(INTDIR)\ares_destroy.obj"
	-@erase "$(INTDIR)\ares_expand_name.obj"
	-@erase "$(INTDIR)\ares_fds.obj"
	-@erase "$(INTDIR)\ares_free_hostent.obj"
	-@erase "$(INTDIR)\ares_free_string.obj"
	-@erase "$(INTDIR)\ares_gethostbyaddr.obj"
	-@erase "$(INTDIR)\ares_gethostbyname.obj"
	-@erase "$(INTDIR)\ares_init.obj"
	-@erase "$(INTDIR)\ares_mkquery.obj"
	-@erase "$(INTDIR)\ares_parse_a_reply.obj"
	-@erase "$(INTDIR)\ares_parse_aaaa_reply.obj"
	-@erase "$(INTDIR)\ares_parse_ptr_reply.obj"
	-@erase "$(INTDIR)\ares_process.obj"
	-@erase "$(INTDIR)\ares_query.obj"
	-@erase "$(INTDIR)\ares_search.obj"
	-@erase "$(INTDIR)\ares_send.obj"
	-@erase "$(INTDIR)\ares_strerror.obj"
	-@erase "$(INTDIR)\ares_timeout.obj"
	-@erase "$(INTDIR)\ares_version.obj"
	-@erase "$(INTDIR)\bitncmp.obj"
	-@erase "$(INTDIR)\inet_net_pton.obj"
	-@erase "$(INTDIR)\inet_ntop.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\windows_port.obj"
	-@erase "$(OUTDIR)\areslib.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /I "..\.." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "HAVE_IOCTLSOCKET" /D "HAVE_STRUCT_IN6_ADDR" /D "HAVE_AF_INET6" /D "HAVE_STRUCT_SOCKADDR_IN6" /D "HAVE_STRUCT_ADDRINFO" /Fp"$(INTDIR)\areslib.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\areslib.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\areslib.lib" 
LIB32_OBJS= \
	"$(INTDIR)\ares__close_sockets.obj" \
	"$(INTDIR)\ares__get_hostent.obj" \
	"$(INTDIR)\ares__read_line.obj" \
	"$(INTDIR)\ares_destroy.obj" \
	"$(INTDIR)\ares_expand_name.obj" \
	"$(INTDIR)\ares_fds.obj" \
	"$(INTDIR)\ares_free_hostent.obj" \
	"$(INTDIR)\ares_free_string.obj" \
	"$(INTDIR)\ares_gethostbyaddr.obj" \
	"$(INTDIR)\ares_gethostbyname.obj" \
	"$(INTDIR)\ares_init.obj" \
	"$(INTDIR)\ares_mkquery.obj" \
	"$(INTDIR)\ares_parse_a_reply.obj" \
	"$(INTDIR)\ares_parse_ptr_reply.obj" \
	"$(INTDIR)\ares_process.obj" \
	"$(INTDIR)\ares_query.obj" \
	"$(INTDIR)\ares_search.obj" \
	"$(INTDIR)\ares_cancel.obj" \
	"$(INTDIR)\ares_version.obj" \
	"$(INTDIR)\ares_send.obj" \
	"$(INTDIR)\ares_strerror.obj" \
	"$(INTDIR)\ares_timeout.obj" \
	"$(INTDIR)\windows_port.obj" \
	"$(INTDIR)\inet_ntop.obj" \
	"$(INTDIR)\inet_net_pton.obj" \
	"$(INTDIR)\bitncmp.obj" \
	"$(INTDIR)\ares_parse_aaaa_reply.obj"

"$(OUTDIR)\areslib.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("areslib.dep")
!INCLUDE "areslib.dep"
!ELSE 
!MESSAGE Warning: cannot find "areslib.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "areslib - Win32 Release" || "$(CFG)" == "areslib - Win32 Debug"
SOURCE=..\..\ares__close_sockets.c

"$(INTDIR)\ares__close_sockets.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares__get_hostent.c

"$(INTDIR)\ares__get_hostent.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares__read_line.c

"$(INTDIR)\ares__read_line.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_cancel.c

"$(INTDIR)\ares_cancel.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_destroy.c

"$(INTDIR)\ares_destroy.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_expand_name.c

"$(INTDIR)\ares_expand_name.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_fds.c

"$(INTDIR)\ares_fds.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_free_hostent.c

"$(INTDIR)\ares_free_hostent.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_free_string.c

"$(INTDIR)\ares_free_string.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_gethostbyaddr.c

"$(INTDIR)\ares_gethostbyaddr.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_gethostbyname.c

"$(INTDIR)\ares_gethostbyname.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_init.c

"$(INTDIR)\ares_init.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_mkquery.c

"$(INTDIR)\ares_mkquery.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_parse_a_reply.c

"$(INTDIR)\ares_parse_a_reply.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_parse_aaaa_reply.c

"$(INTDIR)\ares_parse_aaaa_reply.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_parse_ptr_reply.c

"$(INTDIR)\ares_parse_ptr_reply.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_process.c

"$(INTDIR)\ares_process.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_query.c

"$(INTDIR)\ares_query.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_search.c

"$(INTDIR)\ares_search.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_send.c

"$(INTDIR)\ares_send.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_strerror.c

"$(INTDIR)\ares_strerror.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_timeout.c

"$(INTDIR)\ares_timeout.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\ares_version.c

"$(INTDIR)\ares_version.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\bitncmp.c

"$(INTDIR)\bitncmp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\inet_net_pton.c

"$(INTDIR)\inet_net_pton.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\inet_ntop.c

"$(INTDIR)\inet_ntop.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\windows_port.c

"$(INTDIR)\windows_port.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

