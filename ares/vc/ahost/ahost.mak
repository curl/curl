# Microsoft Developer Studio Generated NMAKE File, Based on ahost.dsp
!IF "$(CFG)" == ""
CFG=ahost - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ahost - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ahost - Win32 Release" && "$(CFG)" != "ahost - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ahost.mak" CFG="ahost - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ahost - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "ahost - Win32 Debug" (based on "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "ahost - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ahost.exe"

!ELSE 

ALL : "areslib - Win32 Release" "$(OUTDIR)\ahost.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"areslib - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ahost.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\ahost.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\ahost.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ahost.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=wsock32.lib areslib.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\ahost.pdb" /machine:I386 /out:"$(OUTDIR)\ahost.exe" /libpath:"..\areslib\Release" 
LINK32_OBJS= \
	"$(INTDIR)\ahost.obj" \
	"..\areslib\Release\areslib.lib"

"$(OUTDIR)\ahost.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ahost - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ahost.exe" "$(OUTDIR)\ahost.bsc"

!ELSE 

ALL : "areslib - Win32 Debug" "$(OUTDIR)\ahost.exe" "$(OUTDIR)\ahost.bsc"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"areslib - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ahost.obj"
	-@erase "$(INTDIR)\ahost.sbr"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\ahost.bsc"
	-@erase "$(OUTDIR)\ahost.exe"
	-@erase "$(OUTDIR)\ahost.ilk"
	-@erase "$(OUTDIR)\ahost.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\ahost.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ  /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ahost.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\ahost.sbr"

"$(OUTDIR)\ahost.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=wsock32.lib areslib.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\ahost.pdb" /debug /machine:I386 /out:"$(OUTDIR)\ahost.exe" /pdbtype:sept /libpath:"..\areslib\Debug" 
LINK32_OBJS= \
	"$(INTDIR)\ahost.obj" \
	"..\areslib\Debug\areslib.lib"

"$(OUTDIR)\ahost.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
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
!IF EXISTS("ahost.dep")
!INCLUDE "ahost.dep"
!ELSE 
!MESSAGE Warning: cannot find "ahost.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "ahost - Win32 Release" || "$(CFG)" == "ahost - Win32 Debug"
SOURCE=..\..\ahost.c

!IF  "$(CFG)" == "ahost - Win32 Release"


"$(INTDIR)\ahost.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ahost - Win32 Debug"


"$(INTDIR)\ahost.obj"	"$(INTDIR)\ahost.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

!IF  "$(CFG)" == "ahost - Win32 Release"

"areslib - Win32 Release" : 
   cd ".\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Release" 
   cd "..\ahost"

"areslib - Win32 ReleaseCLEAN" : 
   cd ".\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Release" RECURSE=1 CLEAN 
   cd "..\ahost"

!ELSEIF  "$(CFG)" == "ahost - Win32 Debug"

"areslib - Win32 Debug" : 
   cd ".\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Debug" 
   cd "..\ahost"

"areslib - Win32 DebugCLEAN" : 
   cd ".\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\ahost"

!ENDIF 


!ENDIF 

