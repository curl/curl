# Microsoft Developer Studio Generated NMAKE File, Based on adig.dsp
!IF "$(CFG)" == ""
CFG=adig - Win32 Debug
!MESSAGE No configuration specified. Defaulting to adig - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "adig - Win32 Release" && "$(CFG)" != "adig - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "adig.mak" CFG="adig - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "adig - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "adig - Win32 Debug" (based on "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "adig - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\adig.exe"

!ELSE 

ALL : "areslib - Win32 Release" "$(OUTDIR)\adig.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"areslib - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\adig.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\adig.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\adig.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\adig.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=wsock32.lib areslib.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\adig.pdb" /machine:I386 /out:"$(OUTDIR)\adig.exe" /libpath:"..\areslib\Release" 
LINK32_OBJS= \
	"$(INTDIR)\adig.obj" \
	"$(INTDIR)\getopt.obj" \
	"..\areslib\Release\areslib.lib"

"$(OUTDIR)\adig.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "adig - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\adig.exe"

!ELSE 

ALL : "areslib - Win32 Debug" "$(OUTDIR)\adig.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"areslib - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\adig.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\adig.exe"
	-@erase "$(OUTDIR)\adig.ilk"
	-@erase "$(OUTDIR)\adig.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\adig.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ  /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\adig.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=wsock32.lib areslib.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\adig.pdb" /debug /machine:I386 /out:"$(OUTDIR)\adig.exe" /pdbtype:sept /libpath:"..\areslib\Debug" 
LINK32_OBJS= \
	"$(INTDIR)\adig.obj" \
	"$(INTDIR)\getopt.obj" \
	"..\areslib\Debug\areslib.lib"

"$(OUTDIR)\adig.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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
!IF EXISTS("adig.dep")
!INCLUDE "adig.dep"
!ELSE 
!MESSAGE Warning: cannot find "adig.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "adig - Win32 Release" || "$(CFG)" == "adig - Win32 Debug"
SOURCE=..\..\adig.c

"$(INTDIR)\adig.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\getopt.c

"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "adig - Win32 Release"

"areslib - Win32 Release" : 
   cd "..\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Release" 
   cd "..\adig"

"areslib - Win32 ReleaseCLEAN" : 
   cd "..\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Release" RECURSE=1 CLEAN 
   cd "..\adig"

!ELSEIF  "$(CFG)" == "adig - Win32 Debug"

"areslib - Win32 Debug" : 
   cd "..\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Debug" 
   cd "..\adig"

"areslib - Win32 DebugCLEAN" : 
   cd "..\areslib"
   $(MAKE) /$(MAKEFLAGS) /F ".\areslib.mak" CFG="areslib - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\adig"

!ENDIF 


!ENDIF 

