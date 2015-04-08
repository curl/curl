@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2014 - 2015, Steve Holme, <steve_holme@hotmail.com>.
rem *
rem * This software is licensed as described in the file COPYING, which
rem * you should have received as part of this distribution. The terms
rem * are also available at http://curl.haxx.se/docs/copyright.html.
rem *
rem * You may opt to use, copy, modify, merge, publish, distribute and/or sell
rem * copies of the Software, and permit persons to whom the Software is
rem * furnished to do so, under the terms of the COPYING file.
rem *
rem * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
rem * KIND, either express or implied.
rem *
rem ***************************************************************************

rem NOTES
rem
rem Do not set %ERRORLEVEL% to anything. %ERRORLEVEL% is a special variable
rem that only contains errorlevel when %ERRORLEVEL% is not set. Same for %CD%.
rem http://blogs.msdn.com/b/oldnewthing/archive/2008/09/26/8965755.aspx
rem If you need to set the errorlevel do this instead: CALL :seterr [#]

:begin
  rem Check we are running on a Windows NT derived OS
  if not "%OS%" == "Windows_NT" goto nodos

  rem Check we are not running on a network drive
  if "%~d0."=="\\." goto nonetdrv

  rem Switch to this batch file's directory
  cd /d "%~0\.." 1>NUL 2>&1

  rem Set our variables
  setlocal ENABLEEXTENSIONS
  set VERSION=ALL
  set MODE=GENERATE

  rem Detect programs. HAVE_<PROGNAME>
  rem When not found the variable is set undefined. The undefined pattern
  rem allows for statements like "if not defined HAVE_PERL (command)"
  groff --version <NUL 1>NUL 2>&1
  if %ERRORLEVEL% EQU 0 (set HAVE_GROFF=Y) else (set HAVE_GROFF=)
  nroff --version <NUL 1>NUL 2>&1
  if %ERRORLEVEL% EQU 0 (set HAVE_NROFF=Y) else (set HAVE_NROFF=)
  perl --version <NUL 1>NUL 2>&1
  if %ERRORLEVEL% EQU 0 (set HAVE_PERL=Y) else (set HAVE_PERL=)
  gzip --version <NUL 1>NUL 2>&1
  if %ERRORLEVEL% EQU 0 (set HAVE_GZIP=Y) else (set HAVE_GZIP=)

  rem Display the help
  if /i "%~1" == "-?" goto syntax
  if /i "%~1" == "-h" goto syntax
  if /i "%~1" == "-help" goto syntax

:parseArgs
  if "%~1" == "" goto start

  if /i "%~1" == "vc6" (
    set VERSION=VC6
  ) else if /i "%~1" == "vc7" (
    set VERSION=VC7
  ) else if /i "%~1" == "vc7.1" (
    set VERSION=VC7.1
  ) else if /i "%~1" == "vc8" (
    set VERSION=VC8
  ) else if /i "%~1" == "vc9" (
    set VERSION=VC9
  ) else if /i "%~1" == "vc10" (
    set VERSION=VC10
  ) else if /i "%~1" == "vc11" (
    set VERSION=VC11
  ) else if /i "%~1" == "vc12" (
    set VERSION=VC12
  ) else if /i "%~1" == "-clean" (
    set MODE=CLEAN
  ) else (
    goto unknown
  )
  shift & goto parseArgs
 
:start
  if "%MODE%" == "GENERATE" (
    echo.
    echo Generating prerequisite files
    CALL :gen_curlbuild
    if errorlevel 1 goto error
    CALL :gen_hugehelp
    if errorlevel 1 goto error
  ) else (
    echo.
    echo Removing prerequisite files
    call :clean ..\include\curl\curlbuild.h
    call :clean ..\src\tool_hugehelp.c
  )
  if "%VERSION%" == "VC6" goto vc6
  if "%VERSION%" == "VC7" goto vc7
  if "%VERSION%" == "VC7.1" goto vc71
  if "%VERSION%" == "VC8" goto vc8
  if "%VERSION%" == "VC9" goto vc9
  if "%VERSION%" == "VC10" goto vc10
  if "%VERSION%" == "VC11" goto vc11
  if "%VERSION%" == "VC12" goto vc12

:vc6
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC6 project files
    call :generate dsp Windows\VC6\src\curlsrc.tmpl Windows\VC6\src\curlsrc.dsp
    call :generate dsp Windows\VC6\lib\libcurl.tmpl Windows\VC6\lib\libcurl.dsp
  ) else (
    echo Removing VC6 project files
    call :clean Windows\VC6\src\curlsrc.dsp
    call :clean Windows\VC6\lib\libcurl.dsp
  )

  if not "%VERSION%" == "ALL" goto success

:vc7
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC7 project files
    call :generate vcproj1 Windows\VC7\src\curlsrc.tmpl Windows\VC7\src\curlsrc.vcproj
    call :generate vcproj1 Windows\VC7\lib\libcurl.tmpl Windows\VC7\lib\libcurl.vcproj
  ) else (
    echo Removing VC7 project files
    call :clean Windows\VC7\src\curlsrc.vcproj
    call :clean Windows\VC7\lib\libcurl.vcproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc71
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC7.1 project files
    call :generate vcproj1 Windows\VC7.1\src\curlsrc.tmpl Windows\VC7.1\src\curlsrc.vcproj
    call :generate vcproj1 Windows\VC7.1\lib\libcurl.tmpl Windows\VC7.1\lib\libcurl.vcproj
  ) else (
    echo Removing VC7.1 project files
    call :clean Windows\VC7.1\src\curlsrc.vcproj
    call :clean Windows\VC7.1\lib\libcurl.vcproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc8
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC8 project files
    call :generate vcproj2 Windows\VC8\src\curlsrc.tmpl Windows\VC8\src\curlsrc.vcproj
    call :generate vcproj2 Windows\VC8\lib\libcurl.tmpl Windows\VC8\lib\libcurl.vcproj
  ) else (
    echo Removing VC8 project files
    call :clean Windows\VC8\src\curlsrc.vcproj
    call :clean Windows\VC8\lib\libcurl.vcproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc9
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC9 project files
    call :generate vcproj2 Windows\VC9\src\curlsrc.tmpl Windows\VC9\src\curlsrc.vcproj
    call :generate vcproj2 Windows\VC9\lib\libcurl.tmpl Windows\VC9\lib\libcurl.vcproj
  ) else (
    echo Removing VC9 project files
    call :clean Windows\VC9\src\curlsrc.vcproj
    call :clean Windows\VC9\lib\libcurl.vcproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc10
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC10 project files
    call :generate vcxproj Windows\VC10\src\curlsrc.tmpl Windows\VC10\src\curlsrc.vcxproj
    call :generate vcxproj Windows\VC10\lib\libcurl.tmpl Windows\VC10\lib\libcurl.vcxproj
  ) else (
    echo Removing VC10 project files
    call :clean Windows\VC10\src\curlsrc.vcxproj
    call :clean Windows\VC10\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc11
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC11 project files
    call :generate vcxproj Windows\VC11\src\curlsrc.tmpl Windows\VC11\src\curlsrc.vcxproj
    call :generate vcxproj Windows\VC11\lib\libcurl.tmpl Windows\VC11\lib\libcurl.vcxproj
  ) else (
    echo Removing VC11 project files
    call :clean Windows\VC11\src\curlsrc.vcxproj
    call :clean Windows\VC11\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc12
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC12 project files
    call :generate vcxproj Windows\VC12\src\curlsrc.tmpl Windows\VC12\src\curlsrc.vcxproj
    call :generate vcxproj Windows\VC12\lib\libcurl.tmpl Windows\VC12\lib\libcurl.vcxproj
  ) else (
    echo Removing VC12 project files
    call :clean Windows\VC12\src\curlsrc.vcxproj
    call :clean Windows\VC12\lib\libcurl.vcxproj
  )

  goto success

rem Main generate function.
rem
rem %1 - Project Type (dsp for VC6, vcproj1 for VC7 and VC7.1, vcproj2 for VC8 and VC9
rem      or vcxproj for VC10, VC11 and VC12)
rem %2 - Input template file
rem %3 - Output project file
rem
:generate
  if not exist %2 (
    echo.
    echo Error: Cannot open %CD%\%2
    exit /B
  )

  if exist %3 (  
    del %3
  )

  echo * %CD%\%3
  for /f "usebackq delims=" %%i in (`"findstr /n ^^ %2"`) do (
    set "var=%%i"
    setlocal enabledelayedexpansion
    set "var=!var:*:=!"

    if "!var!" == "CURL_SRC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\src\*.c') do call :element %1 src "%%c" %3
    ) else if "!var!" == "CURL_SRC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\src\*.h') do call :element %1 src "%%h" %3
    ) else if "!var!" == "CURL_SRC_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\src\*.rc') do call :element %1 src "%%r" %3
    ) else if "!var!" == "CURL_SRC_X_C_FILES" (
      call :element %1 lib "strtoofft.c" %3
      call :element %1 lib "rawstr.c" %3
      call :element %1 lib "nonblock.c" %3
      call :element %1 lib "warnless.c" %3
    ) else if "!var!" == "CURL_SRC_X_H_FILES" (
      call :element %1 lib "config-win32.h" %3
      call :element %1 lib "curl_setup.h" %3
      call :element %1 lib "strtoofft.h" %3
      call :element %1 lib "rawstr.h" %3
      call :element %1 lib "nonblock.h" %3
      call :element %1 lib "warnless.h" %3
    ) else if "!var!" == "CURL_LIB_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\*.c') do call :element %1 lib "%%c" %3
    ) else if "!var!" == "CURL_LIB_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\*.h') do call :element %1 lib "%%h" %3
    ) else if "!var!" == "CURL_LIB_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\lib\*.rc') do call :element %1 lib "%%r" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vauth\*.c') do call :element %1 lib\vauth "%%c" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vauth\*.h') do call :element %1 lib\vauth "%%h" %3
    ) else if "!var!" == "CURL_LIB_VTLS_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vtls\*.c') do call :element %1 lib\vtls "%%c" %3
    ) else if "!var!" == "CURL_LIB_VTLS_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vtls\*.h') do call :element %1 lib\vtls "%%h" %3
    ) else (
      echo.!var!>> %3
    )

    endlocal
  )
  exit /B

rem Generates a single file xml element.
rem
rem %1 - Project Type (dsp for VC6, vcproj1 for VC7 and VC7.1, vcproj2 for VC8 and VC9
rem      or vcxproj for VC10, VC11 and VC12)
rem %2 - Directory (src, lib, lib\vauth or lib\vtls)
rem %3 - Source filename
rem %4 - Output project file
rem
:element
  set "SPACES=    "
  if "%2" == "lib\vauth" (
    set "TABS=				"
  ) else if "%2" == "lib\vtls" (
    set "TABS=				"
  ) else (
    set "TABS=			"
  )

  call :extension %3 ext

  if "%1" == "dsp" (
    echo # Begin Source File>> %4
    echo.>> %4
    echo SOURCE=..\..\..\..\%2\%~3>> %4
    echo # End Source File>> %4
  ) else if "%1" == "vcproj1" (
    echo %TABS%^<File>> %4
    echo %TABS%	RelativePath="..\..\..\..\%2\%~3"^>>> %4
    echo %TABS%^</File^>>> %4
  ) else if "%1" == "vcproj2" (
    echo %TABS%^<File>> %4
    echo %TABS%	RelativePath="..\..\..\..\%2\%~3">> %4
    echo %TABS%^>>> %4
    echo %TABS%^</File^>>> %4
  ) else if "%1" == "vcxproj" (
    if "%ext%" == "c" (
      echo %SPACES%^<ClCompile Include=^"..\..\..\..\%2\%~3^" /^>>> %4
    ) else if "%ext%" == "h" (
      echo %SPACES%^<ClInclude Include=^"..\..\..\..\%2\%~3^" /^>>> %4
    ) else if "%ext%" == "rc" (
      echo %SPACES%^<ResourceCompile Include=^"..\..\..\..\%2\%~3^" /^>>> %4
    )
  )

  exit /B

rem Returns the extension for a given filename.
rem
rem %1 - The filename
rem %2 - The return value
rem
:extension
  set fname=%~1
  set ename=
:loop1
  if "%fname%"=="" (
    set %2=
    exit /B
  )

  if not "%fname:~-1%"=="." (
    set ename=%fname:~-1%%ename%
    set fname=%fname:~0,-1%
    goto loop1
  )

  set %2=%ename%
  exit /B

rem Removes the given project file.
rem
rem %1 - The filename
rem
:clean
  echo * %CD%\%1

  if exist %1 (  
    del %1
  )

  exit /B

rem CALL this function to generate ..\src\tool_hugehelp.c
rem Returns exit code 0 on success or 1 on failure.
:gen_hugehelp
  setlocal
  set LC_ALL=C
  set ROFFCMD=
  if defined HAVE_PERL (
    if defined HAVE_GROFF (
      set ROFFCMD=groff -mtty-char -Tascii -P-c -man
    ) else if defined HAVE_NROFF (
      set ROFFCMD=nroff -c -Tascii -man
    )
  )
  echo * %CD%\..\src\tool_hugehelp.c
  echo #include "tool_setup.h"> ..\src\tool_hugehelp.c
  echo #include "tool_hugehelp.h">> ..\src\tool_hugehelp.c
  if defined ROFFCMD (
    if defined HAVE_GZIP (
      echo #ifndef HAVE_LIBZ>> ..\src\tool_hugehelp.c
    )
    %ROFFCMD% ..\docs\curl.1 2>NUL | perl ..\src\mkhelp.pl ..\docs\MANUAL >> ..\src\tool_hugehelp.c
    if defined HAVE_GZIP (
      echo #else>> ..\src\tool_hugehelp.c
      %ROFFCMD% ..\docs\curl.1 2>NUL | perl ..\src\mkhelp.pl -c ..\docs\MANUAL >> ..\src\tool_hugehelp.c
      echo #endif /^* HAVE_LIBZ ^*/>> ..\src\tool_hugehelp.c
    )
  ) else (
    echo.
    echo Warning: The curl manual could not be integrated in the source. This means when
    echo you build curl the manual will not be available (curl --man^). Integration of
    echo the manual is not required and a summary of the options will still be available
    echo (curl --help^). To integrate the manual your PATH is required to have
    echo groff/nroff, perl and optionally gzip for compression.
    echo.
    echo void hugehelp(void^)>> ..\src\tool_hugehelp.c
    echo #ifdef USE_MANUAL>> ..\src\tool_hugehelp.c
    echo { fputs("built-in manual not included\n", stdout^); }>> ..\src\tool_hugehelp.c
    echo #else>> ..\src\tool_hugehelp.c
    echo {}>> ..\src\tool_hugehelp.c
    echo #endif>> ..\src\tool_hugehelp.c
  )
  findstr "/C:void hugehelp(void)" ..\src\tool_hugehelp.c 1>NUL 2>&1
  if %ERRORLEVEL% NEQ 0 (
    echo Error: Unable to generate ..\src\tool_hugehelp.c
    exit /B 1
  )
  exit /B 0

rem CALL this function to generate ..\include\curl\curlbuild.h
rem Returns exit code 0 on success or 1 on failure.
:gen_curlbuild
  setlocal
  echo * %CD%\..\include\curl\curlbuild.h
  copy /y ..\include\curl\curlbuild.h.dist ..\include\curl\curlbuild.h 1>NUL
  if %ERRORLEVEL% NEQ 0 (
    echo Error: Unable to generate ..\include\curl\curlbuild.h
    exit /B 1
  )
  exit /B 0

:syntax
  rem Display the help
  echo.
  echo Usage: generate [compiler] [-clean]
  echo.
  echo Compiler:
  echo.
  echo vc6       - Use Visual Studio 6
  echo vc7       - Use Visual Studio .NET
  echo vc7.1     - Use Visual Studio .NET 2003
  echo vc8       - Use Visual Studio 2005
  echo vc9       - Use Visual Studio 2008
  echo vc10      - Use Visual Studio 2010
  echo vc11      - Use Visual Studio 2012
  echo vc12      - Use Visual Studio 2013
  echo.
  echo -clean    - Removes the project files
  goto error

:unknown
  echo.
  echo Error: Unknown argument '%1'
  goto error

:nodos
  echo.
  echo Error: Only a Windows NT based Operating System is supported
  goto error

:nonetdrv
  echo.
  echo Error: This batch file cannot run from a network drive
  goto error

:seterr
  rem Set the caller's errorlevel.
  rem %1[opt]: Errorlevel as integer.
  rem If %1 is empty the errorlevel will be set to 0.
  rem If %1 is not empty and not an integer the errorlevel will be set to 1.
  setlocal
  set EXITCODE=%~1
  if not defined EXITCODE set EXITCODE=0
  echo %EXITCODE%|findstr /r "[^0-9\-]" 1>NUL 2>&1
  if %ERRORLEVEL% EQU 0 set EXITCODE=1
  exit /b %EXITCODE%

:error
  endlocal
  exit /B 1

:success
  endlocal
  exit /B 0
