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

:begin
  rem Check we are running on a Windows NT derived OS
  if not "%OS%" == "Windows_NT" goto nodos

  rem Set our variables
  setlocal
  set VERSION=ALL
  set MODE=GENERATE

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
rem %2 - Directory (src, lib or lib\vtls)
rem %3 - Source filename
rem %4 - Output project file
rem
:element
  set "SPACES=    "
  if "%2" == "lib\vtls" (
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

:error
  endlocal
  exit /B 1

:success
  endlocal
  exit /B 0
