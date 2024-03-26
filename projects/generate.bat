@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
rem *
rem * This software is licensed as described in the file COPYING, which
rem * you should have received as part of this distribution. The terms
rem * are also available at https://curl.se/docs/copyright.html.
rem *
rem * You may opt to use, copy, modify, merge, publish, distribute and/or sell
rem * copies of the Software, and permit persons to whom the Software is
rem * furnished to do so, under the terms of the COPYING file.
rem *
rem * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
rem * KIND, either express or implied.
rem *
rem * SPDX-License-Identifier: curl
rem *
rem ***************************************************************************

:begin
  rem Check we are running on a Windows NT derived OS
  if not "%OS%" == "Windows_NT" goto nodos

  rem Set our variables
  setlocal ENABLEEXTENSIONS
  set VERSION=ALL
  set MODE=GENERATE

  rem Check we are not running on a network drive
  if "%~d0."=="\\." goto nonetdrv

  rem Switch to this batch file's directory
  cd /d "%~0\.." 1>NUL 2>&1

  rem Check we are running from a curl git repository
  if not exist ..\GIT-INFO.md goto norepo

:parseArgs
  if "%~1" == "" goto start

  if /i "%~1" == "pre" (
    set VERSION=PRE
  ) else if /i "%~1" == "vc10" (
    set VERSION=VC10
  ) else if /i "%~1" == "vc11" (
    set VERSION=VC11
  ) else if /i "%~1" == "vc12" (
    set VERSION=VC12
  ) else if /i "%~1" == "vc14" (
    set VERSION=VC14
  ) else if /i "%~1" == "vc14.10" (
    set VERSION=VC14.10
  ) else if /i "%~1" == "vc14.20" (
    set VERSION=VC14.20
  ) else if /i "%~1" == "vc14.30" (
    set VERSION=VC14.30
  ) else if /i "%~1" == "-clean" (
    set MODE=CLEAN
  ) else if /i "%~1" == "-?" (
    goto syntax
  ) else if /i "%~1" == "-h" (
    goto syntax
  ) else if /i "%~1" == "-help" (
    goto syntax
  ) else (
    goto unknown
  )

  shift & goto parseArgs

:start
  if exist ..\buildconf.bat (
    if "%MODE%" == "GENERATE" (
      call ..\buildconf
    ) else if "%VERSION%" == "PRE" (
      call ..\buildconf -clean
    ) else if "%VERSION%" == "ALL" (
      call ..\buildconf -clean
    )
  )
  if "%VERSION%" == "PRE" goto success
  if "%VERSION%" == "VC10" goto vc10
  if "%VERSION%" == "VC11" goto vc11
  if "%VERSION%" == "VC12" goto vc12
  if "%VERSION%" == "VC14" goto vc14
  if "%VERSION%" == "VC14.10" goto vc14.10
  if "%VERSION%" == "VC14.20" goto vc14.20
  if "%VERSION%" == "VC14.30" goto vc14.30

:vc10
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC10 project files
    call :generate vcxproj Windows\VC10\src\curl.tmpl Windows\VC10\src\curl.vcxproj
    call :generate vcxproj Windows\VC10\lib\libcurl.tmpl Windows\VC10\lib\libcurl.vcxproj
  ) else (
    echo Removing VC10 project files
    call :clean Windows\VC10\src\curl.vcxproj
    call :clean Windows\VC10\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc11
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC11 project files
    call :generate vcxproj Windows\VC11\src\curl.tmpl Windows\VC11\src\curl.vcxproj
    call :generate vcxproj Windows\VC11\lib\libcurl.tmpl Windows\VC11\lib\libcurl.vcxproj
  ) else (
    echo Removing VC11 project files
    call :clean Windows\VC11\src\curl.vcxproj
    call :clean Windows\VC11\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc12
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC12 project files
    call :generate vcxproj Windows\VC12\src\curl.tmpl Windows\VC12\src\curl.vcxproj
    call :generate vcxproj Windows\VC12\lib\libcurl.tmpl Windows\VC12\lib\libcurl.vcxproj
  ) else (
    echo Removing VC12 project files
    call :clean Windows\VC12\src\curl.vcxproj
    call :clean Windows\VC12\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc14
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC14 project files
    call :generate vcxproj Windows\VC14\src\curl.tmpl Windows\VC14\src\curl.vcxproj
    call :generate vcxproj Windows\VC14\lib\libcurl.tmpl Windows\VC14\lib\libcurl.vcxproj
  ) else (
    echo Removing VC14 project files
    call :clean Windows\VC14\src\curl.vcxproj
    call :clean Windows\VC14\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc14.10
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC14.10 project files
    call :generate vcxproj Windows\VC14.10\src\curl.tmpl Windows\VC14.10\src\curl.vcxproj
    call :generate vcxproj Windows\VC14.10\lib\libcurl.tmpl Windows\VC14.10\lib\libcurl.vcxproj
  ) else (
    echo Removing VC14.10 project files
    call :clean Windows\VC14.10\src\curl.vcxproj
    call :clean Windows\VC14.10\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc14.20
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC14.20 project files
    call :generate vcxproj Windows\VC14.20\src\curl.tmpl Windows\VC14.20\src\curl.vcxproj
    call :generate vcxproj Windows\VC14.20\lib\libcurl.tmpl Windows\VC14.20\lib\libcurl.vcxproj
  ) else (
    echo Removing VC14.20 project files
    call :clean Windows\VC14.20\src\curl.vcxproj
    call :clean Windows\VC14.20\lib\libcurl.vcxproj
  )

  if not "%VERSION%" == "ALL" goto success

:vc14.30
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC14.30 project files
    call :generate vcxproj Windows\VC14.30\src\curl.tmpl Windows\VC14.30\src\curl.vcxproj
    call :generate vcxproj Windows\VC14.30\lib\libcurl.tmpl Windows\VC14.30\lib\libcurl.vcxproj
  ) else (
    echo Removing VC14.30 project files
    call :clean Windows\VC14.30\src\curl.vcxproj
    call :clean Windows\VC14.30\lib\libcurl.vcxproj
  )

  goto success

rem Main generate function.
rem
rem %1 - Project Type (vcxproj for VC10, VC11, VC12, VC14, VC14.10, VC14.20 and VC14.30)
rem %2 - Input template file
rem %3 - Output project file
rem
:generate
  if not exist %2 (
    echo.
    echo Error: Cannot open %2
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
      call :element %1 lib "timediff.c" %3
      call :element %1 lib "nonblock.c" %3
      call :element %1 lib "warnless.c" %3
      call :element %1 lib "curl_multibyte.c" %3
      call :element %1 lib "version_win32.c" %3
      call :element %1 lib "dynbuf.c" %3
      call :element %1 lib "base64.c" %3
    ) else if "!var!" == "CURL_SRC_X_H_FILES" (
      call :element %1 lib "config-win32.h" %3
      call :element %1 lib "curl_setup.h" %3
      call :element %1 lib "strtoofft.h" %3
      call :element %1 lib "timediff.h" %3
      call :element %1 lib "nonblock.h" %3
      call :element %1 lib "warnless.h" %3
      call :element %1 lib "curl_ctype.h" %3
      call :element %1 lib "curl_multibyte.h" %3
      call :element %1 lib "version_win32.h" %3
      call :element %1 lib "dynbuf.h" %3
      call :element %1 lib "curl_base64.h" %3
    ) else if "!var!" == "CURL_LIB_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\*.c') do call :element %1 lib "%%c" %3
    ) else if "!var!" == "CURL_LIB_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\include\curl\*.h') do call :element %1 include\curl "%%h" %3
      for /f "delims=" %%h in ('dir /b ..\lib\*.h') do call :element %1 lib "%%h" %3
    ) else if "!var!" == "CURL_LIB_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\lib\*.rc') do call :element %1 lib "%%r" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vauth\*.c') do call :element %1 lib\vauth "%%c" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vauth\*.h') do call :element %1 lib\vauth "%%h" %3
    ) else if "!var!" == "CURL_LIB_VQUIC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vquic\*.c') do call :element %1 lib\vquic "%%c" %3
    ) else if "!var!" == "CURL_LIB_VQUIC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vquic\*.h') do call :element %1 lib\vquic "%%h" %3
    ) else if "!var!" == "CURL_LIB_VSSH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vssh\*.c') do call :element %1 lib\vssh "%%c" %3
    ) else if "!var!" == "CURL_LIB_VSSH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vssh\*.h') do call :element %1 lib\vssh "%%h" %3
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
rem %1 - Project Type (vcxproj for VC10, VC11, VC12, VC14, VC14.10, VC14.20 and VC14.30)
rem %2 - Directory (src, lib, lib\vauth, lib\vquic, lib\vssh, lib\vtls)
rem %3 - Source filename
rem %4 - Output project file
rem
:element
  set "SPACES=    "
  if "%2" == "lib\vauth" (
    set "TABS=				"
  ) else if "%2" == "lib\vquic" (
    set "TABS=				"
  ) else if "%2" == "lib\vssh" (
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

:syntax
  rem Display the help
  echo.
  echo Usage: generate [what] [-clean]
  echo.
  echo What to generate:
  echo.
  echo pre       - Prerequisites only
  echo vc10      - Use Visual Studio 2010
  echo vc11      - Use Visual Studio 2012
  echo vc12      - Use Visual Studio 2013
  echo vc14      - Use Visual Studio 2015
  echo vc14.10   - Use Visual Studio 2017
  echo vc14.20   - Use Visual Studio 2019
  echo vc14.30   - Use Visual Studio 2022
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

:norepo
  echo.
  echo Error: This batch file should only be used from a curl git repository
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
  if "%OS%" == "Windows_NT" endlocal
  exit /B 1

:success
  endlocal
  exit /B 0
