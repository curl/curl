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

  if /i "%~1" == "vc10" (
    set VERSION=VC10
  ) else if /i "%~1" == "vc11" (
    set VERSION=VC11
  ) else if /i "%~1" == "vc12" (
    set VERSION=VC12
  ) else if /i "%~1" == "-clean" (
    set MODE=CLEAN
  ) else if /i "%~1" == "-?" (
    goto syntax
  ) else if /i "%~1" == "/?" (
    goto syntax
  ) else if /i "%~1" == "-h" (
    goto syntax
  ) else if /i "%~1" == "-help" (
    goto syntax
  ) else if /i "%~1" == "--help" (
    goto syntax
  ) else (
    goto unknown
  )

  shift & goto parseArgs

:start
  if "%VERSION%" == "VC10" goto vc10
  if "%VERSION%" == "VC11" goto vc11
  if "%VERSION%" == "VC12" goto vc12

:vc10
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC10 project files
    call :generate Windows\VC10\src\curl.tmpl Windows\VC10\src\curl.vcxproj
    call :generate Windows\VC10\lib\libcurl.tmpl Windows\VC10\lib\libcurl.vcxproj
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
    call :generate Windows\VC11\src\curl.tmpl Windows\VC11\src\curl.vcxproj
    call :generate Windows\VC11\lib\libcurl.tmpl Windows\VC11\lib\libcurl.vcxproj
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
    call :generate Windows\VC12\src\curl.tmpl Windows\VC12\src\curl.vcxproj
    call :generate Windows\VC12\lib\libcurl.tmpl Windows\VC12\lib\libcurl.vcxproj
  ) else (
    echo Removing VC12 project files
    call :clean Windows\VC12\src\curl.vcxproj
    call :clean Windows\VC12\lib\libcurl.vcxproj
  )

  goto success

rem Main generate function.
rem
rem %1 - Input template file
rem %2 - Output project file
rem
:generate
  if not exist %1 (
    echo.
    echo Error: Cannot open %1
    exit /B
  )

  if exist %2 (
    del %2
  )

  echo * %CD%\%2
  for /f "usebackq delims=" %%i in (`"findstr /n ^^ %1"`) do (
    set "var=%%i"
    setlocal enabledelayedexpansion
    set "var=!var:*:=!"

    if "!var!" == "CURL_SRC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\src\*.c') do (
        if /i "%%c" NEQ "curlinfo.c" call :element src "%%c" %2
      )
    ) else if "!var!" == "CURL_SRC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\src\*.h') do call :element src "%%h" %2
    ) else if "!var!" == "CURL_SRC_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\src\*.rc') do call :element src "%%r" %2
    ) else if "!var!" == "CURL_SRC_X_H_FILES" (
      call :element lib "config-win32.h" %2
      call :element lib "curl_setup.h" %2
    ) else if "!var!" == "CURL_LIB_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\*.c') do call :element lib "%%c" %2
    ) else if "!var!" == "CURL_LIB_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\include\curl\*.h') do call :element include\curl "%%h" %2
      for /f "delims=" %%h in ('dir /b ..\lib\*.h') do call :element lib "%%h" %2
    ) else if "!var!" == "CURL_LIB_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\lib\*.rc') do call :element lib "%%r" %2
    ) else if "!var!" == "CURL_LIB_CURLX_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\curlx\*.c') do call :element lib\curlx "%%c" %2
    ) else if "!var!" == "CURL_LIB_CURLX_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\curlx\*.h') do call :element lib\curlx "%%h" %2
    ) else if "!var!" == "CURL_LIB_VAUTH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vauth\*.c') do call :element lib\vauth "%%c" %2
    ) else if "!var!" == "CURL_LIB_VAUTH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vauth\*.h') do call :element lib\vauth "%%h" %2
    ) else if "!var!" == "CURL_LIB_VQUIC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vquic\*.c') do call :element lib\vquic "%%c" %2
    ) else if "!var!" == "CURL_LIB_VQUIC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vquic\*.h') do call :element lib\vquic "%%h" %2
    ) else if "!var!" == "CURL_LIB_VSSH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vssh\*.c') do call :element lib\vssh "%%c" %2
    ) else if "!var!" == "CURL_LIB_VSSH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vssh\*.h') do call :element lib\vssh "%%h" %2
    ) else if "!var!" == "CURL_LIB_VTLS_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vtls\*.c') do call :element lib\vtls "%%c" %2
    ) else if "!var!" == "CURL_LIB_VTLS_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vtls\*.h') do call :element lib\vtls "%%h" %2
    ) else (
      echo.!var!>> %2
    )

    endlocal
  )
  exit /B

rem Generates a single file xml element.
rem
rem %1 - Directory (src, lib, lib\vauth, lib\vquic, lib\vssh, lib\vtls)
rem %2 - Source filename
rem %3 - Output project file
rem
:element
  set "SPACES=    "

  call :extension %2 ext

  if "%ext%" == "c" (
    echo %SPACES%^<ClCompile Include=^"..\..\..\..\%1\%~2^" /^>>> %3
  ) else if "%ext%" == "h" (
    echo %SPACES%^<ClInclude Include=^"..\..\..\..\%1\%~2^" /^>>> %3
  ) else if "%ext%" == "rc" (
    echo %SPACES%^<ResourceCompile Include=^"..\..\..\..\%1\%~2^" /^>>> %3
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
  echo vc10      - Use Visual Studio 2010
  echo vc11      - Use Visual Studio 2012
  echo vc12      - Use Visual Studio 2013
  echo.
  echo Only legacy Visual Studio project files can be generated.
  echo.
  echo To generate recent versions of Visual Studio project files use cmake.
  echo Refer to INSTALL-CMAKE.md in the docs directory.
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
