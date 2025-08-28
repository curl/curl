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
  if "%MODE%" == "GENERATE" (
    call :generate_proj VC10
  ) else (
    call :clean_proj VC10
  )

  if not "%VERSION%" == "ALL" goto success

:vc11
  if "%MODE%" == "GENERATE" (
    call :generate_proj VC11
  ) else (
    call :clean_proj VC11
  )

  if not "%VERSION%" == "ALL" goto success

:vc12
  if "%MODE%" == "GENERATE" (
    call :generate_proj VC12
  ) else (
    call :clean_proj VC12
  )

  goto success

rem Main project generate function.
rem
rem %1 - version
rem %2 - Input template file
rem %3 - Output project file
rem
:generate_proj
  echo.
  echo Generating %1 project files
  if not exist Windows\%1\lib md Windows\%1\lib
  if not exist Windows\%1\src md Windows\%1\src
  call :generate %1 Windows\tmpl\curl-all.sln            Windows\%1\curl-all.sln
  call :generate %1 Windows\tmpl\curl.sln                Windows\%1\src\curl.sln
  call :generate %1 Windows\tmpl\curl.vcxproj            Windows\%1\src\curl.vcxproj
  call :generate %1 Windows\tmpl\curl.vcxproj.filters    Windows\%1\src\curl.vcxproj.filters
  call :generate %1 Windows\tmpl\libcurl.sln             Windows\%1\lib\libcurl.sln
  call :generate %1 Windows\tmpl\libcurl.vcxproj         Windows\%1\lib\libcurl.vcxproj
  call :generate %1 Windows\tmpl\libcurl.vcxproj.filters Windows\%1\lib\libcurl.vcxproj.filters

  exit /B

rem Main project clean function.
rem
rem %1 - version
rem
:clean_proj
  echo.
  echo Removing %1 project files
  call :clean Windows\%1\curl-all.sln
  call :clean Windows\%1\src\curl.sln
  call :clean Windows\%1\src\curl.vcxproj
  call :clean Windows\%1\src\curl.vcxproj.filters
  call :clean Windows\%1\lib\libcurl.sln
  call :clean Windows\%1\lib\libcurl.vcxproj
  call :clean Windows\%1\lib\libcurl.vcxproj.filters

  exit /B

rem Main file generate function.
rem
rem %1 - version
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

  set "S01=$FORMATVER"
  set "S02=$PLATFORMTOOLSET"
  set "S03=$SUBDIR"
  set "S04=$TOOLSVER"

  if "%1" == "VC10" (
    set "R01=11.00"
    set "R02=v100"
    set "R03=VC10"
    set "R04=4.0"
  ) else if "%1%" == "VC11" (
    set "R01=12.00"
    set "R02=v110"
    set "R03=VC11"
    set "R04=4.0"
  ) else if "%1%" == "VC12" (
    set "R01=12.00"
    set "R02=v120"
    set "R03=VC12"
    set "R04=12.0"
  )

  echo * %CD%\%3
  for /f "usebackq delims=" %%i in (`"findstr /n ^^ %2"`) do (
    set "var=%%i"
    setlocal enabledelayedexpansion
    set "var=!var:%S01%=%R01%!"
    set "var=!var:%S02%=%R02%!"
    set "var=!var:%S03%=%R03%!"
    set "var=!var:%S04%=%R04%!"

    set "var=!var:*:=!"

    if "!var!" == "CURL_SRC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\src\*.c') do (
        if /i "%%c" NEQ "curlinfo.c" call :element src "%%c" %3
      )
    ) else if "!var!" == "CURL_SRC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\src\*.h') do call :element src "%%h" %3
    ) else if "!var!" == "CURL_SRC_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\src\*.rc') do call :element src "%%r" %3
    ) else if "!var!" == "CURL_SRC_X_H_FILES" (
      call :element lib "config-win32.h" %3
      call :element lib "curl_setup.h" %3
    ) else if "!var!" == "CURL_LIB_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\*.c') do call :element lib "%%c" %3
    ) else if "!var!" == "CURL_LIB_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\include\curl\*.h') do call :element include\curl "%%h" %3
      for /f "delims=" %%h in ('dir /b ..\lib\*.h') do call :element lib "%%h" %3
    ) else if "!var!" == "CURL_LIB_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\lib\*.rc') do call :element lib "%%r" %3
    ) else if "!var!" == "CURL_LIB_CURLX_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\curlx\*.c') do call :element lib\curlx "%%c" %3
    ) else if "!var!" == "CURL_LIB_CURLX_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\curlx\*.h') do call :element lib\curlx "%%h" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vauth\*.c') do call :element lib\vauth "%%c" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vauth\*.h') do call :element lib\vauth "%%h" %3
    ) else if "!var!" == "CURL_LIB_VQUIC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vquic\*.c') do call :element lib\vquic "%%c" %3
    ) else if "!var!" == "CURL_LIB_VQUIC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vquic\*.h') do call :element lib\vquic "%%h" %3
    ) else if "!var!" == "CURL_LIB_VSSH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vssh\*.c') do call :element lib\vssh "%%c" %3
    ) else if "!var!" == "CURL_LIB_VSSH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vssh\*.h') do call :element lib\vssh "%%h" %3
    ) else if "!var!" == "CURL_LIB_VTLS_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vtls\*.c') do call :element lib\vtls "%%c" %3
    ) else if "!var!" == "CURL_LIB_VTLS_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vtls\*.h') do call :element lib\vtls "%%h" %3
    ) else (
      echo.!var!>> %3
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
