@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2012 - 2015, Steve Holme, <steve_holme@hotmail.com>.
rem * Copyright (C) 2015, Jay Satiro, <raysatiro@yahoo.com>.
rem *
rem * This software is licensed as described in the file COPYING, which
rem * you should have received as part of this distribution. The terms
rem * are also available at https://curl.haxx.se/docs/copyright.html.
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

  setlocal ENABLEEXTENSIONS

  rem Set our variables
  set BUILD_CONFIG=
  set BUILD_PLATFORM=
  set "DEFAULT_START_DIR=%~dp0..\..\wolfssl"
  set START_DIR=
  set SUCCESSFUL_BUILDS=
  set VC_DESC=
  set VC_PATH=
  set VC_TOOLSET=
  set VC_VER=

:parseArgs
  if /i "%~1" == "" goto syntax
  if /i "%~1" == "-?" goto syntax
  if /i "%~1" == "/?" goto syntax
  if /i "%~1" == "-h" goto syntax
  if /i "%~1" == "-help" goto syntax
  if /i "%~1" == "--help" goto syntax

  if /i "%~1" == "vc10" (
    set VC_VER=10.0
    set VC_DESC=VC10
    set VC_TOOLSET=v100
    set "VC_PATH=Microsoft Visual Studio 10.0\VC"
  ) else if /i "%~1" == "vc11" (
    set VC_VER=11.0
    set VC_DESC=VC11
    set VC_TOOLSET=v110
    set "VC_PATH=Microsoft Visual Studio 11.0\VC"
  ) else if /i "%~1" == "vc12" (
    set VC_VER=12.0
    set VC_DESC=VC12
    set VC_TOOLSET=v120
    set "VC_PATH=Microsoft Visual Studio 12.0\VC"
  ) else if /i "%~1" == "vc14" (
    set VC_VER=14.0
    set VC_DESC=VC14
    set VC_TOOLSET=v140
    set "VC_PATH=Microsoft Visual Studio 14.0\VC"
  ) else goto unknown

  if "%~2" == "" goto prerequisites

  if /i "%~2" == "x86" (
    set BUILD_PLATFORM=x86
  ) else if /i "%~2" == "x64" (
    set BUILD_PLATFORM=x64
  ) else if /i "%~2" == "both" (
    set BUILD_PLATFORM=
  ) else goto unknown

  if "%~3" == "" goto prerequisites

  if /i "%~3" == "debug" (
    set BUILD_CONFIG=debug
  ) else if /i "%~3" == "release" (
    set BUILD_CONFIG=release
  ) else if /i "%~3" == "both" (
    set BUILD_CONFIG=
  ) else goto unknown

  if "%~4" == "" goto prerequisites

  set "START_DIR=%~4"

  if not "%~5" == "" goto unknown

:prerequisites
  rem Set the defaults
  if not defined VC_VER goto syntax
  if not defined START_DIR set "START_DIR=%DEFAULT_START_DIR%"

  rem Check the start directory exists
  if not exist "%START_DIR%" goto nowolfssl

  rem Calculate the program files directory
  set PF=
  if defined PROGRAMFILES (
    set "PF=%PROGRAMFILES%"
    set OS_PLATFORM=x86
  )
  if defined PROGRAMFILES(x86) (
    set "PF=%PROGRAMFILES(x86)%"
    set OS_PLATFORM=x64
  )

  rem Check we have a program files directory
  if not defined PF goto nopf

  rem Check we have Visual Studio installed
  if not exist "%PF%\%VC_PATH%" goto novc

  rem These variables are passed to the vcvarsall script
  set X86_PLATFORM_NAME=x86
  set X64_PLATFORM_NAME=
  if "%VC_VER%" == "10.0" set X64_PLATFORM_NAME=x64
  if "%VC_VER%" == "11.0" set X64_PLATFORM_NAME=amd64
  if "%VC_VER%" == "12.0" set X64_PLATFORM_NAME=amd64
  if "%VC_VER%" == "14.0" set X64_PLATFORM_NAME=amd64
  if not defined X64_PLATFORM_NAME (
    echo Error: Missing X64_PLATFORM_NAME! & goto error
  )

  set X86_VC_INIT_CMDLINE=call "%PF%\%VC_PATH%\vcvarsall" %X86_PLATFORM_NAME%
  set X64_VC_INIT_CMDLINE=call "%PF%\%VC_PATH%\vcvarsall" %X64_PLATFORM_NAME%

:start
  set "SAVED_PATH=%CD%"
  cd /d "%START_DIR%"
  if %ERRORLEVEL% neq 0 echo Error: cd "%START_DIR%" failed! & goto error

  set PLATFORMS=%BUILD_PLATFORM%
  if not defined PLATFORMS set PLATFORMS=x86 x64

  set CONFIGS=%BUILD_CONFIG%
  if not defined CONFIGS set CONFIGS=debug release

  set LIBTYPES=shared static

  for %%a in (%PLATFORMS%) do (
    for %%b in (%CONFIGS%) do (
      for %%c in (%LIBTYPES%) do (
        set SKIP_BUILD=
        if %%a == x64 if not defined X64_PLATFORM_NAME set SKIP_BUILD=defined
        if not defined SKIP_BUILD (
          call :build %%a %%b %%c
          if errorlevel 1 goto error
        )
      )
    )
  )

  goto success

:build
  rem This function builds wolfSSL.
  rem Usage: CALL :build <x86|x64> <debug|release> <shared|static>
  rem Before calling this function:
  rem - The current directory must be the wolfSSL source directory.
  rem Returns: 1 on fail, 0 on success.
  rem An informational message should be shown before any return on fail.
  rem Only return via an exit statement and not a goto (ie goto error) since
  rem the main script/caller may be using those tags for cleanup and that code
  rem could expect the entire batch file is terminating.

  rem BEGIN block common to build-openssl build-wolfssl

  setlocal ENABLEEXTENSIONS DISABLEDELAYEDEXPANSION
  set ERR=Error: build:
  set "SRC_PATH=%CD%"
  rem PLATFORM cannot be used as a variable name since it's used by VC init
  set "ARCH=%~1"
  set "CONFIG=%~2"
  set "LIBTYPE=%~3"
  if not "%ARCH%" == "x86" if not "%ARCH%" == "x64" (
    echo %ERR% Unrecognized architecture: "%ARCH%" & exit /b 1
  )
  if not "%CONFIG%" == "debug" if not "%CONFIG%" == "release" (
    echo %ERR% Unrecognized configuration: "%CONFIG%" & exit /b 1
  )
  if not "%LIBTYPE%" == "shared" if not "%LIBTYPE%" == "static" (
    echo %ERR% Unrecognized libtype: "%LIBTYPE%" & exit /b 1
  )
  set FRIENDLY_NAME="%ARCH% %CONFIG% %LIBTYPE%"
  set ERR=%ERR% %FRIENDLY_NAME%:

  if %ARCH% == x86 set "OUTDIR=build\Win32\%VC_DESC%"
  if %ARCH% == x64 set "OUTDIR=build\Win64\%VC_DESC%"

  rem The OUTDIR later has a LEAF appended to it (LIB Release, DLL Debug, etc)
  if %LIBTYPE% == shared (set LEAF=DLL) else set LEAF=LIB
  if %CONFIG% == debug (set LEAF=%LEAF% Debug) else set LEAF=%LEAF% Release

  if %ARCH% == x86 set INIT_CMD=%X86_VC_INIT_CMDLINE%
  if %ARCH% == x64 set INIT_CMD=%X64_VC_INIT_CMDLINE%
  if not defined INIT_CMD echo %ERR% VC init not found! & exit /b 1
  %INIT_CMD%
  if %ERRORLEVEL% neq 0 echo %ERR% VC init failed! & exit /b 1

  cd /d "%SRC_PATH%"
  if %ERRORLEVEL% neq 0 echo %ERR% cd "%SRC_PATH%" failed! & exit /b 1

  rem END block common to build-openssl build-wolfssl

  echo. & echo.
  echo Building and running tests for wolfSSL %FRIENDLY_NAME%.
  echo. & echo.

  if %LIBTYPE% == static set MSBUILD_CONFIG=%CONFIG%
  if %LIBTYPE% == shared set MSBUILD_CONFIG=DLL %CONFIG%

  if %ARCH% == x86 set MSBUILD_PLATFORM=Win32
  if %ARCH% == x64 set MSBUILD_PLATFORM=x64

  rem DST_PATH and TMP_PATH must be full paths and not have trailing
  rem backslashes, which are added later.
  set "DST_PATH=%SRC_PATH%\%OUTDIR%\%LEAF%"
  set "TMP_PATH=%DST_PATH%\temp"

  if not exist wolfssl64.sln (
    echo %ERR% wolfssl64.sln not found in "%CD%"
    exit /b 1
  )

  copy /v /y "%~dp0\wolfssl_options.h" .\cyassl\options.h
  if %ERRORLEVEL% neq 0 (
    echo %ERR% Couldn't replace .\cyassl\options.h
    exit /b 1
  )

  copy /v /y "%~dp0\wolfssl_options.h" .\wolfssl\options.h
  if %ERRORLEVEL% neq 0 (
    echo %ERR% Couldn't replace .\wolfssl\options.h
    exit /b 1
  )

  rem Extra trailing \ in Dirs because otherwise it thinks a quote is escaped
  msbuild wolfssl64.sln ^
    -p:CustomAfterMicrosoftCommonTargets="%~dp0\wolfssl_override.props" ^
    -p:Configuration="%MSBUILD_CONFIG%" ^
    -p:Platform="%MSBUILD_PLATFORM%" ^
    -p:PlatformToolset="%VC_TOOLSET%" ^
    -p:OutDir="%DST_PATH%\\" ^
    -p:IntDir="%TMP_PATH%\\"
  if %ERRORLEVEL% neq 0 echo %ERR% msbuild failed! & exit /b 1

  rem For tests to run properly the wolfSSL directory must remain the current.
  "%DST_PATH%\testsuite.exe"
  if %ERRORLEVEL% neq 0 echo %ERR% testsuite failed! & exit /b 1

  echo. & echo.
  echo Success: Built and all tests passed for wolfSSL %FRIENDLY_NAME%.
  echo. & echo.

  rem Remove the temporary build files (obj,test,etc)
  rmdir /s /q "%TMP_PATH%" 1>NUL 2>&1

  rem This line is necessary to export SUCCESSFUL_BUILDS back to the caller
  endlocal & set SUCCESSFUL_BUILDS=%FRIENDLY_NAME% %SUCCESSFUL_BUILDS%
  exit /b 0

:syntax
  rem Display the help
  echo.
  echo Usage: build-wolfssl ^<compiler^> [platform] [configuration] [directory]
  echo.
  echo Compiler:
  echo.
  echo vc10      - Use Visual Studio 2010
  echo vc11      - Use Visual Studio 2012
  echo vc12      - Use Visual Studio 2013
  echo vc14      - Use Visual Studio 2015
  echo.
  echo Platform:
  echo.
  echo x86       - Perform a 32-bit build
  echo x64       - Perform a 64-bit build
  echo both      - Do both ^(default^)
  echo.
  echo Configuration:
  echo.
  echo debug     - Perform a debug build
  echo release   - Perform a release build
  echo both      - Do both ^(default^)
  echo.
  echo Directory:
  echo.
  echo The wolfSSL source directory.
  echo The default is "%DEFAULT_START_DIR%"
  echo.
  goto error

:unknown
  echo.
  echo Error: Unknown argument, for usage run build-wolfssl /?
  goto error

:nodos
  echo.
  echo Error: Only a Windows NT based Operating System is supported
  goto error

:nopf
  echo.
  echo Error: Cannot obtain the directory for Program Files
  goto error

:novc
  echo.
  echo Error: %VC_DESC% is not installed
  goto error

:nox64
  echo.
  echo Error: %VC_DESC% does not support 64-bit builds
  goto error

:nowolfssl
  echo.
  echo Error: Cannot locate wolfSSL source directory, expected "%START_DIR%"
  goto error

:error
  if "%OS%" == "Windows_NT" endlocal
  exit /B 1

:success
  if defined SUCCESSFUL_BUILDS (
    echo.
    echo.
    echo Build complete.
    echo.
    echo The following configurations were built and tested successfully:
    echo.
    echo %SUCCESSFUL_BUILDS%
    echo.
  )
  cd /d "%SAVED_PATH%"
  endlocal
  exit /B 0
