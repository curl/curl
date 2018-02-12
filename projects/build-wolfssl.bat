@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2012 - 2017, Steve Holme, <steve_holme@hotmail.com>.
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

  rem Set our variables
  setlocal
  set SUCCESSFUL_BUILDS=
  set VC_VER=
  set BUILD_PLATFORM=

  rem Ensure we have the required arguments
  if /i "%~1" == "" goto syntax

:parseArgs
  if "%~1" == "" goto prerequisites

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
  ) else if /i "%~1" == "vc15" (
    set VC_VER=15.0
    set VC_DESC=VC15
    set VC_TOOLSET=v141
    set "VC_PATH=Microsoft Visual Studio\2017\Community\VC"
  ) else if /i "%~1" == "x86" (
    set BUILD_PLATFORM=x86
  ) else if /i "%~1" == "x64" (
    set BUILD_PLATFORM=x64
  ) else if /i "%~1" == "debug" (
    set BUILD_CONFIG=debug
  ) else if /i "%~1" == "release" (
    set BUILD_CONFIG=release
  ) else if /i "%~1" == "-?" (
    goto syntax
  ) else if /i "%~1" == "-h" (
    goto syntax
  ) else if /i "%~1" == "-help" (
    goto syntax
  ) else (
    if not defined START_DIR (
      set START_DIR=%~1
    ) else (
      goto unknown
    )
  )

  shift & goto parseArgs

:prerequisites
  rem Compiler and platform are required parameters.
  if not defined VC_VER goto syntax
  if not defined BUILD_PLATFORM goto syntax

  rem Default the start directory if one isn't specified
  if not defined START_DIR set START_DIR=..\..\wolfssl

  rem Calculate the program files directory
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

  rem Check the start directory exists
  if not exist "%START_DIR%" goto nowolfssl

:configure
  if "%BUILD_PLATFORM%" == "" set BUILD_PLATFORM=%OS_PLATFORM%

  if "%BUILD_PLATFORM%" == "x86" (
    set VCVARS_PLATFORM=x86
  ) else if "%BUILD_PLATFORM%" == "x64" (
    if "%VC_VER%" == "10.0" set VCVARS_PLATFORM=%BUILD_PLATFORM%
    if "%VC_VER%" == "11.0" set VCVARS_PLATFORM=amd64
    if "%VC_VER%" == "12.0" set VCVARS_PLATFORM=amd64
    if "%VC_VER%" == "14.0" set VCVARS_PLATFORM=amd64
    if "%VC_VER%" == "15.0" set VCVARS_PLATFORM=amd64
  )

:start
  echo.
  set SAVED_PATH=%CD%

  if "%VC_VER%" == "15.0" (
    call "%PF%\%VC_PATH%\Auxiliary\Build\vcvarsall" %VCVARS_PLATFORM%
  ) else (
    call "%PF%\%VC_PATH%\vcvarsall" %VCVARS_PLATFORM%
  )

  echo.
  cd %SAVED_PATH%
  cd %START_DIR%
  goto %BUILD_PLATFORM%

:x64
  rem Calculate our output directory
  set OUTDIR=build\Win64\%VC_DESC%
  if not exist %OUTDIR% md %OUTDIR%

  if "%BUILD_CONFIG%" == "release" goto x64release

:x64debug
  rem Perform 64-bit Debug Build

  call :build Debug x64
  if errorlevel 1 goto error

  call :build "DLL Debug" x64
  if errorlevel 1 goto error

  if "%BUILD_CONFIG%" == "debug" goto success

:x64release
  rem Perform 64-bit Release Build

  call :build Release x64
  if errorlevel 1 goto error

  call :build "DLL Release" x64
  if errorlevel 1 goto error

  goto success

:x86
  rem Calculate our output directory
  set OUTDIR=build\Win32\%VC_DESC%
  if not exist %OUTDIR% md %OUTDIR%

  if "%BUILD_CONFIG%" == "release" goto x86release

:x86debug
  rem Perform 32-bit Debug Build

  call :build Debug Win32
  if errorlevel 1 goto error

  call :build "DLL Debug" Win32
  if errorlevel 1 goto error

  if "%BUILD_CONFIG%" == "debug" goto success

:x86release
  rem Perform 32-bit Release Build

  call :build Release Win32
  if errorlevel 1 goto error

  call :build "DLL Release" Win32
  if errorlevel 1 goto error

  goto success

:build
  rem This function builds wolfSSL.
  rem Usage: CALL :build <configuration> <platform>
  rem The current directory must be the wolfSSL directory.
  rem VS Configuration: Debug, Release, DLL Debug or DLL Release.
  rem VS Platform: Win32 or x64.
  rem Returns: 1 on fail, 0 on success.
  rem An informational message should be shown before any return.
  setlocal
  set MSBUILD_CONFIG=%~1
  set MSBUILD_PLATFORM=%~2

  if not exist wolfssl64.sln (
    echo.
    echo Error: build: wolfssl64.sln not found in "%CD%"
    exit /b 1
  )

  rem OUTDIR isn't a full path, only relative. MSBUILD_OUTDIR must be full and
  rem not have trailing backslashes, which are handled later.
  if "%MSBUILD_CONFIG%" == "Debug" (
    set "MSBUILD_OUTDIR=%CD%\%OUTDIR%\LIB Debug"
  ) else if "%MSBUILD_CONFIG%" == "Release" (
    set "MSBUILD_OUTDIR=%CD%\%OUTDIR%\LIB Release"
  ) else if "%MSBUILD_CONFIG%" == "DLL Debug" (
    set "MSBUILD_OUTDIR=%CD%\%OUTDIR%\DLL Debug"
  ) else if "%MSBUILD_CONFIG%" == "DLL Release" (
    set "MSBUILD_OUTDIR=%CD%\%OUTDIR%\DLL Release"
  ) else (
    echo.
    echo Error: build: Configuration not recognized.
    exit /b 1
  )

  if not "%MSBUILD_PLATFORM%" == "Win32" if not "%MSBUILD_PLATFORM%" == "x64" (
    echo.
    echo Error: build: Platform not recognized.
    exit /b 1
  )

  copy /v /y "%~dp0\wolfssl_options.h" .\cyassl\options.h
  if %ERRORLEVEL% neq 0 (
    echo.
    echo Error: build: Couldn't replace .\cyassl\options.h
    exit /b 1
  )

  copy /v /y "%~dp0\wolfssl_options.h" .\wolfssl\options.h
  if %ERRORLEVEL% neq 0 (
    echo.
    echo Error: build: Couldn't replace .\wolfssl\options.h
    exit /b 1
  )

  rem Extra trailing \ in Dirs because otherwise it thinks a quote is escaped
  msbuild wolfssl64.sln ^
    -p:CustomAfterMicrosoftCommonTargets="%~dp0\wolfssl_override.props" ^
    -p:Configuration="%MSBUILD_CONFIG%" ^
    -p:Platform="%MSBUILD_PLATFORM%" ^
    -p:PlatformToolset="%VC_TOOLSET%" ^
    -p:OutDir="%MSBUILD_OUTDIR%\\" ^
    -p:IntDir="%MSBUILD_OUTDIR%\obj\\"

  if %ERRORLEVEL% neq 0 (
    echo.
    echo Error: Failed building wolfSSL %MSBUILD_CONFIG%^|%MSBUILD_PLATFORM%.
    exit /b 1
  )

  rem For tests to run properly the wolfSSL directory must remain the current.
  set "PATH=%MSBUILD_OUTDIR%;%PATH%"
  "%MSBUILD_OUTDIR%\testsuite.exe"

  if %ERRORLEVEL% neq 0 (
    echo.
    echo Error: Failed testing wolfSSL %MSBUILD_CONFIG%^|%MSBUILD_PLATFORM%.
    exit /b 1
  )

  echo.
  echo Success: Built and tested wolfSSL %MSBUILD_CONFIG%^|%MSBUILD_PLATFORM%.
  echo.
  echo.
  rem This is necessary to export our local variables back to the caller.
  endlocal & set SUCCESSFUL_BUILDS="%MSBUILD_CONFIG%|%MSBUILD_PLATFORM%" ^
    %SUCCESSFUL_BUILDS%
  exit /b 0

:syntax
  rem Display the help
  echo.
  echo Usage: build-wolfssl ^<compiler^> ^<platform^> [configuration] [directory]
  echo.
  echo Compiler:
  echo.
  echo vc10      - Use Visual Studio 2010
  echo vc11      - Use Visual Studio 2012
  echo vc12      - Use Visual Studio 2013
  echo vc14      - Use Visual Studio 2015
  echo vc15      - Use Visual Studio 2017
  echo.
  echo Platform:
  echo.
  echo x86       - Perform a 32-bit build
  echo x64       - Perform a 64-bit build
  echo.
  echo Configuration:
  echo.
  echo debug     - Perform a debug build
  echo release   - Perform a release build
  echo.
  echo Other:
  echo.
  echo directory - Specifies the wolfSSL source directory
  goto error

:unknown
  echo.
  echo Error: Unknown argument '%1'
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
  cd %SAVED_PATH%
  endlocal
  exit /B 0
