@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2012 - 2019, Steve Holme, <steve_holme@hotmail.com>.
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
  setlocal ENABLEDELAYEDEXPANSION
  set VC_VER=
  set BUILD_PLATFORM=
  set BUILD_CONFIG=

  rem Ensure we have the required arguments
  if /i "%~1" == "" goto syntax

  rem Calculate the program files directory
  if defined PROGRAMFILES (
    set "PF=%PROGRAMFILES%"
    set OS_PLATFORM=x86
  )
  if defined PROGRAMFILES(x86) (
    set "PF=%PROGRAMFILES(x86)%"
    set OS_PLATFORM=x64
  )

:parseArgs
  if not "%~1" == "" (
    if /i "%~1" == "vc6" (
      set VC_VER=6.0
      set VC_DESC=VC6
      set "VC_PATH=Microsoft Visual Studio\VC98"
    ) else if /i "%~1" == "vc7" (
      set VC_VER=7.0
      set VC_DESC=VC7
      set "VC_PATH=Microsoft Visual Studio .NET\Vc7"
    ) else if /i "%~1" == "vc7.1" (
      set VC_VER=7.1
      set VC_DESC=VC7.1
      set "VC_PATH=Microsoft Visual Studio .NET 2003\Vc7"
    ) else if /i "%~1" == "vc8" (
      set VC_VER=8.0
      set VC_DESC=VC8
      set "VC_PATH=Microsoft Visual Studio 8\VC"
    ) else if /i "%~1" == "vc9" (
      set VC_VER=9.0
      set VC_DESC=VC9
      set "VC_PATH=Microsoft Visual Studio 9.0\VC"
    ) else if /i "%~1" == "vc10" (
      set VC_VER=10.0
      set VC_DESC=VC10
      set "VC_PATH=Microsoft Visual Studio 10.0\VC"
    ) else if /i "%~1" == "vc11" (
      set VC_VER=11.0
      set VC_DESC=VC11
      set "VC_PATH=Microsoft Visual Studio 11.0\VC"
    ) else if /i "%~1" == "vc12" (
      set VC_VER=12.0
      set VC_DESC=VC12
      set "VC_PATH=Microsoft Visual Studio 12.0\VC"
    ) else if /i "%~1" == "vc14" (
      set VC_VER=14.0
      set VC_DESC=VC14
      set "VC_PATH=Microsoft Visual Studio 14.0\VC"
    ) else if /i "%~1" == "vc14.1" (
      set VC_VER=14.1
      set VC_DESC=VC14.1

      rem Determine the VC14.1 path based on the installed edition in descending
      rem order (Enterprise, then Professional and finally Community)
      if exist "%PF%\Microsoft Visual Studio\2017\Enterprise\VC" (
        set "VC_PATH=Microsoft Visual Studio\2017\Enterprise\VC"
      ) else if exist "%PF%\Microsoft Visual Studio\2017\Professional\VC" (
        set "VC_PATH=Microsoft Visual Studio\2017\Professional\VC"
      ) else (
        set "VC_PATH=Microsoft Visual Studio\2017\Community\VC"
      )
    ) else if /i "%~1%" == "x86" (
      set BUILD_PLATFORM=x86
    ) else if /i "%~1%" == "x64" (
      set BUILD_PLATFORM=x64
    ) else if /i "%~1%" == "debug" (
      set BUILD_CONFIG=debug
    ) else if /i "%~1%" == "release" (
      set BUILD_CONFIG=release
    ) else if /i "%~1" == "-?" (
      goto syntax
    ) else if /i "%~1" == "-h" (
      goto syntax
    ) else if /i "%~1" == "-help" (
      goto syntax
    ) else if /i "%~1" == "-VSpath" (
      if "%~2" == "" (
        echo.
        echo Error. Please provide VS Path.
        goto error
      ) else (
        set "ABS_VC_PATH=%~2\VC"
        shift
      )
    ) else if /i "%~1" == "-perlpath" (
      if "%~2" == "" (
        echo.
        echo Error. Please provide Perl root Path.
        goto error
      ) else (
        set "PERL_PATH=%~2"
        shift
      )
    ) else (
      if not defined START_DIR (
        set START_DIR=%~1%
      ) else (
        goto unknown
      )
    )

    shift & goto parseArgs
  )

:prerequisites
  rem Compiler is a required parameter
  if not defined VC_VER goto syntax

  rem Default the start directory if one isn't specified
  if not defined START_DIR set START_DIR=..\..\openssl

  if not defined ABS_VC_PATH (
    rem Check we have a program files directory
    if not defined PF goto nopf
    set "ABS_VC_PATH=%PF%\%VC_PATH%"
  )

  rem Check we have Visual Studio installed
  if not exist "%ABS_VC_PATH%" goto novc

  if not defined PERL_PATH (
    rem Check we have Perl in our path
    perl --version <NUL 1>NUL 2>&1
    if errorlevel 1 (
      rem It isn't so check we have it installed and set the path if it is
      if exist "%SystemDrive%\Perl" (
        set "PATH=%SystemDrive%\Perl\bin;%PATH%"
      ) else (
        if exist "%SystemDrive%\Perl64" (
          set "PATH=%SystemDrive%\Perl64\bin;%PATH%"
        ) else (
          goto noperl
        )
      )
    )
  ) else (
    set "PATH=%PERL_PATH%\Perl\bin;%PATH%"
  )

  rem Check the start directory exists
  if not exist "%START_DIR%" goto noopenssl

:setup
  if "%BUILD_PLATFORM%" == "" (
    if "%VC_VER%" == "6.0" (
      set BUILD_PLATFORM=x86
    ) else if "%VC_VER%" == "7.0" (
      set BUILD_PLATFORM=x86
    ) else if "%VC_VER%" == "7.1" (
      set BUILD_PLATFORM=x86
    ) else (
      set BUILD_PLATFORM=%OS_PLATFORM%
    )
  )

  if "%BUILD_PLATFORM%" == "x86" (
    set VCVARS_PLATFORM=x86
  ) else if "%BUILD_PLATFORM%" == "x64" (
    if "%VC_VER%" == "6.0" goto nox64
    if "%VC_VER%" == "7.0" goto nox64
    if "%VC_VER%" == "7.1" goto nox64
    if "%VC_VER%" == "8.0" set VCVARS_PLATFORM=x86_amd64
    if "%VC_VER%" == "9.0" set VCVARS_PLATFORM=%BUILD_PLATFORM%
    if "%VC_VER%" == "10.0" set VCVARS_PLATFORM=%BUILD_PLATFORM%
    if "%VC_VER%" == "11.0" set VCVARS_PLATFORM=amd64
    if "%VC_VER%" == "12.0" set VCVARS_PLATFORM=amd64
    if "%VC_VER%" == "14.0" set VCVARS_PLATFORM=amd64
    if "%VC_VER%" == "14.1" set VCVARS_PLATFORM=amd64
  )

  if exist "%START_DIR%\ms\do_ms.bat" (
    set LEGACY_BUILD=TRUE
  ) else (
    set LEGACY_BUILD=FALSE
  )

:start
  echo.
  set SAVED_PATH=%CD%

  if "%VC_VER%" == "6.0" (
    call "%ABS_VC_PATH%\bin\vcvars32"
  ) else if "%VC_VER%" == "7.0" (
    call "%ABS_VC_PATH%\bin\vcvars32"
  ) else if "%VC_VER%" == "7.1" (
    call "%ABS_VC_PATH%\bin\vcvars32"
  ) else if "%VC_VER%" == "14.1" (
    call "%ABS_VC_PATH%\Auxiliary\Build\vcvarsall" %VCVARS_PLATFORM%
  ) else (
    call "%ABS_VC_PATH%\vcvarsall" %VCVARS_PLATFORM%
  )

  echo.
  cd /d %SAVED_PATH%
  if defined START_DIR cd /d %START_DIR%
  goto %BUILD_PLATFORM%

:x64
  rem Calculate our output directory
  set OUTDIR=build\Win64\%VC_DESC%
  if not exist %OUTDIR% md %OUTDIR%

  if not "%BUILD_CONFIG%" == "release" (
    rem Configuring 64-bit Static Library Debug Build
    call :configure x64 debug static %LEGACY_BUILD%

    rem Perform the build
    call :build x64 static %LEGACY_BUILD%

    rem Perform the install
    call :install debug static %LEGACY_BUILD%

    rem Configuring 64-bit Shared Library Debug Build
    call :configure x64 debug shared %LEGACY_BUILD%

    rem Perform the build
    call :build x64 shared %LEGACY_BUILD%

    rem Perform the install
    call :install debug shared %LEGACY_BUILD%
  )

  if not "%BUILD_CONFIG%" == "debug" (
    rem Configuring 64-bit Static Library Release Build
    call :configure x64 release static %LEGACY_BUILD%

    rem Perform the build
    call :build x64 static %LEGACY_BUILD%

    rem Perform the install
    call :install release static %LEGACY_BUILD%

    rem Configuring 64-bit Shared Library Release Build
    call :configure x64 release shared %LEGACY_BUILD%

    rem Perform the build
    call :build x64 shared %LEGACY_BUILD%

    rem Perform the install
    call :install release shared %LEGACY_BUILD%
  )

  goto success

:x86
  rem Calculate our output directory
  set OUTDIR=build\Win32\%VC_DESC%
  if not exist %OUTDIR% md %OUTDIR%

  if not "%BUILD_CONFIG%" == "release" (
    rem Configuring 32-bit Static Library Debug Build
    call :configure x86 debug static %LEGACY_BUILD%

    rem Perform the build
    call :build x86 static %LEGACY_BUILD%

    rem Perform the install
    call :install debug static %LEGACY_BUILD%

    rem Configuring 32-bit Shared Library Debug Build
    call :configure x86 debug shared %LEGACY_BUILD%

    rem Perform the build
    call :build x86 shared %LEGACY_BUILD%

    rem Perform the install
    call :install debug shared %LEGACY_BUILD%
  )

  if not "%BUILD_CONFIG%" == "debug" (
    rem Configuring 32-bit Static Library Release Build
    call :configure x86 release static %LEGACY_BUILD%

    rem Perform the build
    call :build x86 static %LEGACY_BUILD%

    rem Perform the install
    call :install release static %LEGACY_BUILD%

    rem Configuring 32-bit Shared Library Release Build
    call :configure x86 release shared %LEGACY_BUILD%

    rem Perform the build
    call :build x86 shared %LEGACY_BUILD%

    rem Perform the install
    call :install release shared %LEGACY_BUILD%
  )

  goto success

rem Function to configure the build.
rem
rem %1 - Platform (x86 or x64)
rem %2 - Configuration (release or debug)
rem %3 - Build Type (static or shared)
rem %4 - Build type (TRUE for legacy aka pre v1.1.0; otherwise FALSE)
rem
:configure
  setlocal

  if "%1" == "" exit /B 1
  if "%2" == "" exit /B 1
  if "%3" == "" exit /B 1
  if "%4" == "" exit /B 1

  if "%4" == "TRUE" (
    rem Calculate the build directory
    set build_dir=%cd%

    rem Calculate the configure options
    if "%1" == "x86" (
      if "%2" == "debug" (
        set options=debug-VC-WIN32
      ) else if "%2" == "release" (
        set options=VC-WIN32
      ) else (
        exit /B 1
      )

      set options=!options! no-asm
    ) else if "%1" == "x64" (
      if "%2" == "debug" (
        set options=debug-VC-WIN64A
      ) else if "%2" == "release" (
        set options=VC-WIN64A
      ) else (
        exit /B 1
      )
    ) else (
      exit /B 1
    )
  ) else if "%4" == "FALSE" (
    rem Has configure already been ran?
    if exist makefile (
      rem Clean up the previous build
      nmake clean

      rem Remove the old makefile
      del makefile 1>nul
    )

    rem Calculate the build directory
    set build_dir=%cd%\build\tmp

    rem Calculate the configure options
    if "%1" == "x86" (
      set options=VC-WIN32
    ) else if "%1" == "x64" (
      set options=VC-WIN64A
    ) else (
      exit /B 1
    )

    if "%2" == "debug" (
      set options=!options! --debug
    ) else if "%2" == "release" (
      set options=!options! --release
    ) else (
      exit /B 1
    )

    if "%3" == "static" (
      set options=!options! no-shared
    ) else if not "%3" == "shared" (
      exit /B 1
    )

    set options=!options! no-asm
  ) else (
    exit /B 1
  )

  set options=%options% --prefix=%build_dir%

  rem Run the configure
  perl Configure %options%

  exit /B %ERRORLEVEL

rem Main build function.
rem
rem %1 - Platform (x86 or x64)
rem %2 - Build Type (static or shared)
rem %3 - Build type (TRUE for legacy aka pre v1.1.0; otherwise FALSE)
rem
:build
  setlocal

  if "%1" == "" exit /B 1
  if "%2" == "" exit /B 1
  if "%3" == "" exit /B 1

  if "%3" == "TRUE" (
    if "%1" == "x86" (
      call ms\do_ms.bat
    ) else if "%1" == "x64" (
      call ms\do_win64a.bat
    ) else (
      exit /B 1
    )

    if "%2" == "static" (
      nmake -f ms\nt.mak
    ) else if "%2" == "shared" (
      nmake -f ms\ntdll.mak
    ) else (
      exit /B 1
    )
  ) else if "%2" == "FALSE" (
    nmake
  ) else (
    exit /B 1
  )

  exit /B 0

rem Main installation function.
rem
rem %1 - Configuration (release or debug)
rem %2 - Build Type (static or shared)
rem %3 - Build type (TRUE for legacy aka pre v1.1.0; otherwise FALSE)
rem
:install
  setlocal

  if "%1" == "" exit /B 1
  if "%2" == "" exit /B 1
  if "%3" == "" exit /B 1

  rem Copy the generated files to our directory structure
  if "%3" == "TRUE" (
    if "%1" == "debug" (
      if "%2" == "static" (
        rem Move the output directories
        if exist "%OUTDIR%\LIB Debug" (
          copy /y out32.dbg\* "%OUTDIR%\LIB Debug" 1>nul
          rd out32.dbg /s /q
        ) else (
          move out32.dbg "%OUTDIR%\LIB Debug" 1>nul
        )

        rem Move the PDB files
        move tmp32.dbg\lib.pdb "%OUTDIR%\LIB Debug" 1>nul

        rem Remove the intermediate directories
        rd tmp32.dbg /s /q
      ) else if "%2" == "shared" (
        if exist "%OUTDIR%\DLL Debug" (
          copy /y out32dll.dbg\* "%OUTDIR%\DLL Debug" 1>nul
          rd out32dll.dbg /s /q
        ) else (
          move out32dll.dbg "%OUTDIR%\DLL Debug" 1>nul
        )

        rem Move the PDB files
        move tmp32dll.dbg\lib.pdb "%OUTDIR%\DLL Debug" 1>nul

        rem Remove the intermediate directories
        rd tmp32dll.dbg /s /q
      ) else (
        exit /B 1
      )
    ) else if "%1" == "release" (
      if "%2" == "static" (
        rem Move the output directories
        if exist "%OUTDIR%\LIB Release" (
          copy /y out32\* "%OUTDIR%\LIB Release" 1>nul
          rd out32 /s /q
        ) else (
          move out32 "%OUTDIR%\LIB Release" 1>nul
        )

        rem Move the PDB files
        move tmp32\lib.pdb "%OUTDIR%\LIB Release" 1>nul

        rem Remove the intermediate directories
        rd tmp32 /s /q
      ) else if "%2" == "shared" (
        if exist "%OUTDIR%\DLL Release" (
          copy /y out32dll\* "%OUTDIR%\DLL Release" 1>nul
          rd out32dll /s /q
        ) else (
          move out32dll "%OUTDIR%\DLL Release" 1>nul
        )

        rem Move the PDB files
        move tmp32dll\lib.pdb "%OUTDIR%\DLL Release" 1>nul

        rem Remove the intermediate directories
        rd tmp32dll /s /q
      ) else (
        exit /B 1
      )
    )
  ) else if "%3" == "FALSE" (
    rem Calculate the build directory
    set build_dir=%cd%\build\tmp

    rem Perform the installation
    nmake install_sw

    rem Move the output directories
    if "%1" == "debug" (
      if "%2" == "static" (
        if not exist "%OUTDIR%\LIB Debug" (
          mkdir "%OUTDIR%\LIB Debug" 1>nul
        )

        move !build_dir!\lib\*.lib "%OUTDIR%\LIB Debug" 1>nul
        move !build_dir!\bin\*.exe "%OUTDIR%\LIB Debug" 1>nul
      ) else if "%2" == "shared" (
        if not exist "%OUTDIR%\DLL Debug" (
          mkdir "%OUTDIR%\DLL Debug" 1>nul
        )

        move !build_dir!\lib\*.lib "%OUTDIR%\DLL Debug" 1>nul
        move !build_dir!\bin\*.dll "%OUTDIR%\DLL Debug" 1>nul
        move !build_dir!\bin\*.exe "%OUTDIR%\DLL Debug" 1>nul
        move !build_dir!\bin\*.pdb "%OUTDIR%\DLL Debug" 1>nul
      ) else (
        exit /B 1
      )
    ) else if "%1" == "release" (
      if "%2" == "static" (
        if not exist "%OUTDIR%\LIB Release" (
          mkdir "%OUTDIR%\LIB Release" 1>nul
        )

        move !build_dir!\lib\*.lib "%OUTDIR%\LIB Release" 1>nul
        move !build_dir!\bin\*.exe "%OUTDIR%\LIB Release" 1>nul
      ) else if "%2" == "shared" (
        if not exist "%OUTDIR%\DLL Release" (
          mkdir "%OUTDIR%\DLL Release" 1>nul
        )
  
        move !build_dir!\lib\*.lib "%OUTDIR%\DLL Release" 1>nul
        move !build_dir!\bin\*.dll "%OUTDIR%\DLL Release" 1>nul
        move !build_dir!\bin\*.exe "%OUTDIR%\DLL Release" 1>nul
      ) else (
        exit /B 1
      )
    ) else (
      exit /B 1
    )

    rem Remove the output directories
    rd !build_dir! /s /q
  ) else (
    exit /B 1
  )

  exit /B 0

:syntax
  rem Display the help
  echo.
  echo Usage: build-openssl ^<compiler^> [platform] [configuration] [directory] [-VSpath] ["VSpath"] [-perlpath] ["perlpath"]
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
  echo vc14      - Use Visual Studio 2015
  echo vc14.1    - Use Visual Studio 2017
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
  echo directory - Specifies the OpenSSL source directory
  echo.
  echo -VSpath - Specify the custom VS path if Visual Studio is installed at other location
  echo           then "C:/<ProgramFiles>/Microsoft Visual Studio[version]
  echo           For e.g. -VSpath "C:\apps\MVS14"
  echo.
  echo -perlpath - Specify the custom perl root path if perl is not located at "C:\Perl" and it is a
  echo             portable copy of perl and not installed on the win system
  echo             For e.g. -perlpath "D:\strawberry-perl-5.24.3.1-64bit-portable"
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
  echo Error: Please check whether Visual compiler is installed at the path "%ABS_VC_PATH%"
  echo Error: Please provide proper VS Path by using -VSpath
  goto error

:noperl
  echo.
  echo Error: Perl is not installed
  echo Error: Please check whether Perl is installed or it is at location "C:\Perl"
  echo Error: If Perl is portable please provide perl root path by using -perlpath
  goto error

:nox64
  echo.
  echo Error: %VC_DESC% does not support 64-bit builds
  goto error

:noopenssl
  echo.
  echo Error: Cannot locate OpenSSL source directory
  goto error

:error
  if "%OS%" == "Windows_NT" endlocal
  exit /B 1

:success
  cd /d %SAVED_PATH%
  endlocal
  exit /B 0
