@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2012 - 2016, Steve Holme, <steve_holme@hotmail.com>.
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
  set "DEFAULT_START_DIR=%~dp0..\..\openssl"
  set START_DIR=
  set SUCCESSFUL_BUILDS=
  set VC_DESC=
  set VC_PATH=
  set VC_VER=

:parseArgs
  if /i "%~1" == "" goto syntax
  if /i "%~1" == "-?" goto syntax
  if /i "%~1" == "/?" goto syntax
  if /i "%~1" == "-h" goto syntax
  if /i "%~1" == "-help" goto syntax
  if /i "%~1" == "--help" goto syntax

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
  if not exist "%START_DIR%" goto noopenssl

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
  if "%VC_VER%" == "6.0" set X64_PLATFORM_NAME=
  if "%VC_VER%" == "7.0" set X64_PLATFORM_NAME=
  if "%VC_VER%" == "7.1" set X64_PLATFORM_NAME=
  if "%VC_VER%" == "8.0" set X64_PLATFORM_NAME=x86_amd64
  if "%VC_VER%" == "9.0" set X64_PLATFORM_NAME=x64
  if "%VC_VER%" == "10.0" set X64_PLATFORM_NAME=x64
  if "%VC_VER%" == "11.0" set X64_PLATFORM_NAME=amd64
  if "%VC_VER%" == "12.0" set X64_PLATFORM_NAME=amd64
  if "%VC_VER%" == "14.0" set X64_PLATFORM_NAME=amd64

  if defined X64_PLATFORM_NAME (
    set X86_VC_INIT_CMDLINE=call "%PF%\%VC_PATH%\vcvarsall" %X86_PLATFORM_NAME%
    set X64_VC_INIT_CMDLINE=call "%PF%\%VC_PATH%\vcvarsall" %X64_PLATFORM_NAME%
  ) else (
    rem Old VC versions without x64 support don't have vcvarsall
    set X86_VC_INIT_CMDLINE=call "%PF%\%VC_PATH%\bin\vcvars32"
    set X64_VC_INIT_CMDLINE=
  )

  rem Check we have Perl in our path
  set ADD_PERL_PATH=
  perl -e "" 2>nul
  if %ERRORLEVEL% neq 0 (
    for %%a in ("\Perl\bin" "\Perl64\bin" "\Strawberry\perl\bin") do (
      if not defined ADD_PERL_PATH (
        "%SystemDrive%%%~a\perl" -e "" 2>nul
        if errorlevel 0 if not errorlevel 1 (
          set "ADD_PERL_PATH=%SystemDrive%%%~a"
        )
      )
    )
  )
  if defined ADD_PERL_PATH set "PATH=%ADD_PERL_PATH%;%PATH%"
  perl -e "" 2>nul
  if %ERRORLEVEL% neq 0 goto noperl

:start
  set "SAVED_PATH=%CD%"
  cd /d "%START_DIR%"
  if %ERRORLEVEL% neq 0 echo Error: cd "%START_DIR%" failed! & goto error

  rem Skip to legacy build for OpenSSL 1.0.2 and earlier
  if exist ms\do_ms.bat goto build_legacy

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

:build_legacy
  rem Legacy build for OpenSSL 1.0.2 and earlier
  rem BUILD_PLATFORM and/or BUILD_CONFIG may be unset

  if "%BUILD_PLATFORM%" == "x86" goto x86

:x64
  setlocal
  if not defined X64_VC_INIT_CMDLINE goto x64done
  %X64_VC_INIT_CMDLINE%
  if %ERRORLEVEL% neq 0 echo Error: VC init failed! & goto error

  rem Calculate our output directory
  set OUTDIR=build\Win64\%VC_DESC%
  if not exist %OUTDIR% md %OUTDIR%

  if "%BUILD_CONFIG%" == "release" goto x64release

:x64debug
  rem Configuring 64-bit Debug Build
  perl Configure debug-VC-WIN64A "--prefix=%CD%"

  rem Perform the build
  call ms\do_win64a              ^
  && nmake -f ms\nt.mak          ^
  && nmake -f ms\nt.mak test     ^
  && nmake -f ms\ntdll.mak       ^
  && nmake -f ms\ntdll.mak test
  if %ERRORLEVEL% neq 0 echo nmake failed to build x64debug! & goto error

  rem Copy the output
  xcopy /E /I /Q /H /R /Y out32.dbg "%OUTDIR%\LIB Debug"                ^
  && xcopy /E /I /Q /H /R /Y tmp32.dbg\lib.pdb "%OUTDIR%\LIB Debug"     ^
  && xcopy /E /I /Q /H /R /Y out32dll.dbg "%OUTDIR%\DLL Debug"          ^
  && xcopy /E /I /Q /H /R /Y tmp32dll.dbg\lib.pdb "%OUTDIR%\DLL Debug"
  if %ERRORLEVEL% neq 0 echo xcopy failed to copy x64debug! & goto error

  rem Remove the intermediate directories
  for /d %%a in ("tmp32*" "out32*") do (rd "%%~a" /s /q)

  set SUCCESSFUL_BUILDS="x64 debug static" %SUCCESSFUL_BUILDS%
  set SUCCESSFUL_BUILDS="x64 debug shared" %SUCCESSFUL_BUILDS%

  if "%BUILD_CONFIG%" == "debug" goto x64done

:x64release
  rem Configuring 64-bit Release Build
  perl Configure VC-WIN64A "--prefix=%CD%"

  rem Perform the build
  call ms\do_win64a              ^
  && nmake -f ms\nt.mak          ^
  && nmake -f ms\nt.mak test     ^
  && nmake -f ms\ntdll.mak       ^
  && nmake -f ms\ntdll.mak test
  if %ERRORLEVEL% neq 0 echo nmake failed to build x64release! & goto error

  rem Copy the output
  xcopy /E /I /Q /H /R /Y out32 "%OUTDIR%\LIB Release"                  ^
  && xcopy /E /I /Q /H /R /Y out32dll "%OUTDIR%\DLL Release"            ^
  && xcopy /E /I /Q /H /R /Y tmp32\lib.pdb "%OUTDIR%\LIB Release"       ^
  && xcopy /E /I /Q /H /R /Y tmp32dll\lib.pdb "%OUTDIR%\DLL Release"
  if %ERRORLEVEL% neq 0 echo xcopy failed to copy x64release! & goto error

  rem Remove the intermediate directories
  for /d %%a in ("tmp32*" "out32*") do (rd "%%~a" /s /q)

  set SUCCESSFUL_BUILDS="x64 release static" %SUCCESSFUL_BUILDS%
  set SUCCESSFUL_BUILDS="x64 release shared" %SUCCESSFUL_BUILDS%

:x64done
  rem Export SUCCESSFUL_BUILDS
  endlocal & set SUCCESSFUL_BUILDS=%SUCCESSFUL_BUILDS%

  if "%BUILD_PLATFORM%" == "x64" goto success

:x86
  setlocal
  %X86_VC_INIT_CMDLINE%
  if %ERRORLEVEL% neq 0 echo Error: VC init failed! & goto error

  rem Calculate our output directory
  set OUTDIR=build\Win32\%VC_DESC%
  if not exist %OUTDIR% md %OUTDIR%

  if "%BUILD_CONFIG%" == "release" goto x86release

:x86debug
  rem Configuring 32-bit Debug Build
  perl Configure debug-VC-WIN32 no-asm "--prefix=%CD%"

  rem Perform the build
  call ms\do_ms                  ^
  && nmake -f ms\nt.mak          ^
  && nmake -f ms\nt.mak test     ^
  && nmake -f ms\ntdll.mak       ^
  && nmake -f ms\ntdll.mak test
  if %ERRORLEVEL% neq 0 echo nmake failed to build x86debug! & goto error

  rem Copy the output
  xcopy /E /I /Q /H /R /Y out32.dbg "%OUTDIR%\LIB Debug"                ^
  && xcopy /E /I /Q /H /R /Y out32dll.dbg "%OUTDIR%\DLL Debug"          ^
  && xcopy /E /I /Q /H /R /Y tmp32.dbg\lib.pdb "%OUTDIR%\LIB Debug"     ^
  && xcopy /E /I /Q /H /R /Y tmp32dll.dbg\lib.pdb "%OUTDIR%\DLL Debug"
  if %ERRORLEVEL% neq 0 echo xcopy failed to copy x86debug! & goto error

  rem Remove the intermediate directories
  for /d %%a in ("tmp32*" "out32*") do (rd "%%~a" /s /q)

  set SUCCESSFUL_BUILDS="x86 debug static" %SUCCESSFUL_BUILDS%
  set SUCCESSFUL_BUILDS="x86 debug shared" %SUCCESSFUL_BUILDS%

  if "%BUILD_CONFIG%" == "debug" goto x86done

:x86release
  rem Configuring 32-bit Release Build
  perl Configure VC-WIN32 no-asm "--prefix=%CD%"

  rem Perform the build
  call ms\do_ms                  ^
  && nmake -f ms\nt.mak          ^
  && nmake -f ms\nt.mak test     ^
  && nmake -f ms\ntdll.mak       ^
  && nmake -f ms\ntdll.mak test
  if %ERRORLEVEL% neq 0 echo nmake failed to build x86release! & goto error

  rem Copy the output
  xcopy /E /I /Q /H /R /Y out32 "%OUTDIR%\LIB Release"                  ^
  && xcopy /E /I /Q /H /R /Y out32dll "%OUTDIR%\DLL Release"            ^
  && xcopy /E /I /Q /H /R /Y tmp32\lib.pdb "%OUTDIR%\LIB Release"       ^
  && xcopy /E /I /Q /H /R /Y tmp32dll\lib.pdb "%OUTDIR%\DLL Release"
  if %ERRORLEVEL% neq 0 echo xcopy failed to copy x86release! & goto error

  rem Remove the intermediate directories
  for /d %%a in ("tmp32*" "out32*") do (rd "%%~a" /s /q)

  set SUCCESSFUL_BUILDS="x86 release static" %SUCCESSFUL_BUILDS%
  set SUCCESSFUL_BUILDS="x86 release shared" %SUCCESSFUL_BUILDS%

:x86done
  rem Export SUCCESSFUL_BUILDS
  endlocal & set SUCCESSFUL_BUILDS=%SUCCESSFUL_BUILDS%

  goto success

:build
  rem This function builds OpenSSL 1.1.x or later.
  rem Usage: CALL :build <x86|x64> <debug|release> <shared|static>
  rem Before calling this function:
  rem - The current directory must be the OpenSSL source directory.
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
  echo Building and running tests for OpenSSL %FRIENDLY_NAME%.
  echo. & echo.

  rem This is the build name passed to OpenSSL's Configure
  if %ARCH% == x86 (set VCTYPE=VC-WIN32) else set VCTYPE=VC-WIN64A
  if %CONFIG% == debug set VCTYPE=debug-%VCTYPE%

  rem OPTS will be passed unquoted since it may contain multiple options that
  rem are expected to already be quoted if necessary.
  set OPTS=
  set OPTS=%OPTS% no-asm
  if %LIBTYPE% == static set OPTS=%OPTS% no-shared

  rem nmake installs to PKG_PATH and then we copy necessary files to DST_PATH
  set "DST_PATH=%SRC_PATH%\%OUTDIR%\%LEAF%"
  set "PKG_PATH=%DST_PATH%\_package"
  set "TMP_PATH=%DST_PATH%\temp"

  rem Build OpenSSL. Perform an out-of-tree style build from TMP_PATH so as not
  rem to mix any artifacts from the different builds.

  if not exist "%TMP_PATH%" mkdir "%TMP_PATH%"
  cd /d "%TMP_PATH%"
  if %ERRORLEVEL% neq 0 echo %ERR% cd "%TMP_PATH%" failed! & exit /b 1

  perl "%SRC_PATH%\Configure" %VCTYPE% %OPTS%
  if %ERRORLEVEL% neq 0 echo %ERR% Configure %VCTYPE% failed! & exit /b 1

  nmake test
  if %ERRORLEVEL% neq 0 echo %ERR% nmake test failed! & exit /b 1

  nmake install "DESTDIR=%PKG_PATH%"
  if %ERRORLEVEL% neq 0 echo %ERR% nmake install failed! & exit /b 1

  rem Get the PROG_PATH that nmake actually installed to.
  rem
  rem nmake installed for packaging to PKG_PATH, meaning it used that as the
  rem root and then appended the default prefix without the drive.
  rem
  rem Example:
  rem C:\Program Files becomes PKG_PATH + \Program Files
  rem C:\openssl_src\build\Win32\VC12\DLL Debug\_package\Program Files\OpenSSL
  rem
  rem From the OpenSSL NOTES.WIN document, default prefix uses these env vars:
  rem
  rem VC-WIN32: ProgramFiles(x86) or if that doesn't exist then ProgramFiles.
  rem VC-WIN64: ProgramW6432 or if that doesn't exist then ProgramFiles.
  rem
  rem Note substring extraction in batch files is buggy in if statement
  rem comparison when the variable does not exist or it's not the last colon in
  rem the statement, so instead assign the substring to S and work from
  rem multiple if statements.
  set S=
  set PROG_PATH=
  if %ARCH% == x86 set "S=%ProgramFiles(x86):~1,1%"
  if %ARCH% == x86 if "%S%" equ ":" set "PROG_PATH=%ProgramFiles(x86):~2%"
  if %ARCH% == x64 set "S=%ProgramW6432:~1,1%"
  if %ARCH% == x64 if "%S%" equ ":" set "PROG_PATH=%ProgramW6432:~2%"
  set S=
  if not defined PROG_PATH set "S=%ProgramFiles:~1,1%"
  if "%S%" equ ":" set "PROG_PATH=%ProgramFiles:~2%"
  if not defined PROG_PATH echo %ERR% Program Files dir not found! & exit /b 1
  set "PROG_PATH=%PKG_PATH%\%PROG_PATH%\OpenSSL"
  if not exist "%PROG_PATH%" (
    echo %ERR% OpenSSL package not found in "%PROG_PATH%" & exit /b 1
  )

  xcopy /E /I /Q /H /R /Y "%PROG_PATH%\bin" "%DST_PATH%" 1>NUL
  if %ERRORLEVEL% neq 0 echo %ERR% xcopy bin dir failed! & exit /b 1

  xcopy /E /I /Q /H /R /Y "%PROG_PATH%\lib" "%DST_PATH%" 1>NUL
  if %ERRORLEVEL% neq 0 echo %ERR% xcopy libs dir failed! & exit /b 1

  xcopy /E /I /Q /H /R /Y "%PROG_PATH%\include" "%DST_PATH%\include" 1>NUL
  if %ERRORLEVEL% neq 0 echo %ERR% xcopy include dir failed! & exit /b 1

  cd /d "%DST_PATH%"
  if %ERRORLEVEL% neq 0 echo %ERR% cd "%DST_PATH%" failed! & exit /b 1

  echo. & echo.
  echo Success: Built and all tests passed for OpenSSL %FRIENDLY_NAME%.
  echo. & echo.

  rem Remove the temporary build files (obj,test,etc)
  rmdir /s /q "%TMP_PATH%" 1>NUL 2>&1

  rem This line is necessary to export SUCCESSFUL_BUILDS back to the caller
  endlocal & set SUCCESSFUL_BUILDS=%FRIENDLY_NAME% %SUCCESSFUL_BUILDS%
  exit /b 0

:syntax
  rem Display the help
  echo.
  echo Usage: build-openssl ^<compiler^> [platform] [configuration] [directory]
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
  echo The OpenSSL source directory.
  echo The default is "%DEFAULT_START_DIR%"
  echo.
  goto error

:unknown
  echo.
  echo Error: Unknown argument, for usage run build-openssl /?
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

:noperl
  echo.
  echo Error: Perl is not installed
  goto error

:nox64
  echo.
  echo Error: %VC_DESC% does not support 64-bit builds
  goto error

:noopenssl
  echo.
  echo Error: Cannot locate OpenSSL source directory, expected "%START_DIR%"
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
