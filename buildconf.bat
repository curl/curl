@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

rem NOTES
rem
rem This batch file must be used to set up a git tree to build on systems where
rem there is no autotools support (i.e. DOS and Windows).
rem

:begin
  rem Set our variables
  if "%OS%" == "Windows_NT" setlocal
  set MODE=GENERATE

  rem Switch to this batch file's directory
  cd /d "%~0\.." 1>NUL 2>&1

  rem Check we are running from a curl git repository
  if not exist GIT-INFO goto norepo

  rem Detect programs. HAVE_<PROGNAME>
  rem When not found the variable is set undefined. The undefined pattern
  rem allows for statements like "if not defined HAVE_PERL (command)"
  groff --version <NUL 1>NUL 2>&1
  if errorlevel 1 (set HAVE_GROFF=) else (set HAVE_GROFF=Y)
  nroff --version <NUL 1>NUL 2>&1
  if errorlevel 1 (set HAVE_NROFF=) else (set HAVE_NROFF=Y)
  perl --version <NUL 1>NUL 2>&1
  if errorlevel 1 (set HAVE_PERL=) else (set HAVE_PERL=Y)
  gzip --version <NUL 1>NUL 2>&1
  if errorlevel 1 (set HAVE_GZIP=) else (set HAVE_GZIP=Y)

:parseArgs
  if "%~1" == "" goto start

  if /i "%~1" == "-clean" (
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
  if "%MODE%" == "GENERATE" (
    echo.
    echo Generating prerequisite files

    call :generate
    if errorlevel 3 goto nogenhugehelp
    if errorlevel 2 goto nogenmakefile
    if errorlevel 1 goto warning

  ) else (
    echo.
    echo Removing prerequisite files

    call :clean
    if errorlevel 2 goto nocleanhugehelp
    if errorlevel 1 goto nocleanmakefile
  )

  goto success

rem Main generate function.
rem
rem Returns:
rem
rem 0 - success
rem 1 - success with simplified tool_hugehelp.c
rem 2 - failed to generate Makefile
rem 3 - failed to generate tool_hugehelp.c
rem
:generate
  if "%OS%" == "Windows_NT" setlocal
  set BASIC_HUGEHELP=0

  rem Create Makefile
  echo * %CD%\Makefile
  if exist Makefile.dist (
    copy /Y Makefile.dist Makefile 1>NUL 2>&1
    if errorlevel 1 (
      if "%OS%" == "Windows_NT" endlocal
      exit /B 2
    )
  )

  rem Create tool_hugehelp.c
  echo * %CD%\src\tool_hugehelp.c
  call :genHugeHelp
  if errorlevel 2 (
    if "%OS%" == "Windows_NT" endlocal
    exit /B 3
  )
  if errorlevel 1 (
    set BASIC_HUGEHELP=1
  )
  cmd /c exit 0

  rem Setup c-ares git tree
  if exist ares\buildconf.bat (
    echo.
    echo Configuring c-ares build environment
    cd ares
    call buildconf.bat
    cd ..
  )

  if "%BASIC_HUGEHELP%" == "1" (
    if "%OS%" == "Windows_NT" endlocal
    exit /B 1
  )

  if "%OS%" == "Windows_NT" endlocal
  exit /B 0

rem Main clean function.
rem
rem Returns:
rem
rem 0 - success
rem 1 - failed to clean Makefile
rem 2 - failed to clean tool_hugehelp.c
rem
:clean
  rem Remove Makefile
  echo * %CD%\Makefile
  if exist Makefile (
    del Makefile 2>NUL
    if exist Makefile (
      exit /B 1
    )
  )

  rem Remove tool_hugehelp.c
  echo * %CD%\src\tool_hugehelp.c
  if exist src\tool_hugehelp.c (
    del src\tool_hugehelp.c 2>NUL
    if exist src\tool_hugehelp.c (
      exit /B 2
    )
  )

  exit /B

rem Function to generate src\tool_hugehelp.c
rem
rem Returns:
rem
rem 0 - full tool_hugehelp.c generated
rem 1 - simplified tool_hugehelp.c
rem 2 - failure
rem
:genHugeHelp
  if "%OS%" == "Windows_NT" setlocal
  set LC_ALL=C
  set ROFFCMD=
  set BASIC=1

  if defined HAVE_PERL (
    if defined HAVE_GROFF (
      set ROFFCMD=groff -mtty-char -Tascii -P-c -man
    ) else if defined HAVE_NROFF (
      set ROFFCMD=nroff -c -Tascii -man
    )
  )

  if defined ROFFCMD (
    echo #include "tool_setup.h"> src\tool_hugehelp.c
    echo #include "tool_hugehelp.h">> src\tool_hugehelp.c

    if defined HAVE_GZIP (
      echo #ifndef HAVE_LIBZ>> src\tool_hugehelp.c
    )

    %ROFFCMD% docs\curl.1 2>NUL | perl src\mkhelp.pl docs\MANUAL >> src\tool_hugehelp.c
    if defined HAVE_GZIP (
      echo #else>> src\tool_hugehelp.c
      %ROFFCMD% docs\curl.1 2>NUL | perl src\mkhelp.pl -c docs\MANUAL >> src\tool_hugehelp.c
      echo #endif /^* HAVE_LIBZ ^*/>> src\tool_hugehelp.c
    )

    set BASIC=0
  ) else (
    if exist src\tool_hugehelp.c.cvs (
      copy /Y src\tool_hugehelp.c.cvs src\tool_hugehelp.c 1>NUL 2>&1
    ) else (
      echo #include "tool_setup.h"> src\tool_hugehelp.c
      echo #include "tool_hugehelp.h">> src\tool_hugehelp.c
      echo.>> src\tool_hugehelp.c
      echo void hugehelp(void^)>> src\tool_hugehelp.c
      echo {>> src\tool_hugehelp.c
      echo #ifdef USE_MANUAL>> src\tool_hugehelp.c
      echo   fputs("Built-in manual not included\n", stdout^);>> src\tool_hugehelp.c
      echo #endif>> src\tool_hugehelp.c
      echo }>> src\tool_hugehelp.c
    )
  )

  findstr "/C:void hugehelp(void)" src\tool_hugehelp.c 1>NUL 2>&1
  if errorlevel 1 (
    if "%OS%" == "Windows_NT" endlocal
    exit /B 2
  )

  if "%BASIC%" == "1" (
    if "%OS%" == "Windows_NT" endlocal
    exit /B 1
  )

  if "%OS%" == "Windows_NT" endlocal
  exit /B 0

rem Function to clean-up local variables under DOS, Windows 3.x and
rem Windows 9x as setlocal isn't available until Windows NT
rem
:dosCleanup
  set MODE=
  set HAVE_GROFF=
  set HAVE_NROFF=
  set HAVE_PERL=
  set HAVE_GZIP=
  set BASIC_HUGEHELP=
  set LC_ALL
  set ROFFCMD=
  set BASIC=

  exit /B

:syntax
  rem Display the help
  echo.
  echo Usage: buildconf [-clean]
  echo.
  echo -clean    - Removes the files
  goto error

:unknown
  echo.
  echo Error: Unknown argument '%1'
  goto error

:norepo
  echo.
  echo Error: This batch file should only be used with a curl git repository
  goto error

:nogenmakefile
  echo.
  echo Error: Unable to generate Makefile
  goto error

:nogenhugehelp
  echo.
  echo Error: Unable to generate src\tool_hugehelp.c
  goto error

:nocleanmakefile
  echo.
  echo Error: Unable to clean Makefile
  goto error

:nocleanhugehelp
  echo.
  echo Error: Unable to clean src\tool_hugehelp.c
  goto error

:warning
  echo.
  echo Warning: The curl manual could not be integrated in the source. This means when
  echo you build curl the manual will not be available (curl --man^). Integration of
  echo the manual is not required and a summary of the options will still be available
  echo (curl --help^). To integrate the manual your PATH is required to have
  echo groff/nroff, perl and optionally gzip for compression.
  goto success

:error
  if "%OS%" == "Windows_NT" (
    endlocal
  ) else (
    call :dosCleanup
  )
  exit /B 1

:success
  if "%OS%" == "Windows_NT" (
    endlocal
  ) else (
    call :dosCleanup
  )
  exit /B 0
