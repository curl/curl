@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
rem This batch file must be used to set up a git tree to build on systems where
rem there is no autotools support (i.e. DOS and Windows).
rem
rem This file is not included or required for curl's release archives or daily 
rem snapshot archives.

:begin
  rem Set our variables
  if "%OS%" == "Windows_NT" setlocal
  set MODE=GENERATE

  rem Switch to this batch file's directory
  cd /d "%~0\.." 1>NUL 2>&1

  rem Check we are running from a curl git repository
  if not exist GIT-INFO goto norepo

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
    if errorlevel 3 goto nogencurlbuild
    if errorlevel 2 goto nogenhugehelp
    if errorlevel 1 goto nogenmakefile
  ) else (
    echo.
    echo Removing prerequisite files

    call :clean
    if errorlevel 3 goto nocleancurlbuild
    if errorlevel 2 goto nocleanhugehelp
    if errorlevel 1 goto nocleanmakefile
  )

  goto success

rem Main generate function.
rem Returns:
rem
rem 0 - success
rem 1 - failure to generate Makefile
rem 2 - failure to generate tool_hugehelp.c
rem 3 - failure to generate curlbuild.h
rem
rem
:generate
  rem create Makefile
  if exist Makefile.dist (
    echo * %CD%\Makefile
    copy /Y Makefile.dist Makefile 1>NUL 2>&1
    if errorlevel 1 (
      exit /B 1
    )
  )

  rem create tool_hugehelp.c
  if exist src\tool_hugehelp.c.cvs (
    echo * %CD%\src\tool_hugehelp.c
    copy /Y src\tool_hugehelp.c.cvs src\tool_hugehelp.c 1>NUL 2>&1
    if errorlevel 1 (
      exit /B 2
    )
  )

  rem create curlbuild.h
  if exist include\curl\curlbuild.h.dist (
    echo * %CD%\include\curl\curlbuild.h
    copy /Y include\curl\curlbuild.h.dist include\curl\curlbuild.h 1>NUL 2>&1
    if errorlevel 1 (
      exit /B 3
    )
  )

  rem setup c-ares git tree
  if exist ares\buildconf.bat (
    echo.
    echo Configuring c-ares build environment
    cd ares
    call buildconf.bat
    cd ..
  )

  exit /B 0

rem Main clean function.
rem
rem Returns:
rem
rem 0 - success
rem 1 - failure to clean Makefile
rem 2 - failure to clean tool_hugehelp.c
rem 3 - failure to clean curlbuild.h
rem
:clean
  echo * %CD%\Makefile
  if exist Makefile (
    del Makefile 2>NUL
    if exist Makefile (
      exit /B 1
    )
  )

  echo * %CD%\src\tool_hugehelp.c
  if exist src\tool_hugehelp.c (
    del src\tool_hugehelp.c 2>NUL
    if exist src\tool_hugehelp.c (
      exit /B 2
    )
  )

  echo * %CD%\include\curl\curlbuild.h
  if exist include\curl\curlbuild.h (
    del include\curl\curlbuild.h 2>NUL
    if exist include\curl\curlbuild.h (
      exit /B 3
    )
  )

  exit /B 0

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

:nogencurlbuild
  echo.
  echo Error: Unable to generate include\curl\curlbuild.h
  goto error

:nocleanmakefile
  echo.
  echo Error: Unable to clean Makefile
  goto error

:nocleanhugehelp
  echo.
  echo Error: Unable to clean src\tool_hugehelp.c
  goto error

:nocleancurlbuild
  echo.
  echo Error: Unable to clean include\curl\curlbuild.h
  goto error

:error
  if "%OS%" == "Windows_NT" (
    endlocal
  ) else (
    set MODE=
  )
  exit /B 1

:success
  if "%OS%" == "Windows_NT" (
    endlocal
  ) else (
    set MODE=
  )
  exit /B 0
