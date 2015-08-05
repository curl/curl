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
rem there is no autotools support (i.e. Windows).
rem
rem This file is not included or required for curl's release archives or daily 
rem snapshot archives.

:begin
  rem Display the help
  if /i "%~1" == "-?" goto syntax
  if /i "%~1" == "-h" goto syntax
  if /i "%~1" == "-help" goto syntax

  rem Switch to this batch file's directory
  cd /d "%~0\.." 1>NUL 2>&1

  if not exist GIT-INFO goto nogitinfo

  rem Set our variables
  setlocal
  set MODE=GENERATE

:parseArgs
  if "%~1" == "" goto start

  if /i "%~1" == "-clean" (
    set MODE=CLEAN
  ) else (
    goto unknown
  )

  shift & goto parseArgs

:start
  if "%MODE%" == "GENERATE" (
    call :generate
  ) else (
    call :clean
  )

  goto success

rem Main generate function.
rem
:generate
  echo.
  echo Generating prerequisite files

  rem create tool_hugehelp.c
  if exist src\tool_hugehelp.c.cvs (
    echo * %CD%\src\tool_hugehelp.c
    copy /Y src\tool_hugehelp.c.cvs src\tool_hugehelp.c 1>NUL
  )

  rem create Makefile
  if exist Makefile.dist (
    echo * %CD%\Makefile
    copy /Y Makefile.dist Makefile 1>NUL
  )

  rem create curlbuild.h
  if exist include\curl\curlbuild.h.dist (
    echo * %CD%\include\curl\curlbuild.h
    copy /Y include\curl\curlbuild.h.dist include\curl\curlbuild.h 1>NUL
  )

  rem setup c-ares git tree
  if exist ares\buildconf.bat (
    echo.
    echo Configuring c-ares build environment
    cd ares
    call buildconf.bat
    cd ..
  )

  exit /B

rem Main clean function.
rem
:clean
  echo.
  echo Removing prerequisite files

  echo * %CD%\Makefile
  if exist Makefile (
    del Makefile
  )

  echo * %CD%\src\tool_hugehelp.c
  if exist src\tool_hugehelp.c (
    del src\tool_hugehelp.c
  )

  echo * %CD%\include\curl\curlbuild.h
  if exist include\curl\curlbuild.h (
    del include\curl\curlbuild.h
  )

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

:nogitinfo
  echo.
  echo ERROR: This file shall only be used with a curl git tree checkout.
  goto error

:error
  endlocal
  exit /B 1

:success
  endlocal
  exit /B 0
