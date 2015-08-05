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

  if not exist GIT-INFO goto nogitinfo

:start
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

  goto success

:syntax
  rem Display the help
  echo.
  echo Usage: buildconf
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
