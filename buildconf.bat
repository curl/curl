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
rem create tool_hugehelp.c
if not exist src\tool_hugehelp.c.cvs goto end_hugehelp_c
copy /Y src\tool_hugehelp.c.cvs src\tool_hugehelp.c
:end_hugehelp_c

rem create Makefile
if not exist Makefile.dist goto end_makefile
copy /Y Makefile.dist Makefile
:end_makefile

rem create curlbuild.h
if not exist include\curl\curlbuild.h.dist goto end_curlbuild_h
copy /Y include\curl\curlbuild.h.dist include\curl\curlbuild.h
:end_curlbuild_h

rem setup c-ares git tree
if not exist ares\buildconf.bat goto end_c_ares
cd ares
call buildconf.bat
cd ..
:end_c_ares
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
