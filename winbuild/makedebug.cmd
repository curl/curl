@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

where.exe nmake.exe >nul 2>&1

IF %ERRORLEVEL% == 1 (
  ECHO Error: Can't find `nmake.exe` - be sure to run this script from within a Developer Command-Prompt
  ECHO.
) ELSE (
  nmake /f Makefile.vc mode=static DEBUG=yes GEN_PDB=yes
  IF %ERRORLEVEL% NEQ 0 (
    ECHO "Error: Build Failed"
  )
)
