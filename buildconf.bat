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
  if not exist GIT-INFO.md goto norepo

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
    if errorlevel 2 goto nogenmakefile
    if errorlevel 1 goto warning

  ) else (
    echo.
    echo Removing prerequisite files

    call :clean
    if errorlevel 1 goto nocleanmakefile
  )

  goto success

rem Main generate function.
rem
rem Returns:
rem
rem 0 - success
rem 2 - failed to generate Makefile
rem
:generate
  if "%OS%" == "Windows_NT" setlocal

  rem Create Makefile
  echo * %CD%\Makefile
  if exist Makefile.dist (
    copy /Y Makefile.dist Makefile 1>NUL 2>&1
    if errorlevel 1 (
      if "%OS%" == "Windows_NT" endlocal
      exit /B 2
    )
  )
  cmd /c exit 0

  if "%OS%" == "Windows_NT" endlocal
  exit /B 0

rem Main clean function.
rem
rem Returns:
rem
rem 0 - success
rem 1 - failed to clean Makefile
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

  exit /B

rem Function to clean-up local variables under DOS, Windows 3.x and
rem Windows 9x as setlocal isn't available until Windows NT
rem
:dosCleanup
  set MODE=
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

:nocleanmakefile
  echo.
  echo Error: Unable to clean Makefile
  goto error

:warning
  echo.
  echo Warning: The curl manual could not be integrated in the source. This means when
  echo you build curl the manual will not be available (curl --manual^). Integration of
  echo the manual is not required and a summary of the options will still be available
  echo (curl --help^). To integrate the manual build with configure or cmake.
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
