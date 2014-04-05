@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2014, Steve Holme, <steve_holme@hotmail.com>
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

rem Generate VC8 project files
call :generate Windows\VC8\src\curlsrc.tmpl Windows\VC8\src\curlsrc.vcproj
call :generate Windows\VC8\lib\libcurl.tmpl Windows\VC8\lib\libcurl.vcproj

goto exit

rem Main generate function.
rem
rem %1 - Input template file
rem %2 - Output project file
rem
:generate
  echo.

  if not exist %1 (
    echo Error: Cannot open %CD%\%1
    exit /B
  )

  if exist %2 (  
    echo Deleting %2
    del %2
  )

  echo Generating %2
  for /f "delims=" %%i in (%1) do (
    if "%%i" == "CURL_SRC_C_FILES" (
      for /f %%c in ('dir /b ..\src\*.c') do call :element src %%c %2
    ) else if "%%i" == "CURL_SRC_H_FILES" (
      for /f %%h in ('dir /b ..\src\*.h') do call :element src %%h %2
    ) else if "%%i" == "CURL_SRC_RC_FILES" (
      for /f %%r in ('dir /b ..\src\*.rc') do call :element src %%r %2
    ) else if "%%i" == "CURL_LIB_C_FILES" (
      for /f %%c in ('dir /b ..\lib\*.c') do call :element lib %%c %2
    ) else if "%%i" == "CURL_LIB_H_FILES" (
      for /f %%h in ('dir /b ..\lib\*.h') do call :element lib %%h %2
    ) else if "%%i" == "CURL_LIB_RC_FILES" (
      for /f %%r in ('dir /b ..\lib\*.rc') do call :element lib %%r %2
    ) else if "%%i" == "CURL_LIB_VTLS_C_FILES" (
      for /f %%c in ('dir /b ..\lib\vtls\*.c') do call :element lib\vtls %%c %2
    ) else if "%%i" == "CURL_LIB_VTLS_H_FILES" (
      for /f %%h in ('dir /b ..\lib\vtls\*.h') do call :element lib\vtls %%h %2
    ) else (
      echo %%i>> %2
    )
  )
  exit /B

rem Generates a single file xml element.
rem
rem %1 - Directory (eg src, lib or lib\vtls)
rem %2 - Source filename
rem %3 - Output project file
rem
:element
  if "%1" == "lib\vtls" (
    set "TABS=        "
  ) else (
    set "TABS=      "
  )
  echo %TABS%^<File>> %3
  echo %TABS%  RelativePath="..\..\..\..\%1\%2">> %3
  echo %TABS%^>>> %3
  echo %TABS%^</File^>>> %3
  exit /B

:exit
  echo.
  pause
