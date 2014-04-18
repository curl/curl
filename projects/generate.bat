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
setlocal ENABLEDELAYEDEXPANSION

echo Generating VC8 project files
call :generate vcproj Windows\VC8\src\curlsrc.tmpl Windows\VC8\src\curlsrc.vcproj
call :generate vcproj Windows\VC8\lib\libcurl.tmpl Windows\VC8\lib\libcurl.vcproj

echo.
echo Generating VC9 project files
call :generate vcproj Windows\VC9\src\curlsrc.tmpl Windows\VC9\src\curlsrc.vcproj
call :generate vcproj Windows\VC9\lib\libcurl.tmpl Windows\VC9\lib\libcurl.vcproj

echo.
echo Generating VC10 project files
call :generate vcxproj Windows\VC10\src\curlsrc.tmpl Windows\VC10\src\curlsrc.vcxproj
call :generate vcxproj Windows\VC10\lib\libcurl.tmpl Windows\VC10\lib\libcurl.vcxproj

echo.
echo Generating VC11 project files
call :generate vcxproj Windows\VC11\src\curlsrc.tmpl Windows\VC11\src\curlsrc.vcxproj
call :generate vcxproj Windows\VC11\lib\libcurl.tmpl Windows\VC11\lib\libcurl.vcxproj

goto exit

rem Main generate function.
rem
rem %1 - Project Type (dsp, vcproj or vcxproj)
rem %2 - Input template file
rem %3 - Output project file
rem
:generate
  if not exist %2 (
    echo.
    echo Error: Cannot open %CD%\%2
    exit /B
  )

  if exist %3 (  
    del %3
  )

  echo * %CD%\%3
  for /f "delims=" %%i in (%2) do (
    if "%%i" == "CURL_SRC_C_FILES" (
      for /f %%c in ('dir /b ..\src\*.c') do call :element %1 src %%c %3
    ) else if "%%i" == "CURL_SRC_H_FILES" (
      for /f %%h in ('dir /b ..\src\*.h') do call :element %1 src %%h %3
    ) else if "%%i" == "CURL_SRC_RC_FILES" (
      for /f %%r in ('dir /b ..\src\*.rc') do call :element %1 src %%r %3
    ) else if "%%i" == "CURL_LIB_C_FILES" (
      for /f %%c in ('dir /b ..\lib\*.c') do call :element %1 lib %%c %3
    ) else if "%%i" == "CURL_LIB_H_FILES" (
      for /f %%h in ('dir /b ..\lib\*.h') do call :element %1 lib %%h %3
    ) else if "%%i" == "CURL_LIB_RC_FILES" (
      for /f %%r in ('dir /b ..\lib\*.rc') do call :element %1 lib %%r %3
    ) else if "%%i" == "CURL_LIB_VTLS_C_FILES" (
      for /f %%c in ('dir /b ..\lib\vtls\*.c') do call :element %1 lib\vtls %%c %3
    ) else if "%%i" == "CURL_LIB_VTLS_H_FILES" (
      for /f %%h in ('dir /b ..\lib\vtls\*.h') do call :element %1 lib\vtls %%h %3
    ) else (
      echo %%i>> %3
    )
  )
  exit /B

rem Generates a single file xml element.
rem
rem %1 - Project Type (dsp, vcproj or vcxproj)
rem %2 - Directory (src, lib or lib\vtls)
rem %3 - Source filename
rem %4 - Output project file
rem
:element
  set "SPACES=    "
  if "%2" == "lib\vtls" (
    set "TABS=        "
  ) else (
    set "TABS=      "
  )

  call :extension %3 ext

  if "%1" == "vcproj" (
    echo %TABS%^<File>> %4
    echo %TABS%  RelativePath="..\..\..\..\%2\%3">> %4
    echo %TABS%^>>> %4
    echo %TABS%^</File^>>> %4
  ) else if "%1" == "vcxproj" (
    if "%ext%" == "c" (
      echo %SPACES%^<ClCompile Include=^"..\..\..\..\%2\%3^" /^>>> %4
    ) else if "%ext%" == "h" (
      echo %SPACES%^<ClInclude Include=^"..\..\..\..\%2\%3^" /^>>> %4
    ) else if "%ext%" == "rc" (
      echo %SPACES%^<ResourceCompile Include=^"..\..\..\..\%2\%3^" /^>>> %4
    )
  )

  exit /B

rem Returns the extension for a given filename.
rem
rem %1 - The filename
rem %2 - The return value
rem
:extension
  set fname=%1
  set ename=
:loop1
  if "%fname%"=="" (
    set %2=
    exit /B
  )

  if not "%fname:~-1%"=="." (
    set ename=%fname:~-1%%ename%
    set fname=%fname:~0,-1%
    goto loop1
  )

  set %2=%ename%
  exit /B

:exit
  echo.
  endlocal
  pause
