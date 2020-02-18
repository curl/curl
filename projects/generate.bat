@echo off
rem ***************************************************************************
rem *                                  _   _ ____  _
rem *  Project                     ___| | | |  _ \| |
rem *                             / __| | | | |_) | |
rem *                            | (__| |_| |  _ <| |___
rem *                             \___|\___/|_| \_\_____|
rem *
rem * Copyright (C) 2014 - 2020, Steve Holme, <steve_holme@hotmail.com>.
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

  rem Set our variables
  setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
  set VERSION=ALL
  set MODE=GENERATE

  set VC6_LIBTMPL=dsp Windows\VC6\lib\libcurl.dsp.tmpl
  set VC6_LIBDSP=Windows\VC6\lib\libcurl.dsp
  set VC6_SRCTMPL=Windows\VC6\src\curl.dsp.tmpl
  set VC6_SRCDSP=Windows\VC6\src\curl.dsp

  set VC7_LIBTMPL=Windows\VC7\lib\libcurl.vcproj.tmpl
  set VC7_LIBVCPROJ=Windows\VC7\lib\libcurl.vcproj
  set VC7_SRCTMPL=Windows\VC7\src\curl.vcproj.tmpl
  set VC7_SRCVCPROJ=Windows\VC7\src\curl.vcproj

  set VC71_LIBTMPL=Windows\VC7.1\lib\libcurl.vcproj.tmpl
  set VC71_LIBVCPROJ=Windows\VC7.1\lib\libcurl.vcproj
  set VC71_SRCTMPL=Windows\VC7.1\src\curl.vcproj.tmpl
  set VC71_SRCVCPROJ=Windows\VC7.1\src\curl.vcproj

  set VC8_LIBTMPL=Windows\VC8\lib\libcurl.vcproj.tmpl
  set VC8_LIBVCPROJ=Windows\VC8\lib\libcurl.vcproj
  set VC8_SRCTMPL=Windows\VC8\src\curl.vcproj.tmpl
  set VC8_SRCVCPROJ=Windows\VC8\src\curl.vcproj

  set VC9_LIBTMPL=Windows\VC9\lib\libcurl.vcproj.tmpl
  set VC9_LIBVCPROJ=Windows\VC9\lib\libcurl.vcproj
  set VC9_SRCTMPL=Windows\VC9\src\curl.vcproj.tmpl
  set VC9_SRCVCPROJ=Windows\VC9\src\curl.vcproj

  set VC10_LIBTMPL=Windows\VC10\lib\libcurl.vcxproj.tmpl
  set VC10_LIBVCXPROJ=Windows\VC10\lib\libcurl.vcxproj
  set VC10_LIBFILTERSTMPL=Windows\VC10\lib\libcurl.vcxproj.filters.tmpl
  set VC10_LIBFILTERS=Windows\VC10\lib\libcurl.vcxproj.filters
  set VC10_SRCTMPL=Windows\VC10\src\curl.vcxproj.tmpl
  set VC10_SRCVCXPROJ=Windows\VC10\src\curl.vcxproj
  set VC10_SRCFILTERSTMPL=Windows\VC10\src\curl.vcxproj.filters.tmpl
  set VC10_SRCFILTERS=Windows\VC10\src\curl.vcxproj.filters

  set VC11_LIBTMPL=Windows\VC11\lib\libcurl.vcxproj.tmpl
  set VC11_LIBVCXPROJ=Windows\VC11\lib\libcurl.vcxproj
  set VC11_LIBFILTERSTMPL=Windows\VC11\lib\libcurl.vcxproj.filters.tmpl
  set VC11_LIBFILTERS=Windows\VC11\lib\libcurl.vcxproj.filters
  set VC11_SRCTMPL=Windows\VC11\src\curl.vcxproj.tmpl
  set VC11_SRCVCXPROJ=Windows\VC11\src\curl.vcxproj
  set VC11_SRCFILTERSTMPL=Windows\VC11\src\curl.vcxproj.filters.tmpl
  set VC11_SRCFILTERS=Windows\VC11\src\curl.vcxproj.filters

  set VC12_LIBTMPL=Windows\VC12\lib\libcurl.vcxproj.tmpl
  set VC12_LIBVCXPROJ=Windows\VC12\lib\libcurl.vcxproj
  set VC12_LIBFILTERSTMPL=Windows\VC12\lib\libcurl.vcxproj.filters.tmpl
  set VC12_LIBFILTERS=Windows\VC12\lib\libcurl.vcxproj.filters
  set VC12_SRCTMPL=Windows\VC12\src\curl.vcxproj.tmpl
  set VC12_SRCVCXPROJ=Windows\VC12\src\curl.vcxproj
  set VC12_SRCFILTERSTMPL=Windows\VC12\src\curl.vcxproj.filters.tmpl
  set VC12_SRCFILTERS=Windows\VC12\src\curl.vcxproj.filters

  set VC14_LIBTMPL=Windows\VC14\lib\libcurl.vcxproj.tmpl
  set VC14_LIBVCXPROJ=Windows\VC14\lib\libcurl.vcxproj
  set VC14_LIBFILTERSTMPL=Windows\VC14\lib\libcurl.vcxproj.filters.tmpl
  set VC14_LIBFILTERS=Windows\VC14\lib\libcurl.vcxproj.filters
  set VC14_SRCTMPL=Windows\VC14\src\curl.vcxproj.tmpl
  set VC14_SRCVCXPROJ=Windows\VC14\src\curl.vcxproj
  set VC14_SRCFILTERSTMPL=Windows\VC14\src\curl.vcxproj.filters.tmpl
  set VC14_SRCFILTERS=Windows\VC14\src\curl.vcxproj.filters

  set VC15_LIBTMPL=Windows\VC15\lib\libcurl.vcxproj.tmpl
  set VC15_LIBVCXPROJ=Windows\VC15\lib\libcurl.vcxproj
  set VC15_LIBFILTERSTMPL=Windows\VC15\lib\libcurl.vcxproj.filters.tmpl
  set VC15_LIBFILTERS=Windows\VC15\lib\libcurl.vcxproj.filters
  set VC15_SRCTMPL=Windows\VC15\src\curl.vcxproj.tmpl
  set VC15_SRCVCXPROJ=Windows\VC15\src\curl.vcxproj
  set VC15_SRCFILTERSTMPL=Windows\VC15\src\curl.vcxproj.filters.tmpl
  set VC15_SRCFILTERS=Windows\VC15\src\curl.vcxproj.filters

  rem Check we are not running on a network drive
  if "%~d0."=="\\." goto nonetdrv

  rem Switch to this batch file's directory
  cd /d "%~0\.." 1>NUL 2>&1

  rem Check we are running from a curl git repository
  if not exist ..\GIT-INFO goto norepo

:parseArgs
  if "%~1" == "" goto start

  if /i "%~1" == "pre" (
    set VERSION=PRE
  ) else if /i "%~1" == "vc6" (
    set VERSION=VC6
  ) else if /i "%~1" == "vc7" (
    set VERSION=VC7
  ) else if /i "%~1" == "vc7.1" (
    set VERSION=VC7.1
  ) else if /i "%~1" == "vc8" (
    set VERSION=VC8
  ) else if /i "%~1" == "vc9" (
    set VERSION=VC9
  ) else if /i "%~1" == "vc10" (
    set VERSION=VC10
  ) else if /i "%~1" == "vc11" (
    set VERSION=VC11
  ) else if /i "%~1" == "vc12" (
    set VERSION=VC12
  ) else if /i "%~1" == "vc14" (
    set VERSION=VC14
  ) else if /i "%~1" == "vc15" (
    set VERSION=VC15
  ) else if /i "%~1" == "-clean" (
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
  if exist ..\buildconf.bat (
    if "%MODE%" == "GENERATE" (
      call ..\buildconf
    ) else if "%VERSION%" == "PRE" (
      call ..\buildconf -clean
    ) else if "%VERSION%" == "ALL" (
      call ..\buildconf -clean
    )
  )
  if "%VERSION%" == "PRE" goto success
  if "%VERSION%" == "VC6" goto vc6
  if "%VERSION%" == "VC7" goto vc7
  if "%VERSION%" == "VC7.1" goto vc71
  if "%VERSION%" == "VC8" goto vc8
  if "%VERSION%" == "VC9" goto vc9
  if "%VERSION%" == "VC10" goto vc10
  if "%VERSION%" == "VC11" goto vc11
  if "%VERSION%" == "VC12" goto vc12
  if "%VERSION%" == "VC14" goto vc14
  if "%VERSION%" == "VC15" goto vc15

:vc6
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC6 project files
    call :generate dsp %VC6_SRCTMPL% %VC6_SRCDSP%
    call :generate %VC6_LIBTMPL% %VC6_LIBDSP%
  ) else (
    echo Removing VC6 project files
    call :clean %VC6_SRCDSP%
    call :clean %VC6_LIBDSP%
  )

  if not "%VERSION%" == "ALL" goto success

:vc7
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC7 project files
    call :generate vcproj1 %VC7_SRCTMPL% %VC7_SRCVCPROJ%
    call :generate vcproj1 %VC7_LIBTMPL% %VC7_LIBVCPROJ%
  ) else (
    echo Removing VC7 project files
    call :clean %VC7_SRCVCPROJ%
    call :clean %VC7_LIBVCPROJ%
  )

  if not "%VERSION%" == "ALL" goto success

:vc71
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC7.1 project files
    call :generate vcproj1 %VC71_SRCTMPL% %VC71_SRCVCPROJ%
    call :generate vcproj1 %VC71_LIBTMPL% %VC71_LIBVCPROJ%
  ) else (
    echo Removing VC7.1 project files
    call :clean %VC71_SRCVCPROJ%
    call :clean %VC71_LIBVCPROJ%
  )

  if not "%VERSION%" == "ALL" goto success

:vc8
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC8 project files
    call :generate vcproj2 %VC8_SRCTMPL% %VC8_SRCVCPROJ%
    call :generate vcproj2 %VC8_LIBTMPL% %VC8_LIBVCPROJ%
  ) else (
    echo Removing VC8 project files
    call :clean %VC8_SRCVCPROJ%
    call :clean %VC8_LIBVCPROJ%
  )

  if not "%VERSION%" == "ALL" goto success

:vc9
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC9 project files
    call :generate vcproj2 %VC9_SRCTMPL% %VC9_SRCVCPROJ%
    call :generate vcproj2 %VC9_LIBTMPL% %VC9_LIBVCPROJ%
  ) else (
    echo Removing VC9 project files
    call :clean %VC9_SRCVCPROJ%
    call :clean %VC9_LIBVCPROJ%
  )

  if not "%VERSION%" == "ALL" goto success

:vc10
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC10 project files
    call :generate vcxproj %VC10_SRCTMPL% %VC10_SRCVCXPROJ%
    call :generate filters %VC10_SRCFILTERSTMPL% %VC10_SRCFILTERS%
    call :generate vcxproj %VC10_LIBTMPL% %VC10_LIBVCXPROJ%
    call :generate filters %VC10_LIBFILTERSTMPL% %VC10_LIBFILTERS%
  ) else (
    echo Removing VC10 project files
    call :clean %VC10_SRCVCXPROJ%
    call :clean %VC10_SRCFILTERS%
    call :clean %VC10_LIBVCXPROJ%
    call :clean %VC10_LIBFILTERS%
  )

  if not "%VERSION%" == "ALL" goto success

:vc11
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC11 project files
    call :generate vcxproj %VC11_SRCTMPL% %VC11_SRCVCXPROJ%
    call :generate filters %VC11_SRCFILTERSTMPL% %VC11_SRCFILTERS%
    call :generate vcxproj %VC11_LIBTMPL% %VC11_LIBVCXPROJ%
    call :generate filters %VC11_LIBFILTERSTMPL% %VC11_LIBFILTERS%
  ) else (
    echo Removing VC11 project files
    call :clean %VC11_SRCVCXPROJ%
    call :clean %VC11_SRCFILTERS%
    call :clean %VC11_LIBVCXPROJ%
    call :clean %VC11_LIBFILTERS%
  )

  if not "%VERSION%" == "ALL" goto success

:vc12
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC12 project files
    call :generate vcxproj %VC12_SRCTMPL% %VC12_SRCVCXPROJ%
    call :generate filters %VC12_SRCFILTERSTMPL% %VC12_SRCFILTERS%
    call :generate vcxproj %VC12_LIBTMPL% %VC12_LIBVCXPROJ%
    call :generate filters %VC12_LIBFILTERSTMPL% %VC12_LIBFILTERS%
  ) else (
    echo Removing VC12 project files
    call :clean %VC12_SRCVCXPROJ%
    call :clean %VC12_SRCFILTERS%
    call :clean %VC12_LIBVCXPROJ%
    call :clean %VC12_LIBFILTERS%
  )

  if not "%VERSION%" == "ALL" goto success

:vc14
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC14 project files
    call :generate vcxproj %VC14_SRCTMPL% %VC14_SRCVCXPROJ%
    call :generate filters %VC14_SRCFILTERSTMPL% %VC14_SRCFILTERS%
    call :generate vcxproj %VC14_LIBTMPL% %VC14_LIBVCXPROJ%
    call :generate filters %VC14_LIBFILTERSTMPL% %VC14_LIBFILTERS%
  ) else (
    echo Removing VC14 project files
    call :clean %VC14_SRCVCXPROJ%
    call :clean %VC14_SRCFILTERS%
    call :clean %VC14_LIBVCXPROJ%
    call :clean %VC14_LIBFILTERS%
  )

  if not "%VERSION%" == "ALL" goto success

:vc15
  echo.

  if "%MODE%" == "GENERATE" (
    echo Generating VC15 project files
    call :generate vcxproj %VC15_SRCTMPL% %VC15_SRCVCXPROJ%
    call :generate filters %VC15_SRCFILTERSTMPL% %VC15_SRCFILTERS%
    call :generate vcxproj %VC15_LIBTMPL% %VC15_LIBVCXPROJ%
    call :generate filters %VC15_LIBFILTERSTMPL% %VC15_LIBFILTERS%
  ) else (
    echo Removing VC15 project files
    call :clean %VC15_SRCVCXPROJ%
    call :clean %VC15_SRCFILTERS%
    call :clean %VC15_LIBVCXPROJ%
    call :clean %VC15_LIBFILTERS%
  )

  goto success

rem Main generate function.
rem
rem %1 - File Type: dsp for Developer Studio Project files
rem                   * Visual Studio 98 (Version 6)
rem                 vcproj1 for Visual Studio Project (Format 1) files
rem                   * Visual Studio.net (Version 7)
rem                   * Visual Studio 2003.net (Version 7.1)
rem                 vcproj2 for Visual Studio Project (Format 2) files
rem                   * Visual Studio 2008 (Version 8)
rem                   * Visual Studio 2009 (Version 9)
rem                 vcxproj for Visual Studio XML Project files
rem                   * Visual Studio 2010 (Version 10)
rem                   * Visual Studio 2012 (Version 11)
rem                   * Visual Studio 2013 (Version 12)
rem                   * Visual Studio 2015 (Version 14)
rem                   * Visual Studio 2017 (Version 15)
rem                 filters for Visual Studio Project Filter files
rem                   * Visual Studio 2010 (Version 10)
rem                   * Visual Studio 2012 (Version 11)
rem                   * Visual Studio 2013 (Version 12)
rem                   * Visual Studio 2015 (Version 14)
rem                   * Visual Studio 2017 (Version 15)
rem %2 - Template file
rem %3 - Output file
rem
:generate
  if not exist %2 (
    echo.
    echo Error: Cannot open %2
    exit /B
  )

  if exist %3 (
    del %3
  )

  echo * %CD%\%3
  for /f "usebackq delims=" %%i in (`"findstr /n ^^ %2"`) do (
    set "var=%%i"
    setlocal enabledelayedexpansion
    set "var=!var:*:=!"

    if "!var!" == "CURL_SRC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\src\*.c') do call :element %1 src "%%c" %3
    ) else if "!var!" == "CURL_SRC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\src\*.h') do call :element %1 src "%%h" %3
    ) else if "!var!" == "CURL_SRC_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\src\*.rc') do call :element %1 src "%%r" %3
    ) else if "!var!" == "CURL_SRC_X_C_FILES" (
      call :element %1 lib "strtoofft.c" %3
      call :element %1 lib "nonblock.c" %3
      call :element %1 lib "warnless.c" %3
      call :element %1 lib "curl_ctype.c" %3
    ) else if "!var!" == "CURL_SRC_X_H_FILES" (
      call :element %1 lib "config-win32.h" %3
      call :element %1 lib "curl_setup.h" %3
      call :element %1 lib "strtoofft.h" %3
      call :element %1 lib "nonblock.h" %3
      call :element %1 lib "warnless.h" %3
      call :element %1 lib "curl_ctype.h" %3
    ) else if "!var!" == "CURL_LIB_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\*.c') do call :element %1 lib "%%c" %3
    ) else if "!var!" == "CURL_LIB_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\include\curl\*.h') do call :element %1 include\curl "%%h" %3
      for /f "delims=" %%h in ('dir /b ..\lib\*.h') do call :element %1 lib "%%h" %3
    ) else if "!var!" == "CURL_LIB_RC_FILES" (
      for /f "delims=" %%r in ('dir /b ..\lib\*.rc') do call :element %1 lib "%%r" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vauth\*.c') do call :element %1 lib\vauth "%%c" %3
    ) else if "!var!" == "CURL_LIB_VAUTH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vauth\*.h') do call :element %1 lib\vauth "%%h" %3
    ) else if "!var!" == "CURL_LIB_VQUIC_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vquic\*.c') do call :element %1 lib\vquic "%%c" %3
    ) else if "!var!" == "CURL_LIB_VQUIC_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vquic\*.h') do call :element %1 lib\vquic "%%h" %3
    ) else if "!var!" == "CURL_LIB_VSSH_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vssh\*.c') do call :element %1 lib\vssh "%%c" %3
    ) else if "!var!" == "CURL_LIB_VSSH_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vssh\*.h') do call :element %1 lib\vssh "%%h" %3
    ) else if "!var!" == "CURL_LIB_VTLS_C_FILES" (
      for /f "delims=" %%c in ('dir /b ..\lib\vtls\*.c') do call :element %1 lib\vtls "%%c" %3
    ) else if "!var!" == "CURL_LIB_VTLS_H_FILES" (
      for /f "delims=" %%h in ('dir /b ..\lib\vtls\*.h') do call :element %1 lib\vtls "%%h" %3
    ) else (
      echo.!var!>> %3
    )

    endlocal
  )
  exit /B

rem Generates a single file xml element.
rem
rem %1 - File Type: dsp for Developer Studio Project files
rem                   * Visual Studio 98 (Version 6)
rem                 vcproj1 for Visual Studio Project (Format 1) files
rem                   * Visual Studio.net (Version 7)
rem                   * Visual Studio 2003.net (Version 7.1)
rem                 vcproj2 for Visual Studio Project (Format 2) files
rem                   * Visual Studio 2008 (Version 8)
rem                   * Visual Studio 2009 (Version 9)
rem                 vcxproj for Visual Studio XML Project files
rem                   * Visual Studio 2010 (Version 10)
rem                   * Visual Studio 2012 (Version 11)
rem                   * Visual Studio 2013 (Version 12)
rem                   * Visual Studio 2015 (Version 14)
rem                   * Visual Studio 2017 (Version 15)
rem                 filters for Visual Studio Project Filter files
rem                   * Visual Studio 2010 (Version 10)
rem                   * Visual Studio 2012 (Version 11)
rem                   * Visual Studio 2013 (Version 12)
rem                   * Visual Studio 2015 (Version 14)
rem                   * Visual Studio 2017 (Version 15)
rem %2 - Directory (src, lib, lib\vauth, lib\vquic, lib\vssh, lib\vtls)
rem %3 - Template file
rem %4 - Output file
rem
:element
  set "SPACES=    "
  if "%2" == "lib\vauth" (
    set "TABS=				"
  ) else if "%2" == "lib\vquic" (
    set "TABS=				"
  ) else if "%2" == "lib\vssh" (
    set "TABS=				"
  ) else if "%2" == "lib\vtls" (
    set "TABS=				"
  ) else (
    set "TABS=			"
  )

  call :extension %3 ext

  if "%1" == "dsp" (
    echo # Begin Source File>> %4
    echo.>> %4
    echo SOURCE=..\..\..\..\%2\%~3>> %4
    echo # End Source File>> %4
  ) else if "%1" == "vcproj1" (
    echo %TABS%^<File>> %4
    echo %TABS%	RelativePath="..\..\..\..\%2\%~3"^>>> %4
    echo %TABS%^</File^>>> %4
  ) else if "%1" == "vcproj2" (
    echo %TABS%^<File>> %4
    echo %TABS%	RelativePath="..\..\..\..\%2\%~3">> %4
    echo %TABS%^>>> %4
    echo %TABS%^</File^>>> %4
  ) else if "%1" == "vcxproj" (
    if "%ext%" == "c" (
      echo %SPACES%^<ClCompile Include=^"..\..\..\..\%2\%~3^" /^>>> %4
    ) else if "%ext%" == "h" (
      echo %SPACES%^<ClInclude Include=^"..\..\..\..\%2\%~3^" /^>>> %4
    ) else if "%ext%" == "rc" (
      echo %SPACES%^<ResourceCompile Include=^"..\..\..\..\%2\%~3^" /^>>> %4
    )
  ) else if "%1" == "filters" (
    rem Calculate the relative FILTER path from src or lib
    set FILTER=%2
    if "!FILTER:~0,4!" == "lib\" (
      set FILTER=!FILTER:~3!
    ) else (
      set FILTER=
    )

    if "%ext%" == "c" (
      echo %SPACES%^<ClCompile Include=^"..\..\..\..\%2\%~3^"^>>> %4
      echo %SPACES%  ^<Filter^>Source Files!FILTER!^</Filter^>>> %4
      echo %SPACES%^</ClCompile^>>> %4
    ) else if "%ext%" == "h" (
      echo %SPACES%^<ClInclude Include=^"..\..\..\..\%2\%~3^"^>>> %4
      echo %SPACES%  ^<Filter^>Header Files!FILTER!^</Filter^>>> %4
      echo %SPACES%^</ClInclude^>>> %4
    ) else if "%ext%" == "rc" (
      echo %SPACES%^<ResourceCompile Include=^"..\..\..\..\%2\%~3^"^>>> %4
      echo %SPACES%  ^<Filter^>Resource Files^</Filter^>>> %4
      echo %SPACES%^</ResourceCompile^>>> %4
    )
  )

  exit /B

rem Returns the extension for a given filename.
rem
rem %1 - The filename
rem %2 - The return value
rem
:extension
  set fname=%~1
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

rem Removes the given project file.
rem
rem %1 - The filename
rem
:clean
  echo * %CD%\%1

  if exist %1 (
    del %1
  )

  exit /B

:syntax
  rem Display the help
  echo.
  echo Usage: generate [what] [-clean]
  echo.
  echo What to generate:
  echo.
  echo pre       - Prerequisites only
  echo vc6       - Use Visual Studio 6
  echo vc7       - Use Visual Studio .NET
  echo vc7.1     - Use Visual Studio .NET 2003
  echo vc8       - Use Visual Studio 2005
  echo vc9       - Use Visual Studio 2008
  echo vc10      - Use Visual Studio 2010
  echo vc11      - Use Visual Studio 2012
  echo vc12      - Use Visual Studio 2013
  echo vc14      - Use Visual Studio 2015
  echo vc15      - Use Visual Studio 2017
  echo.
  echo -clean    - Removes the project files
  goto error

:unknown
  echo.
  echo Error: Unknown argument '%1'
  goto error

:nodos
  echo.
  echo Error: Only a Windows NT based Operating System is supported
  goto error

:nonetdrv
  echo.
  echo Error: This batch file cannot run from a network drive
  goto error

:norepo
  echo.
  echo Error: This batch file should only be used from a curl git repository
  goto error

:seterr
  rem Set the caller's errorlevel.
  rem %1[opt]: Errorlevel as integer.
  rem If %1 is empty the errorlevel will be set to 0.
  rem If %1 is not empty and not an integer the errorlevel will be set to 1.
  setlocal
  set EXITCODE=%~1
  if not defined EXITCODE set EXITCODE=0
  echo %EXITCODE%|findstr /r "[^0-9\-]" 1>NUL 2>&1
  if %ERRORLEVEL% EQU 0 set EXITCODE=1
  exit /b %EXITCODE%

:error
  if "%OS%" == "Windows_NT" endlocal
  exit /B 1

:success
  endlocal
  exit /B 0
