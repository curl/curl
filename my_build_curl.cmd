@echo off
rem
rem Script for building Curl as a DLL for win32 & x64 using CMake
rem
rem Compilation time:  ~ 2-3 minutes
rem
rem Compiles curl as a dll with SSL support from Windows (Schannel).
rem At the end copies the DLLs along with the IMPLIBs, PDBs and header-includes in the Compiled folder
rem
rem Requires CMake and Visual Studio
rem

set CURL_DIR=%~dp0
set VS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise
set VCVARSALL="%VS%\VC\Auxiliary\Build\vcvarsall.bat"
set COMPILED_FOLDER=%CURL_DIR%Compiled
set BUILD_DIR_X86=%CURL_DIR%build_x86
set BUILD_DIR_X64=%CURL_DIR%build_x64
set MARK=%~nx0 --------------------------------------------------------------

echo %MARK%
pushd %~dp0

echo.
echo Building x86 configuration...
rmdir /s /q %BUILD_DIR_X86% > nul 2>&1
mkdir %BUILD_DIR_X86% || ( call :last_message "Cannot create build_x86 directory" & exit /b 1 )

cd %BUILD_DIR_X86% || ( call :last_message "Cannot change to build_x86 directory" & exit /b 2 )

rem Configure CMake for x86
cmake .. ^
    -G "Visual Studio 17 2022" ^
    -A Win32 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DBUILD_SHARED_LIBS=ON ^
    -DCURL_USE_SCHANNEL=ON ^
    -DCURL_STATICLIB=OFF ^
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
    -DCURL_DISABLE_LIBPSL=ON ^
    -DCURL_USE_LIBPSL=OFF ^
    -DCURL_USE_LIBSSH2=OFF ^
    -DCURL_ZLIB=OFF ^
    -DENABLE_THREADED_RESOLVER=ON ^
    -DMACHINE=x86 ^
    -DP_ARCH=x86 ^
    -DLIBCURL_OUTPUT_NAME=libcurl_x86 ^
    || ( call :last_message "CMake configuration failed for x86" & exit /b 3 )

rem Build
cmake --build . --config Release || ( call :last_message "Build failed for x86" & exit /b 4 )

echo.
echo Building x64 configuration...
cd %CURL_DIR% || ( call :last_message "Cannot return to curl directory" & exit /b 5 )

rmdir /s /q %BUILD_DIR_X64% > nul 2>&1
mkdir %BUILD_DIR_X64% || ( call :last_message "Cannot create build_x64 directory" & exit /b 6 )

cd %BUILD_DIR_X64% || ( call :last_message "Cannot change to build_x64 directory" & exit /b 7 )

rem Configure CMake for x64
cmake .. ^
    -G "Visual Studio 17 2022" ^
    -A x64 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DBUILD_SHARED_LIBS=ON ^
    -DCURL_USE_SCHANNEL=ON ^
    -DCURL_STATICLIB=OFF ^
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
    -DCURL_DISABLE_LIBPSL=ON ^
    -DCURL_USE_LIBPSL=OFF ^
    -DCURL_USE_LIBSSH2=OFF ^
    -DCURL_ZLIB=OFF ^
    -DENABLE_THREADED_RESOLVER=ON ^
    -DMACHINE=x64 ^
    -DP_ARCH=ia64 ^
    -DLIBCURL_OUTPUT_NAME=libcurl_x64 ^
    || ( call :last_message "CMake configuration failed for x64" & exit /b 8 )

rem Build
cmake --build . --config Release || ( call :last_message "Build failed for x64" & exit /b 9 )

echo.
echo Populating Compiled folder...
cd %CURL_DIR% || ( call :last_message "Cannot return to curl directory" & exit /b 10 )

rmdir /s /q %COMPILED_FOLDER%\curl      > nul 2>&1
del /q %COMPILED_FOLDER%\*.lib          > nul 2>&1
del /q %COMPILED_FOLDER%\*.dll          > nul 2>&1
del /q %COMPILED_FOLDER%\*.pdb          > nul 2>&1
mkdir %COMPILED_FOLDER%\curl            || ( call :last_message "Cannot create curl include dir" & exit /b 11 )

rem Copy x86 binaries
copy %BUILD_DIR_X86%\lib\Release\libcurl_x86.dll %COMPILED_FOLDER%\        || ( call :last_message "Cannot copy x86 DLL" & exit /b 12 )
copy %BUILD_DIR_X86%\lib\Release\libcurl_x86_imp.lib %COMPILED_FOLDER%\libcurl_x86.lib || ( call :last_message "Cannot copy x86 LIB" & exit /b 13 )
copy %BUILD_DIR_X86%\lib\Release\libcurl_x86.pdb %COMPILED_FOLDER%\        || ( call :last_message "Cannot copy x86 PDB" & exit /b 14 )

rem Copy x64 binaries
copy %BUILD_DIR_X64%\lib\Release\libcurl_x64.dll %COMPILED_FOLDER%\        || ( call :last_message "Cannot copy x64 DLL" & exit /b 15 )
copy %BUILD_DIR_X64%\lib\Release\libcurl_x64_imp.lib %COMPILED_FOLDER%\libcurl_x64.lib || ( call :last_message "Cannot copy x64 LIB" & exit /b 16 )
copy %BUILD_DIR_X64%\lib\Release\libcurl_x64.pdb %COMPILED_FOLDER%\        || ( call :last_message "Cannot copy x64 PDB" & exit /b 17 )

rem Copy header files
copy %CURL_DIR%include\curl\*.h %COMPILED_FOLDER%\curl\                    || ( call :last_message "Cannot copy headers" & exit /b 18 )

del /q %COMPILED_FOLDER%\*.exp > nul 2>&1

echo.
echo Compile script SUCCEEDED
call :cleanup
exit /b 0

:last_message
	SET RET=%ERRORLEVEL%
	echo *** ERROR: %~1  (error %RET%)
	echo Compile script FAILED (Compiled folder may contain partial compiled files)
	call :cleanup
	GOTO:eof

:cleanup
	echo %MARK%
	popd
	GOTO:eof
