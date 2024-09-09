@echo off
rem 
rem Script for building cul Driver dependency curl repo
rem At the end files are copied in Compiled folder, then nuget.exe is invoked for creating a .nupkg
rem Please commit all the files and also the nuget package.
rem 
rem 

set NUGET_EXE=c:\src\driver\.nuget\nuget.exe
set CRT_VERSION=8.9.1.2

cls
pushd %~dp0


call my_build_curl.cmd || ( call :inform_about "curl" & exit /b 1 )
rem add other script invokes here

echo Creating nuget package

%NUGET_EXE% pack -Version %CRT_VERSION% -Symbols -NoPackageAnalysis -OutputDirectory Compiled UiPath.Curl.nuspec -Prop OutputPath=Compiled\  || ( call :inform_about "nuget package" & exit /b 1 )

echo.
echo.
echo All dependencies built, "git commit -a Compile" by yourself.
popd
exit /b 0

:inform_about
	SET RET=%ERRORLEVEL%
	echo *** ERROR: cannot build %~1  (error %RET%)
	popd
	GOTO:eof
