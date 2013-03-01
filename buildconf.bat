@echo off
REM
REM
REM This batch file must be used to set up a git tree to build on
REM systems where there is no autotools support (i.e. Microsoft).
REM
REM This file is not included nor needed for curl's release
REM archives, neither for curl's daily snapshot archives.

if exist GIT-INFO goto start_doing
ECHO ERROR: This file shall only be used with a curl git tree checkout.
goto end_all
:start_doing

REM create tool_hugehelp.c
if not exist src\tool_hugehelp.c.cvs goto end_hugehelp_c
copy /Y src\tool_hugehelp.c.cvs src\tool_hugehelp.c
:end_hugehelp_c

REM create Makefile
if not exist Makefile.dist goto end_makefile
copy /Y Makefile.dist Makefile
:end_makefile

REM create curlbuild.h
if not exist include\curl\curlbuild.h.dist goto end_curlbuild_h
copy /Y include\curl\curlbuild.h.dist include\curl\curlbuild.h
:end_curlbuild_h

REM setup c-ares git tree
if not exist ares\buildconf.bat goto end_c_ares
cd ares
call buildconf.bat
cd ..
:end_c_ares

:end_all

