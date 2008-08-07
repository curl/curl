@echo off
REM set up a CVS tree to build when there's no autotools
REM $Revision$
REM $Date$

REM create hugehelp.c
copy src\hugehelp.c.cvs src\hugehelp.c

REM create Makefile
copy Makefile.dist Makefile

REM create curlbuild.h
copy include\curl\curlbuild.h.dist include\curl\curlbuild.h
