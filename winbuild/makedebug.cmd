@echo off

where.exe nmake.exe >nul 2>&1

IF %ERRORLEVEL == 1 (
    ECHO Error: Can't find `nmake.exe` - be sure to run this script from within a Developer Command-Prompt
    ECHO.
) ELSE (
    nmake /f Makefile.vc mode=static DEBUG=yes GEN_PDB=yes 
    IF %ERRORLEVEL% NEQ 0 (ECHO "Error: Build Failed")
)

