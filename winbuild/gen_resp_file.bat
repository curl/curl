@echo OFF
@del %OUTFILE%
@echo %MACRO_NAME% = \> %OUTFILE%
@for %%i in (%*) do @echo		%DIROBJ%/%%i \>>  %OUTFILE%
@echo. >>  %OUTFILE%
:END
