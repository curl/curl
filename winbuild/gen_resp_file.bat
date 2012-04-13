@echo OFF
@del %OUTFILE%
@echo %MACRO_NAME% = \> %OUTFILE%
@for %%i in (%*) do @echo		%LIBCURL_DIROBJ%/%%i \>>  %OUTFILE%
@echo. >>  %OUTFILE%
:END
