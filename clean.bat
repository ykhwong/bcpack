@echo off
REM
REM This library is free software; you can redistribute it and/or
REM modify it under the terms of the GNU Lesser General Public
REM License as published by the Free Software Foundation; either
REM version 2.1 of the License, or (at your option) any later version.
REM
REM This library is distributed in the hope that it will be useful,
REM but WITHOUT ANY WARRANTY; without even the implied warranty of
REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
REM Lesser General Public License for more details.
REM
REM You should have received a copy of the GNU Lesser General Public
REM License along with this library; if not, write to the Free Software
REM Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
REM
if not "%OS%" == "Windows_NT" goto nt_err
SETLOCAL enableextensions >nul 2>&1
SETLOCAL DisableDelayedExpansion >nul 2>&1
SET PATH_VAR=%PATH%;.
cd /d "%~dp0" >nul 2>&1

SET FINDSTR_ENABLED=0
SET WORKSPACE_DIR=.\workspace\
SET CONFIG_FILE=config.cfg

if exist "%CONFIG_FILE%" goto set_workspace

:check
if exist "%WORKSPACE_DIR%" (
	rmdir /s /q "%WORKSPACE_DIR%" 2>nul
	if exist "%WORKSPACE_DIR%" (
		echo Failed to remove: %WORKSPACE_DIR%
	) else (
		echo Done
	)
	pause >nul
	goto done
)
echo Nothing to do && pause >nul
goto done

:set_workspace
for %%A in ("%PATH_VAR:;=";"%") do (
	if exist "%%~A\findstr.exe" SET FINDSTR_ENABLED=1 && goto :set_workspace2
)

:set_workspace2
if "%FINDSTR_ENABLED%" == "0" (
	echo FINDSTR is not available. Setting WORKSPACE_DIR to %WORKSPACE_DIR%
	goto check
)

set MYVAR=
FOR /F "usebackq delims=" %%a in (`"findstr /R "^RESULT_PATH=" %CONFIG_FILE%"`) do (
	set MYVAR=%%a
)
set WORKSPACE_DIR=%MYVAR:~12%
goto check

:nt_err
echo This program requires Microsoft Windows NT-family.
goto done

:done
