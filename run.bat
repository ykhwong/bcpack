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
set RETCODE=0
set CMD_ENABLED=0
set CHCP_ENABLED=0
set PERL_ENABLED=0
set MAIN_TOOL=.\tool\main.pl

if not "%OS%" == "Windows_NT" goto nt_err
setlocal enableextensions >nul 2>&1
cd /d "%~dp0" >nul 2>&1

REM Check PATH
if "%PATH%" == "" goto start
for %%A in ("%path:;=";"%") do (
	if "%CHCP_ENABLED%" == "0" (
		if exist "%%~A\chcp.com" set CHCP_ENABLED=1
	)
	if "%PERL_ENABLED%" == "0" (
		if exist "%%~A\perl.exe" set PERL_ENABLED=1
	)
	if "%CMD_ENABLED%" == "0" (
		if exist "%%~A\cmd.exe" set CMD_ENABLED=1
	)
	if "%CHCP_ENABLED%" == "1" (
		if "%PERL_ENABLED%" == "1" (
			if "%CMD_ENABLED%" == "1" (
				goto :eof
			)
		)
	)
)

:start
REM Check perl availability
if not "%PERL_ENABLED%" == "1" (
	echo Perl is not available. && pause >nul
	if "%CMD_ENABLED%" == "1" cmd /c "exit /b 1"
	goto done
)

REM Set codepage to 437
REM if "%CHCP_ENABLED%" == "1" chcp 437 >nul

REM Check main tool
if not exist "%MAIN_TOOL%" (
	echo File not found: "%MAIN_TOOL%" && pause >nul
	if "%CMD_ENABLED%" == "1" cmd /c "exit /b 1"
	goto done
)

REM Execute the main tool
perl "%MAIN_TOOL%" %*
set RETCODE=%errorlevel% && pause >nul
if "%CMD_ENABLED%" == "1" cmd /c "exit /b %RETCODE%"
goto done

:nt_err
echo This program requires Microsoft Windows NT-family.
goto done

:done
