::@echo off
setlocal EnableExtensions
set "EXIT_CODE=0"
chcp 65001 2>nul >nul

::------------------------------------------------------------------------------------
:: wrap for easier domain query to 
:: https://www.virustotal.com/vtapi/v2/domain/report?apikey=<apikey>&domain=<domain>
::------------------------------------------------------------------------------------
for /f "tokens=*" %%a in ('type %~sdp0API.txt') do (set API=%%a)

set "DOMAIN=%~1"

if ["%DOMAIN%"] NEQ [""] ( goto HAS_ARG )


for /f "tokens=*" %%a in ('%~sdp0bin\input2stdout.exe VirusTotal-SubDomains-Query') do (set DOMAIN=%%a)



:HAS_ARG
echo.----------------------------------------
call "%~sdp0index.cmd" "%API%" "%DOMAIN%"
set "EXIT_CODE=%ErrorLevel%"
echo.----------------------------------------


:END
  pause
  exit /b %EXIT_CODE%
