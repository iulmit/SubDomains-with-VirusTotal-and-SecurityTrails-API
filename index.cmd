@echo off
chcp 65001 1>nul 2>nul
pushd "%~dp0"

call "node.exe" "%~dp0index.js" %*
set /a EXIT_CODE=%ErrorLevel%

echo [INFO] EXIT_CODE: %EXIT_CODE% 1>&2
pause
popd
exit /b %EXIT_CODE%
