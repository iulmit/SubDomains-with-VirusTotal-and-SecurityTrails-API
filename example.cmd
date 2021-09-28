@echo off
chcp 65001 1>nul 2>nul
pushd "%~dp0"
call "index.cmd" %*
set "EXIT_CODE=%ErrorLevel%"
popd
exit /b %EXIT_CODE%
