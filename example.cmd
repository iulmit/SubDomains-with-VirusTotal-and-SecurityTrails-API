@echo off
chcp 65001 2>nul >nul
pushd "%~sdp0"

call "node.exe" "%~sdp0index.js" %*

::pause
exit /b 0
