@echo off
set "EXIT_CODE=0"

chcp 65001 2>nul >nul


:HAS_ARG
call "node.exe" "%~sdp0index.js" %*
set "EXIT_CODE=%ErrorLevel%"

goto EXIT


:EXIT
  pause
  exit /b %EXIT_CODE%
