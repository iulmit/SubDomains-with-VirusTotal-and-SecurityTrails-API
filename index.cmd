@echo off
chcp 65001 1>nul 2>nul
pushd "%~dp0"

if not exist "API_SECURITYTRAILS.txt" ( goto ERROR_NEED_TO_RENAME_API_FILES )
if not exist "API_VIRUSTOTAL.txt"     ( goto ERROR_NEED_TO_RENAME_API_FILES )

call "node.exe" "%~dp0index.js" %*
set /a EXIT_CODE=%ErrorLevel%


:ERROR_NEED_TO_RENAME_API_FILES
  set /a EXIT_CODE=111
  echo [ERROR] you need to rename the .txt.example to just .txt and place your API keys inside.
  goto END

:END
  echo [INFO] EXIT_CODE: %EXIT_CODE% 1>&2
  pause
  popd
  exit /b %EXIT_CODE%
