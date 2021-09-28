@echo off
chcp 65001 1>nul 2>nul
pushd "%~dp0"

if not exist "API_SECURITYTRAILS.txt" ( goto ERROR_NEED_TO_RENAME_API_FILES )
if not exist "API_VIRUSTOTAL.txt"     ( goto ERROR_NEED_TO_RENAME_API_FILES )

::"--trace-warnings"
call "node.exe" "--no-warnings" "%~dp0index.js" %*
set "EXIT_CODE=%ErrorLevel%"

if ["%EXIT_CODE%"] NEQ ["0"] ( goto ERROR_NODE )

echo [INFO] success. 1>&2

goto END


:ERROR_NEED_TO_RENAME_API_FILES
  set "EXIT_CODE=222"
  echo [ERROR] you need to rename the .txt.example to just .txt and place your API keys inside. 1>&2
  goto END

:ERROR_NODE
  ::EXIT_CODE is already provided by node.exe (111 is "soft" error, of no results).
  echo [ERROR] node.exe ended up with an error. 1>&2
  goto END
  
:END
  echo [INFO] EXIT_CODE: %EXIT_CODE% 1>&2
  if ["%EXIT_CODE%"] NEQ ["0"] ( pause )
  popd
  exit /b %EXIT_CODE%
