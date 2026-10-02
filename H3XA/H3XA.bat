@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title H3XA - All-in-One OSINT Framework
set PYTHONUTF8=1
set PY=
where py >nul 2>nul && set PY=py -3
if not defined PY where python >nul 2>nul && set PY=python
if not defined PY (
  echo.
  echo   Python 3.10+ nahi mila. Install karein: https://www.python.org/downloads/
  echo   Install ke waqt "Add python.exe to PATH" ko tick zaroor karein.
  echo.
  start https://www.python.org/downloads/
  pause
  exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" || (
  echo   Python 3.10 ya naya chahiye.
  pause
  exit /b 1
)
mode con: cols=110 lines=45 >nul 2>nul
if not exist "vendor\spiderfoot" (
  echo.
  echo   First run: H3XA will now unpack the 8 modules and set up their environments.
  echo   This needs internet access and can take a few minutes - please wait.
  echo.
)
%PY% -m h3xa
if errorlevel 1 pause
endlocal
