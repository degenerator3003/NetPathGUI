@echo off
setlocal ENABLEDELAYEDEXPANSION

rem === Create desktop shortcut ===
rem === Customize name if you like ===
set "APPNAME=NetPathGUI"
set "SCRIPTNAME_PYW=NetPathGUI.pyw"
set "SCRIPTNAME_PYE=NetPathGUI.py"

rem --- Paths next to this .cmd ---
set "BASEDIR=%~dp0"
set "PYW_VENV1=%BASEDIR%.venv\Scripts\pythonw.exe"
set "PYW_VENV2=%BASEDIR%venv\Scripts\pythonw.exe"
set "SCRIPT_PYW=%BASEDIR%%SCRIPTNAME_PYW%"
set "SCRIPT_PY=%BASEDIR%%SCRIPTNAME_PYE%"
set "DESKTOP=%USERPROFILE%\Desktop"
set "SHORTCUT=%DESKTOP%\%APPNAME%.lnk"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

rem --- Pick the script next to this file ---
set "SCRIPT="
if exist "%SCRIPT_PYW%" set "SCRIPT=%SCRIPT_PYW%"
if not defined SCRIPT if exist "%SCRIPT_PY%" set "SCRIPT=%SCRIPT_PY%"
if not defined SCRIPT (
  echo [ERROR] Could not find regex_tester.py or regex_tester.pyw next to this file.
  pause
  exit /b 1
)

rem --- Find a GUI-capable Python (no console) ---
set "PYEXE="
if exist "%PYW_VENV1%" set "PYEXE=%PYW_VENV1%"
if not defined PYEXE if exist "%PYW_VENV2%" set "PYEXE=%PYW_VENV2%"
if not defined PYEXE (
  for /f "usebackq delims=" %%P in (`where pythonw 2^>NUL`) do (
    set "PYEXE=%%P"
    goto :found_py
  )
)
:found_py
if not defined PYEXE if exist "%WINDIR%\pyw.exe" set "PYEXE=%WINDIR%\pyw.exe"

if not defined PYEXE (
  echo [ERROR] Could not find pythonw.exe or pyw.exe. Install Python 3.x or the Python Launcher.
  pause
  exit /b 1
)

rem --- Build target/args ---
set "TARGET=%PYEXE%"
set "ARGS="
for %%F in ("%TARGET%") do set "TARGETNAME=%%~nxF"
if /I "%TARGETNAME%"=="pyw.exe" set "ARGS=-3 "

set "ARGS=%ARGS%""%SCRIPT%"""
set "WORKDIR=%BASEDIR%"

rem --- Icon (use pythonw.exe by default; prefer dbms.ico if present) ---
set "ICON=%PYEXE%"
if exist "%BASEDIR%dbms.ico" set "ICON=%BASEDIR%dbms.ico"

rem --- Create the .lnk via PowerShell COM ---
"%PS%" -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%SHORTCUT%');" ^
  "$s.TargetPath='%TARGET%';" ^
  "$s.Arguments='%ARGS%';" ^
  "$s.WorkingDirectory='%WORKDIR%';" ^
  "$s.WindowStyle=1;" ^
  "$s.IconLocation='%ICON%';" ^
  "$s.Description='Launch %APPNAME%';" ^
  "$s.Save()"

if errorlevel 1 (
  echo [ERROR] Failed to create shortcut: %SHORTCUT%
  pause
  exit /b 1
)

echo [OK] Created shortcut: %SHORTCUT%
endlocal
exit /b 0

pause

