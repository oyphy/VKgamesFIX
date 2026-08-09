@echo off
chcp 65001 >nul
set "VKPM_BAT=%~f0"
set "VKPM_DIR=%~dp0"
if /i "%~1"=="go" goto work
if /i "%~1"=="user" goto user

powershell.exe -NoProfile -Command "$p=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent(); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
if errorlevel 1 goto user

echo.
echo фикс запустился от админа, перезапускаю с обычными правами...
powershell.exe -NoProfile -Command "$s=New-Object -ComObject Shell.Application; $s.ShellExecute($env:VKPM_BAT,'user',$env:VKPM_DIR,'open',1)"
exit /b

:user
powershell.exe -NoProfile -Command "$p=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent(); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
if not errorlevel 1 goto nouser
powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -Command "& $env:VKPM_BAT go"
exit /b

:nouser
echo.
echo не получилось убрать права администратора
echo включи UAC и перезагрузи компьютер
echo.
pause
exit /b 1

:work
setlocal
cd /d "%~dp0"
title VK Play Machine Fix

set "py=python"
python --version >nul 2>&1 && goto pyok
set "py=py"
py --version >nul 2>&1 && goto pyok

echo.
echo питона нет, щас попробую поставить сам
where winget >nul 2>&1
if errorlevel 1 goto nopy

winget install --id Python.Python.3.12 -e --scope user --silent --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto nopy

set "py=%LocalAppData%\Programs\Python\Python312\python.exe"
if exist "%py%" goto pyok
set "py=py"
py --version >nul 2>&1 && goto pyok
goto nopy

:nopy
echo.
echo сам питон не поставился
echo скачай его тут: https://www.python.org/downloads/
echo и поставь галочку Add Python to PATH
echo.
pause
exit /b 1

:pyok

echo.
echo ================================
echo      VK PLAY MACHINE FIX
echo ================================
echo.
echo щас поставлю что нужно и запущу машину
echo это окно потом не закрывай пока играешь
echo.

"%py%" -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 (
  echo.
  echo не получилось поставить библиотеки
  echo проверь интернет и попробуй еще раз
  pause
  exit /b 1
)

echo.
"%py%" -m vkpm_fix fix
echo.
echo фикс остановлен
pause
endlocal
