@echo off
chcp 65001 >nul
if /i not "%~1"=="go" (
  start "VK Play Machine Fix" powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -Command "& '%~f0' go"
  exit /b
)
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
