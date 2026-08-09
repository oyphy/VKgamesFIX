@echo off
cd /d "%~dp0"
start "VK Play Machine Fix" powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -Command "& '%~dp0run.bat' go"
