@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -Command "& '%~dp0run.bat' go"
