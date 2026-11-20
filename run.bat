@echo off
title Anti Security Scanner
cd /d "%~dp0"
py -3 anti.py %*
if errorlevel 1 pause
