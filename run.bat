@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright 2026 Leon Priest (GitHub: 7h3v01d)
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe call setup.bat || exit /b 1
.venv\Scripts\python.exe -m envwarden %*
