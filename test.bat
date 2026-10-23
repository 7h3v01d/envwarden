@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright 2026 Leon Priest (GitHub: 7h3v01d)
rem Runs the test-suite, then the revert-proof harness.
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe call setup.bat || exit /b 1
set QT_QPA_PLATFORM=offscreen
.venv\Scripts\python.exe -m pytest -q tests || exit /b 1
.venv\Scripts\python.exe tests\revert_check.py || exit /b 1
echo.
echo [test] pip backend pass
set ENVWARDEN_BACKEND=pip
.venv\Scripts\python.exe -m pytest -q tests || exit /b 1
