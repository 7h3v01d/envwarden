@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright 2026 Leon Priest (GitHub: 7h3v01d)
rem Creates .venv and installs EnvWarden from the hash-locked dependency set.
rem Every package (including the setuptools build backend) is verified against
rem requirements-lock.txt; nothing unpinned is downloaded.
setlocal
cd /d "%~dp0"
where uv >nul 2>nul
if %errorlevel%==0 (
    echo [setup] uv found - using uv
    uv venv .venv || goto :fail
    uv pip sync --python .venv\Scripts\python.exe --require-hashes requirements-lock.txt || goto :fail
    uv pip install --python .venv\Scripts\python.exe --no-deps --no-build-isolation -e . || goto :fail
) else (
    echo [setup] uv not found - using python -m venv + pip
    echo [setup] tip: "winget install astral-sh.uv" makes EnvWarden much faster
    python -m venv .venv || goto :fail
    .venv\Scripts\python.exe -m pip install --require-hashes -r requirements-lock.txt || goto :fail
    .venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e . || goto :fail
)
.venv\Scripts\python.exe -m pip check 2>nul
echo [setup] done. Run run.bat
exit /b 0
:fail
echo [setup] FAILED
exit /b 1
