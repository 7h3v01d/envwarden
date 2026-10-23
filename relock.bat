@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright 2026 Leon Priest (GitHub: 7h3v01d)
rem Re-resolve dependencies after editing pyproject.toml, then regenerate the
rem hashed install lock and the SBOM. Commit all three files together.
rem   relock.bat            keep current versions where possible
rem   relock.bat --upgrade  move everything to the newest allowed versions
setlocal
cd /d "%~dp0"
uv lock %* || goto :fail
uv export --frozen --no-emit-project --all-extras --group build --format requirements.txt -o requirements-lock.txt || goto :fail
uv export --frozen --no-dev --format cyclonedx1.5 -o sbom.cdx.json || goto :fail
echo [relock] updated uv.lock, requirements-lock.txt and sbom.cdx.json
exit /b 0
:fail
echo [relock] FAILED
exit /b 1
