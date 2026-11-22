$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Build the Windows EXE inside Windows 10/11, not Linux/macOS." }
Set-Location (Resolve-Path (Join-Path $PSScriptRoot ".."))
$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Create a Python 3.13 virtual environment first: py -3.13 -m venv .venv" }
& $python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "PySide6 installation failed." }
& $python -m pip install pytest pyinstaller
if ($LASTEXITCODE -ne 0) { throw "Build dependencies failed." }
& $python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed; packaging stopped." }
& $python -m PyInstaller --noconfirm --clean --onedir --windowed --name SSG8 --paths src src\ssg8\main.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
if (-not (Test-Path "dist\SSG8\SSG8.exe")) { throw "Build completed without dist\SSG8\SSG8.exe." }
Write-Host "Build finished: dist\SSG8\SSG8.exe"
Write-Host "Still required: Windows GUI, read-only window observation, and recovery testing inside VirtualBox."
