@echo off
echo ========================================================
echo   NetPhantom v3.3.2 — Build Pipeline
echo ========================================================

cd /d "%~dp0"

REM --- Step 1: Install Python dependencies ---
echo.
echo [1/3] Installing Python dependencies...
pip install -r ..\..\requirements.txt pyinstaller --quiet 2>nul

REM --- Step 2: Build NetPhantom application bundle ---
echo.
echo [2/3] Building NetPhantom application bundle...
pyinstaller -y --clean NetPhantom.spec
if errorlevel 1 (
    echo ERROR: Failed to build NetPhantom.exe
    echo Check the output above for details.
    pause
    exit /b 1
)

if not exist "dist\NetPhantom\NetPhantom.exe" (
    echo ERROR: NetPhantom.exe not found in dist\NetPhantom\
    pause
    exit /b 1
)

echo SUCCESS: dist\NetPhantom\NetPhantom.exe built.

REM --- Step 3: Build Setup Installer ---
echo.
echo [3/3] Building NetPhantom_Setup.exe installer...
pyinstaller -y --clean NetPhantom_Setup.spec
if errorlevel 1 (
    echo ERROR: Failed to build NetPhantom_Setup.exe
    pause
    exit /b 1
)

if exist "dist\NetPhantom_Setup.exe" (
    echo.
    echo Packaging installer into NetPhantom_Setup.zip...
    powershell -Command "Compress-Archive -Path 'dist\NetPhantom_Setup.exe' -DestinationPath 'dist\NetPhantom_Setup.zip' -Force"
    echo.
    echo ===================================================
    echo  BUILD COMPLETE!
    echo  Application: dist\NetPhantom\NetPhantom.exe
    echo  Installer:   dist\NetPhantom_Setup.exe
    echo  Zip:         dist\NetPhantom_Setup.zip
    echo ===================================================
) else (
    echo ERROR: PyInstaller failed to generate NetPhantom_Setup.exe
)
pause
