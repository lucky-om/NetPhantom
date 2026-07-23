@echo off
echo ===================================================
echo   Building NetPhantom Lightweight Web-Installer
echo ===================================================

cd /d "%~dp0"

echo Building installer.exe via PyInstaller...
pyinstaller --clean NetPhantom_Setup.spec

if exist "dist\NetPhantom_Setup.exe" (
    echo.
    echo Packaging installer into NetPhantom_Setup.zip...
    powershell -Command "Compress-Archive -Path 'dist\NetPhantom_Setup.exe' -DestinationPath 'dist\NetPhantom_Setup.zip' -Force"
    echo.
    echo ===================================================
    echo  SUCCESS: dist\NetPhantom_Setup.zip generated!
    echo ===================================================
) else (
    echo ERROR: PyInstaller failed to generate NetPhantom_Setup.exe
)
pause
