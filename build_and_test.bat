@echo off
REM PolicyEnumerator Build and Test Helper
REM Run from Administrator Command Prompt

setlocal enabledelayedexpansion

echo ================================================
echo  WDAC Policy Enumerator - Build and Test Helper
echo ================================================
echo.

:menu
echo Select an option:
echo.
echo  1. Build driver (requires WDK environment)
echo  2. Sign driver (test certificate)
echo  3. Install and start driver
echo  4. Stop and uninstall driver
echo  5. Enable test signing
echo  6. Disable test signing
echo  7. View driver output (start DebugView)
echo  8. Check if policies exist
echo  9. Exit
echo.
set /p choice="Enter choice (1-9): "

if "%choice%"=="1" goto build
if "%choice%"=="2" goto sign
if "%choice%"=="3" goto install
if "%choice%"=="4" goto uninstall
if "%choice%"=="5" goto enable_test
if "%choice%"=="6" goto disable_test
if "%choice%"=="7" goto debugview
if "%choice%"=="8" goto check_policies
if "%choice%"=="9" goto end
goto menu

:build
echo.
echo Building driver...
if exist "PolicyEnumerator.vcxproj" (
    msbuild PolicyEnumerator.vcxproj /p:Configuration=Release /p:Platform=x64
) else (
    echo ERROR: Project file not found. Build manually in Visual Studio.
)
echo.
pause
goto menu

:sign
echo.
echo Creating test certificate and signing driver...
echo.

REM Check if certificate already exists
certmgr /s /r localMachine root | findstr "PolicyEnumTest" > nul
if %errorlevel%==0 (
    echo Certificate already exists.
) else (
    echo Creating test certificate...
    makecert -r -pe -ss PrivateCertStore -n "CN=PolicyEnumTest" PolicyEnumTest.cer
    certmgr /add PolicyEnumTest.cer /s /r localMachine root
    certmgr /add PolicyEnumTest.cer /s /r localMachine trustedpublisher
)

echo.
echo Signing driver...
if exist "x64\Release\PolicyEnumerator.sys" (
    signtool sign /s PrivateCertStore /n "PolicyEnumTest" /t http://timestamp.digicert.com x64\Release\PolicyEnumerator.sys
    echo Driver signed successfully.
) else if exist "PolicyEnumerator.sys" (
    signtool sign /s PrivateCertStore /n "PolicyEnumTest" /t http://timestamp.digicert.com PolicyEnumerator.sys
    echo Driver signed successfully.
) else (
    echo ERROR: Driver file not found. Build first.
)
echo.
pause
goto menu

:install
echo.
echo Installing and starting driver...
echo.

REM Find the driver file
set DRIVER_PATH=
if exist "x64\Release\PolicyEnumerator.sys" set DRIVER_PATH=x64\Release\PolicyEnumerator.sys
if exist "PolicyEnumerator.sys" set DRIVER_PATH=PolicyEnumerator.sys

if "%DRIVER_PATH%"=="" (
    echo ERROR: Driver file not found.
    pause
    goto menu
)

REM Copy to system directory
echo Copying driver to system directory...
copy "%DRIVER_PATH%" "%SystemRoot%\System32\drivers\" /Y

REM Create service
echo Creating service...
sc create PolicyEnumerator type= kernel binPath= "%SystemRoot%\System32\drivers\PolicyEnumerator.sys" start= demand

REM Start service
echo Starting driver...
sc start PolicyEnumerator

echo.
echo Driver installed and started.
echo View output in DebugView (option 7).
echo.
pause
goto menu

:uninstall
echo.
echo Stopping and uninstalling driver...
echo.

sc stop PolicyEnumerator
sc delete PolicyEnumerator
del "%SystemRoot%\System32\drivers\PolicyEnumerator.sys" /F

echo Driver removed.
echo.
pause
goto menu

:enable_test
echo.
echo Enabling test signing mode...
echo This requires a reboot.
echo.
bcdedit /set testsigning on
echo.
echo Test signing enabled.
set /p reboot="Reboot now? (Y/N): "
if /i "%reboot%"=="Y" shutdown /r /t 10 /c "Rebooting to enable test signing..."
pause
goto menu

:disable_test
echo.
echo Disabling test signing mode...
echo This requires a reboot.
echo.
bcdedit /set testsigning off
echo.
echo Test signing disabled.
set /p reboot="Reboot now? (Y/N): "
if /i "%reboot%"=="Y" shutdown /r /t 10 /c "Rebooting to disable test signing..."
pause
goto menu

:debugview
echo.
echo Starting DebugView...
echo.
echo If DebugView is installed, it will open.
echo Otherwise, download from:
echo https://learn.microsoft.com/sysinternals/downloads/debugview
echo.
echo Remember to enable "Capture Kernel" (Ctrl+K) in DebugView!
echo.

REM Try to launch DebugView
if exist "C:\Program Files\Sysinternals\Dbgview.exe" (
    start "" "C:\Program Files\Sysinternals\Dbgview.exe"
) else if exist "Dbgview.exe" (
    start "" "Dbgview.exe"
) else (
    echo DebugView not found in standard locations.
    echo Please launch manually.
)

pause
goto menu

:check_policies
echo.
echo Checking for WDAC policy files...
echo.

if exist "%SystemRoot%\System32\CodeIntegrity\SiPolicy.p7b" (
    echo [FOUND] SiPolicy.p7b
    dir "%SystemRoot%\System32\CodeIntegrity\SiPolicy.p7b" | findstr "p7b"
) else (
    echo [NOT FOUND] SiPolicy.p7b
)

echo.
if exist "%SystemRoot%\System32\CodeIntegrity\driversipolicy.p7b" (
    echo [FOUND] driversipolicy.p7b
    dir "%SystemRoot%\System32\CodeIntegrity\driversipolicy.p7b" | findstr "p7b"
) else (
    echo [NOT FOUND] driversipolicy.p7b
)

echo.
if exist "%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active" (
    echo [FOUND] Multiple policy directory
    dir "%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\*.cip" 2>nul
) else (
    echo [NOT FOUND] Multiple policy directory
)

echo.
echo You can also use: CiTool.exe -lp (Windows 11 2022+)
echo.
pause
goto menu

:end
echo.
echo Exiting...
endlocal
exit /b 0

