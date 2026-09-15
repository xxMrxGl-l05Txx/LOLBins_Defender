@echo off
setlocal
echo Installing Security Monitoring System as a Windows service...

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Administrative privileges required.
    echo Please run this script as an administrator.
    pause
    exit /b 1
)

:: Set paths. SCRIPT_DIR ends with a backslash; APP_DIR does not, because a
:: trailing backslash before a closing quote breaks argument parsing.
set "SCRIPT_DIR=%~dp0"
set "APP_DIR=%SCRIPT_DIR:~0,-1%"
set "NSSM=%SCRIPT_DIR%nssm.exe"
set "LOG_DIR=%SCRIPT_DIR%data\logs"
set "SERVICE_NAME=SecurityMonitoringService"
set "SERVICE_DISPLAY_NAME=Security Monitoring and Alerting System"
set "SERVICE_DESCRIPTION=Monitors system resources and detects potential security incidents"

:: Resolve the full path to Python - services do not inherit the user's PATH,
:: and the Microsoft Store "python.exe" alias does not work for services.
set "PYTHON_EXE="
for /f "delims=" %%i in ('where python 2^>nul ^| findstr /v /i "WindowsApps"') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
if not defined PYTHON_EXE (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)
echo Using Python: %PYTHON_EXE%

:: Install dependencies before the service tries to start
echo Installing required Python packages...
"%PYTHON_EXE%" -m pip install -r "%SCRIPT_DIR%requirements.txt"
if %errorLevel% neq 0 (
    echo Error: Failed to install Python packages.
    pause
    exit /b 1
)

:: Download NSSM if needed
if not exist "%NSSM%" (
    echo Downloading NSSM - the Non-Sucking Service Manager...
    powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest 'https://nssm.cc/release/nssm-2.24.zip' -OutFile \"$env:TEMP\nssm.zip\"; Expand-Archive \"$env:TEMP\nssm.zip\" -DestinationPath \"$env:TEMP\nssm\" -Force"
    copy "%TEMP%\nssm\nssm-2.24\win64\nssm.exe" "%NSSM%" >nul
    del /q "%TEMP%\nssm.zip" >nul 2>&1
    rmdir /s /q "%TEMP%\nssm" >nul 2>&1
)
if not exist "%NSSM%" (
    echo Error: Could not download NSSM. Download it manually from https://nssm.cc and place nssm.exe next to this script.
    pause
    exit /b 1
)

:: Remove an existing installation
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo Service already exists. Removing...
    "%NSSM%" stop %SERVICE_NAME% >nul 2>&1
    "%NSSM%" remove %SERVICE_NAME% confirm >nul 2>&1
    timeout /t 2 >nul
)

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:: Install service using NSSM
echo Installing service using NSSM...
"%NSSM%" install %SERVICE_NAME% "%PYTHON_EXE%" -m backend.utils.enhanced_service_runner --daemon
"%NSSM%" set %SERVICE_NAME% DisplayName "%SERVICE_DISPLAY_NAME%"
"%NSSM%" set %SERVICE_NAME% Description "%SERVICE_DESCRIPTION%"
"%NSSM%" set %SERVICE_NAME% AppDirectory "%APP_DIR%"
"%NSSM%" set %SERVICE_NAME% AppStdout "%LOG_DIR%\service.log"
"%NSSM%" set %SERVICE_NAME% AppStderr "%LOG_DIR%\service_error.log"
"%NSSM%" set %SERVICE_NAME% AppRotateFiles 1
"%NSSM%" set %SERVICE_NAME% AppRotateOnline 1
"%NSSM%" set %SERVICE_NAME% AppRotateSeconds 86400
"%NSSM%" set %SERVICE_NAME% Start SERVICE_AUTO_START

:: Start the service
echo Starting the service...
"%NSSM%" start %SERVICE_NAME%

echo.
echo Security Monitoring Service installed successfully!
echo Service Name: %SERVICE_NAME%
echo API: http://127.0.0.1:5000/api/v1/status
echo Logs: %LOG_DIR%
echo.
echo To uninstall, run: "%NSSM%" remove %SERVICE_NAME% confirm
echo.

pause
