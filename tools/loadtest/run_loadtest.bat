@echo off
REM Cerberus Load Tester - Quick Launch Script

echo.
echo ========================================
echo   Cerberus Load Tester (Go Edition)
echo ========================================
echo.

REM Build if executable doesn't exist
if not exist loadtest.exe (
    echo Building load tester...
    go build -o loadtest.exe .
    if errorlevel 1 (
        echo Failed to build!
        pause
        exit /b 1
    )
    echo Build successful!
    echo.
)

REM Run with default parameters or pass through arguments
if "%~1"=="" (
    echo Running with default parameters...
    echo.
    loadtest.exe
) else (
    echo Running with custom parameters: %*
    echo.
    loadtest.exe %*
)

echo.
echo ========================================
echo   Test Complete
echo ========================================
echo.
pause
