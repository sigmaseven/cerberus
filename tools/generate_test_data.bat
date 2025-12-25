@echo off
REM Comprehensive Test Data Generation Script for Cerberus SIEM
REM This script seeds the database and executes attack scenarios

echo ========================================
echo Cerberus Test Data Generation
echo ========================================
echo.

REM Check if Cerberus API is running
echo [1/5] Checking if Cerberus API is running...
curl -s -o NUL -w "%%{http_code}" http://localhost:8080/api/v1/health > temp_status.txt 2>&1
set /p STATUS=<temp_status.txt
del temp_status.txt

if NOT "%STATUS%"=="200" (
    echo ERROR: Cerberus API is not running on http://localhost:8080
    echo Please start the Cerberus API first: ./cerberus.exe
    echo.
    pause
    exit /b 1
)
echo OK - API is running
echo.

REM Step 1: Seed rules and actions
echo [2/5] Seeding detection rules, correlation rules, and actions...
bin\seed.exe -rules -actions -clear
if errorlevel 1 (
    echo ERROR: Failed to seed rules and actions
    pause
    exit /b 1
)
echo.

REM Step 2: Wait for rules to be loaded
echo [3/5] Waiting 5 seconds for rules to be loaded...
timeout /t 5 /nobreak > NUL
echo.

REM Step 3: Execute generic scenarios
echo [4/5] Executing generic attack scenarios...
echo.

echo   - Executing Brute Force scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/brute_force.yaml
echo.

echo   - Executing Port Scan scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/port_scan.yaml
echo.

echo   - Executing Data Exfiltration scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/data_exfiltration.yaml
echo.

echo   - Executing Lateral Movement scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/lateral_movement.yaml
echo.

REM Step 4: Execute Windows-specific scenarios
echo [5/5] Executing Windows-specific attack scenarios...
echo.

echo   - Executing Windows Brute Force scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_brute_force.yaml
echo.

echo   - Executing Windows Account Compromise scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_account_compromise.yaml
echo.

echo   - Executing Windows Privilege Escalation scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_privilege_escalation.yaml
echo.

echo   - Executing Windows Audit Tampering scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_audit_tampering.yaml
echo.

echo   - Executing Windows Persistence scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_persistence.yaml
echo.

echo   - Executing Windows Mass Deletion scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_mass_deletion.yaml
echo.

echo   - Executing Windows Lateral Movement scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_lateral_movement.yaml
echo.

echo   - Executing Windows System Compromise scenario...
bin\scenario.exe -scenario tools/scenarios/definitions/windows_system_compromise.yaml
echo.

echo ========================================
echo Test Data Generation Complete!
echo ========================================
echo.
echo You can now view the generated data:
echo   - Events: http://localhost:8080/events
echo   - Alerts: http://localhost:8080/alerts
echo   - Dashboard: http://localhost:8080/
echo.
pause
