REM
REM This script continuously runs 'opencode' in non-interactive mode
REM to find and fix bugs in the current project directory.
REM
REM REQUIREMENTS:
REM 1. 'opencode' must be installed (e.g., via npm).
REM 2. The Windows-specific installation bugs must be fixed.
REM 3. 'opencode' must be configured (via opencode.json) to
REM    use the 'grok-code' model by default.
REM

:loop
    echo [INFO] Starting bug check cycle...

    REM This is the command to run opencode non-interactively
    REM and give it a specific prompt.
    REM
    REM 'CALL' is required to ensure the loop continues
    REM after the 'opencode.cmd' script finishes.
    CALL opencode run "Review the entire codebase for bugs and code smell and implement fixes for those issues. Please also identify any outstanding compiler warnings and/or errors for all files and fix them accordingly."

    echo [INFO] Cycle complete. Waiting 60 seconds before restart...

    REM Waits for 60 seconds.
    timeout /t 60 > nul

goto loop