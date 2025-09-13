@echo off

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: must be run as superuser.
    pause
    exit /b 1
)

python envena.py
