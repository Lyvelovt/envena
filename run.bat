@echo off

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: must be runned as root.
    pause
    exit /b 1
)

python envena.py
