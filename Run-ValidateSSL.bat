@echo off
REM ============================================================================
REM  ValidateSSL - Wrapper para execucao facilitada no cliente.
REM  Nao altera ExecutionPolicy do sistema - usa Bypass local apenas.
REM  Parametros de execucao vem do config.json (secao "execution").
REM ============================================================================

setlocal

set SCRIPT_DIR=%~dp0
set CONFIG_FILE=%SCRIPT_DIR%config.json

if not exist "%CONFIG_FILE%" (
    echo.
    echo [ERRO] Arquivo config.json nao encontrado em: %CONFIG_FILE%
    echo.
    echo Copie config.example.json para config.json e ajuste os valores:
    echo     copy "%SCRIPT_DIR%config.example.json" "%CONFIG_FILE%"
    echo.
    pause
    exit /b 1
)

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%ValidateSSL.ps1" ^
    -ConfigFile "%CONFIG_FILE%"

echo.
pause
