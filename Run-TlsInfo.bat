@echo off
REM ============================================================================
REM  Wrapper para Get-TlsInfo.ps1
REM
REM  Uso:
REM    Run-TlsInfo.bat
REM        -> usa default (www.hext.nucleaportabilidade.com.br:443)
REM
REM    Run-TlsInfo.bat <host>
REM        -> altera so o host, porta = 443
REM
REM    Run-TlsInfo.bat <host> <porta>
REM        -> altera host e porta (ex: 172.28.46.11 9080)
REM
REM    Run-TlsInfo.bat <host> <porta> <sni>
REM        -> host conecta por IP, mas SNI forcado (util para IP literal)
REM ============================================================================

setlocal

if "%~1"=="" (
    set HOST=www.hext.nucleaportabilidade.com.br
) else (
    set HOST=%~1
)

if "%~2"=="" (
    set PORT=443
) else (
    set PORT=%~2
)

if "%~3"=="" (
    set SNI_ARG=
) else (
    set SNI_ARG=-Sni %~3
)

echo.
echo Executando Get-TlsInfo para %HOST%:%PORT%
echo.

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0Get-TlsInfo.ps1" ^
    -HostName %HOST% ^
    -Port %PORT% ^
    %SNI_ARG%

echo.
pause
