<#
.SYNOPSIS
    Inspeciona handshake TLS de um host - similar a 'openssl s_client'.

.DESCRIPTION
    Captura:
      - Chain completa de certificados (subject, issuer, validade, SANs)
      - Versao TLS negociada
      - Cipher suite
      - Tamanho da chave publica
      - Validacao do certificado

    Limitacao: .NET Framework 4.x nao expoe 'Acceptable client CAs'.
    Para isso, use openssl.exe (vem no Git for Windows) ou curl.exe -v.

.PARAMETER Host
    Hostname a inspecionar (ex: www.exemplo.com.br)

.PARAMETER Port
    Porta (default 443)

.PARAMETER Sni
    Server Name Indication. Se omitido, usa o proprio Host.

.EXAMPLE
    .\Get-TlsInfo.ps1 -Host www.hext.nucleaportabilidade.com.br

.EXAMPLE
    .\Get-TlsInfo.ps1 -Host 172.28.46.11 -Port 9080 -Sni www.cliente.com.br
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,

    [int]$Port = 443,

    [string]$Sni,

    [ValidateSet("Tls", "Tls11", "Tls12", "Tls13", "Default")]
    [string]$Protocol = "Default",

    [ValidateRange(1, 60)]
    [int]$ConnectTimeoutSeconds = 10,

    [string]$OutputDir = ".\\logs",

    [switch]$StrictValidation
)

$ErrorActionPreference = 'Stop'

if (-not $Sni) { $Sni = $HostName }

if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $resolvedOutputDir = $OutputDir
}
else {
    $resolvedOutputDir = Join-Path $PSScriptRoot $OutputDir
}

if (-not (Test-Path $resolvedOutputDir -PathType Container)) {
    New-Item -Path $resolvedOutputDir -ItemType Directory -Force | Out-Null
}

$safeHost = ($HostName -replace '[^a-zA-Z0-9._-]', '_')
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $resolvedOutputDir ("tlsinfo_{0}_{1}_{2}.txt" -f $safeHost, $Port, $ts)

Start-Transcript -Path $reportFile -Force | Out-Null
$script:transcriptStarted = $true

function Stop-AndExit {
    param([int]$Code)

    if ($script:transcriptStarted) {
        try { Stop-Transcript | Out-Null }
        catch { }
    }

    if ($Code -eq 0) {
        Write-Host "Report salvo em: $reportFile" -ForegroundColor Green
    }
    else {
        Write-Host "Report salvo em: $reportFile" -ForegroundColor Yellow
    }

    exit $Code
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  Get-TlsInfo - inspecao de handshake TLS"
Write-Host "============================================================"
Write-Host "Host    : $HostName"
Write-Host "Port    : $Port"
Write-Host "SNI     : $Sni"
Write-Host "Protocol: $Protocol"
Write-Host "Strict  : $($StrictValidation.IsPresent)"
Write-Host ""

# DNS
$dnsMs = $null
try {
    $dnsSw = [System.Diagnostics.Stopwatch]::StartNew()
    $ips = [System.Net.Dns]::GetHostAddresses($HostName)
    $dnsSw.Stop()
    $dnsMs = $dnsSw.ElapsedMilliseconds
    Write-Host "DNS resolvido:" -ForegroundColor DarkGray
    foreach ($ip in $ips) {
        Write-Host "  -> $($ip.IPAddressToString)" -ForegroundColor DarkGray
    }
    Write-Host ("DNS time: {0} ms" -f $dnsMs) -ForegroundColor DarkGray
}
catch {
    Write-Host "DNS falhou: $($_.Exception.Message)" -ForegroundColor Red
    Stop-AndExit 1
}
Write-Host ""

# Conectar
$tcp = New-Object System.Net.Sockets.TcpClient
$tcpMs = $null
try {
    $tcpSw = [System.Diagnostics.Stopwatch]::StartNew()
    $connectTask = $tcp.ConnectAsync($HostName, $Port)
    if (-not $connectTask.Wait($ConnectTimeoutSeconds * 1000)) {
        throw "TCP timeout apos $ConnectTimeoutSeconds segundos"
    }
    $tcpSw.Stop()
    $tcpMs = $tcpSw.ElapsedMilliseconds
    Write-Host "TCP conectado em $($tcp.Client.RemoteEndPoint)" -ForegroundColor Green
    Write-Host ("TCP time: {0} ms" -f $tcpMs) -ForegroundColor DarkGray
}
catch {
    Write-Host "TCP falhou: $($_.Exception.Message)" -ForegroundColor Red
    Stop-AndExit 1
}

# Captura certs no callback de validacao
$script:capturedChain = @()
$script:capturedSslPolicyErrors = [System.Net.Security.SslPolicyErrors]::None
$script:capturedChainStatus = @()
$validationCallback = {
    param($sender, $cert, $chain, $sslErrors)
    $script:capturedSslPolicyErrors = $sslErrors
    foreach ($elem in $chain.ChainElements) {
        $script:capturedChain += $elem.Certificate
    }
    $script:capturedChainStatus = @()
    foreach ($st in $chain.ChainStatus) {
        $script:capturedChainStatus += [pscustomobject]@{
            Status = $st.Status.ToString()
            Info   = ($st.StatusInformation -replace "\r|\n", " ").Trim()
        }
    }
    $true  # aceita para fins de diagnostico
}

$sslProtocols = switch ($Protocol) {
    "Tls"     { [System.Security.Authentication.SslProtocols]::Tls }
    "Tls11"   { [System.Security.Authentication.SslProtocols]::Tls11 }
    "Tls12"   { [System.Security.Authentication.SslProtocols]::Tls12 }
    "Tls13"   {
        try { [System.Security.Authentication.SslProtocols]::Tls13 }
        catch {
            Write-Warning "Tls13 nao disponivel neste .NET. Usando Tls12|Tls13 automatico (Default)."
            [System.Security.Authentication.SslProtocols]::None  # SChannel escolhe
        }
    }
    "Default" { [System.Security.Authentication.SslProtocols]::None }  # deixa SChannel decidir
}

$ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $validationCallback)

$tlsMs = $null
try {
    $tlsSw = [System.Diagnostics.Stopwatch]::StartNew()
    $ssl.AuthenticateAsClient($Sni, $null, $sslProtocols, $true)
    $tlsSw.Stop()
    $tlsMs = $tlsSw.ElapsedMilliseconds
}
catch {
    Write-Host "TLS handshake falhou: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host "  Inner: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    $tcp.Close()
    Stop-AndExit 1
}

Write-Host ""
Write-Host "HANDSHAKE OK" -ForegroundColor Green
Write-Host ""

# Info de sessao
Write-Host "============================================================"
Write-Host "  TLS Session"
Write-Host "============================================================"
Write-Host ("  Protocol            : {0}" -f $ssl.SslProtocol)
Write-Host ("  TLS handshake time  : {0} ms" -f $tlsMs)
Write-Host ("  Cipher              : {0} ({1} bits)" -f $ssl.CipherAlgorithm, $ssl.CipherStrength)
Write-Host ("  Hash                : {0} ({1} bits)" -f $ssl.HashAlgorithm, $ssl.HashStrength)
Write-Host ("  Key exchange        : {0} ({1} bits)" -f $ssl.KeyExchangeAlgorithm, $ssl.KeyExchangeStrength)
Write-Host ("  Mutually authenticated: {0}" -f $ssl.IsMutuallyAuthenticated)
Write-Host ""

# Resumo de validacao TLS/certificado
$certHasIssues = $false
if ($script:capturedSslPolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None) {
    $certHasIssues = $true
}

$chainProblems = @($script:capturedChainStatus | Where-Object { $_.Status -ne "NoError" -and $_.Status -ne "0" })
if ($chainProblems.Count -gt 0) {
    $certHasIssues = $true
}

Write-Host "============================================================"
Write-Host "  TLS Validation"
Write-Host "============================================================"
if (-not $certHasIssues) {
    Write-Host "  Result              : PASS" -ForegroundColor Green
}
else {
    Write-Host "  Result              : WARNING" -ForegroundColor Yellow
}

Write-Host ("  SslPolicyErrors     : {0}" -f $script:capturedSslPolicyErrors)
if ($chainProblems.Count -gt 0) {
    Write-Host "  ChainStatus         :" -ForegroundColor Yellow
    foreach ($item in $chainProblems) {
        if ([string]::IsNullOrWhiteSpace($item.Info)) {
            Write-Host ("    - {0}" -f $item.Status) -ForegroundColor Yellow
        }
        else {
            Write-Host ("    - {0}: {1}" -f $item.Status, $item.Info) -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "  ChainStatus         : NoError"
}
Write-Host ""

Write-Host "============================================================"
Write-Host "  Stage Timings"
Write-Host "============================================================"
Write-Host ("  DNS                : {0} ms" -f $dnsMs)
Write-Host ("  TCP Connect        : {0} ms" -f $tcpMs)
Write-Host ("  TLS Handshake      : {0} ms" -f $tlsMs)
Write-Host ""

# Chain
Write-Host "============================================================"
Write-Host "  Certificate chain"
Write-Host "============================================================"
$i = 0
foreach ($c in $script:capturedChain) {
    Write-Host "[$i]" -ForegroundColor Yellow
    Write-Host ("  Subject   : {0}" -f $c.Subject)
    Write-Host ("  Issuer    : {0}" -f $c.Issuer)
    Write-Host ("  NotBefore : {0}" -f $c.NotBefore.ToString("o"))
    Write-Host ("  NotAfter  : {0}" -f $c.NotAfter.ToString("o"))
    Write-Host ("  Serial    : {0}" -f $c.SerialNumber)
    Write-Host ("  Algorithm : {0} ({1} bits)" -f $c.SignatureAlgorithm.FriendlyName, $c.PublicKey.Key.KeySize)
    Write-Host ("  Thumbprint: {0}" -f $c.Thumbprint)

    # SAN (Subject Alternative Names)
    $sanExt = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($sanExt) {
        $sans = $sanExt.Format($true) -split "`r?`n" | Where-Object { $_ -match '\S' }
        Write-Host "  SANs      :"
        foreach ($s in ($sans | Select-Object -First 10)) {
            Write-Host "    $s" -ForegroundColor DarkGray
        }
        if ($sans.Count -gt 10) {
            Write-Host ("    ... (+{0} outros)" -f ($sans.Count - 10)) -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    $i++
}

$ssl.Close()
$tcp.Close()

Write-Host "============================================================"
Write-Host "  Dica: para ver 'Acceptable client CAs' (mTLS),"
Write-Host "  use openssl.exe ou curl.exe (vem no Git for Windows e Windows 10+):"
Write-Host "============================================================"
Write-Host ""
Write-Host "  openssl s_client -connect ${HostName}:${Port} -servername $Sni" -ForegroundColor DarkGray
Write-Host "  curl.exe -v https://${HostName}:${Port}/" -ForegroundColor DarkGray
Write-Host ""

if ($StrictValidation -and $certHasIssues) {
    Write-Host "StrictValidation ativo: encerrando com erro devido a problemas de validacao TLS." -ForegroundColor Red
    Stop-AndExit 2
}

Stop-AndExit 0
