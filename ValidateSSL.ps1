<#
.SYNOPSIS
    Ferramenta de diagnostico de conexao HTTPS intermitente.

.DESCRIPTION
    Executa N vezes uma sequencia (login -> consumo de metodo) em paralelo
    configuravel, capturando metricas granulares por requisicao:
      - Timestamp UTC
      - IP remoto resolvido
      - Tempo de DNS
      - Tempo total
      - Status HTTP
      - Tipo de erro (incluindo SocketErrorCode em falhas de rede)
      - Mensagem completa (com InnerException)

    Salva CSV por execucao e imprime um resumo com p95/p99 e distribuicao de erros.

.PARAMETER ConfigFile
    Caminho para arquivo JSON de configuracao (ver config.example.json).

.PARAMETER Iterations
    Total de pares (login + consumo) a executar. Default: 1 (safe-by-default).
    Use config.execution.iterations ou -Iterations para aumentar para troubleshooting real.

.PARAMETER Concurrency
    Quantas iteracoes simultaneas. Default: 1 (safe-by-default).
    Use config.execution.concurrency ou -Concurrency para aumentar.

.PARAMETER OutputDir
    Diretorio para gravar os logs CSV. Default: .\logs

.PARAMETER ForceTls
    Forca uma versao especifica de TLS. Util para isolar se o problema
    e negociacao de protocolo. Default: Tls12.

.PARAMETER TimeoutSeconds
    Timeout de cada request em segundos. Default: 30.

.PARAMETER KeepAlive
    Se presente, reusa conexoes (HTTP KeepAlive). Por padrao desabilitado para
    forcar nova conexao a cada request (ajuda a diagnosticar pool envenenado).

.PARAMETER IgnoreCertErrors
    Aceita certificados invalidos. Use APENAS para diagnostico.

.EXAMPLE
    .\ValidateSSL.ps1 -ConfigFile .\config.json

.EXAMPLE
    .\ValidateSSL.ps1 -ConfigFile .\config.json -Iterations 500 -Concurrency 10 -ForceTls Tls12

.NOTES
    Requer Windows PowerShell 5.1+ (.NET Framework 4.x).
    Executar com: powershell.exe -ExecutionPolicy Bypass -File .\ValidateSSL.ps1 ...
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ConfigFile,

    [ValidateRange(1, 100000)]
    [int]$Iterations = 1,

    [ValidateRange(1, 200)]
    [int]$Concurrency = 1,

    [string]$OutputDir = ".\logs",

    [ValidateSet("Tls", "Tls11", "Tls12", "Tls13", "All")]
    [string]$ForceTls = "Tls12",

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 30,

    [switch]$KeepAlive,

    [switch]$IgnoreCertErrors
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# Helpers
# ============================================================================

function ConvertTo-HashtableRecursive {
    <#
        ConvertFrom-Json em PS 5.1 devolve PSCustomObject.
        Para passar de forma segura para runspaces usamos hashtable.
        Em PS 6+ bastaria -AsHashtable, mas o alvo aqui eh PS 5.1.
    #>
    param($InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $ht = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-HashtableRecursive $prop.Value
        }
        return $ht
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        return @($InputObject | ForEach-Object { ConvertTo-HashtableRecursive $_ })
    }

    return $InputObject
}

function Initialize-HttpEnvironment {
    param(
        [string]$TlsMode,
        [bool]$IgnoreCerts
    )

    # .NET Framework 4.x default = Tls 1.0 apenas. Precisamos habilitar explicitamente.
    $protocols = switch ($TlsMode) {
        "Tls"   { [System.Net.SecurityProtocolType]::Tls }
        "Tls11" { [System.Net.SecurityProtocolType]::Tls11 }
        "Tls12" { [System.Net.SecurityProtocolType]::Tls12 }
        "Tls13" {
            try {
                [System.Net.SecurityProtocolType]::Tls13
            }
            catch {
                throw "TLS 1.3 nao suportado neste .NET Framework (precisa 4.8+ e Windows 10 2004+). Use Tls12 ou All."
            }
        }
        "All"   {
            [System.Net.SecurityProtocolType]::Tls12 -bor `
            [System.Net.SecurityProtocolType]::Tls11 -bor `
            [System.Net.SecurityProtocolType]::Tls
        }
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $protocols

    # Evita latencia extra em POST: .NET envia Expect: 100-continue por default.
    [System.Net.ServicePointManager]::Expect100Continue = $false

    # CRITICO: default eh 2. Se nao aumentar, concorrencia vira fila e o teste fica invalido.
    [System.Net.ServicePointManager]::DefaultConnectionLimit = 200

    # Forca DNS lookup a cada request - importante para LBs com varios IPs.
    [System.Net.ServicePointManager]::DnsRefreshTimeout = 0

    if ($IgnoreCerts) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Write-Warning "IgnoreCertErrors ATIVO - certificados invalidos serao aceitos. Use apenas para diagnostico."
    }
}

# ============================================================================
# ScriptBlock executado em cada runspace (1 iteracao = login + consume)
# ============================================================================

$RequestBlock = {
    param(
        [int]$Id,
        [hashtable]$Config,
        [int]$TimeoutSec,
        [bool]$KeepAliveEnabled
    )

    # Helper interno ao runspace - cada runspace tem seu proprio escopo.
    function Invoke-InstrumentedRequest {
        param(
            [int]$RequestId,
            [string]$Operation,
            [string]$Url,
            [string]$Method,
            [string]$Body,
            [hashtable]$Headers,
            [int]$Timeout,
            [bool]$KeepAliveFlag
        )

        $result = [pscustomobject]@{
            RequestId      = $RequestId
            Operation      = $Operation
            TimestampUtc   = [DateTime]::UtcNow.ToString("o")
            Url            = $Url
            Method         = $Method
            RemoteIp       = $null
            StatusCode     = $null
            DnsMs          = $null
            TotalMs        = $null
            Success        = $false
            ErrorType      = $null
            ErrorMessage   = $null
            ResponseSize   = 0
        }

        $totalSw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $uri = [System.Uri]$Url

            # 1) DNS resolution explicito (para capturar tempo e IP)
            $dnsSw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($uri.Host)
                $result.RemoteIp = (($addresses | ForEach-Object { $_.ToString() }) -join ";")
            }
            catch {
                $result.ErrorType    = "DnsResolutionFailed"
                $result.ErrorMessage = $_.Exception.Message
                return $result
            }
            finally {
                $dnsSw.Stop()
                $result.DnsMs = $dnsSw.ElapsedMilliseconds
            }

            # 2) Preparar HttpWebRequest
            $req = [System.Net.HttpWebRequest]::Create($uri)
            $req.Method           = $Method
            $req.Timeout          = $Timeout * 1000
            $req.ReadWriteTimeout = $Timeout * 1000
            $req.KeepAlive        = $KeepAliveFlag
            $req.AllowAutoRedirect = $false
            $req.UserAgent        = "ValidateSSL/1.0 (PowerShell)"

            if ($Headers) {
                foreach ($k in $Headers.Keys) {
                    switch -Regex ($k) {
                        '^(?i)Content-Type$' { $req.ContentType = $Headers[$k] }
                        '^(?i)Accept$'       { $req.Accept      = $Headers[$k] }
                        default              { $req.Headers.Add($k, $Headers[$k]) }
                    }
                }
            }

            if ($Body -and ($Method -in @("POST","PUT","PATCH"))) {
                if (-not $req.ContentType) { $req.ContentType = "application/json" }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
                $req.ContentLength = $bytes.Length
                $reqStream = $req.GetRequestStream()
                try { $reqStream.Write($bytes, 0, $bytes.Length) }
                finally { $reqStream.Close() }
            }

            # 3) Executar
            $response = $req.GetResponse()
            try {
                $result.StatusCode = [int]$response.StatusCode
                $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
                try {
                    $responseBody = $reader.ReadToEnd()
                    $result.ResponseSize = $responseBody.Length
                    $result.Success = ($result.StatusCode -ge 200 -and $result.StatusCode -lt 400)
                    # Retorna body APENAS no login (para extrair token). Removido antes do CSV.
                    if ($Operation -eq "LOGIN") {
                        $result | Add-Member -NotePropertyName "ResponseBody" -NotePropertyValue $responseBody -Force
                    }
                }
                finally { $reader.Close() }
            }
            finally { $response.Close() }
        }
        catch [System.Net.WebException] {
            $we = $_.Exception
            $result.ErrorType    = $we.Status.ToString()
            $result.ErrorMessage = $we.Message

            if ($we.Response) {
                try {
                    $result.StatusCode = [int]$we.Response.StatusCode
                    $errReader = New-Object System.IO.StreamReader($we.Response.GetResponseStream())
                    try {
                        $errBody = $errReader.ReadToEnd()
                        $result.ResponseSize = $errBody.Length
                    }
                    finally { $errReader.Close() }
                }
                catch { }
            }

            # InnerException frequentemente carrega o motivo real (SocketException, IOException...)
            if ($we.InnerException) {
                $result.ErrorMessage += " | Inner: " + $we.InnerException.Message
                if ($we.InnerException -is [System.Net.Sockets.SocketException]) {
                    $result.ErrorType += "/" + $we.InnerException.SocketErrorCode.ToString()
                }
            }
        }
        catch {
            $result.ErrorType    = $_.Exception.GetType().Name
            $result.ErrorMessage = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $result.ErrorMessage += " | Inner: " + $_.Exception.InnerException.Message
            }
        }
        finally {
            $totalSw.Stop()
            $result.TotalMs = $totalSw.ElapsedMilliseconds
        }

        return $result
    }

    $results = New-Object System.Collections.ArrayList

    # ------ LOGIN ------
    $loginUrl = $Config.baseUrl.TrimEnd('/') + '/' + $Config.login.path.TrimStart('/')
    $loginBody = $null
    if ($Config.login.body) {
        # body totalmente parametrizavel: qualquer objeto JSON do config eh serializado e enviado.
        $loginBody = $Config.login.body | ConvertTo-Json -Compress -Depth 10
    }
    $loginHeaders = @{
        "Content-Type" = "application/json"
        "Accept"       = "application/json"
    }

    # Basic Auth (gerado em runtime - evita deixar base64 persistido no config).
    if ($Config.login.ContainsKey('basicAuth') -and $Config.login.basicAuth) {
        $ba = $Config.login.basicAuth
        if (-not $ba.username -or $null -eq $ba.password) {
            throw "login.basicAuth exige 'username' e 'password'."
        }
        $pair    = "$($ba.username):$($ba.password)"
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
        $loginHeaders["Authorization"] = "Basic $encoded"
    }

    # Headers customizados do config - tem precedencia sobre os defaults acima.
    if ($Config.login.ContainsKey('headers') -and $Config.login.headers) {
        foreach ($k in $Config.login.headers.Keys) {
            $loginHeaders[$k] = $Config.login.headers[$k]
        }
    }

    $loginResult = Invoke-InstrumentedRequest `
        -RequestId $Id `
        -Operation "LOGIN" `
        -Url $loginUrl `
        -Method $Config.login.method `
        -Body $loginBody `
        -Headers $loginHeaders `
        -Timeout $TimeoutSec `
        -KeepAliveFlag $KeepAliveEnabled

    # Extrair token antes de remover o ResponseBody
    $token = $null
    if ($loginResult.Success -and ($loginResult.PSObject.Properties.Name -contains 'ResponseBody')) {
        try {
            $loginJson = $loginResult.ResponseBody | ConvertFrom-Json
            $tokenField = $Config.login.tokenField
            if (-not $tokenField) { $tokenField = "token" }
            $token = $loginJson.$tokenField
            if (-not $token) {
                $loginResult.ErrorType    = "TokenNotFoundInResponse"
                $loginResult.ErrorMessage = "Campo '$tokenField' ausente ou vazio na resposta."
                $loginResult.Success      = $false
            }
        }
        catch {
            $loginResult.ErrorType    = "TokenParseFailed"
            $loginResult.ErrorMessage = $_.Exception.Message
            $loginResult.Success      = $false
        }
        finally {
            $loginResult.PSObject.Properties.Remove('ResponseBody')
        }
    }

    $null = $results.Add($loginResult)

    # ------ CONSUME ------
    $consumeUrl = $Config.baseUrl.TrimEnd('/') + '/' + $Config.consume.path.TrimStart('/')
    $consumeHeaders = @{ "Accept" = "application/json" }
    if ($token) { $consumeHeaders["Authorization"] = "Bearer $token" }

    # Headers customizados do config - tem precedencia sobre os defaults acima.
    # Obs: se o usuario definir Authorization aqui manualmente, sobrescreve o Bearer gerado.
    if ($Config.consume.ContainsKey('headers') -and $Config.consume.headers) {
        foreach ($k in $Config.consume.headers.Keys) {
            $consumeHeaders[$k] = $Config.consume.headers[$k]
        }
    }

    $consumeBody = $null
    if ($Config.consume.body) {
        $consumeBody = $Config.consume.body | ConvertTo-Json -Compress -Depth 10
    }

    if ($token) {
        $consumeResult = Invoke-InstrumentedRequest `
            -RequestId $Id `
            -Operation "CONSUME" `
            -Url $consumeUrl `
            -Method $Config.consume.method `
            -Body $consumeBody `
            -Headers $consumeHeaders `
            -Timeout $TimeoutSec `
            -KeepAliveFlag $KeepAliveEnabled

        $null = $results.Add($consumeResult)
    }
    else {
        $skipped = [pscustomobject]@{
            RequestId      = $Id
            Operation      = "CONSUME"
            TimestampUtc   = [DateTime]::UtcNow.ToString("o")
            Url            = $consumeUrl
            Method         = $Config.consume.method
            RemoteIp       = $null
            StatusCode     = $null
            DnsMs          = $null
            TotalMs        = 0
            Success        = $false
            ErrorType      = "SkippedNoToken"
            ErrorMessage   = "Login previo falhou - consumo nao executado"
            ResponseSize   = 0
        }
        $null = $results.Add($skipped)
    }

    return $results.ToArray()
}

# ============================================================================
# Orquestracao principal
# ============================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  ValidateSSL - Diagnostico de conexao HTTPS intermitente" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Carregar config
Write-Host "[+] Carregando configuracao: $ConfigFile"
$rawConfig = Get-Content -Path $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
$config = ConvertTo-HashtableRecursive $rawConfig

# Validacoes basicas
foreach ($required in @('baseUrl','login','consume')) {
    if (-not $config.ContainsKey($required)) {
        throw "Configuracao invalida: campo obrigatorio '$required' ausente."
    }
}

# ----------------------------------------------------------------------------
# Resolucao de parametros de execucao
# Precedencia: CLI (PSBoundParameters) > config.execution > default do param()
# ----------------------------------------------------------------------------
$effectiveKeepAlive        = $KeepAlive.IsPresent
$effectiveIgnoreCertErrors = $IgnoreCertErrors.IsPresent

if ($config.ContainsKey('execution') -and $config.execution) {
    $exec = $config.execution

    if (-not $PSBoundParameters.ContainsKey('Iterations')    -and $exec.ContainsKey('iterations')    -and $exec.iterations)    { $Iterations    = [int]$exec.iterations }
    if (-not $PSBoundParameters.ContainsKey('Concurrency')   -and $exec.ContainsKey('concurrency')   -and $exec.concurrency)   { $Concurrency   = [int]$exec.concurrency }
    if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds') -and $exec.ContainsKey('timeoutSeconds') -and $exec.timeoutSeconds) { $TimeoutSeconds = [int]$exec.timeoutSeconds }
    if (-not $PSBoundParameters.ContainsKey('ForceTls')      -and $exec.ContainsKey('forceTls')      -and $exec.forceTls)      { $ForceTls      = [string]$exec.forceTls }
    if (-not $PSBoundParameters.ContainsKey('OutputDir')     -and $exec.ContainsKey('outputDir')     -and $exec.outputDir)     { $OutputDir     = [string]$exec.outputDir }
    if (-not $PSBoundParameters.ContainsKey('KeepAlive')     -and $exec.ContainsKey('keepAlive'))        { $effectiveKeepAlive        = [bool]$exec.keepAlive }
    if (-not $PSBoundParameters.ContainsKey('IgnoreCertErrors') -and $exec.ContainsKey('ignoreCertErrors')) { $effectiveIgnoreCertErrors = [bool]$exec.ignoreCertErrors }

    # ValidateRange so dispara na entrada do param(). Revalidar manualmente.
    if ($Iterations -lt 1 -or $Iterations -gt 100000) {
        throw "execution.iterations fora do intervalo 1..100000: $Iterations"
    }
    if ($Concurrency -lt 1 -or $Concurrency -gt 200) {
        throw "execution.concurrency fora do intervalo 1..200: $Concurrency"
    }
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 300) {
        throw "execution.timeoutSeconds fora do intervalo 1..300: $TimeoutSeconds"
    }
    if ($ForceTls -notin @('Tls','Tls11','Tls12','Tls13','All')) {
        throw "execution.forceTls invalido '$ForceTls'. Valores: Tls, Tls11, Tls12, Tls13, All"
    }
}

Write-Host "    Base URL      : $($config.baseUrl)"
Write-Host "    Login         : $($config.login.method) $($config.login.path)"
Write-Host "    Consume       : $($config.consume.method) $($config.consume.path)"

# Reporta modo de autenticacao de forma explicita
if ($config.login.ContainsKey('basicAuth') -and $config.login.basicAuth) {
    $bu = $config.login.basicAuth.username
    Write-Host "    Basic Auth    : ATIVO (usuario='$bu', senha=***)"
}
else {
    Write-Host "    Basic Auth    : (desativado)"
}
if ($config.login.ContainsKey('body') -and $config.login.body) {
    $bodyKeys = @($config.login.body.Keys) -join ', '
    Write-Host "    Login body    : campos={$bodyKeys}"
}

Write-Host "    Iteracoes     : $Iterations"
Write-Host "    Concorrencia  : $Concurrency"
Write-Host "    TLS mode      : $ForceTls"
Write-Host "    KeepAlive     : $effectiveKeepAlive"
Write-Host "    Timeout       : ${TimeoutSeconds}s"
Write-Host "    IgnoreCertErr : $effectiveIgnoreCertErrors"
Write-Host ""

# Inicializar ambiente HTTP/TLS
Initialize-HttpEnvironment -TlsMode $ForceTls -IgnoreCerts $effectiveIgnoreCertErrors

# Preparar output dir
if (-not (Test-Path $OutputDir)) {
    $null = New-Item -ItemType Directory -Path $OutputDir -Force
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath   = Join-Path $OutputDir "run_$timestamp.csv"
Write-Host "[+] Logs gravados em: $csvPath"
Write-Host ""

# Criar RunspacePool
Write-Host "[+] Iniciando RunspacePool (min=1 max=$Concurrency)..."
$pool = [runspacefactory]::CreateRunspacePool(1, $Concurrency)
$pool.ApartmentState = "MTA"
$pool.Open()

# Disparar todas as iteracoes
$jobs = New-Object System.Collections.ArrayList
$overallSw = [System.Diagnostics.Stopwatch]::StartNew()

for ($i = 1; $i -le $Iterations; $i++) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($RequestBlock).
                AddArgument($i).
                AddArgument($config).
                AddArgument($TimeoutSeconds).
                AddArgument($effectiveKeepAlive)
    $handle = $ps.BeginInvoke()
    $null = $jobs.Add([pscustomobject]@{
        PowerShell = $ps
        Handle     = $handle
        Id         = $i
    })
}

Write-Host "[+] $Iterations iteracoes enfileiradas. Executando..."
Write-Host ""

# Aguardar com progresso (iteracao reversa para permitir remocao segura)
$allResults = New-Object System.Collections.ArrayList
$completed  = 0

while ($jobs.Count -gt 0) {
    for ($j = $jobs.Count - 1; $j -ge 0; $j--) {
        $job = $jobs[$j]
        if ($job.Handle.IsCompleted) {
            try {
                $output = $job.PowerShell.EndInvoke($job.Handle)
                foreach ($r in $output) { $null = $allResults.Add($r) }
            }
            catch {
                Write-Warning "Iteracao $($job.Id) lancou excecao: $($_.Exception.Message)"
            }
            finally {
                $job.PowerShell.Dispose()
                $jobs.RemoveAt($j)
                $completed++
            }
        }
    }

    $pct = [int](($completed / $Iterations) * 100)
    Write-Progress -Activity "Executando requests" `
                   -Status  "$completed / $Iterations concluidas" `
                   -PercentComplete $pct

    Start-Sleep -Milliseconds 100
}
Write-Progress -Activity "Executando requests" -Completed

$pool.Close()
$pool.Dispose()
$overallSw.Stop()

Write-Host "[+] Execucao concluida em $([math]::Round($overallSw.Elapsed.TotalSeconds,1))s"
Write-Host ""

# ============================================================================
# Exportar CSV + Sumario
# ============================================================================

$allResults |
    Select-Object RequestId, Operation, TimestampUtc, Url, Method, RemoteIp, StatusCode, DnsMs, TotalMs, Success, ErrorType, ErrorMessage, ResponseSize |
    Sort-Object RequestId, Operation |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "[+] CSV: $csvPath"
Write-Host ""

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RESUMO" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

foreach ($op in @("LOGIN","CONSUME")) {
    $subset = @($allResults | Where-Object { $_.Operation -eq $op })
    if ($subset.Count -eq 0) { continue }

    $success = @($subset | Where-Object { $_.Success })
    $fail    = @($subset | Where-Object { -not $_.Success })

    Write-Host ""
    Write-Host "[$op]" -ForegroundColor Yellow
    Write-Host ("  Total       : {0}" -f $subset.Count)
    Write-Host ("  Sucesso     : {0} ({1}%)" -f $success.Count, ([math]::Round(($success.Count / $subset.Count) * 100, 2)))

    if ($fail.Count -gt 0) {
        Write-Host ("  Falhas      : {0} ({1}%)" -f $fail.Count, ([math]::Round(($fail.Count / $subset.Count) * 100, 2))) -ForegroundColor Red
    }
    else {
        Write-Host ("  Falhas      : 0")
    }

    if ($success.Count -gt 0) {
        $times = $success | ForEach-Object { $_.TotalMs } | Sort-Object
        $avg = [math]::Round(($times | Measure-Object -Average).Average, 1)
        $p50 = $times[[math]::Floor($times.Count * 0.50)]
        $p95 = $times[[math]::Floor($times.Count * 0.95)]
        $p99 = $times[[math]::Floor($times.Count * 0.99)]
        Write-Host ("  Latencia ms : min={0}  p50={1}  avg={2}  p95={3}  p99={4}  max={5}" -f `
                    $times[0], $p50, $avg, $p95, $p99, $times[-1])
    }

    if ($fail.Count -gt 0) {
        Write-Host "  Distribuicao de erros:" -ForegroundColor Red
        $fail | Group-Object ErrorType | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("    - {0}: {1}" -f $_.Name, $_.Count) -ForegroundColor Red
        }

        $ipsFail = $fail | Where-Object { $_.RemoteIp } |
                         Group-Object RemoteIp |
                         Sort-Object Count -Descending
        if ($ipsFail) {
            Write-Host "  IPs envolvidos nas falhas (top 5):" -ForegroundColor Red
            $ipsFail | Select-Object -First 5 | ForEach-Object {
                Write-Host ("    - {0}: {1} falhas" -f $_.Name, $_.Count) -ForegroundColor Red
            }
        }
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Proximos passos sugeridos:" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  1. Abra o CSV e filtre por Success=False para ver o padrao." -ForegroundColor DarkGray
Write-Host "  2. Se falhas concentradas em um IP -> problema de load balancer/rota." -ForegroundColor DarkGray
Write-Host "  3. Se falhas espalhadas com ErrorType=Timeout -> investigar latencia/firewall." -ForegroundColor DarkGray
Write-Host "  4. Se ErrorType=SecureChannelFailure -> tentar -ForceTls com outros valores." -ForegroundColor DarkGray
Write-Host "  5. Se DnsMs muito variavel -> DNS do cliente degradado." -ForegroundColor DarkGray
Write-Host ""
