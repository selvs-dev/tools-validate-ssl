# ValidateSSL

Ferramenta de diagnóstico para investigar **falhas intermitentes em chamadas HTTPS** de clientes Windows rodando .NET Framework.

Executa um par `login → consumo` repetidas vezes com concorrência configurável, capturando métricas granulares por requisição para permitir análise estatística dos padrões de falha.

## Requisitos

- Windows com **PowerShell 5.1+** (vem instalado desde Windows 8.1 / Server 2012 R2)
- **.NET Framework 4.5+** (4.8 recomendado para suporte a TLS 1.3)
- Sem dependências externas — é um script `.ps1` puro

## Como usar no cliente

### 1. Enviar a pasta

Copie a pasta `ValidateSSL\` inteira para o cliente. Estrutura esperada:

```
ValidateSSL\
├── ValidateSSL.ps1
├── config.example.json
├── Run-Sample.bat
└── README.md
```

### 2. Configurar

No cliente, copie `config.example.json` para `config.json` e ajuste.

O formato suporta **Basic Auth**, **headers customizados** e **body totalmente parametrizável** (qualquer JSON). Todos os campos marcados como opcional podem ser omitidos.

```json
{
  "baseUrl": "https://api.exemplo.com.br",

  "login": {
    "path": "/auth/login",
    "method": "POST",
    "tokenField": "token",

    "basicAuth": {
      "username": "SEU_USUARIO_APP",
      "password": "SUA_SENHA_APP"
    },

    "headers": {
      "X-Client-Id": "validatessl-troubleshoot"
    },

    "body": {
      "ispb": "00000000",
      "qualquerCampo": "valor"
    }
  },

  "consume": {
    "path": "/api/v1/recurso",
    "method": "GET",

    "headers": {
      "X-Request-Id": "diag"
    },

    "body": null
  }
}
```

**Campos:**

| Campo | Obrigatório | Descrição |
|---|---|---|
| `baseUrl` | sim | URL base da API (sem barra no final). Pode ser HTTP ou HTTPS |
| `execution.iterations` | não (default: 1 — safe-by-default) | Total de pares (login + consume) a executar. Aumente para 100+ quando for fazer troubleshooting real |
| `execution.concurrency` | não (default: 1 — safe-by-default) | Quantas iterações simultâneas. Aumente para 5–10 para expor problemas de pool de conexão |
| `execution.timeoutSeconds` | não (default: 30) | Timeout de cada request em segundos |
| `execution.forceTls` | não (default: `Tls12`) | Força versão de TLS. Valores: `Tls`, `Tls11`, `Tls12`, `Tls13`, `All` |
| `execution.keepAlive` | não (default: `false`) | Se `true`, reusa conexões HTTP (KeepAlive) |
| `execution.ignoreCertErrors` | não (default: `false`) | Se `true`, aceita certificados inválidos |
| `execution.outputDir` | não (default: `./logs`) | Diretório para salvar os CSVs |
| `login.path` | sim | Caminho do endpoint de login |
| `login.method` | sim | Verbo HTTP (normalmente `POST`) |
| `login.tokenField` | não (default: `token`) | Nome do campo na resposta JSON que contém o token |
| `login.basicAuth.username` | não | Usuário para Basic Auth. O script gera o header `Authorization: Basic base64(user:pass)` em runtime |
| `login.basicAuth.password` | não | Senha para Basic Auth |
| `login.headers` | não | Objeto com headers customizados. Sobrescrevem os defaults se houver colisão |
| `login.body` | não | Qualquer objeto JSON — é serializado e enviado como body. Use `null` para omitir |
| `consume.path` | sim | Caminho do endpoint a ser consumido após login |
| `consume.method` | sim | Verbo HTTP |
| `consume.headers` | não | Headers customizados do consumo. O `Authorization: Bearer <token>` é adicionado automaticamente mas pode ser sobrescrito aqui |
| `consume.body` | não | Qualquer objeto JSON para POST/PUT/PATCH; use `null` para GET |

### Exemplo: API que exige Basic Auth + body JSON

Cenário comum em APIs de SPI/Pix (BCB), open banking, e integrações B2B — o login recebe credenciais via Basic Auth **e** exige um body JSON identificando a instituição:

```json
{
  "baseUrl": "http://10.20.30.40:9080",
  "login": {
    "path": "/servico/auth/login",
    "method": "POST",
    "basicAuth": {
      "username": "sistema-cliente",
      "password": "senha-do-sistema"
    },
    "body": {
      "ispb": "12345678"
    }
  },
  "consume": {
    "path": "/servico/api/v1/recurso",
    "method": "GET",
    "body": null
  }
}
```

### Precedência de headers

Os headers de cada request são montados nesta ordem (cada etapa sobrescreve a anterior se colidir):

1. Defaults do script (`Content-Type: application/json`, `Accept: application/json`)
2. `Authorization: Basic <base64>` se `login.basicAuth` estiver configurado
3. `Authorization: Bearer <token>` no consumo (se login teve sucesso)
4. Objeto `headers` customizado do config

Isso significa que você pode, por exemplo, forçar um `Authorization` específico no consumo sobrescrevendo o Bearer padrão — útil para testar APIs que usam outro esquema de auth no endpoint autenticado.

### 3. Executar

**Modo simples (recomendado para o cliente):**

Dar duplo-clique em `Run-Sample.bat`.

**Modo avançado (linha de comando):**

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ValidateSSL.ps1 `
    -ConfigFile .\config.json `
    -Iterations 500 `
    -Concurrency 10 `
    -ForceTls Tls12
```

## Parâmetros CLI e precedência

Todos os parâmetros de execução podem vir do `config.json` (seção `execution`) ou da linha de comando. A regra de precedência é:

**CLI > config.json > default do script**

Ou seja, se você passar `-Iterations 500` na linha de comando, isso ganha mesmo que o config tenha `"iterations": 100`. Isso permite manter uma configuração padrão no JSON e fazer overrides pontuais (ex: smoke test antes do teste real).

| Parâmetro CLI | Campo no config | Default | Descrição |
|---|---|---|---|
| `-ConfigFile` | (só CLI) | obrigatório | Caminho do JSON de configuração |
| `-Iterations` | `execution.iterations` | `1` | Total de pares (login + consume) — default conservador |
| `-Concurrency` | `execution.concurrency` | `1` | Iterações simultâneas — default conservador |
| `-OutputDir` | `execution.outputDir` | `./logs` | Onde salvar o CSV |
| `-ForceTls` | `execution.forceTls` | `Tls12` | `Tls`, `Tls11`, `Tls12`, `Tls13` ou `All` |
| `-TimeoutSeconds` | `execution.timeoutSeconds` | `30` | Timeout por request |
| `-KeepAlive` | `execution.keepAlive` | `false` | Reusa conexões |
| `-IgnoreCertErrors` | `execution.ignoreCertErrors` | `false` | Aceita certificados inválidos |

**Exemplos de uso:**

```powershell
# Usa tudo do config.json
.\ValidateSSL.ps1 -ConfigFile .\config.json

# Mesmo config, mas override rapido para smoke test
.\ValidateSSL.ps1 -ConfigFile .\config.json -Iterations 10 -Concurrency 2

# Override so o TLS para testar hipotese de negociacao de protocolo
.\ValidateSSL.ps1 -ConfigFile .\config.json -ForceTls Tls11
```

## Saída

### CSV por execução: `logs/run_YYYYMMDD_HHMMSS.csv`

Colunas:

- **RequestId** — número da iteração
- **Operation** — `LOGIN` ou `CONSUME`
- **TimestampUtc** — ISO-8601 em UTC
- **Url** — URL chamada
- **Method** — verbo HTTP
- **RemoteIp** — IP(s) resolvido(s) via DNS
- **StatusCode** — status HTTP (null em falha de rede)
- **DnsMs** — tempo de resolução DNS em ms
- **TotalMs** — tempo total da requisição em ms
- **Success** — `True`/`False`
- **ErrorType** — tipo de erro (`Timeout`, `SecureChannelFailure`, `ConnectFailure/ConnectionRefused`, etc.)
- **ErrorMessage** — mensagem completa, incluindo `InnerException`
- **ResponseSize** — bytes da resposta

### Resumo no console

Exibe por operação (LOGIN/CONSUME):
- Total, sucessos e falhas
- Latência: min / p50 / avg / p95 / p99 / max
- Distribuição de erros por tipo
- IPs mais envolvidos em falhas

## Como interpretar os resultados

Este é o ponto crítico. A ferramenta existe para **identificar o padrão** — não basta saber que falha.

### Cenário 1 — Todas as falhas concentradas em um IP específico

Indica **nó doente no load balancer**. O cliente resolve múltiplos IPs via DNS, e um deles está degradado (rede, certificado diferente, backend travado).

**Ação:** pedir ao time de infra para verificar aquele nó. Remover temporariamente do pool.

### Cenário 2 — `ErrorType` majoritariamente `Timeout`

Latência alta ou request travando. Pode ser firewall, proxy, ou backend lento.

**Ação:** comparar `DnsMs` vs `TotalMs`. Se DNS é rápido mas total demora, é rede/backend. Capturar com Wireshark em paralelo para confirmar onde trava (SYN? TLS handshake? primeira resposta?).

### Cenário 3 — `ErrorType=SecureChannelFailure` ou `TrustFailure`

Problema de TLS. Comum quando:
- Cliente roda .NET Framework antigo que não suporta TLS 1.2+
- Cipher suite do servidor mudou e cliente não tem suporte
- Revogação de certificado (CRL/OCSP) travando

**Ação:** rodar com `-ForceTls Tls11`, depois `Tls`, depois `All` e comparar. Se funciona em TLS 1.1 mas não 1.2, é problema de schannel.

### Cenário 4 — `SocketException/ConnectionReset` aleatório

Conexão sendo cortada pelo servidor ou por um middlebox (firewall, IPS).

**Ação:** rodar com `-KeepAlive` ligado e comparar. Se piora com KeepAlive, o servidor está derrubando conexões reusadas. Sem KeepAlive, o problema é mais provável na rede.

### Cenário 5 — `DnsMs` muito variável (alguns ms, alguns segundos)

**DNS do cliente degradado**. Comum em rede corporativa com DNS interno sobrecarregado.

**Ação:** testar com DNS público (8.8.8.8) temporariamente, ou pedir ajuste no DNS corporativo.

### Cenário 6 — Falha após exatamente 2/4/8 concorrentes

**Pool de conexões saturado**. O default do .NET Framework é 2! Este script força 200, mas a aplicação do cliente pode não fazer isso.

**Ação:** na aplicação do cliente, adicionar no startup:

```csharp
ServicePointManager.DefaultConnectionLimit = 100;
```

## Boas práticas ao coletar evidência

1. **Rode 3 vezes em momentos diferentes do dia** — intermitências costumam ter janela temporal.
2. **Colete com Wireshark em paralelo** para correlacionar pacotes com eventos do CSV (use o `TimestampUtc`).
3. **Rode também contra um endpoint público conhecido** (ex: `https://www.google.com`) para descartar problema de stack local.
4. **Compare TLS modes:** rode 3 vezes, uma com `-ForceTls Tls12`, outra com `Tls11`, outra com `All`. Isola se é negociação de protocolo.
5. **Guarde os CSVs** — nunca apague. Histórico é a principal arma contra intermitência.

## Análise rápida no Excel

Abra o CSV, transforme em tabela (`Ctrl+T`) e use:

- **Filtro por `Success=False`** → vê só as falhas
- **Tabela dinâmica** (`ErrorType` nas linhas, `RemoteIp` nas colunas) → distribuição
- **Gráfico de `TotalMs` ao longo do tempo** → identifica picos e correlação temporal

## Segurança

- **Nunca commit `config.json` com credenciais reais** no controle de versão. Adicione ao `.gitignore`.
- Credenciais de `basicAuth` ficam em **plaintext** no arquivo de config — é uma escolha consciente para ferramenta de troubleshooting local. Apague o arquivo após a coleta, ou use variável de ambiente/arquivo protegido via ACL do Windows se for compartilhar a pasta.
- O script gera o base64 do Basic Auth **em memória**, não persiste em disco.
- O script aceita `-IgnoreCertErrors` para casos extremos, mas isso desabilita validação de certificado — use com consciência.
- Os logs **não gravam** o body de login/consumo, nem o token, nem credenciais — apenas tamanhos e metadados de rede.

## Sobre o nome "ValidateSSL" e endpoints HTTP

O script funciona para **HTTP e HTTPS** indistintamente. Se o endpoint-alvo for HTTP (como serviços internos corporativos), o nome fica meio enganoso mas a ferramenta continua útil — a maioria das causas de intermitência (pool de conexões, DNS, socket reset, latência de backend) nada tem a ver com SSL.

Em endpoints HTTP, as flags `-ForceTls` e `-IgnoreCertErrors` são ignoradas silenciosamente pelo .NET Framework. Foque na análise de `ErrorType` e correlação com IP remoto.

## Evoluções possíveis

- Adicionar captura de TLS version/cipher negociado (requer `SslStream` em vez de `HttpWebRequest`)
- Exportar também em formato JSONL para ingestão em Elastic/Splunk
- Suporte a autenticação via cookie/session
- Modo "teste de um único IP" (bypass DNS, conecta direto em um IP do pool)
- Geração automática de gráfico HTML ao final da execução
