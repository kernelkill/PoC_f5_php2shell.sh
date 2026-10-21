# PoC_f5_php2shell.sh — Validador de iRule F5 para php2shell

Script bash para validar que a iRule do F5 BIG-IP está bloqueando o padrão-gatilho
da vulnerabilidade **php2shell** (CVE-2026-109618 / CVE-2026-109619) em runtime PHP.

## ⚠️ IMPORTANTE — O que este script NÃO é

Este script **NÃO é exploit** e **NÃO contém código ofensivo**. Ele:

- ✅ Envia o campo `PHP_SESSION_UPLOAD_PROGRESS` em multipart (padrão-gatilho para validar bloqueio)
- ✅ Varia case, encoding, posição no body, chunked transfer, query string
- ❌ **NÃO** corrompe heap do PHP
- ❌ **NÃO** injeta código PHP em arquivo de sessão
- ❌ **NÃO** encadeia desserialização para RCE
- ❌ **NÃO** executa comandos no alvo
- ❌ **NÃO** valida que o PHP está patched (use `php -v` para isso)
- ❌ **NÃO** detecta comprometimento (use hunting para isso)

Se você precisa de **exploit funcional para validação end-to-end**, este script
**não atende** — procure canais formais:
- Vendor coordination com `php-src-security` ou CERT-EU sob NDA
- TLP:RED threat intel feeds (Cisco Talos, Mandiant, Recorded Future)
- Firma de pentest com escopo assinado cobrindo o alvo e a janela

## Por que usar este script em vez de PoCs públicos?

Vários repositórios públicos no GitHub (ex: `github.com/ikow/php2shell-poc` e
similares) contêm PoCs com nomes como `verify_uaf_asan.php`,
`verify_session_injection.py`, `verify_handler_mismatch.py`. **A maioria é
exploit funcional disfarçado de "verificação"**.

Rodar esses scripts contra sua infraestrutura significa:

- 🔴 Operar exploit funcional de RCE contra sistema de produção
- 🔴 Mesmo bloqueado pelo WAF, gera alerta na SOC e incidente formal
- 🔴 Se NÃO bloqueado (bypass não detectado), **você mesmo causou o
  comprometimento** durante janela de crise
- 🔴 Vulnerável a variantes do código que telemetriam para o autor
- 🔴 Pode conter codificação ofuscada com funções adicionais não-documentadas
- 🔴 Operar exploit funcional contra sistema governamental pode configurar
  ilícito mesmo sem sucesso de exploração, mesmo sendo a sua infraestrutura

Este script foi desenhado para dar **evidência de defesa** sem nunca cruzar a
linha de exploit funcional.

## 5 camadas de evidência HTTP

Cada TP (True Positive) coleta 5 evidências independentes que confirmam que foi
a iRule do F5 que bloqueou (não o backend, não outro WAF, não coincidência):

| Camada | O que valida | Como detecta |
|---|---|---|
| 1. Body content | A iRule disparou (não outra coisa) | Body contém assinatura configurada (default `Blocked`) |
| 2. Content-Type | Origem edge (não backend) | `text/plain` (iRule) vs `text/html` (app) |
| 3. Size | Resposta curta característica | ~7 bytes vs 200+ bytes |
| 4. Timing | Bloqueio no edge | < 200ms (iRule) vs > 200ms (backend) |
| 5. Connection | iRule fecha conexão | `Connection: close` explícito |

Se as 5 camadas confirmarem em todos os TPs, evidência irrefutável de bloqueio
no edge pela sua iRule.

## Como usar

### 1. Configurar

Edite as variáveis no topo do script:

```bash
APP_URL="https://seu-app.exemplo.gov.br"   # URL do alvo
IRULE_RESPONSE_SIGNATURE="Blocked"          # Bate com HTTP::respond da sua iRule
```

Ajuste a assinatura para bater com a resposta HTTP da sua iRule. Se sua iRule
faz `HTTP::respond 403 content "Forbidden"`, mude para
`IRULE_RESPONSE_SIGNATURE="Forbidden"`.

### 2. Rodar (de FORA da sua rede)

```bash
chmod +x test_f5_php2shell.sh
./test_f5_php2shell.sh
```

Rode de fora da rede interna (casa, VPS externa, 4G) para simular atacante
real. Rodando de dentro da rede, você pode passar direto pelo F5 se o Virtual
Server não termina seu tráfego.

### 3. Interpretar resultado

```
[PASS] Mitigação VALIDADA com 20 evidências HTTP coletadas
```

→ Sua iRule está funcionando. Documente o relatório em
`/tmp/waf-test-results/` como evidência de auditoria.

```
[FAIL] Mitigação com X evidência(s) com falha
```

→ Investigue qual camada falhou:

- **Camada 1 (body)**: sua iRule não está respondendo com a assinatura
  configurada — verifique `HTTP::respond` no código da iRule
- **Camada 2 (Content-Type)**: resposta está vindo do backend, não do edge
- **Camada 3 (size)**: resposta é HTML de página de erro do backend
- **Camada 4 (timing)**: backend processou o request (iRule não disparou)
- **Camada 5 (connection)**: backend manteve conexão aberta

## Testes executados

- **TN-1 a TN-5** (True Negatives): tráfego legítimo deve passar — GET,
  POST form, POST JSON, upload multipart normal, upload 9MB
- **TP-1 a TP-4** (True Positives): padrão-gatilho deve ser bloqueado em
  403 — variações de posição do campo no multipart
- **BYPASS-1 a BYPASS-7**: variações que tentam contornar a iRule —
  minúsculas, case misto, URL-encoded, espaço no nome, conteúdo de arquivo,
  chunked transfer, query string
- **STRESS-1, STRESS-2**: performance sob carga — 20 uploads legítimos
  em sequência + 20 triggers em paralelo

Total: 18 testes automatizados, 5 evidências por TP = até 20 evidências
independentes documentadas em relatório de auditoria.

## Pré-requisitos

- `bash` 4+
- `curl` com suporte a multipart, custom headers, e `-w` (qualquer versão
  moderna tem)
- Acesso HTTP ao alvo
- Acesso SSH ao F5 **NÃO** é necessário (v4 funciona só com HTTP)

## Cenários sem F5

Se você rodar contra ambiente que não tem F5, o script vai falhar
(corretamente). Ele foi desenhado para validar especificamente a iRule do F5.

| Cenário | Resultado esperado | Interpretação |
|---|---|---|
| Sem WAF | HTTP 200/302/404/500 nos TPs, `FALSE_NEGATIVES` alto | Aplicação exposta sem mitigação |
| Cloudflare | HTTP 403 nos TPs, mas evidência falha | Bloqueio existe mas não é seu F5 |
| ModSecurity backend | HTTP 403, evidência falha | Backend processou e bloqueou (não é edge protection) |
| Aplicação com plugin PHP de segurança | HTTP 403, evidência falha | Backend bloqueou, não é edge |

Para validar outro WAF, ajuste `IRULE_RESPONSE_SIGNATURE` no topo do script
para bater com a resposta do seu WAF (ex: Cloudflare usa
`"you have been blocked"`).

## FAQ

### O script valida que meu PHP está patched?

**Não.** O script valida que sua iRule bloqueia o padrão-gatilho. Para
validar que o PHP está patched, use `php -v` no host e compare com a versão
do advisory oficial em `https://www.php.net/` e
`https://github.com/php/php-src/security`.

### O script detecta se o ambiente está comprometido?

**Não.** O script é de validação de mitigação, não de detecção de
comprometimento. Para detecção, procure por webshells (`find /var/www -name
'*.php' -newermt '2026-10-20'`), processos filhos suspeitos do php-fpm
(`ps -eo user,cmd | grep www-data`), contas novas em CMS.

### Posso rodar contra ambiente de produção?

**Sim, com ressalvas.** O script só envia padrão-gatilho, mas ainda gera
logs no SIEM/SOC da organização alvo. Recomenda-se rodar em janela de
manutenção aprovada ou documentar o teste previamente com a SOC.

### Roda em macOS?

**Sim**, com bash 4+ (Homebrew: `brew install bash`) e curl moderno.

### Posso customizar as mensagens de evidência?

**Sim.** As 5 camadas são funções bash no script
(`check_body_signature`, `check_content_type`, etc.). Edite conforme
necessário para seu ambiente.

## Output de exemplo

```
============================================================
 TESTE WAF PHP2SHELL v4 — 5 camadas (sem SSH)
 Alvo: https://www.exemplo.gov.br
 Assinatura esperada: "Blocked"
 Relatorio: /tmp/waf-test-results/waf-test-20261021-170000.log
============================================================

[*] BLOCO 2 — True Positives (5 camadas de evidência por teste)
TP-1: PHP_SESSION_UPLOAD_PROGRESS + arquivo
  [ OK ] TP-1: HTTP 403 iRule bloqueou — Campo trigger + arquivo
    [L1] Body match: resposta exata = "Blocked" ✓✓
    [L2] Content-Type: content-type: text/plain (padrao iRule) ✓
    [L3] Size: 7 bytes (<= 17 = padrao iRule curto) ✓
    [L4] Timing: 0.089s (89 ms - rapido, padrao edge block) ✓
    [L5] Connection: connection: close (close = padrao iRule) ✓

============================================================
RESULTADO DOS TESTES:
  17 passaram | 0 falharam | 0 inconclusivos | 0 pulados
  Falsos positivos: 0
  Falsos negativos: 0
  Bypass criticos:  0

MATRIZ DE EVIDÊNCIA (5 camadas HTTP, sem SSH):
  Camada 1 — Body content:    PASS: 4 | FAIL: 0
  Camada 2 — Content-Type:   PASS: 4 | FAIL: 0
  Camada 3 — Size:           PASS: 4 | FAIL: 0
  Camada 4 — Timing:         PASS: 4 | FAIL: 0
  Camada 5 — Connection:     PASS: 4 | FAIL: 0
============================================================

CRITÉRIO DE APROVAÇÃO CONSOLIDADO:
  [PASS] Mitigação VALIDADA com 20 evidências HTTP coletadas
```

## Disclaimer

- Use apenas contra infraestrutura que você administra ou tem autorização
  formal para testar
- O script só envia padrão-gatilho, mas ainda gera logs no SIEM da
  organização alvo
- Não rode contra produção sem janela de mudança aprovada
- Documente sempre o output em `/tmp/waf-test-results/` para auditoria
- Este script **não substitui o patch** do PHP — é mitigação temporária
  até o patcheamento

## Referências

- **PHP security advisories**: https://github.com/php/php-src/security
- **PHP.net**: https://www.php.net/
- **The Hacker News (anúncio)**:
  https://thehackernews.com/2026/10/php2shell-two-unpatched-critical-php.html
- **watchTowr FAQ**: https://watchtowr.com/intelligence/php-cve-2026-109618-faq
- **CVE-2026-109618**: pending CVSS v4.0 9.2
- **CVE-2026-109619**: pending CVSS v4.0 9.2

## Versão

- **Versão**: v4 (sem SSH)
- **CVEs cobertos**: CVE-2026-109618, CVE-2026-109619
- **Compatibilidade**: bash 4+, curl moderno
- **Autor**: Equipe de Segurança da Informação

## Licença

Uso interno para resposta a incidente. Não redistribuir fora do escopo
autorizado.
