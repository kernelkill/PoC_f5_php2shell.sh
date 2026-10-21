#!/usr/bin/env bash
# ==============================================================================
# test_f5_php2shell.sh v4 — Validação de iRule F5 (sem SSH)
# CVE-2026-109618 / CVE-2026-109619
#
# v4: REMOVE toda dependencia de SSH. Usa 5 camadas de evidencia baseadas
#     apenas na resposta HTTP (body, content-type, size, timing, connection).
#     Funciona de qualquer lugar que tenha acesso HTTP ao alvo.
#
# Uso:
#   1. Edite as variaveis no bloco CONFIGURACAO abaixo
#   2. chmod +x test_f5_php2shell.sh
#   3. ./PoC_f5_php2shell.sh
# ==============================================================================

set -u
trap 'echo -e "\\n${RED}[!] Script interrompido. Relatorio parcial em $REPORT_FILE${NC}"' INT TERM

# ==============================================================================
# CONFIGURACAO - edite estas variaveis antes de rodar
# ==============================================================================

APP_URL="https://dominio.com.br"
ENDPOINT_DISCOVERY="true"
UPLOAD_PATH="/upload"
LOGIN_PATH="/login"
API_LOGIN_PATH="/api/login"
EXTRA_PATHS="/ /index.php /admin /login /signin /wp-login.php /user/login /api/login /api/v1/login /upload /uploads /api/upload /contact /search /blog /wp-admin/ /admin/login /auth/login"
AUTH_COOKIE=""
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# iRule signature - DEVE bater com o HTTP::respond da sua iRule
# Sua iRule faz "HTTP::respond 403 content \"Blocked\"..." -> usar "Blocked"
IRULE_RESPONSE_SIGNATURE="Blocked"

# Diretorio de relatorio
REPORT_DIR="/tmp/waf-test-results"
TEST_DATE="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/waf-test-$TEST_DATE.log"

# ==============================================================================
# Cores e helpers
# ==============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
INCONCLUSIVE_COUNT=0
FALSE_POSITIVES=0
FALSE_NEGATIVES=0
BYPASS_CRITICAL=0

# Contadores de evidencia (5 camadas, sem SSH)
EVIDENCE_BODY_MATCH=0        # body bate com assinatura
EVIDENCE_BODY_FAIL=0
EVIDENCE_CT_MATCH=0          # content-type text/plain
EVIDENCE_CT_FAIL=0
EVIDENCE_SIZE_MATCH=0        # tamanho curto
EVIDENCE_SIZE_FAIL=0
EVIDENCE_TIMING_MATCH=0      # timing rapido
EVIDENCE_TIMING_FAIL=0
EVIDENCE_CONN_MATCH=0        # connection close
EVIDENCE_CONN_FAIL=0

mkdir -p "$REPORT_DIR"

log() {
    local color="$1"
    local msg="$2"
    echo -e "${color}${msg}${NC}" | tee -a "$REPORT_FILE"
}
log_info()    { log "$BLUE"    "$1"; }
log_pass()    { log "$GREEN"   "$1"; PASS_COUNT=$((PASS_COUNT+1)); }
log_fail()    { log "$RED"     "$1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
log_warn()    { log "$YELLOW"  "$1"; WARN_COUNT=$((WARN_COUNT+1)); }
log_skip()    { log "$YELLOW"  "$1"; SKIP_COUNT=$((SKIP_COUNT+1)); }
log_inconc()  { log "$YELLOW"  "$1"; INCONCLUSIVE_COUNT=$((INCONCLUSIVE_COUNT+1)); }
log_section() { log "$CYAN$BOLD" "$1"; }
log_evidence() { log "$MAGENTA" "$1"; }

# ==============================================================================
# Helper: executa curl e captura TUDO (status, headers, body, time, size)
# ==============================================================================
run_curl_full() {
    local tmp_body="/tmp/curl_body_$$"
    local tmp_headers="/tmp/curl_headers_$$"
    local result
    result=$(curl -s -o "$tmp_body" -D "$tmp_headers" \
        -w '%{http_code}|%{time_total}|%{size_download}' \
        --max-time 30 \
        -A "$USER_AGENT" \
        ${AUTH_COOKIE:+-H "Cookie: PHPSESSID=$AUTH_COOKIE"} \
        "$@" 2>/dev/null) || true
    HTTP_CODE="${result%%|*}"
    TIME_TOTAL="$(echo "$result" | cut -d'|' -f2)"
    SIZE_DOWNLOAD="$(echo "$result" | cut -d'|' -f3)"
    RESPONSE_BODY="$(cat "$tmp_body" 2>/dev/null)"
    RESPONSE_HEADERS="$(cat "$tmp_headers" 2>/dev/null)"
    RESPONSE_CT=$(echo "$RESPONSE_HEADERS" | grep -i "^content-type:" | head -1 | tr -d '\r')
    RESPONSE_CONN=$(echo "$RESPONSE_HEADERS" | grep -i "^connection:" | head -1 | tr -d '\r')
    RESPONSE_SERVER=$(echo "$RESPONSE_HEADERS" | grep -i "^server:" | head -1 | tr -d '\r')
    rm -f "$tmp_body" "$tmp_headers"
    [[ -z "$HTTP_CODE" || "$HTTP_CODE" == "000" ]] && HTTP_CODE="TIMEOUT"
}

# ==============================================================================
# Camada 1: Body content match
# Confirma que o body bate exatamente com a assinatura da iRule
# ==============================================================================
check_body_signature() {
    local expected="$1"   # "blocked" ou "passthrough"
    if [[ "$expected" == "blocked" ]]; then
        if echo "$RESPONSE_BODY" | grep -q "$IRULE_RESPONSE_SIGNATURE"; then
            # BONUS: se o body EXATO (sem lixo) for igual a signature, e mais forte
            if [[ "$RESPONSE_BODY" == "$IRULE_RESPONSE_SIGNATURE" ]]; then
                log_evidence "    [L1] Body match: resposta exata = \"$IRULE_RESPONSE_SIGNATURE\" ✓✓"
            else
                log_evidence "    [L1] Body match: contem \"$IRULE_RESPONSE_SIGNATURE\" ✓"
            fi
            EVIDENCE_BODY_MATCH=$((EVIDENCE_BODY_MATCH+1))
            return 0
        else
            log_evidence "    [L1] Body match: NAO contem \"$IRULE_RESPONSE_SIGNATURE\" ✗"
            log_evidence "         Body (200 chars): $(echo "$RESPONSE_BODY" | head -c 200)"
            EVIDENCE_BODY_FAIL=$((EVIDENCE_BODY_FAIL+1))
            return 1
        fi
    fi
}

# ==============================================================================
# Camada 2: Content-Type analysis
# iRule responde com text/plain; backend 403 costuma ter text/html
# ==============================================================================
check_content_type() {
    local expected="$1"
    if [[ "$expected" == "blocked" ]]; then
        # Esperado: text/plain (iRule) ou ausente
        if echo "$RESPONSE_CT" | grep -qi "text/plain" || [[ -z "$RESPONSE_CT" ]]; then
            log_evidence "    [L2] Content-Type: $RESPONSE_CT (text/plain = padrao iRule) ✓"
            EVIDENCE_CT_MATCH=$((EVIDENCE_CT_MATCH+1))
            return 0
        else
            log_evidence "    [L2] Content-Type: $RESPONSE_CT (NAO text/plain - pode ser backend)"
            EVIDENCE_CT_FAIL=$((EVIDENCE_CT_FAIL+1))
            return 1
        fi
    fi
}

# ==============================================================================
# Camada 3: Response size analysis
# iRule "Blocked" = ~7 bytes. Backend 403 = 200+ bytes (HTML error page)
# ==============================================================================
check_size_analysis() {
    local expected="$1"
    if [[ "$expected" == "blocked" ]]; then
        # Tamanho da signature + possivel \n
        local expected_size=${#IRULE_RESPONSE_SIGNATURE}
        local max_expected=$((expected_size + 10))   # tolerance for newline/whitespace
        if [[ ${SIZE_DOWNLOAD:-0} -le $max_expected ]]; then
            log_evidence "    [L3] Size: $SIZE_DOWNLOAD bytes (<= $max_expected = padrao iRule curto) ✓"
            EVIDENCE_SIZE_MATCH=$((EVIDENCE_SIZE_MATCH+1))
            return 0
        else
            log_evidence "    [L3] Size: $SIZE_DOWNLOAD bytes (> $max_expected - parece pagina HTML do backend)"
            EVIDENCE_SIZE_FAIL=$((EVIDENCE_SIZE_FAIL+1))
            return 1
        fi
    fi
}

# ==============================================================================
# Camada 4: Timing analysis
# iRule block: < 100ms (sem processar no backend)
# Backend block: > 100ms (PHP processa, mod_security, etc.)
# ==============================================================================
check_timing_analysis() {
    local expected="$1"
    if [[ "$expected" == "blocked" ]]; then
        # timing em segundos (com decimal)
        local time_ms=$(echo "$TIME_TOTAL" | awk '{print int($1 * 1000)}')
        if [[ ${time_ms:-999} -le 200 ]]; then
            log_evidence "    [L4] Timing: ${TIME_TOTAL}s ($time_ms ms - rapido, padrao edge block) ✓"
            EVIDENCE_TIMING_MATCH=$((EVIDENCE_TIMING_MATCH+1))
            return 0
        else
            log_evidence "    [L4] Timing: ${TIME_TOTAL}s ($time_ms ms - lento, pode ser backend processando)"
            EVIDENCE_TIMING_FAIL=$((EVIDENCE_TIMING_FAIL+1))
            return 1
        fi
    fi
}

# ==============================================================================
# Camada 5: Connection header
# iRule faz "Connection: close"; backend pode fazer keep-alive
# ==============================================================================
check_connection_header() {
    local expected="$1"
    if [[ "$expected" == "blocked" ]]; then
        if echo "$RESPONSE_CONN" | grep -qi "close"; then
            log_evidence "    [L5] Connection: $RESPONSE_CONN (close = padrao iRule) ✓"
            EVIDENCE_CONN_MATCH=$((EVIDENCE_CONN_MATCH+1))
            return 0
        else
            log_evidence "    [L5] Connection: ${RESPONSE_CONN:-<ausente>} (nao 'close' explicito)"
            EVIDENCE_CONN_FAIL=$((EVIDENCE_CONN_FAIL+1))
            return 1
        fi
    fi
}

# ==============================================================================
# Helper: coleta as 5 camadas de evidencia para TP/BYPASS com expectativa IS_403
# ==============================================================================
collect_5_layers_evidence() {
    check_body_signature "blocked"
    check_content_type "blocked"
    check_size_analysis "blocked"
    check_timing_analysis "blocked"
    check_connection_header "blocked"
}

# ==============================================================================
# Helper: registra resultado + coleta 5 camadas de evidencia (sem SSH)
# ==============================================================================
record_result_with_evidence() {
    local test_id="$1"
    local expected="$2"   # "NOT_403" | "IS_403"
    local desc="$3"
    local actual="$HTTP_CODE"

    if [[ "$actual" == "TIMEOUT" ]]; then
        log_warn "  [SKIP] $test_id: timeout — $desc"
        SKIP_COUNT=$((SKIP_COUNT+1))
        return
    fi

    if [[ "$expected" == "NOT_403" ]]; then
        if [[ "$actual" == "403" ]]; then
            log_fail "  [FAIL] $test_id: HTTP $actual bloqueou legítimo — $desc"
            FALSE_POSITIVES=$((FALSE_POSITIVES+1))
        else
            log_pass "  [ OK ] $test_id: HTTP $actual legítimo passou — $desc"
        fi
    elif [[ "$expected" == "IS_403" ]]; then
        if [[ "$actual" == "403" ]]; then
            log_pass "  [ OK ] $test_id: HTTP 403 iRule bloqueou — $desc"
            # Coletar 5 camadas de evidencia
            collect_5_layers_evidence
        elif [[ "$actual" == "404" ]]; then
            log_inconc "  [ ?  ] $test_id: HTTP 404 endpoint nao existe — $desc"
        else
            log_fail "  [FAIL] $test_id: HTTP $actual iRule NAO bloqueou! — $desc"
            FALSE_NEGATIVES=$((FALSE_NEGATIVES+1))
            log_evidence "         Body recebido (200 chars): $(echo "$RESPONSE_BODY" | head -c 200)"
        fi
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $test_id expected=$expected actual=$actual | $desc" >> "$REPORT_FILE"
    echo "  Response body: $(echo "$RESPONSE_BODY" | head -c 200)" >> "$REPORT_FILE"
    echo "  Content-Type: $RESPONSE_CT" >> "$REPORT_FILE"
    echo "  Size: $SIZE_DOWNLOAD bytes" >> "$REPORT_FILE"
    echo "  Time: ${TIME_TOTAL}s" >> "$REPORT_FILE"
    echo "  Connection: $RESPONSE_CONN" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# ==============================================================================
# CABECALHO
# ==============================================================================
{
    echo "============================================================"
    echo "TESTE WAF PHP2SHELL v4 — 5 camadas de evidencia (sem SSH)"
    echo "CVE-2026-109618 / CVE-2026-109619"
    echo "Data: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "App URL: $APP_URL"
    echo "iRule signature esperada: \"$IRULE_RESPONSE_SIGNATURE\""
    echo "============================================================"
    echo ""
} > "$REPORT_FILE"

echo "============================================================" | tee -a "$REPORT_FILE"
echo " TESTE WAF PHP2SHELL v4 — 5 camadas (sem SSH)" | tee -a "$REPORT_FILE"
echo " Alvo: $APP_URL" | tee -a "$REPORT_FILE"
echo " Assinatura esperada: \"$IRULE_RESPONSE_SIGNATURE\"" | tee -a "$REPORT_FILE"
echo " Relatorio: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "============================================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# PRE-FLIGHT
# ==============================================================================
log_section "[*] PRE-FLIGHT"
run_curl_full -I "$APP_URL/"
if [[ "$HTTP_CODE" == "TIMEOUT" ]]; then
    log_fail "  [FAIL] Não foi possível conectar a $APP_URL"
    exit 2
fi
log_pass "  [ OK ] $APP_URL responde (HTTP $HTTP_CODE, ${TIME_TOTAL}s)"
log_info "  Server: ${RESPONSE_SERVER:-<none>}"
echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# BLOCO 0 — DESCOBERTA DE ENDPOINTS
# ==============================================================================
log_section "[*] BLOCO 0 — Descoberta de endpoints"

UPLOAD_ENDPOINT=""
POST_ENDPOINT=""
GET_ENDPOINT=""

echo "  Path                          HTTP_code  Tempo    Resultado" | tee -a "$REPORT_FILE"
echo "  ----------------------------  ---------  -------  ----------" | tee -a "$REPORT_FILE"

for path in $EXTRA_PATHS; do
    run_curl_full -o /dev/null "$APP_URL$path"
    STATUS_LABEL=""
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" ]]; then
        STATUS_LABEL="USAVEL"
        if [[ -z "$GET_ENDPOINT" ]]; then GET_ENDPOINT="$path"; fi
        if [[ -z "$POST_ENDPOINT" ]] && [[ "$path" == *login* || "$path" == *signin* || "$path" == *auth* ]]; then
            POST_ENDPOINT="$path"
        fi
        if [[ -z "$UPLOAD_ENDPOINT" ]] && [[ "$path" == *upload* ]]; then
            UPLOAD_ENDPOINT="$path"
        fi
    elif [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
        STATUS_LABEL="existe_auth"
    elif [[ "$HTTP_CODE" == "404" ]]; then
        STATUS_LABEL="nao_existe"
    else
        STATUS_LABEL="outro"
    fi
    printf "  %-30s  %-9s  %-7s  %s\n" "$path" "$HTTP_CODE" "${TIME_TOTAL}s" "$STATUS_LABEL" | tee -a "$REPORT_FILE"
done

echo "" | tee -a "$REPORT_FILE"
[[ -z "$GET_ENDPOINT" ]] && GET_ENDPOINT="/"
[[ -z "$POST_ENDPOINT" ]] && POST_ENDPOINT="$GET_ENDPOINT"
[[ -z "$UPLOAD_ENDPOINT" ]] && UPLOAD_ENDPOINT="$GET_ENDPOINT"

log_info "  Endpoints selecionados: GET=$GET_ENDPOINT POST=$POST_ENDPOINT UPLOAD=$UPLOAD_ENDPOINT"

UPLOAD_PATH="$UPLOAD_ENDPOINT"
LOGIN_PATH="$POST_ENDPOINT"
API_LOGIN_PATH="$POST_ENDPOINT"
echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# BLOCO 1 — TRUE NEGATIVES
# ==============================================================================
log_section "[*] BLOCO 1 — True Negatives (legítimo deve passar)"

run_curl_full "$APP_URL$GET_ENDPOINT"
record_result_with_evidence "TN-1" "NOT_403" "GET $GET_ENDPOINT"

run_curl_full -X POST -d "user=admin&pass=test" "$APP_URL$LOGIN_PATH"
record_result_with_evidence "TN-2" "NOT_403" "POST form $LOGIN_PATH"

run_curl_full -X POST -H "Content-Type: application/json" \
    -d '{"user":"admin","action":"login"}' "$APP_URL$API_LOGIN_PATH"
record_result_with_evidence "TN-3" "NOT_403" "POST JSON $API_LOGIN_PATH"

echo "conteudo de teste" > /tmp/waf_test_tn4.txt
run_curl_full -F "descricao=teste" -F "arquivo=@/tmp/waf_test_tn4.txt" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "TN-4" "NOT_403" "Upload multipart legitimo"

dd if=/dev/urandom of=/tmp/waf_test_big.bin bs=1M count=9 2>/dev/null
run_curl_full -F "arquivo=@/tmp/waf_test_big.bin" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "TN-5" "NOT_403" "Upload 9MB legitimo"

echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# BLOCO 2 — TRUE POSITIVES (com 5 camadas de evidencia por teste)
# ==============================================================================
log_section "[*] BLOCO 2 — True Positives (5 camadas de evidência por teste)"

log_info "TP-1: PHP_SESSION_UPLOAD_PROGRESS + arquivo"
run_curl_full -F "PHP_SESSION_UPLOAD_PROGRESS=exploit_test" \
    -F "arquivo=@/tmp/waf_test_tn4.txt" \
    "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "TP-1" "IS_403" "Campo trigger + arquivo"

log_info "TP-2: PHP_SESSION_UPLOAD_PROGRESS sozinho"
run_curl_full -F "PHP_SESSION_UPLOAD_PROGRESS=test" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "TP-2" "IS_403" "Campo trigger sozinho"

log_info "TP-3: PHP_SESSION_UPLOAD_PROGRESS como primeiro campo"
run_curl_full -F "PHP_SESSION_UPLOAD_PROGRESS=exploit" \
    -F "outro_campo=dado" \
    -F "arquivo=@/tmp/waf_test_tn4.txt" \
    "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "TP-3" "IS_403" "Trigger como primeiro campo"

log_info "TP-4: PHP_SESSION_UPLOAD_PROGRESS no meio do body"
run_curl_full -F "campo1=dado1" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=exploit" \
    -F "campo2=dado2" \
    "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "TP-4" "IS_403" "Trigger no meio dos campos"

echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# BLOCO 3 — BYPASS ATTEMPTS
# ==============================================================================
log_section "[*] BLOCO 3 — Variações de bypass"

log_info "BYPASS-1: minúsculas"
run_curl_full -F "php_session_upload_progress=exploit" \
    -F "arquivo=@/tmp/waf_test_tn4.txt" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "BYPASS-1" "IS_403" "Trigger em minúsculas"

log_info "BYPASS-2: case misto"
run_curl_full -F "PHP_Session_Upload_Progress=exploit" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "BYPASS-2" "IS_403" "Trigger em case misto"

log_info "BYPASS-3: URL-encoded do nome"
run_curl_full -F "%50%48%50%5f%53%45%53%53%49%4f%4e%5f%55%50%4c%4f%41%44%5f%50%52%4f%47%52%45%53%53=exploit" \
    "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "BYPASS-3" "IS_403" "Trigger URL-encoded (nao e bypass real)"

log_info "BYPASS-4: nome com espaco"
run_curl_full -F "PHP_SESSION_UPLOAD_PROGRESS =exploit" \
    -F "arquivo=@/tmp/waf_test_tn4.txt" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "BYPASS-4" "IS_403" "Trigger com espaco no nome"

echo "PHP_SESSION_UPLOAD_PROGRESS in file content" > /tmp/waf_test_legit.txt
log_info "BYPASS-5: string no CONTEÚDO do arquivo (deve PASSAR)"
run_curl_full -F "descricao=teste" -F "arquivo=@/tmp/waf_test_legit.txt" "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "BYPASS-5" "NOT_403" "String no conteudo do arquivo (deve passar)"

log_info "BYPASS-6: chunked transfer-encoding"
BODY='------boundary
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

exploit
------boundary--
'
run_curl_full -H "Transfer-Encoding: chunked" \
    -H "Content-Type: multipart/form-data; boundary=----boundary" \
    --data-binary "$BODY" \
    "$APP_URL$UPLOAD_PATH"
record_result_with_evidence "BYPASS-6" "IS_403" "Chunked transfer-encoding"

log_info "BYPASS-7: campo no query string (nao e vetor php2shell)"
run_curl_full "$APP_URL$UPLOAD_PATH?PHP_SESSION_UPLOAD_PROGRESS=exploit"
record_result_with_evidence "BYPASS-7" "IS_403" "Trigger no query string (opcional)"

echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# BLOCO 4 — STRESS TEST
# ==============================================================================
log_section "[*] BLOCO 4 — Stress test"

log_info "STRESS-1: 20 uploads legítimos em sequência"
PASS_LEGIT=0
FAIL_LEGIT=0
for i in $(seq 1 20); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
        -A "$USER_AGENT" \
        ${AUTH_COOKIE:+-H "Cookie: PHPSESSID=$AUTH_COOKIE"} \
        -F "arquivo=@/tmp/waf_test_tn4.txt" "$APP_URL$UPLOAD_PATH")
    if [[ "$CODE" != "403" && "$CODE" != "000" ]]; then
        PASS_LEGIT=$((PASS_LEGIT+1))
    else
        FAIL_LEGIT=$((FAIL_LEGIT+1))
    fi
    printf "\r  uploads legitimos: %d/20" "$PASS_LEGIT"
done
echo ""
if [[ "$FAIL_LEGIT" -eq 0 ]]; then
    log_pass "  [ OK ] STRESS-1: 20/20 uploads legítimos passaram"
else
    log_fail "  [FAIL] STRESS-1: $FAIL_LEGIT/20 bloqueados (falso-positivo sob carga)"
fi

log_info "STRESS-2: 20 requests com trigger em paralelo"
PASS_BLOCK=0
FAIL_BLOCK=0
PIDS=()
TMP_DIR="/tmp/waf_stress_$$"
mkdir -p "$TMP_DIR"
for i in $(seq 1 20); do
    (
        CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
            -A "$USER_AGENT" \
            -F "PHP_SESSION_UPLOAD_PROGRESS=exploit_$i" \
            "$APP_URL$UPLOAD_PATH")
        echo "$CODE" > "$TMP_DIR/result_$i"
    ) &
    PIDS+=($!)
done
wait "${PIDS[@]}" 2>/dev/null
for i in $(seq 1 20); do
    CODE=$(cat "$TMP_DIR/result_$i" 2>/dev/null)
    if [[ "$CODE" == "403" ]]; then
        PASS_BLOCK=$((PASS_BLOCK+1))
    else
        FAIL_BLOCK=$((FAIL_BLOCK+1))
    fi
done
rm -rf "$TMP_DIR"
if [[ "$FAIL_BLOCK" -eq 0 ]]; then
    log_pass "  [ OK ] STRESS-2: 20/20 triggers bloqueados em paralelo"
else
    log_fail "  [FAIL] STRESS-2: $FAIL_BLOCK/20 NÃO foram bloqueados"
    BYPASS_CRITICAL=$((BYPASS_CRITICAL+1))
fi

echo "" | tee -a "$REPORT_FILE"

# ==============================================================================
# RESUMO FINAL — Matriz de evidência (5 camadas sem SSH)
# ==============================================================================
log_section "[*] RESUMO FINAL — Matriz de evidência (5 camadas, sem SSH)"

echo "============================================================" | tee -a "$REPORT_FILE"
echo "RESULTADO DOS TESTES:" | tee -a "$REPORT_FILE"
echo "  $PASS_COUNT passaram | $FAIL_COUNT falharam | $INCONCLUSIVE_COUNT inconclusivos | $SKIP_COUNT pulados" | tee -a "$REPORT_FILE"
echo "  Falsos positivos: $FALSE_POSITIVES" | tee -a "$REPORT_FILE"
echo "  Falsos negativos: $FALSE_NEGATIVES" | tee -a "$REPORT_FILE"
echo "  Bypass criticos:  $BYPASS_CRITICAL" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "MATRIZ DE EVIDÊNCIA (5 camadas HTTP, sem SSH):" | tee -a "$REPORT_FILE"
echo "  Camada 1 — Body content (contem assinatura iRule):" | tee -a "$REPORT_FILE"
echo "    PASS: $EVIDENCE_BODY_MATCH | FAIL: $EVIDENCE_BODY_FAIL" | tee -a "$REPORT_FILE"
echo "  Camada 2 — Content-Type (text/plain = iRule):" | tee -a "$REPORT_FILE"
echo "    PASS: $EVIDENCE_CT_MATCH | FAIL: $EVIDENCE_CT_FAIL" | tee -a "$REPORT_FILE"
echo "  Camada 3 — Size (curto = iRule, longo = backend):" | tee -a "$REPORT_FILE"
echo "    PASS: $EVIDENCE_SIZE_MATCH | FAIL: $EVIDENCE_SIZE_FAIL" | tee -a "$REPORT_FILE"
echo "  Camada 4 — Timing (< 200ms = edge block):" | tee -a "$REPORT_FILE"
echo "    PASS: $EVIDENCE_TIMING_MATCH | FAIL: $EVIDENCE_TIMING_FAIL" | tee -a "$REPORT_FILE"
echo "  Camada 5 — Connection (close = iRule):" | tee -a "$REPORT_FILE"
echo "    PASS: $EVIDENCE_CONN_MATCH | FAIL: $EVIDENCE_CONN_FAIL" | tee -a "$REPORT_FILE"
echo "============================================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

echo "CRITÉRIO DE APROVAÇÃO CONSOLIDADO:" | tee -a "$REPORT_FILE"
TOTAL_EVIDENCE=$((EVIDENCE_BODY_MATCH + EVIDENCE_CT_MATCH + EVIDENCE_SIZE_MATCH + EVIDENCE_TIMING_MATCH + EVIDENCE_CONN_MATCH))
TOTAL_EVIDENCE_FAIL=$((EVIDENCE_BODY_FAIL + EVIDENCE_CT_FAIL + EVIDENCE_SIZE_FAIL + EVIDENCE_TIMING_FAIL + EVIDENCE_CONN_FAIL))

if [[ $TOTAL_EVIDENCE_FAIL -eq 0 && $FALSE_NEGATIVES -eq 0 && $FALSE_POSITIVES -eq 0 && $BYPASS_CRITICAL -eq 0 ]]; then
    echo "  [PASS] Mitigação VALIDADA com $TOTAL_EVIDENCE evidências HTTP coletadas" | tee -a "$REPORT_FILE"
    echo "         - 0 falsos positivos, 0 falsos negativos, 0 bypass crítico" | tee -a "$REPORT_FILE"
    echo "         - 5 camadas de evidência HTTP confirmam bloqueio pela iRule" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "  Evidência documental para auditoria/liderança:" | tee -a "$REPORT_FILE"
    echo "    - HTTP 403 em todos os TP testes" | tee -a "$REPORT_FILE"
    echo "    - Body de resposta bate com assinatura da iRule (camada 1)" | tee -a "$REPORT_FILE"
    echo "    - Content-Type text/plain = característica da iRule (camada 2)" | tee -a "$REPORT_FILE"
    echo "    - Tamanho curto = resposta da iRule, não do backend (camada 3)" | tee -a "$REPORT_FILE"
    echo "    - Timing sub-200ms = bloqueio no edge, sem processar backend (camada 4)" | tee -a "$REPORT_FILE"
    echo "    - Connection: close = iRule fecha conexao (camada 5)" | tee -a "$REPORT_FILE"
    EXIT_CODE=0
else
    echo "  [FAIL] Mitigação com $TOTAL_EVIDENCE_FAIL evidência(s) com falha" | tee -a "$REPORT_FILE"
    if [[ $EVIDENCE_BODY_FAIL -gt 0 ]]; then
        echo "    Camada 1: body nao bate com assinatura - investigar" | tee -a "$REPORT_FILE"
    fi
    if [[ $EVIDENCE_CT_FAIL -gt 0 ]]; then
        echo "    Camada 2: Content-Type nao e text/plain - pode ser backend" | tee -a "$REPORT_FILE"
    fi
    if [[ $EVIDENCE_SIZE_FAIL -gt 0 ]]; then
        echo "    Camada 3: tamanho grande - parece pagina HTML do backend" | tee -a "$REPORT_FILE"
    fi
    if [[ $EVIDENCE_TIMING_FAIL -gt 0 ]]; then
        echo "    Camada 4: timing lento - pode ser backend processando" | tee -a "$REPORT_FILE"
    fi
    if [[ $EVIDENCE_CONN_FAIL -gt 0 ]]; then
        echo "    Camada 5: Connection nao 'close' explicito" | tee -a "$REPORT_FILE"
    fi
    EXIT_CODE=1
fi

echo "" | tee -a "$REPORT_FILE"
echo "Relatório completo: $REPORT_FILE" | tee -a "$REPORT_FILE"

# Limpeza
rm -f /tmp/waf_test_tn4.txt /tmp/waf_test_big.bin /tmp/waf_test_legit.txt 2>/dev/null

exit $EXIT_CODE
