# PoC_f5_php2shell.sh
Script bash para validar que a iRule do F5 BIG-IP está bloqueando o padrão-gatilho php2shell (CVE-2026-109618 / CVE-2026-109619). Envia apenas o campo PHP_SESSION_UPLOAD_PROGRESS em multipart em variações (case, encoding, posição, chunked, query string) — NÃO é exploit, NÃO realiza RCE.
