#!/usr/bin/env bash
#
# test-alerts.sh — Dispara trafico de prueba para confirmar que Suricata detecta.
#
#   Ejecutalo EN LA MISMA VM (o en un cliente cuyo trafico pase por la interfaz
#   que Suricata escucha). No genera trafico malicioso real: solo firmas de test
#   y un escaneo de puertos a localhost/target de laboratorio.
#
#   Uso:  ./test-alerts.sh [target_ip]
#         target_ip  destino del escaneo nmap (default: 127.0.0.1)
#
set -uo pipefail
c_g=$'\e[32m'; c_y=$'\e[33m'; c_b=$'\e[36m'; c_0=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
ok(){   printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }

TARGET="${1:-127.0.0.1}"
FAST=/var/log/suricata/fast.log

[ -r "$FAST" ] || { warn "No encuentro $FAST. ¿Suricata esta corriendo? (systemctl status suricata)"; exit 1; }

BEFORE="$(wc -l < "$FAST" 2>/dev/null || echo 0)"
info "Alertas actuales en fast.log: $BEFORE"
echo

# ---------------------------------------------------------------- 1) firma ET clasica
info "1/3  Test de firma ET (testmynids.org — 'GPL ATTACK_RESPONSE id check returned root')"
if command -v curl >/dev/null 2>&1; then
  curl -s --max-time 10 http://testmynids.org/uid/index.html >/dev/null 2>&1 \
    && ok "peticion enviada" || warn "curl fallo (¿sin salida a internet? usa el paso 2 y 3)"
else
  warn "curl no instalado (apt-get install -y curl)"
fi

# ---------------------------------------------------------------- 2) escaneo de puertos
info "2/3  Escaneo de puertos con nmap contra ${TARGET} (simula CPE infectado escaneando)"
if command -v nmap >/dev/null 2>&1; then
  nmap -sS -T4 -p 1-1000 "$TARGET" >/dev/null 2>&1 \
    && ok "escaneo SYN enviado" || warn "nmap requiere root para -sS; prueba con sudo"
else
  warn "nmap no instalado (apt-get install -y nmap) — omitiendo"
fi

# ---------------------------------------------------------------- 3) DNS a dominio sospechoso de prueba
info "3/3  Consulta a dominio de test (ruleset ET malware/dns)"
if command -v dig >/dev/null 2>&1; then
  dig +short +tries=1 +time=2 testmyids.com @1.1.1.1 >/dev/null 2>&1 && ok "consulta enviada" || warn "dig fallo (opcional)"
else
  warn "dig no instalado (apt-get install -y dnsutils) — omitiendo"
fi

echo
info "Esperando a que Suricata procese (5s)..."
sleep 5

AFTER="$(wc -l < "$FAST" 2>/dev/null || echo 0)"
NEW=$(( AFTER - BEFORE ))
echo
if [ "$NEW" -gt 0 ]; then
  ok "¡${NEW} alerta(s) nueva(s)! Suricata esta detectando. Ultimas:"
  echo "---------------------------------------------------------------"
  tail -n "$NEW" "$FAST"
  echo "---------------------------------------------------------------"
else
  warn "Sin alertas nuevas todavia. Posibles causas:"
  echo "    - El trafico de prueba no pasa por la interfaz que Suricata escucha."
  echo "      (En un lab de 1 VM sin espejo, el trafico a internet puede no verse;"
  echo "       ahi conviene el modo TZSP/mirror o correr nmap desde otro host de la red.)"
  echo "    - Sin salida a internet para el test ET/DNS."
  echo "    - Las reglas no cargaron: revisa 'systemctl status suricata' y suricata-update."
fi
