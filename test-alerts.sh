#!/usr/bin/env bash
#
# test-alerts.sh — Dispara trafico de prueba para confirmar que Suricata detecta.
#
#   Ejecutalo EN LA MISMA VM. Genera trafico que SALE por la interfaz que Suricata
#   escucha (no a localhost: lo que va por 'lo' nunca lo ve el IDS). No es trafico
#   malicioso real: solo firmas de test de ET Open.
#
#     1) DNS a un dominio .top          -> "ET DNS Query to a *.top domain"        (sid 2023883)
#     2) HTTP con User-Agent wget 3.0   -> "ET ADWARE_PUP Fake Wget User-Agent"    (sid 2007961 + 2013178)
#     3) escaneo nmap al gateway        -> solo si tienes reglas de portscan (ET Open no trae)
#
#   Uso:  ./test-alerts.sh [target_ip]
#         target_ip  destino del escaneo nmap (default: el gateway por defecto)
#
set -uo pipefail
c_g=$'\e[32m'; c_y=$'\e[33m'; c_b=$'\e[36m'; c_0=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
ok(){   printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }

FAST=/var/log/suricata/fast.log
GW="$(ip -o -4 route show to default 2>/dev/null | awk '{print $3; exit}')"
TARGET="${1:-${GW:-}}"

[ -r "$FAST" ] || { warn "No encuentro $FAST. ¿Suricata esta corriendo? (systemctl status suricata)"; exit 1; }

BEFORE="$(wc -l < "$FAST" 2>/dev/null || echo 0)"
info "Alertas actuales en fast.log: $BEFORE"
echo

# ---------------------------------------------------------------- 1) DNS .top
info "1/3  Consulta DNS a un dominio .top (ET DNS Query to a *.top domain)"
if command -v dig >/dev/null 2>&1; then
  dig +short +tries=1 +time=3 "test-suricata-$RANDOM.example.top" >/dev/null 2>&1 \
    && ok "consulta enviada" || warn "dig fallo (¿sin resolver en /etc/resolv.conf?)"
elif command -v getent >/dev/null 2>&1; then
  getent hosts "test-suricata-$RANDOM.example.top" >/dev/null 2>&1 \
    && ok "consulta enviada (getent)" || warn "getent fallo (¿sin resolver en /etc/resolv.conf?)"
else
  warn "ni dig ni getent disponibles — omitiendo"
fi

# ---------------------------------------------------------------- 2) HTTP User-Agent falso
info "2/3  Peticion HTTP con User-Agent 'wget 3.0' (ET ADWARE_PUP Fake Wget User-Agent)"
if command -v curl >/dev/null 2>&1; then
  # la regla compara el UA literal "wget 3.0" (con espacio), no "Wget/3.0"
  curl -s --max-time 10 -A "wget 3.0" -o /dev/null http://deb.debian.org/ \
    && ok "peticion enviada" || warn "curl fallo (¿sin salida HTTP a internet?)"
else
  warn "curl no instalado (apt-get install -y curl)"
fi

# ---------------------------------------------------------------- 3) escaneo de puertos
if [ -n "$TARGET" ]; then
  info "3/3  Escaneo nmap contra ${TARGET} (simula CPE infectado; ET Open no trae reglas de portscan por defecto)"
  if command -v nmap >/dev/null 2>&1; then
    nmap -sS -T4 -p 1-1000 "$TARGET" >/dev/null 2>&1 \
      && ok "escaneo SYN enviado" || warn "nmap requiere root para -sS; prueba con sudo"
  else
    warn "nmap no instalado (apt-get install -y nmap) — omitiendo"
  fi
else
  warn "3/3  Sin gateway detectado y sin target: omito el escaneo"
fi

echo
info "Esperando a que Suricata procese (5s)..."
sleep 5

AFTER="$(wc -l < "$FAST" 2>/dev/null || echo 0)"
NEW=$(( AFTER - BEFORE ))
# Capturar la ventana UNA sola vez: con trafico real fast.log crece mientras se lee
# y dos 'tail' seguidos devuelven lineas distintas (el conteo se descuadra).
NEWLINES=""
[ "$NEW" -gt 0 ] && NEWLINES="$(tail -n "$NEW" "$FAST")"
echo
if [ "$NEW" -gt 0 ]; then
  ok "¡${NEW} alerta(s) nueva(s)! Suricata esta detectando. Ultimas:"
  echo "---------------------------------------------------------------"
  # Mostrar solo las firmas de prueba (con miles de alertas de fondo no se puede volcar todo).
  TESTLINES="$(printf '%s\n' "$NEWLINES" | grep -E '2023883|2007961|2013178' || true)"
  HITS=0
  [ -n "$TESTLINES" ] && HITS="$(printf '%s\n' "$TESTLINES" | wc -l)"
  OTHERS=$(( NEW - HITS ))
  # tope: 19 lineas de prueba + 1 de resumen = 20 como maximo
  [ "$HITS" -gt 0 ] && printf '%s\n' "$TESTLINES" | head -n 19 | cut -c1-160
  [ "$OTHERS" -gt 0 ] && echo "... y ${OTHERS} alertas mas de fondo (no mostradas)"
  echo "---------------------------------------------------------------"
  if [ "${HITS:-0}" -gt 0 ]; then
    ok "de ellas ${HITS} son las firmas de prueba (sid 2023883 / 2007961 / 2013178)"
  else
    warn "ninguna es de las firmas de prueba: fueron otras alertas de fondo (el trafico de test no se detecto)"
  fi
  echo "  Deberian verse tambien en la web EveBox (Alerts)."
else
  warn "Sin alertas nuevas todavia. Posibles causas:"
  echo "    - Suricata no escucha la interfaz por la que sale este trafico (revisa 'interface:' en suricata.yaml)."
  echo "    - Sin salida a internet para DNS/HTTP."
  echo "    - Las reglas no cargaron: revisa 'systemctl status suricata' y suricata-update."
fi
