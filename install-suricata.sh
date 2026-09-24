#!/usr/bin/env bash
#
# install-suricata.sh — Suricata IDS + interfaz web (EveBox) en Debian 13/12
#
#   Instala Suricata en modo IDS pasivo (AF_PACKET) con reglas ET Open y, por
#   defecto, EveBox como interfaz web para ver alertas/flujos/DNS/TLS/HTTP en el
#   navegador. Sin Elastic: EveBox lee eve.json y guarda en SQLite local.
#   Pensado para cualquier VPS o VM Debian limpia.
#
#   One-liner:
#     curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash
#     curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -i ens18 -n 10.0.0.0/24
#
#   Uso:   sudo ./install-suricata.sh [-i IFACE] [-n HOME_NET] [-p PUERTO] [-P CLAVE] [-t] [-W] [-h]
#
#     -i IFACE     interfaz a escuchar (default: auto-deteccion por ruta default)
#     -n HOME_NET  red(es) "casa" en CIDR, separadas por coma (default: la de la interfaz)
#     -p PUERTO    puerto de la web EveBox (default: 5636)
#     -P CLAVE     clave del usuario web 'admin' (default: aleatoria, se muestra al final)
#     -t           receptor TZSP (UDP 37008) para espejo desde MikroTik (/tool sniffer o
#                  mangle action=sniff-tzsp). Desencapsula y entrega a Suricata por un veth.
#     -W           sin web (solo Suricata + logs locales)
#     -h           ayuda
#
#   Idempotente: se puede re-ejecutar; reescribe config y recarga reglas.
#   Si 'admin' ya existe en EveBox no se toca su clave salvo que pases -P.
#
set -euo pipefail

# ----------------------------------------------------------------------------- estilo
c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_b=$'\e[36m'; c_0=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
ok(){   printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }
die(){  printf '%s[x]%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
# Nunca morir en silencio: con set -e cualquier fallo no controlado dice donde fue.
trap 'rc=$?; printf "%s[x]%s Fallo (exit %s) en la linea %s: %s\n" "$c_r" "$c_0" "$rc" "$LINENO" "$BASH_COMMAND" >&2' ERR

usage(){
  cat <<'USAGE'
Uso: sudo ./install-suricata.sh [-i IFACE] [-n HOME_NET] [-p PUERTO] [-P CLAVE] [-m ORIGEN] [-t] [-W] [-h]

  -i IFACE     interfaz a escuchar (default: auto-deteccion por ruta default)
  -n HOME_NET  red(es) "casa" en CIDR, separadas por coma (default: la de la interfaz)
  -p PUERTO    puerto de la web EveBox (default: 5636)
  -P CLAVE     clave del usuario web 'admin' (default: aleatoria, se muestra al final)
  -m ORIGEN    con -t: IP/CIDR del MikroTik que envia el espejo TZSP (una o varias,
               separadas por coma). Restringe UFW y el receptor a ese origen.
               OBLIGATORIO con -t: sin origen conocido cualquier host de la red podria
               inyectar tramas forjadas en el IDS, asi que el receptor no arranca.
  -t           receptor TZSP (UDP 37008) para espejo desde MikroTik (requiere -m)
  -W           sin web (solo Suricata + logs locales)
  -h           esta ayuda

One-liner:
  curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- [opciones]
USAGE
}

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root (sudo)."

# ----------------------------------------------------------------------------- args
IFACE=""; HOME_NET=""; HOME_NET_GIVEN=0; WEB=1; WEB_PORT=5636; WEB_PASS=""; TZSP=0; TZSP_PORT=37008; MIRROR_SRC=""
while getopts "i:n:p:P:m:tWh" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    n) HOME_NET="$OPTARG"; HOME_NET_GIVEN=1 ;;
    p) WEB_PORT="$OPTARG" ;;
    P) WEB_PASS="$OPTARG" ;;
    m) MIRROR_SRC="$OPTARG" ;;
    t) TZSP=1 ;;
    W) WEB=0 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
# por si el usuario pasa -n "[a,b]": el yaml ya pone los corchetes
HOME_NET="${HOME_NET#[}"; HOME_NET="${HOME_NET%]}"
{ [[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ]; } || die "Puerto invalido: $WEB_PORT"
# el receptor TZSP sin lista de origenes aceptaria tramas forjadas de cualquier host de
# la red: -t exige -m para que el espejo tenga un origen conocido.
[ "$TZSP" -eq 0 ] || [ -n "$MIRROR_SRC" ] || die "-t necesita -m <IP_MikroTik> (origen del espejo; admite varios separados por coma)."
export DEBIAN_FRONTEND=noninteractive

# EveBox: se baja el .deb suelto del pool oficial (el repo apt usa firma SHA1 que
# Debian 13 rechaza). Se lee el indice para tomar la version vigente y su SHA256;
# si el indice no responde, se usa esta version fijada.
EVEBOX_BASE="https://evebox.org/files/debian"
EVEBOX_PKGS="${EVEBOX_BASE}/dists/stable/main/binary-amd64/Packages"
EVEBOX_PIN_FILE="pool/main/e/evebox/evebox_0.28.0_amd64.deb"
EVEBOX_PIN_SHA="82b1af759dd9d29877a3717818320d21ad21f66acb2940391db7aa9c0d072765"
EVEBOX_DATA=/var/lib/evebox
EVEBOX_CFG=/etc/evebox/evebox.yaml

# ----------------------------------------------------------------------------- SO
if [ -r /etc/os-release ]; then . /etc/os-release; fi
info "SO: ${PRETTY_NAME:-desconocido}"
case "${VERSION_CODENAME:-}" in
  trixie) ok "Debian 13 (Trixie) detectado." ;;
  bookworm) warn "Debian 12 (Bookworm): funciona igual, seguimos." ;;
  *) warn "Distro no verificada; el paquete suricata de repos deberia servir." ;;
esac
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
if [ "$WEB" -eq 1 ] && [ "$ARCH" != "amd64" ]; then
  warn "Arquitectura ${ARCH}: el .deb de EveBox es amd64; se omite la web."
  WEB=0
fi

# python3 se usa ya para calcular HOME_NET, antes del apt-get install principal
command -v python3 >/dev/null 2>&1 || { apt-get update -qq </dev/null; apt-get install -y -qq python3 </dev/null >/dev/null; }

# ----------------------------------------------------------------------------- iface
if [ -z "$IFACE" ]; then
  IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')"
  [ -n "$IFACE" ] || IFACE="$(ip -o -4 addr show scope global | awk '{print $2; exit}')"
fi
[ -n "$IFACE" ] || die "No pude auto-detectar la interfaz. Pasa -i IFACE."
ip link show "$IFACE" >/dev/null 2>&1 || die "La interfaz '$IFACE' no existe. Revisa: ip -br link"
ok "Interfaz de captura: $IFACE"

if [ -z "$HOME_NET" ]; then
  cidr="$(ip -o -4 addr show dev "$IFACE" scope global | awk '{print $4; exit}')"
  if [ -n "$cidr" ]; then
    # convierte 10.0.0.5/24 -> 10.0.0.0/24
    HOME_NET="$(python3 - "$cidr" <<'PY' 2>/dev/null || true
import ipaddress,sys
print(str(ipaddress.ip_network(sys.argv[1], strict=False)))
PY
)"
  fi
  [ -n "$HOME_NET" ] || { HOME_NET="10.0.0.0/8"; warn "La interfaz ${IFACE} no tiene IPv4: HOME_NET por defecto 10.0.0.0/8; pasa -n con tus redes."; }
fi
ok "HOME_NET: $HOME_NET"

# ----------------------------------------------------------------------------- install
info "Instalando suricata y utilidades..."
# </dev/null: bajo 'curl | bash' el stdin es el propio script; un prompt de dpkg se lo comeria
apt-get update -qq </dev/null
apt-get install -y -qq -o Dpkg::Options::=--force-confold suricata suricata-update jq python3 curl ca-certificates ethtool logrotate </dev/null >/dev/null
ok "Suricata instalado: $(suricata -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

# comprobar capacidades compiladas
if suricata --build-info 2>/dev/null | grep -qi 'AF_PACKET support:.*yes'; then
  ok "AF_PACKET compilado."
else
  warn "No confirmo AF_PACKET en build-info; revisa 'suricata --build-info'."
fi

# ----------------------------------------------------------------------------- reglas
info "Descargando reglas ET Open..."
suricata-update update-sources >/dev/null 2>&1 || true
if [ "$TZSP" -eq 1 ]; then
  # con espejo TZSP (asimetrico) el 95% de las alertas eran STREAM invalid ack/out of window,
  # QUIC error, Applayer Mismatch: puro ruido. suricata-update lee este archivo por defecto.
  DISABLE_CONF=/etc/suricata/disable.conf
  touch "$DISABLE_CONF"
  # Las reglas de diagnostico interno ("SURICATA ...") viven en 22 archivos *-events.rules
  # (stream, decoder, quic, tls, http, http2...). Se desactivan todas por su msg.
  for line in '# install-suricata.sh: con espejo TZSP (asimetrico) estas reglas solo son ruido' \
              'group:stream-events.rules' \
              'group:app-layer-events.rules' \
              're:msg:"SURICATA\s' \
              '# STUN (WebRTC/videollamadas): en un ISP era el 68% de las alertas, solo informativas' \
              '2033078' '2016149' '2016150' '2033077'; do
    grep -qxF -- "$line" "$DISABLE_CONF" || echo "$line" >> "$DISABLE_CONF"
  done
  ok "Reglas de ruido stream/app-layer desactivadas (espejo TZSP)."
fi
suricata-update >/dev/null 2>&1 || suricata-update || warn "suricata-update reporto avisos (normal la 1a vez); valida las reglas antes de recargar."
RULES_COUNT="$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null || true)"; RULES_COUNT="${RULES_COUNT:-?}"
ok "Reglas cargadas: ${RULES_COUNT}"

# ----------------------------------------------------------------------------- reglas propias
# ET Open NO trae deteccion de port-scan. Estas reglas cazan el caso que motiva el lab:
# un CPE de HOME_NET escaneando/atacando hacia afuera. Umbrales por IP origen; sids en
# rango local 90000xx (reservado para reglas propias). Se instalan siempre.
LOCAL_RULES=/var/lib/suricata/rules/local.rules
cat > "$LOCAL_RULES" <<'RULES'
# local.rules — install-suricata.sh — deteccion de actividad saliente de CPEs infectados.
# Rango sid 9000000+ (reglas locales). Ajusta umbrales segun tu red.
#
# IMPORTANTE: aqui NO hay una regla generica "todo SYN/UDP saliente". Sobre un espejo de
# ISP (miles de clientes) una regla que casa cada paquete y hace 'track by_src' mantiene
# un contador por cada IP de la red -> agota la RAM y tumba el sensor. Se cazan solo
# PUERTOS concretos y raros (botnets IoT, gusanos): bajo volumen, tabla de estado pequena.
# Si tu red es pequena (una LAN, no un espejo de ISP) y quieres barrido horizontal
# generico, descomenta con cuidado y vigila la RAM:
#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Posible barrido TCP saliente"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 120, seconds 60; classtype:attempted-recon; sid:9000001; rev:1;)

# --- Puertos tipicos de botnets IoT / gusanos (Mirai y familia) hacia afuera ---
alert tcp $HOME_NET any -> $EXTERNAL_NET [23,2323] (msg:"LOCAL CPE escanea Telnet saliente (botnet IoT/Mirai)"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 15, seconds 60; classtype:attempted-recon; sid:9000010; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 7547 (msg:"LOCAL CPE escanea TR-069/CWMP saliente (Mirai)"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:9000011; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [5555,7777] (msg:"LOCAL CPE escanea ADB/router saliente"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:9000012; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 445 (msg:"LOCAL Escaneo SMB saliente (gusano/ransomware)"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:9000013; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [3389,5900] (msg:"LOCAL Escaneo RDP/VNC saliente"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:9000014; rev:1;)

# --- SMTP directo desde clientes (spambot): un CPE no deberia hablar 25/tcp a internet ---
alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"LOCAL SMTP directo saliente desde cliente (posible spambot)"; flags:S,12; flow:to_server; threshold:type both, track by_src, count 5, seconds 120; classtype:bad-unknown; sid:9000020; rev:1;)
RULES
LOCAL_COUNT="$(grep -c '^alert' "$LOCAL_RULES")"
# registrar local.rules en rule-files (idempotente). Nota: $CFG aun no esta definido
# aqui (se fija en la seccion 'config'), por eso se usa la ruta literal.
if ! grep -qE '^\s*- local\.rules\s*$' /etc/suricata/suricata.yaml 2>/dev/null; then
  sed -i '/^rule-files:/a\  - local.rules' /etc/suricata/suricata.yaml 2>/dev/null || true
fi
ok "Reglas propias de escaneo saliente: ${LOCAL_COUNT} (local.rules)."

# actualizacion diaria de reglas ET + recarga en caliente (sin reiniciar el motor)
cat > /usr/local/bin/suricata-rules-update <<'UPD'
#!/bin/sh
# Actualiza reglas ET Open y recarga Suricata sin reiniciar (rule-reload).
# suricata-update VALIDA las reglas (suricata -T) al final; si el test falla sale
# con error y NO se recarga, evitando cargar un set roto en produccion.
set -e
suricata-update >/tmp/suricata-update.log 2>&1 || { echo "suricata-update fallo (reglas no validadas, NO se recarga):"; cat /tmp/suricata-update.log; exit 1; }
if command -v suricatasc >/dev/null 2>&1 && systemctl is-active --quiet suricata; then
  suricatasc -c reload-rules >/dev/null 2>&1 || systemctl reload suricata || systemctl restart suricata
fi
UPD
chmod 755 /usr/local/bin/suricata-rules-update
cat > /etc/systemd/system/suricata-rules-update.service <<'UNIT'
[Unit]
Description=Actualiza reglas ET Open de Suricata y recarga
After=suricata.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/suricata-rules-update
UNIT
cat > /etc/systemd/system/suricata-rules-update.timer <<'UNIT'
[Unit]
Description=Actualizacion diaria de reglas de Suricata
[Timer]
OnCalendar=*-*-* 04:30:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now suricata-rules-update.timer >/dev/null 2>&1 || true
ok "Auto-update de reglas: diario 04:30 (suricata-rules-update.timer), recarga en caliente."

# ----------------------------------------------------------------------------- config
CFG=/etc/suricata/suricata.yaml
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo backup)"
cp -a "$CFG" "${CFG}.bak-${STAMP}"
info "Backup de config: ${CFG}.bak-${STAMP}"
# conservar solo los 5 backups mas recientes (cada re-ejecucion crea uno)
ls -1t "${CFG}".bak-* 2>/dev/null | tail -n +6 | xargs -r rm -f --

# HOME_NET
sed -i "s#^\(\s*HOME_NET:\).*#\1 \"[${HOME_NET}]\"#" "$CFG"

# interfaz af-packet (primer bloque 'interface: ...')
sed -i "0,/^\(\s*\)- interface:.*/s//\1- interface: ${IFACE}/" "$CFG"
# use-mmap + tpacket-v3 en la interfaz principal (Suricata avisa si falta; solo vienen comentados)
if ! awk -v m="$IFACE" '$0 ~ "^  - interface: "m"$"{f=1;next} f&&/^  - interface:/{exit} f&&/^    tpacket-v3: yes/{ok=1} END{exit !ok}' "$CFG"; then
  sed -i "/^  - interface: ${IFACE}\$/a\    use-mmap: yes\n    tpacket-v3: yes" "$CFG"
fi

# memcaps segun la RAM real y stream para espejo. Con un valor fijo (512mb) el
# reensamblado TCP se llenaba a los ~5 min con espejo real y, como el memcap es
# global, Suricata dejaba de reensamblar TODO (tambien el trafico propio): las
# firmas HTTP dejaban de disparar. Reparto: reassembly 25% RAM, stream 6%, flow 6%,
# defrag 1.5%. midstream/async-oneside solo con TZSP (espejo con perdidas/asimetrico);
# en el yaml de Debian esas claves vienen comentadas, asi que se insertan bajo 'stream:'.
RAM_MB="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
python3 - "$CFG" "$RAM_MB" "$TZSP" <<'PY'
import sys, re
cfg, ram, tzsp = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
def mb(pct, lo, hi): return max(lo, min(hi, ram * pct // 100))
want = {
    ("flow", None): mb(6, 128, 4096),
    ("stream", None): mb(6, 64, 4096),
    ("stream", "reassembly"): mb(25, 256, 16384),
    ("defrag", None): mb(1, 32, 1024),
}
lines = open(cfg, encoding="utf-8").read().split("\n")
top = sub = None
out = []
for l in lines:
    m = re.match(r"^([a-z][\w-]*):", l)
    if m:
        top, sub = m.group(1), None
    elif re.match(r"^  ([a-z][\w-]*):\s*$", l) and top == "stream":
        sub = re.match(r"^  ([a-z][\w-]*):", l).group(1)
    m2 = re.match(r"^(\s*)memcap:\s*\d+\s*[mg]b\b(.*)$", l)
    if m2:
        key = (top, sub) if (top == "stream" and sub == "reassembly" and l.startswith("    ")) else (top, None)
        if key in want:
            l = f"{m2.group(1)}memcap: {want[key]}mb{m2.group(2)}"
    out.append(l)
s = "\n".join(out)
if tzsp:
    # midstream/async-oneside: espejo con perdidas y sesiones ya empezadas.
    # bypass: junto con tls encryption-handling=bypass, deja de reensamblar los flujos
    # cifrados tras el handshake (la mayoria del trafico): sin esto el reensamblado
    # crecia ~100 MB/min sin meseta con espejo real.
    for k in ("midstream", "async-oneside", "bypass"):
        if not re.search(rf"^  {k}:\s*true\s*$", s, re.M):
            s = re.sub(rf"^  {k}:.*\n", "", s, flags=re.M)          # quita valor previo
            s = re.sub(r"^stream:\s*\n", f"stream:\n  {k}: true\n", s, count=1, flags=re.M)
open(cfg, "w", encoding="utf-8").write(s)
PY
if [ "$TZSP" -eq 1 ]; then
  # TLS: no seguir inspeccionando tras el handshake (bypass del flujo)
  sed -i 's/^\(\s*\)#encryption-handling: default\s*$/\1encryption-handling: bypass/' "$CFG"
  # flujos TCP establecidos: 600 -> 300 s (el espejo deja flujos huerfanos que nunca cierran)
  sed -i '/^flow-timeouts:/,/^[a-z]/{/^  tcp:/,/^  [a-z]/{s/^\(\s*established:\)\s*600\s*$/\1 300/}}' "$CFG"
  # profundidad de reensamblado por flujo: 1mb -> 512kb (acota memoria por flujo)
  sed -i 's/^\(\s*depth:\)\s*1mb\(.*\)$/\1 512kb\2/' "$CFG"
fi
ok "Memcaps (RAM ${RAM_MB} MB): $(python3 - "$CFG" <<'PY'
import re,sys
s=open(sys.argv[1],encoding="utf-8").read()
def g(sec,sub=None):
    m=re.search(rf"^{sec}:\n(.*?)(?=^\S)", s, re.S|re.M)
    if not m: return "?"
    body=m.group(1)
    if sub:
        m2=re.search(rf"^  {sub}:[^\n]*\n(.*?)(?=^  \S|\Z)", body, re.S|re.M); body=m2.group(1) if m2 else ""
        m3=re.search(r"^    memcap:\s*(\S+)", body, re.M)
    else:
        m3=re.search(r"^  memcap:\s*(\S+)", body, re.M)
    return m3.group(1) if m3 else "?"
print(f"flow={g('flow')} stream={g('stream')} reassembly={g('stream','reassembly')} defrag={g('defrag')}")
PY
)"
if [ "$TZSP" -eq 1 ]; then
  grep -qE '^  midstream: true' "$CFG" && grep -qE '^  async-oneside: true' "$CFG" \
    && ok "stream: midstream + async-oneside activos (espejo)." \
    || warn "No pude activar midstream/async-oneside en ${CFG}; revisalo a mano."
fi

# archivo de interfaz para el servicio de Debian
if [ -f /etc/default/suricata ]; then
  sed -i "s#^IFACE=.*#IFACE=${IFACE}#" /etc/default/suricata || true
  sed -i "s#^LISTENMODE=.*#LISTENMODE=af-packet#" /etc/default/suricata || true
fi

# ----------------------------------------------------------------------------- logrotate
# Debian trae rotate 14 + copytruncate sin frecuencia (semanal) ni maxsize: con espejo
# real eve.json crecia ~7 GB/dia. Se fuerza diario, tope 2G y 7 copias (idempotente).
LOGROTATE_CFG=/etc/logrotate.d/suricata
if [ -f "$LOGROTATE_CFG" ]; then
  compgen -G "${LOGROTATE_CFG}.bak-*" >/dev/null || cp -a "$LOGROTATE_CFG" "${LOGROTATE_CFG}.bak-${STAMP}"
  grep -qE '^\s*daily' "$LOGROTATE_CFG" || sed -i '0,/{/s//{\n\tdaily\n\tmaxsize 2G/' "$LOGROTATE_CFG"
  sed -i 's/^\(\s*rotate\) 14/\1 7/' "$LOGROTATE_CFG"
  # maxsize solo actua cuando corre logrotate y el timer de Debian es diario: pasarlo a
  # cada hora, asi eve.json nunca pasa de ~2G + una hora de escritura.
  install -d /etc/systemd/system/logrotate.timer.d
  printf '[Timer]\nOnCalendar=\nOnCalendar=hourly\nAccuracySec=5min\n' > /etc/systemd/system/logrotate.timer.d/10-hourly.conf
  systemctl daemon-reload
  systemctl enable --now logrotate.timer >/dev/null 2>&1 || true
  ok "logrotate: cada hora, maxsize 2G, 7 copias (eve.json crece rapido con espejo)."
fi

# ----------------------------------------------------------------------------- informe diario
# EveBox sirve para investigar, no para vigilar. Este informe saca cada manana el top de
# IPs origen con alertas graves (sin ET INFO) de las ultimas 24h y, si hay un token de
# Telegram en /etc/suricata-report.conf, lo envia; si no, lo deja en /var/log/suricata/.
cat > /usr/local/bin/suricata-report <<'REP'
#!/usr/bin/env python3
"""Informe diario de Suricata en lenguaje claro: quien esta infectado y que hacer."""
import glob, gzip, io, json, os, socket, time, urllib.request, urllib.parse, urllib.error
from collections import Counter, defaultdict

CONF = "/etc/suricata-report.conf"
LOGDIR = "/var/log/suricata"
HOURS = 24
cutoff = time.time() - HOURS * 3600
MAX_LINES = 20_000_000
try:
    import resource
    _cap = 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (_cap, _cap))
except Exception:
    pass

def conf():
    d = {}
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); d[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return d

def opener(p):
    return io.TextIOWrapper(gzip.open(p, "rb")) if p.endswith(".gz") else open(p, encoding="utf-8", errors="replace")

# Clasificacion: (claves, nivel, explicacion, accion). nivel 1=infectado, 2=atacando, 3=sospechoso.
# Gana la primera regla cuya palabra clave aparece en la firma.
REGLAS = [
    # Nivel 1 (rojo) = comunicacion real con el atacante = infeccion confirmada. Una
    # simple consulta DNS a un dominio de mala fama NO es nivel 1 (por eso "malware" a
    # secas cae en nivel 3): el destino suele ser tu propio DNS, no el atacante.
    (("cnc", "c2 ", "command and control", "checkin", "check-in", "botnet", "mirai", "katana",
      "trojan", "ransom", " rat ", "coinmin", "cryptomin", "compromised"),
     1, "equipo infectado hablando con su centro de mando", "aislar/cuarentena y avisar al cliente"),
    (("ssh scan", "brute", "password"),
     2, "atacando contrasenas (SSH/servicios) hacia afuera", "bloquear salida y revisar el equipo"),
    (("scan", "recon", "sweep", "escanea", "barrido", "portscan"),
     2, "escaneando puertos hacia internet (tipico de infeccion)", "revisar el equipo, muy probable infeccion"),
    (("exploit", "attack", "cve-", "shellcode", "attempted-admin"),
     2, "intentando explotar/atacar hacia afuera", "revisar el equipo"),
    (("malware", "dns query", "tld", "dyn_dns", "dynamic_dns", "duckdns", "dyndns", "no-ip",
      "suspicious", "likely hostile", "adware", "pup", "observed dns"),
     3, "consultas a dominios sospechosos (dyndns/.cc/.su/.top/reputacion malware)", "vigilar; comun en equipos comprometidos"),
]

def clasifica(sig):
    s = sig.lower()
    for claves, nivel, expl, accion in REGLAS:
        if any(k in s for k in claves):
            return nivel, expl, accion
    return 3, "actividad sospechosa", "vigilar"

# Exclusiones (apartado Exclusiones del panel + lineas IGNORAR_* legacy)
def cargar_exclusiones():
    reglas = []; ahora = time.time()
    try:
        data = json.load(open("/etc/suricata-exclusiones.json", encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if not r.get("ip"):
                    continue
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                if hasta and ahora > hasta:
                    continue                             # exclusion temporal vencida
                reglas.append((r.get("tipo", "dst"), r["ip"],
                               [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()],
                               str(r.get("sid") or "")))
    except Exception:
        pass
    _c = conf()
    reglas += [("dst", x.strip(), [], "") for x in _c.get("IGNORAR_DESTINOS", "").split(",") if x.strip()]
    reglas += [("src", x.strip(), [], "") for x in _c.get("IGNORAR_ORIGENES", "").split(",") if x.strip()]
    return reglas
EXCL = cargar_exclusiones()
def excluido(src, dst, dport, sid=None):
    for tipo, ip, pts, rsid in EXCL:
        quien = dst if tipo == "dst" else src
        if quien != ip:
            continue
        if pts and not (dport is not None and dport in pts):
            continue
        if rsid and str(sid) != rsid:                    # regla ligada a una firma concreta
            continue
        return True
    return False

# Confianza para marcar INFECTADO (nivel 1): no basta el texto de UNA firma. Se exige
# REPETICION (>= UMBRAL_INFECTADO alertas de nivel 1) o >=2 firmas CnC distintas (SIDs).
# Una sola alerta de CnC aislada se degrada a nivel 2 "posible, sin confirmar".
try:
    UMBRAL_INFECTADO = max(1, int(conf().get("UMBRAL_INFECTADO", "3") or "3"))
except Exception:
    UMBRAL_INFECTADO = 3

by_src_nivel = {}
by_src_expl = {}
by_src_accion = {}
by_src_total = Counter()
n1_hits = Counter()            # alertas de nivel 1 (CnC/botnet) por IP -> repeticion
n1_sids = defaultdict(set)     # firmas CnC distintas por IP (SID o texto) -> contexto
pair = defaultdict(Counter)
total = 0
seen = 0

files = sorted(glob.glob(f"{LOGDIR}/eve.json*"), key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
for p in files:
    try:
        if os.path.getmtime(p) < cutoff - 3600:
            continue
    except OSError:
        continue
    try:
        for line in opener(p):
            seen += 1
            if seen > MAX_LINES:
                break
            if '"event_type":"alert"' not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event_type") != "alert":
                continue
            a = e.get("alert", {})
            sig = a.get("signature", "")
            cat = a.get("category") or ""
            if sig.startswith("ET INFO") or "Not Suspicious" in cat or "Misc activity" in cat:
                continue
            src = e.get("src_ip", "?"); dst = e.get("dest_ip", "?")
            if excluido(src, dst, e.get("dest_port"), a.get("signature_id")):   # exclusiones configuradas
                continue
            nivel, expl, accion = clasifica(sig)
            by_src_total[src] += 1
            pair[src][sig] += 1
            if nivel == 1:
                n1_hits[src] += 1
                n1_sids[src].add(a.get("signature_id") or sig)
            if src not in by_src_nivel or nivel < by_src_nivel[src]:
                by_src_nivel[src] = nivel; by_src_expl[src] = expl; by_src_accion[src] = accion
            total += 1
    except OSError:
        continue

host = socket.gethostname()
NOMBRE = {1: "INFECTADOS (actuar ya)", 2: "ATACANDO / ESCANEANDO (revisar)", 3: "SOSPECHOSOS (vigilar)"}

# Confirmacion de INFECTADO: solo se queda en nivel 1 si hubo repeticion (>= UMBRAL_INFECTADO
# alertas de nivel 1) o >=2 firmas CnC distintas. Una alerta de CnC aislada baja a nivel 2
# como "posible, sin confirmar" (evita marcar infectado por el texto de UNA sola firma).
for ip in list(by_src_nivel):
    if by_src_nivel[ip] == 1 and not (n1_hits[ip] >= UMBRAL_INFECTADO or len(n1_sids[ip]) >= 2):
        by_src_nivel[ip] = 2
        by_src_expl[ip] = (f"posible infeccion SIN confirmar: solo {n1_hits[ip]} alerta(s) de "
                           f"CnC aislada(s) (se piden {UMBRAL_INFECTADO} o 2 firmas distintas)")
        by_src_accion[ip] = "confirmar primero: ver si se repite o hay mas indicadores antes de aislar"

grupos = defaultdict(list)
for ip in by_src_total:
    grupos[by_src_nivel[ip]].append(ip)

L = []
L.append(f"IDS {host} - resumen de {HOURS}h")
n1 = len(grupos.get(1, [])); n2 = len(grupos.get(2, [])); n3 = len(grupos.get(3, []))
L.append(f"Infectados: {n1}   Atacando: {n2}   Sospechosos: {n3}   (alertas graves: {total})")
if not total:
    L.append("")
    L.append("Sin alertas graves. Revisa que este llegando trafico del espejo.")
for nivel in (1, 2, 3):
    ips = grupos.get(nivel, [])
    if not ips:
        continue
    ips.sort(key=lambda ip: by_src_total[ip], reverse=True)
    L.append("")
    L.append(f"== {NOMBRE[nivel]} ==")
    for ip in ips[:15]:
        veces = by_src_total[ip]
        L.append(f"  {ip:16s}  {by_src_expl[ip]}")
        L.append(f"  {'':16s}  -> {by_src_accion[ip]}  ({veces} alertas)")
    if len(ips) > 15:
        L.append(f"  ... y {len(ips)-15} equipos mas en este grupo")
report = "\n".join(L)

out = os.path.join(LOGDIR, "report-" + time.strftime("%Y%m%d") + ".txt")
try:
    open(out, "w", encoding="utf-8").write(report + "\n")
except OSError:
    pass
# conservar solo los 20 informes de texto mas recientes
try:
    import glob as _g
    ts = sorted(_g.glob(os.path.join(LOGDIR, "report-*.txt")), key=os.path.getmtime, reverse=True)
    for _v in ts[20:]:
        try:
            os.remove(_v)
        except OSError:
            pass
except OSError:
    pass

c = conf()
tok, chat = c.get("TELEGRAM_TOKEN"), c.get("TELEGRAM_CHAT_ID")
if tok and chat:
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": report[:4000]}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data=data, timeout=20)
    except Exception as ex:
        print("Telegram fallo:", ex)
print(report)
REP
chmod 755 /usr/local/bin/suricata-report
if [ ! -f /etc/suricata-report.conf ]; then
  cat > /etc/suricata-report.conf <<'CONF'
# Informe diario de Suricata. Para enviarlo por Telegram, rellena estas dos lineas
# (crea un bot con @BotFather y saca tu chat_id con @userinfobot). Sin ellas, el
# informe solo se guarda en /var/log/suricata/report-AAAAMMDD.txt.
#TELEGRAM_TOKEN=123456:ABC...
#TELEGRAM_CHAT_ID=123456789

# IPs de infraestructura propia a EXCLUIR de reportes/feed (separadas por coma). Util
# para tus DNS: las consultas de clientes a dominios de mala fama van dirigidas a tu DNS
# y ensucian el panel. Pon aqui las IP de tus resolvers y reinicia: systemctl restart suricata-dashboard
#IGNORAR_DESTINOS=10.66.66.2,205.235.3.8
#IGNORAR_ORIGENES=
CONF
  chmod 600 /etc/suricata-report.conf
fi
# archivo de exclusiones (lo gestiona el apartado Exclusiones del panel)
[ -f /etc/suricata-exclusiones.json ] || echo '[]' > /etc/suricata-exclusiones.json
chmod 644 /etc/suricata-exclusiones.json

# --- feeds de reputacion IP (abuse.ch Feodo, CINS Army, Spamhaus DROP/EDROP) ---
# Alimentan la senal de "reputacion" del puntaje de riesgo por CPE. Falla suave.
cat > /usr/local/bin/suricata-feeds-update <<'FEEDS'
#!/usr/bin/env python3
"""Baja feeds de reputacion (IPs y dominios) CON PROCEDENCIA y CADUCIDAD POR FUENTE.
Cada fuente se guarda por separado en src/<fuente>.lst (indicador por linea); si una
descarga falla o no es valida, se CONSERVA la ultima version valida de esa fuente y se
marca su estado (valido/vacio/error/sin-clave). reputation.lst/domains.lst se rearman
uniendo solo las fuentes NO caducadas, con la fuente en cada linea (indicador<TAB>fuente).
Auth-Key de abuse.ch (URLhaus/ThreatFox) opcional en /etc/suricata-feeds.conf."""
import ipaddress, json, os, sys, time, urllib.request, urllib.error

DIR = "/var/lib/suricata-feeds"
SRCDIR = os.path.join(DIR, "src")
CONF = "/etc/suricata-feeds.conf"
os.makedirs(SRCDIR, exist_ok=True)

def _conf(k, d=""):
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l.startswith(k + "="):
                return l.split("=", 1)[1].strip()
    except OSError:
        pass
    return d

AUTH_KEY = _conf("ABUSE_CH_AUTH_KEY", "")
AIDB_KEY = _conf("ABUSEIPDB_KEY", "")
# Cada fuente dice COMO se autentica, porque no todas lo hacen igual: abuse.ch manda la
# clave en la cabecera Auth-Key y AbuseIPDB en la cabecera Key. "" = fuente abierta.
CLAVES = {"abusech": AUTH_KEY, "aidb": AIDB_KEY}
CABECERA = {"abusech": "Auth-Key", "aidb": "Key"}

def _clave_de(auth):
    return CLAVES.get(auth, "")

# fuente: (nombre, url, ttl_horas[caducidad], tipo[ip|dom], categoria, auth, min_min[intervalo minimo de descarga])
# EDROP se ELIMINO como fuente aparte: se fusiono en Spamhaus DROP (abr-2024).
# Feodo: lista RECOMENDADA (servidores C2 activos/recientes), refresca cada 5 min upstream.
IPF = [
    ("feodo",         _conf("FEODO_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"), 6, "ip", "c2-activo", "", 10),
    ("cins",          _conf("CINS_URL", "https://cinsscore.com/list/ci-badguys.txt"), 48, "ip", "atacante-observado", "", 720),
    ("spamhaus-drop", _conf("SPAMHAUS_DROP_URL", "https://www.spamhaus.org/drop/drop.txt"), 192, "cidr", "infra-delictiva", "", 1440),
    # AbuseIPDB: IPs denunciadas por la comunidad. El plan gratuito da 5 descargas al dia
    # y devuelve las de confianza 100 (acotar el umbral es de pago), asi que se baja como
    # mucho cada 6 h: la lista queda fresca y sobra cuota. Una peticion trae hasta 10.000.
    ("abuseipdb",     _conf("ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/blacklist?plaintext&limit=10000"), 24, "ip", "atacante-denunciado", "aidb", 360),
]
DOMF = [
    ("urlhaus",   _conf("URLHAUS_URL", "https://urlhaus.abuse.ch/downloads/hostfile/"), 24, "dom", "distribucion-malware", "abusech", 60),
    ("threatfox", _conf("THREATFOX_URL", "https://threatfox.abuse.ch/downloads/hostfile/"), 24, "dom", "c2-ioc", "abusech", 60),
]

def _fetch(url, auth=""):
    hdrs = {"User-Agent": "suricata-feeds/2.0", "Accept": "text/plain"}
    clave = _clave_de(auth)
    if clave:
        hdrs[CABECERA.get(auth, "Auth-Key")] = clave    # abuse.ch: Auth-Key; AbuseIPDB: Key
    url = url.replace("{AUTH}", clave)                  # o clave en la URL, si la fuente la usa asi
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=30) as r:
        ctype = (r.headers.get("Content-Type", "") or "").lower()
        body = r.read().decode("utf-8", "replace")
    return body, ctype

def _es_html(body):
    b = body.lstrip()[:400].lower()
    return b.startswith("<!doctype html") or b.startswith("<html") or "<head" in b or "<title" in b

def _parse_ip(body):
    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        tok = line.split(";")[0].split()[0].strip()
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version == 4:
                    out.add(str(net))
            else:
                ip = ipaddress.ip_address(tok)
                if ip.version == 4:
                    out.add(str(ip))
        except ValueError:
            continue
    return out

def _parse_dom(body):
    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line[0] == "#":
            continue
        parts = line.split()
        dom = (parts[-1] if len(parts) >= 2 else parts[0]).strip().lower().rstrip(".")
        if not dom or "." not in dom or dom in ("localhost", "0.0.0.0", "127.0.0.1", "::1"):
            continue
        # dominio plausible: labels validos, TLD alfabetico
        labs = dom.split(".")
        if len(labs) < 2 or not labs[-1].isalpha() or any(not l or len(l) > 63 for l in labs):
            continue
        out.add(dom)
    return out

def _cargar_meta():
    try:
        return json.load(open(os.path.join(DIR, "reputation.meta"), encoding="utf-8"))
    except Exception:
        return {}

meta_prev = _cargar_meta()
src_prev = meta_prev.get("sources", {})
sources = {}
now = int(time.time())

def procesar(name, url, ttl_h, tipo, cat, auth, min_min):
    prev = src_prev.get(name, {})
    estado = "error"; n = prev.get("count", 0); fv = prev.get("fetched_valid", 0)
    parse = _parse_dom if tipo == "dom" else _parse_ip
    if fv and prev.get("estado") == "valido" and (now - fv) < min_min * 60 \
            and os.path.exists(os.path.join(SRCDIR, name + ".lst")):
        estado = "valido"                   # descargado hace poco: no re-bajar (respeta el upstream)
    elif auth and not _clave_de(auth):
        estado = "sin-clave"                # necesita clave y no hay -> se conserva lo viejo
    else:
        try:
            body, ctype = _fetch(url, auth)
            if "text/html" in ctype or _es_html(body):
                estado = "error"            # respuesta HTML (login/portal/error), NO una lista
            else:
                items = parse(body)
                if not items:
                    estado = "vacio"        # descarga OK pero sin entradas validas
                else:
                    tmp = os.path.join(SRCDIR, name + ".lst.tmp")
                    open(tmp, "w", encoding="utf-8").write("\n".join(sorted(items)) + "\n")
                    os.replace(tmp, os.path.join(SRCDIR, name + ".lst"))
                    estado, n, fv = "valido", len(items), now
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and auth:
                estado = "sin-clave"
            elif e.code == 429 and fv:
                estado = prev.get("estado", "valido")   # cuota diaria agotada: lo de ayer vale
            else:
                estado = "error"
            sys.stderr.write(f"{name}: HTTP {e.code}\n")
        except Exception as e:
            estado = "error"; sys.stderr.write(f"{name}: {e}\n")
    expira = (fv + ttl_h * 3600) if fv else 0
    caducado = fv and now > expira
    sources[name] = {"estado": estado, "count": n, "url": url, "tipo": tipo, "categoria": cat,
                     "ttl_horas": ttl_h, "fetched_valid": fv, "expira": expira,
                     "vigente": bool(fv and not caducado), "requiere_auth": bool(auth),
                     "auth": auth}

for f in IPF + DOMF:
    procesar(*f)

def _leer_src(name):
    try:
        return [l.strip() for l in open(os.path.join(SRCDIR, name + ".lst"), encoding="utf-8") if l.strip()]
    except OSError:
        return []

# rearmar reputation.lst / domains.lst uniendo SOLO fuentes vigentes (no caducadas),
# con la fuente en cada linea: "indicador<TAB>fuente".
rep_lines = []; dom_lines = []; n_ip = 0; n_dom = 0
for name, s in sources.items():
    if not s["vigente"]:
        continue
    for ind in _leer_src(name):
        if s["tipo"] == "dom":
            dom_lines.append(f"{ind}\t{name}"); n_dom += 1
        else:
            rep_lines.append(f"{ind}\t{name}"); n_ip += 1
if rep_lines:
    tmp = os.path.join(DIR, "reputation.lst.tmp")
    open(tmp, "w", encoding="utf-8").write("\n".join(rep_lines) + "\n")
    os.replace(tmp, os.path.join(DIR, "reputation.lst"))
if dom_lines:
    tmp = os.path.join(DIR, "domains.lst.tmp")
    open(tmp, "w", encoding="utf-8").write("\n".join(dom_lines) + "\n")
    os.replace(tmp, os.path.join(DIR, "domains.lst"))

meta = {"generated": now, "total": n_ip, "total_dominios": n_dom, "sources": sources}
open(os.path.join(DIR, "reputation.meta"), "w", encoding="utf-8").write(json.dumps(meta, indent=2))
vig = sum(1 for s in sources.values() if s["vigente"])
print(f"reputation.lst: {n_ip} IPs; domains.lst: {n_dom} dominios; {vig}/{len(sources)} fuentes vigentes")
for name, s in sources.items():
    print(f"  {name}: {s['estado']} ({s['count']}) vigente={s['vigente']}")
if not rep_lines and not dom_lines:
    sys.exit(1)
FEEDS
chmod 755 /usr/local/bin/suricata-feeds-update
# config opcional de feeds: Auth-Key de abuse.ch (URLhaus/ThreatFox) y overrides de URL.
if [ ! -f /etc/suricata-feeds.conf ]; then
  cat > /etc/suricata-feeds.conf <<'FCONF'
# Feeds de reputacion del panel Suricata. Tras editar: /usr/local/bin/suricata-feeds-update
# abuse.ch (URLhaus y ThreatFox) EXIGE Auth-Key gratis: https://auth.abuse.ch/
# Descomenta y pega tu clave (este archivo es 600, la clave NO sale del server):
#ABUSE_CH_AUTH_KEY=tu-auth-key
# Overrides de URL (opcional; si abuse.ch cambia el endpoint):
#URLHAUS_URL=https://urlhaus.abuse.ch/downloads/hostfile/
#THREATFOX_URL=https://threatfox.abuse.ch/downloads/hostfile/
# AbuseIPDB (clave gratuita en https://www.abuseipdb.com/account/api). Sirve para dos
# cosas: la lista masiva de atacantes de aqui arriba y las consultas por IP del panel.
#ABUSEIPDB_KEY=tu-clave
#ABUSEIPDB_URL=https://api.abuseipdb.com/api/v2/blacklist?plaintext&limit=10000
FCONF
  chmod 600 /etc/suricata-feeds.conf
fi
# cron cada 15 min: cada fuente respeta su propio intervalo minimo (Feodo se refresca
# seguido; DROP/CINS se bajan 1x/dia aunque el cron corra), asi no se martillan los feeds.
cat > /etc/cron.d/suricata-feeds <<'CRON'
# Refresca los feeds de reputacion del panel Suricata (falla suave, intervalo por fuente)
*/15 * * * * root /usr/local/bin/suricata-feeds-update >> /var/log/suricata-feeds.log 2>&1
CRON
chmod 644 /etc/cron.d/suricata-feeds
# primera carga ya (best-effort; si no hay internet, el score corre con reputacion=0)
/usr/local/bin/suricata-feeds-update >> /var/log/suricata-feeds.log 2>&1 || true

# --- Mapa "a donde atacan": assets del mapa (vendorizados) + base GeoIP IP->pais (offline) ---
# Todo best-effort: si no hay internet en la instalacion, el mapa se dibuja vacio con un aviso
# y el resto del panel funciona igual. Se puede reconstruir re-ejecutando el instalador.
REPO_RAW="https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main"
install -d -m 755 /var/lib/suricata-mapa /var/lib/suricata-geoip
_mapa_get() {  # $1=archivo  $2=sha256 esperado
  f="/var/lib/suricata-mapa/$1"
  [ -f "$f" ] && [ "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" = "$2" ] && return 0
  curl -fsSL "$REPO_RAW/vendor/mapa/$1" -o "$f.new" 2>/dev/null || { rm -f "$f.new"; echo "mapa: no se bajo $1 (sin internet?)"; return 1; }
  if [ "$(sha256sum "$f.new" | cut -d' ' -f1)" = "$2" ]; then mv "$f.new" "$f"; echo "mapa: $1 OK"; else rm -f "$f.new"; echo "mapa: SHA no coincide en $1"; return 1; fi
}
_mapa_get countries-110m.json a73ecc17bac82de28af19fa593f9e1a2e76619c51855490da735b7883ec48715 || true
_mapa_get topojson-client.min.js ec362ac1599ef406ea9e79616a4ad47d4a3b3939882d47da7e4bc827a56f629c || true
if [ ! -s /var/lib/suricata-geoip/ipv4.bin ]; then
  python3 - <<'GEOPY' || echo "geoip: no se construyo (el mapa quedara vacio hasta reconstruir)"
import urllib.request, ipaddress, array, struct, os
URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"
try:
    data = urllib.request.urlopen(URL, timeout=180).read().decode("utf-8", "replace")
except Exception as e:
    raise SystemExit("descarga geoip fallo: %s" % e)
rows = []
for ln in data.splitlines():
    p = ln.split(",")
    if len(p) < 3:
        continue
    cc = p[2].strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        continue
    try:
        s = int(ipaddress.IPv4Address(p[0].strip())); e = int(ipaddress.IPv4Address(p[1].strip()))
    except Exception:
        continue
    if e >= s:
        rows.append((s, e, cc))
if len(rows) < 1000:
    raise SystemExit("geoip: muy pocas filas (%d), aborto" % len(rows))
rows.sort()
starts = array.array("I", [r[0] for r in rows]); ends = array.array("I", [r[1] for r in rows])
if starts.itemsize != 4:
    raise SystemExit("geoip: array 'I' no es de 4 bytes en esta plataforma")
ccb = b"".join(r[2].encode("ascii") for r in rows)
tmp = "/var/lib/suricata-geoip/ipv4.bin.tmp"
with open(tmp, "wb") as f:
    f.write(struct.pack("<I", len(rows))); starts.tofile(f); ends.tofile(f); f.write(ccb)
os.replace(tmp, "/var/lib/suricata-geoip/ipv4.bin")
print("geoip: %d rangos -> /var/lib/suricata-geoip/ipv4.bin" % len(rows))
GEOPY
fi

# --- reporte HTML grafico (puertos, IPs origen/destino, linea de tiempo, tabla) ---
cat > /usr/local/bin/suricata-html-report <<'HREP'
#!/usr/bin/env python3
"""Genera un reporte HTML grafico de ataques desde eve.json de Suricata.

Muestra: puertos de destino atacados, IPs origen (atacantes), IPs destino
(objetivos), linea de tiempo por hora, y una tabla origen IP:puerto -> destino
IP:puerto con firma, protocolo, primera/ultima hora y duracion. Autocontenido
(sin dependencias externas): se abre en el navegador o se imprime a PDF.

Uso: suricata-html-report [horas]   (default 24)
Salida: /var/log/suricata/report-AAAAMMDD-HHMM.html
"""
import glob, gzip, io, json, os, re, sys, html, time, socket, urllib.request, urllib.error
import array, struct, bisect
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

TZ_EC = timezone(timedelta(hours=-5))   # hora de Ecuador (America/Guayaquil, sin horario de verano)

# Extraccion por regex (mucho mas rapida que json.loads por linea sobre cientos de MB).
_RE = {k: re.compile(p) for k, p in {
    "ts": r'"timestamp":"([^"]+)"',
    "src_ip": r'"src_ip":"([^"]+)"',
    "dest_ip": r'"dest_ip":"([^"]+)"',
    "src_port": r'"src_port":(\d+)',
    "dest_port": r'"dest_port":(\d+)',
    "proto": r'"proto":"([^"]+)"',
    "sig": r'"signature":"((?:[^"\\]|\\.)*)"',
    "cat": r'"category":"((?:[^"\\]|\\.)*)"',
    "sev": r'"severity":(\d+)',
    "sid": r'"signature_id":(\d+)',
    "rev": r'"rev":(\d+)',
    "flow_id": r'"flow_id":(\d+)',
    "rrname": r'"rrname":"([^"]+)"',
    # por que interfaz entro la alerta: con varios MikroTik, cada uno espeja por la
    # suya, asi que esto dice de QUE NODO es el CPE. Sin el, dos nodos que usan el
    # mismo rango privado (10.0.0.x en los dos) serian el mismo cliente.
    "iface": r'"in_iface":"([^"]+)"',
}.items()}

# Firmas de "infeccion" (CnC/botnet/troyano): mismas claves que el informe. Para marcar
# INFECTADO no basta una: se exige repeticion (UMBRAL_INFECTADO) o >=2 firmas distintas.
CNC_KW = ("cnc", "c2 ", "command and control", "checkin", "check-in", "botnet", "mirai",
          "katana", "trojan", "ransom", " rat ", "coinmin", "cryptomin", "compromised")
UMBRAL_INFECTADO = 3

# DNS SOSPECHOSO (Camino A): alertas de consulta DNS a dominios de botnet/C2/malware.
# Se detecta una firma que hable de DNS y ademas de contexto malicioso. Un CPE que
# consulta esos dominios probablemente esta infectado -> lista aparte en el MikroTik.
DNS_MAL = ("malware", "trojan", "botnet", "c2 ", "cnc", "command and control", "dga",
           "sinkhole", "hostile", "phishing", "stealer", "ransom", "known bad",
           "observed", "suspicious domain")
UMBRAL_DNS = 3
def es_dns_sospechoso(sig, cat):
    s = (sig or "").lower(); c = (cat or "").lower()
    if "dns" not in s and "dns" not in c:
        return False
    return any(k in s for k in DNS_MAL) or "c2" in c or "command and control" in c

# --- Allowlist "nunca bloquear": IPs/CIDR que JAMAS entran a cuarentena (infra, clientes
# criticos). El panel las gestiona; aqui solo se excluyen de las listas de candidatos. ---
import ipaddress as _ipm
NUNCA_FILE = "/etc/suricata-nunca-bloquear.lst"
_NUNCA_IPS = set(); _NUNCA_NETS = []
try:
    for _l in open(NUNCA_FILE, encoding="utf-8"):
        _l = _l.split("#", 1)[0].strip()
        if not _l:
            continue
        try:
            if "/" in _l:
                _NUNCA_NETS.append(_ipm.ip_network(_l, strict=False))
            else:
                _NUNCA_IPS.add(_l)
        except ValueError:
            pass
except OSError:
    pass
def nunca_bloquear(ip):
    if ip in _NUNCA_IPS:
        return True
    if _NUNCA_NETS:
        try:
            a = _ipm.ip_address(ip)
            return any(a in n for n in _NUNCA_NETS)
        except ValueError:
            pass
    return False

def _conf_key(k, default):
    try:
        for _l in open("/etc/suricata-dashboard.conf", encoding="utf-8"):
            if _l.strip().startswith(k + "="):
                return _l.split("=", 1)[1].strip()
    except OSError:
        pass
    return default
# Doble senal: para CONFIRMAR infeccion se exigen >=2 senales independientes (repeticion,
# variedad de firmas, fan-out, volumen), o una senal abrumadora. Menos falsos positivos.
# Se apaga con DOBLE_SENAL=0 en /etc/suricata-dashboard.conf.
DOBLE_SENAL = _conf_key("DOBLE_SENAL", "1") == "1"

# --- Que origenes son CPEs TUYOS ---
# El motor de cuarentena existe para tus abonados. Sin este filtro, una IP de internet
# que dispara una firma ENTRANTE (ET Open trae varias con la palabra "compromised", que
# aqui cuenta como infeccion) entraba como "CPE infectado", puntuaba en el ranking de
# riesgo y, con politicas automaticas, podia acabar en la address-list de cuarentena:
# no bloquea nada util y ensucia la lista. Los ataques de fuera se siguen viendo, pero
# en su propio apartado.
# Configurable con MIS_REDES=CIDR,CIDR en /etc/suricata-dashboard.conf (util si das IP
# publica a tus clientes). Por defecto: privadas RFC1918 + CGNAT.
_MIS_NETS = []
for _t in (_conf_key("MIS_REDES", "").replace(";", ",").split(",")
           or []):
    _t = _t.strip()
    if not _t:
        continue
    try:
        _MIS_NETS.append(_ipm.ip_network(_t, strict=False))
    except ValueError:
        pass
if not _MIS_NETS:
    for _t in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
        _MIS_NETS.append(_ipm.ip_network(_t))

def es_mi_cpe(ip):
    """True si la IP pertenece a tus redes (un abonado), False si es de internet."""
    try:
        a = _ipm.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _MIS_NETS)


# Destinos CONFIABLES (falsos positivos): p.ej. un DNS que dispara alertas en muchos CPEs.
# Las alertas HACIA estas IPs no cuentan -> los clientes dejan de ser candidatos por su culpa.
DEST_OK_FILE = "/etc/suricata-destinos-confianza.lst"
DEST_OK = set()
try:
    for _l in open(DEST_OK_FILE, encoding="utf-8"):
        _l = _l.split("#", 1)[0].strip()
        if _l:
            DEST_OK.add(_l)
except OSError:
    pass

def campos(line):
    def g(k):
        m = _RE[k].search(line)
        return m.group(1) if m else ""
    return g

LOGDIR = "/var/log/suricata"

# --- De que MikroTik es cada alerta ---
# El panel publica aqui un mapa SIN claves (solo id, nombre e interfaz de espejo) para
# que el generador no tenga que leer el archivo de routers, que lleva las contrasenas
# de la API. Si no existe, se asume un solo nodo y todo se comporta como siempre.
ROUTERS_MAP = "/var/log/suricata-routers-map.json"
_IFACE_ROUTER = {}      # interfaz -> {"id","nombre"}
_ROUTER_NOMBRE = {}     # id -> nombre
try:
    for _r in (json.load(open(ROUTERS_MAP, encoding="utf-8")) or []):
        _rid = (_r.get("id") or "").strip()
        if _rid:
            _IFACE_ROUTER[(_r.get("iface") or "").strip()] = {"id": _rid, "nombre": _r.get("nombre") or _rid}
            _ROUTER_NOMBRE[_rid] = _r.get("nombre") or _rid
except Exception:
    pass
MULTI_ROUTER = len(_ROUTER_NOMBRE) > 1

def router_de(iface):
    """Id del router por cuya interfaz entro la alerta. Con un solo nodo devuelve ''
    y todo sigue indexado por IP, como hasta ahora."""
    if not MULTI_ROUTER:
        return ""
    r = _IFACE_ROUTER.get(iface or "")
    return r["id"] if r else ""

def nombre_router(rid):
    return _ROUTER_NOMBRE.get(rid, rid or "")

def clave_cpe(ip, rid):
    """Identidad de un CPE. Con varios nodos es (router, IP): la IP sola no identifica
    a nadie cuando dos routers usan el mismo rango privado."""
    return (rid + "|" + ip) if rid else ip

def _chip_nodo(clave):
    """Etiqueta del nodo. Con un solo MikroTik no se muestra nada (seria ruido)."""
    r = rid_de(clave)
    if not r:
        return ""
    return f"<span class='nodochip' title='Espejo de este MikroTik'>{esc(nombre_router(r))}</span>"

def ip_de(clave):
    """La IP pelada de una identidad de CPE (para mostrar, geolocalizar o bloquear)."""
    return clave.split("|", 1)[1] if "|" in clave else clave

def rid_de(clave):
    """El router de una identidad de CPE ("" si la instalacion tiene un solo nodo)."""
    return clave.split("|", 1)[0] if "|" in clave else ""

# IPs ya enviadas a la cuarentena del MikroTik (lo escribe el panel): para que el boton
# del Top muestre "En cuarentena" en vez de "Cuarentena" cuando ya se envio.
# Son DOS listas (infectados y DNS sospechoso): si solo se mira la primera, un CPE
# enviado a la de DNS aparece en el Top como si no estuviera en cuarentena.
# El panel publica aqui lo que el reporte necesita saber de el. Va aparte del .conf de
# feeds a proposito: ese lleva las CLAVES y aqui no hace falta ninguna.
try:
    _FLAGS = json.load(open("/var/log/suricata-panel-flags.json", encoding="utf-8"))
except (OSError, ValueError):
    _FLAGS = {}
_AIDB_REPORTAR = bool(_FLAGS.get("aidb_reportar"))

_MK_ENVIADOS = set()
for _pe in ("/var/log/suricata-cuarentena-enviados.json", "/var/log/suricata-dns-enviados.json"):
    try:
        _MK_ENVIADOS |= set(json.load(open(_pe, encoding="utf-8")).keys())
    except Exception:
        pass
# Ventana del resumen en MINUTOS (argv[1]); por defecto 24h. Con una ventana corta
# (p.ej. 30 min) los cuadros muestran solo la actividad reciente: una IP atendida hace
# rato se cae sola del top al no tener alertas nuevas.
VENTANA_MIN = int(sys.argv[1]) if len(sys.argv) > 1 else 1440
if VENTANA_MIN < 5:
    VENTANA_MIN = 5
cutoff = time.time() - VENTANA_MIN * 60
# la linea de tiempo apunta a ~48 barras: el bucket se adapta a la ventana (min 1 min)
BUCKET_MIN = max(1, round(VENTANA_MIN / 48))
BUCKET = BUCKET_MIN * 60
MAX_LINES = 20_000_000
MAX_FLUJOS = 200_000     # tope de flujos unicos guardados (evita agotar la RAM en espejos de ISP)

# Red de seguridad: limitar la memoria del proceso. Si se pasa, muere con MemoryError
# en vez de tumbar el servidor (paso en un espejo real: millones de flujos unicos).
try:
    import resource
    _cap = 1536 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (_cap, _cap))
except Exception:
    pass

# Candado: si ya hay una generacion en curso, salir (evita dos generadores a la vez).
try:
    import fcntl
    _lock = open("/run/suricata-html-report.lock", "w")
    fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(0)
except Exception:
    pass

def opener(p):
    return io.TextIOWrapper(gzip.open(p, "rb")) if p.endswith(".gz") else open(p, encoding="utf-8", errors="replace")

_RE_TS_LINEA = re.compile(r'"timestamp":"([^"]+)"')

def abrir_desde(p, corte, margen=4 * 1024 * 1024):
    """Abre un log de Suricata posicionado justo antes de `corte`.

    eve.json y dns.json son append-only y van ordenados por tiempo, asi que para una
    ventana de unas horas no hace falta leer el archivo entero: se busca por BISECCION
    el primer punto dentro de la ventana y se empieza ahi. En un dns.json de 1,8 GB con
    ventana de 6 h, esto pasa de leer 1,8 GB a leer unos pocos cientos de MB.

    Los .gz no se pueden posicionar (habria que descomprimir igual), asi que se abren
    como siempre; de todas formas los rotados viejos ya se saltan por su mtime.
    El margen deja un colchon: es preferible leer de mas que perderse eventos."""
    if p.endswith(".gz") or not corte:
        return opener(p)
    try:
        f = open(p, encoding="utf-8", errors="replace")
        tam = os.path.getsize(p)
    except OSError:
        return opener(p)
    if tam <= margen * 2:
        return f
    lo, hi = 0, tam
    try:
        while hi - lo > margen:
            mid = (lo + hi) // 2
            f.seek(mid)
            f.readline()                  # la primera suele venir cortada: se tira
            ts = None
            for _ in range(20):           # alguna linea puede no traer timestamp
                ln = f.readline()
                if not ln:
                    break
                m = _RE_TS_LINEA.search(ln)
                if m:
                    ts = parse_ts(m.group(1))
                    if ts:
                        break
            if ts is None:
                break                     # no se pudo orientar: leer desde donde se este
            if ts < corte:
                lo = mid
            else:
                hi = mid
        ini = max(0, lo - margen)
        f.seek(ini)
        if ini:
            # alinear al principio de una linea entera. Solo si NO se empieza en 0: en el
            # offset 0 la primera linea ya esta entera y descartarla perdia un evento.
            f.readline()
    except (OSError, ValueError):
        f.seek(0)
    return f

def cargar_exclusiones():
    """Reglas de exclusion: {tipo:'dst'|'src', ip, puertos:[int]}. Desde
    /etc/suricata-exclusiones.json (apartado Exclusiones) + lineas IGNORAR_* legacy."""
    reglas = []; ahora = time.time()
    try:
        data = json.load(open("/etc/suricata-exclusiones.json", encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if not r.get("ip"):
                    continue
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                if hasta and ahora > hasta:
                    continue                             # exclusion temporal vencida
                reglas.append((r.get("tipo", "dst"), r["ip"],
                               [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()],
                               str(r.get("sid") or "")))
    except Exception:
        pass
    try:
        for l in open("/etc/suricata-report.conf", encoding="utf-8"):
            l = l.strip()
            if l.startswith("IGNORAR_DESTINOS="):
                reglas += [("dst", x.strip(), [], "") for x in l.split("=", 1)[1].split(",") if x.strip()]
            elif l.startswith("IGNORAR_ORIGENES="):
                reglas += [("src", x.strip(), [], "") for x in l.split("=", 1)[1].split(",") if x.strip()]
    except OSError:
        pass
    return reglas

EXCL = cargar_exclusiones()

def excluido(src, dst, dport, sid=None):
    for tipo, ip, pts, rsid in EXCL:
        quien = dst if tipo == "dst" else src
        if quien != ip:
            continue
        if pts and not (dport is not None and dport in pts):
            continue
        if rsid and str(sid) != rsid:                    # regla ligada a una firma concreta
            continue
        return True
    return False

_TRAD = [
    (("poor reputation", "cins", "compromised ip", "dshield", "spamhaus", "abuse.ch", "known attacker", "cinsscore"), "Mala reputacion"),
    (("tor exit", "tor node", "tor "), "Red Tor"),
    (("katana",), "Botnet Katana"),
    (("mirai",), "Botnet Mirai"),
    (("cnc", "c2 ", "command and control", "checkin", "check-in"), "Botnet CnC"),
    (("botnet",), "Botnet"),
    (("ransom",), "Ransomware"),
    (("trojan",), "Troyano"),
    (("coinmin", "cryptomin", "miner"), "Criptomineria"),
    (("ssh scan",), "Escaneo SSH"),
    (("brute", "password"), "Fuerza bruta"),
    (("rdp", "vnc"), "RDP/VNC"),
    (("telnet",), "Escaneo Telnet"),
    (("tr-069", "cwmp", "7547"), "Escaneo TR-069"),
    (("port scan", "portscan", "sweep", "recon", "barrido"), "Escaneo de puertos"),
    (("scan",), "Escaneo saliente"),
    (("exploit", "cve-", "shellcode", "attempted-admin"), "Exploit"),
    (("connectivity check", "connectivity-check"), "Chequeo de conectividad"),
    (("403 forbidden",), "Acceso denegado (403)"),
    (("go http client",), "Cliente HTTP Go"),
    (("fake wget", "wget 3.0"), "User-Agent falso"),
    (("user_agent", "user agent", "user-agent"), "User-Agent raro"),
    (("bittorrent", "p2p", "dht"), "BitTorrent / P2P"),
    (("stun ",), "STUN (video)"),
    (("snmp",), "Acceso SNMP"),
    (("dyn_dns", "dynamic_dns", "dyndns", "duckdns", "no-ip"), "DNS dinamico"),
    (("dns query", ".cc tld", ".su tld", ".top domain", " tld", "dns lookup"), "DNS sospechoso"),
    (("adware", "pup"), "Adware / PUP"),
    (("malware", "compromised"), "Trafico de malware"),
    (("quic",), "Anomalia QUIC"),
    (("tls", "ssl"), "Anomalia TLS/SSL"),
    (("http",), "Anomalia HTTP"),
    (("stream", "tcp "), "Anomalia TCP"),
]
def traducir(sig):
    s = sig.lower()
    for claves, txt in _TRAD:
        if any(k in s for k in claves):
            return txt
    # Sin traduccion salia la firma ENTERA, con su prefijo de ruleset, y la columna de
    # categorias quedaba ilegible ("ET HUNTING Terse Unencrypted Request for Google...").
    # Se le quita el prefijo y se acota.
    limpio = re.sub(r"^(?:ET|GPL)\s+(?:[A-Z_]{3,}\s+)?", "", sig).strip() or sig
    return (limpio[:44] + "\u2026") if len(limpio) > 45 else limpio

_TS_CACHE = {}
_TS_CACHE_MAX = 200000

def _parse_ts_lento(s):
    # Parsea con el offset de la marca (eve.json trae -0500) para obtener el epoch absoluto.
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except (ValueError, TypeError):
            pass
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=TZ_EC).timestamp()
    except Exception:
        return None

def parse_ts(s):
    """Epoch de una marca de eve.json, CON MEMORIA.

    strptime es carisimo y en un espejo de ISP esto se llama millones de veces por
    corrida: era el grueso de los 9 minutos de CPU que tardaba el generador. La clave del
    cache es el SEGUNDO (fecha, hora y zona, sin los microsegundos), asi que miles de
    lineas del mismo segundo colapsan en un unico strptime.

    Se pierde la precision por debajo del segundo, y no la usa nadie: todo se compara
    contra la ventana, se agrupa en barras de un minuto o mas, o se guarda como entero."""
    if not s:
        return None
    # "2026-09-23T11:48:39.123456-0500" -> "2026-09-23T11:48:39" + "-0500"
    clave = (s[:19] + s[26:]) if len(s) > 26 else s
    v = _TS_CACHE.get(clave)
    if v is not None:
        return v
    r = _parse_ts_lento(clave)
    if r is not None and len(_TS_CACHE) < _TS_CACHE_MAX:
        _TS_CACHE[clave] = r
    return r

by_dport = Counter()
by_src = Counter()
by_dst = Counter()
by_hour = Counter()
pais_dst = Counter()   # alertas por PAIS del destino (para el mapa "a donde atacan")
# Detalle por pais para el mapa: que IPs destino, que puertos y que CPEs (tu red) peticionan.
# OJO con la cardinalidad: pais_srcs y pais_ports no guardan "uno por CPE/puerto" sino un
# par (pais, CPE) y (pais, puerto) -> en un espejo de ISP un CPE que toca 20 paises ocupa
# 20 entradas y el crecimiento es MULTIPLICATIVO. Sin tope es el mismo tipo de fuga que
# tumbo la VM por OOM. Solo se muestran los 4-6 primeros de cada lista, asi que acotar no
# cambia lo que se ve (el "+N mas" pasa a ser un minimo, que sigue siendo cierto).
# --- Metricas por DIA: el numero que un ISP tiene que poder ENSEÑAR ---------------
# Los reportes HTML se podan a los 3 dias, asi que la tendencia no se puede reconstruir
# desde ellos. Esto se guarda aparte y sobrevive.
#
# Se acumula de forma INCREMENTAL (solo lo posterior a la ultima corrida) en vez de
# recontar la ventana: la ventana es configurable y si alguien la baja a 30 min, recontar
# daria un "hoy" ridiculamente bajo sin avisar de nada. Con el incremental, el total del
# dia es correcto sea cual sea la ventana.
# Lo que NO es abuso hacia fuera. Molesta en el panel, pero no hace que a nadie le
# baneen una IP: si BitTorrent o un chequeo de conectividad con Google cuentan como
# "ataque saliente", el numero que hay que poder enseñar no significa nada. Se siguen
# viendo, pero aparte.
CATS_NO_ABUSO = {
    "BitTorrent / P2P", "STUN (video)", "Chequeo de conectividad", "Anomalia QUIC",
    "Anomalia TLS/SSL", "Anomalia HTTP", "Anomalia TCP", "Cliente HTTP Go",
    "User-Agent raro", "User-Agent falso", "DNS dinamico", "Acceso denegado (403)",
}

METRICAS_FILE = "/var/log/suricata-metricas.json"
METRICAS_DIAS = 400          # algo mas de un año de tendencia; el archivo sigue siendo pequeño
METRICAS_MAX_CPES = 5000     # tope del conjunto de CPEs por dia (por encima, el conteo es un minimo)
dias_m = defaultdict(lambda: {"sal": 0, "ent": 0, "ruido": 0, "cpes": set(),
                              "puertos": Counter(), "cats": Counter(), "nodos": Counter()})

MAX_PAIS_CARD = 800
pais_ips = defaultdict(Counter)     # cc -> Counter(ip_destino -> alertas)
pais_ports = defaultdict(Counter)   # cc -> Counter("dport/proto" -> alertas)
pais_srcs = defaultdict(Counter)    # cc -> Counter(cpe_origen -> alertas)

def _cuenta_acotada(contador, clave):
    """Suma 1 solo si la clave ya existe o aun hay sitio: cota la RAM por pais."""
    if clave in contador or len(contador) < MAX_PAIS_CARD:
        contador[clave] += 1

# --- GeoIP IP->pais (offline, base DB-IP lite via ip-location-db, CC-BY-4.0) ---
# Formato compacto en /var/lib/suricata-geoip/ipv4.bin: [uint32 N][N x start u32]
# [N x end u32][N x 2 bytes cc]. Lo genera el instalador; aqui solo se consulta con
# busqueda binaria (Python puro, sin dependencias). Si falta, pais() devuelve "".
GEOIP_BIN = "/var/lib/suricata-geoip/ipv4.bin"
_G_S = _G_E = _G_C = None
_G_loaded = False
_G_ok = False
_geo_cache = {}

def _geo_load():
    global _G_S, _G_E, _G_C, _G_loaded, _G_ok
    if _G_loaded:
        return
    _G_loaded = True
    try:
        with open(GEOIP_BIN, "rb") as f:
            n = struct.unpack("<I", f.read(4))[0]
            s = array.array("I"); s.fromfile(f, n)
            e = array.array("I"); e.fromfile(f, n)
            c = f.read(n * 2)
        if n > 0 and len(c) == n * 2 and s.itemsize == 4:
            _G_S, _G_E, _G_C, _G_ok = s, e, c, True
    except Exception:
        _G_ok = False

def pais(ip):
    """ISO2 del pais de una IPv4 publica (o '' si no se sabe / es privada / IPv6)."""
    if not ip or ":" in ip:
        return ""
    v = _geo_cache.get(ip)
    if v is not None:
        return v
    _geo_load()
    r = ""
    if _G_ok:
        try:
            a = _ipm.IPv4Address(ip)
            if not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast):
                n = int(a)
                i = bisect.bisect_right(_G_S, n) - 1
                if i >= 0 and n <= _G_E[i]:
                    r = _G_C[2 * i:2 * i + 2].decode("ascii", "ignore")
        except Exception:
            r = ""
    _geo_cache[ip] = r
    return r
flujos = {}            # (src,sport,dst,dport,proto,sig) -> [count, first, last]
ips_vistas = set()     # TODAS las IPs vistas en la ventana (cualquier evento, no solo alertas)
MAX_IPS = 300000       # tope de cardinalidad del set (proteje la RAM en flotas grandes)
# --- Senales para el PUNTAJE DE RIESGO por CPE (IP origen) 0-100 ---
NOW = time.time()
sev_by_src = {}                    # peor severidad Suricata vista (1=alta..3=baja)
dst_by_src = defaultdict(set)      # IPs destino distintas (barrido/propagacion)
dpt_by_src = defaultdict(set)      # puertos destino distintos (port-sweep)
# Con CUENTA, no solo distintos: para saber si un CPE es "el del 25/tcp" hace falta el
# volumen, no la variedad. Acotados igual que el resto para no comerse la RAM.
dport_cnt_by_src = defaultdict(Counter)   # CPE -> Counter("25/tcp" -> alertas)
cat_cnt_by_src = defaultdict(Counter)     # CPE -> Counter("Fuerza bruta" -> alertas)
n5_by_src = Counter()              # alertas en los ultimos 5 min (actividad ahora)
n1h_by_src = Counter()             # alertas en la ultima hora (sostenido)
patron_src = defaultdict(set)      # (sig,dport) -> CPEs que lo comparten (correlacion de flota)
inf_hits = Counter()               # alertas CnC/botnet por CPE (para confirmar infeccion)
inf_sids = defaultdict(set)        # firmas CnC distintas por CPE (SID o texto)
inf_sig = {}                       # firma CnC mas reciente por CPE (para el motivo)
dns_hits = Counter()               # alertas de DNS sospechoso por CPE
dns_sids = defaultdict(set)        # firmas DNS distintas por CPE
dns_sig = {}                       # firma DNS mas reciente por CPE
pruebas_by_src = defaultdict(list)  # evidencia por alerta (SID/rev/flow_id/dst/ts) por CPE, tope 8
MAX_CARD = 2500                    # tope por set (el score satura mucho antes; protege RAM)
total = 0
seen = 0
ts_min = None          # timestamp del evento mas antiguo dentro de la ventana (cobertura real)
ts_max = 0             # el mas nuevo: la marca desde la que contara la proxima corrida
try:                   # hasta donde se conto ya (para no contar dos veces ni perderse nada)
    _mprev = json.load(open("/var/log/suricata-metricas.json", encoding="utf-8"))
    METR_DESDE = float(_mprev.get("ultimo_ts") or 0)
except (OSError, ValueError, TypeError):
    _mprev = {}
    METR_DESDE = 0.0

# --- Camino B: dominios malos (feeds URLhaus/ThreatFox) para cruzar con las consultas DNS.
# DEBE definirse ANTES del bucle: el parseo de dns.json usa DOM_OK/dominio_malo. ---
FEEDS_DIR = "/var/lib/suricata-feeds"
DOM_MAL = {}          # dominio -> fuente (procedencia)
DOM_OK = False
try:
    _dm = json.load(open(os.path.join(FEEDS_DIR, "reputation.meta"), encoding="utf-8"))
    # caducidad fina por fuente ya aplicada al rearmar domains.lst; guarda gruesa de 3 dias
    if time.time() - _dm.get("generated", 0) <= 3 * 86400:
        for _l in open(os.path.join(FEEDS_DIR, "domains.lst"), encoding="utf-8"):
            _l = _l.rstrip("\n")
            if not _l or _l[0] in "#;":
                continue
            _d, _, _s = _l.partition("\t")
            _d = _d.strip().lower()
            if _d:
                DOM_MAL[_d] = _s.strip() or "feed"
        DOM_OK = len(DOM_MAL) > 0
except Exception:
    pass

def dominio_malo(dom):
    """Fuente que reporta el dominio (o su dominio padre), o '' si ninguna."""
    s = DOM_MAL.get(dom)
    if s:
        return s
    p = dom.split(".")
    for i in range(1, len(p) - 1):          # a.b.evil.com -> b.evil.com -> evil.com (no el TLD solo)
        s = DOM_MAL.get(".".join(p[i:]))
        if s:
            return s
    return ""

files = sorted(glob.glob(f"{LOGDIR}/eve.json*") + glob.glob(f"{LOGDIR}/dns.json*"),
               key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
for p in files:
    try:
        if os.path.getmtime(p) < cutoff - 3600:
            continue
    except OSError:
        continue
    try:
        for line in abrir_desde(p, cutoff):
            seen += 1
            if seen > MAX_LINES:
                break
            # contar TODAS las IPs vistas (cualquier evento: tls, http, snmp, alert...),
            # no solo las que atacan. Solo lineas con src_ip y dentro de la ventana.
            if len(ips_vistas) < MAX_IPS and '"src_ip":"' in line:
                _mt = _RE["ts"].search(line)
                _tv = parse_ts(_mt.group(1)) if _mt else None
                if _tv is None or _tv >= cutoff:
                    _ms = _RE["src_ip"].search(line)
                    _md = _RE["dest_ip"].search(line)
                    if _ms: ips_vistas.add(_ms.group(1))
                    if _md: ips_vistas.add(_md.group(1))
            # Camino B: consulta DNS a dominio malo (cruce con feeds de dominios)
            if DOM_OK and '"event_type":"dns"' in line and '"rrname":"' in line:
                _qm = _RE["rrname"].search(line); _sm = _RE["src_ip"].search(line)
                if _qm and _sm:
                    _dom = _qm.group(1).lower().rstrip(".")
                    if dominio_malo(_dom):
                        _mt = _RE["ts"].search(line)
                        _tv = parse_ts(_mt.group(1)) if _mt else None
                        if _tv is None or _tv >= cutoff:
                            _s = _sm.group(1)
                            dns_hits[_s] += 1
                            # tope como el de dst_by_src: con tunel DNS o dominios DGA
                            # (subdominios aleatorios bajo un dominio de los feeds) este
                            # set crecia sin fin. Solo se usa su len(), asi que acotarlo
                            # no cambia ninguna decision.
                            if len(dns_sids[_s]) < MAX_CARD:
                                dns_sids[_s].add("dom:" + _dom[:80])
                            dns_sig[_s] = "DNS a dominio malo: " + _dom[:60]
            if '"event_type":"alert"' not in line:
                continue
            g = campos(line)
            sig = g("sig"); cat = g("cat")
            if sig.startswith("ET INFO") or "Not Suspicious" in cat or "Misc activity" in cat:
                continue
            ts = parse_ts(g("ts"))
            if ts and ts < cutoff:
                continue
            # La identidad del CPE se compone AQUI, una sola vez: a partir de este punto
            # todos los acumuladores quedan indexados por (router, IP) cuando hay varios
            # nodos, y por la IP a secas cuando hay uno solo (igual que siempre).
            src = clave_cpe(g("src_ip") or "?", router_de(g("iface")))
            dst = g("dest_ip") or "?"
            sport = g("src_port"); dport = g("dest_port")
            proto = g("proto")
            if excluido(src, dst, int(dport) if dport else None, g("sid")):   # exclusiones configuradas
                continue
            if dst in DEST_OK:     # destino marcado confiable (falso positivo): la alerta no cuenta
                continue
            # --- metricas del dia (solo lo que aun no se habia contado) ---
            if ts:
                if ts > ts_max:
                    ts_max = ts
                if ts > METR_DESDE:
                    _ipsrc = ip_de(src)
                    _mio_src = es_mi_cpe(_ipsrc); _mio_dst = es_mi_cpe(dst)
                    if _mio_src and not _mio_dst:          # TU red hacia fuera
                        _d = dias_m[time.strftime("%Y-%m-%d", time.localtime(ts))]
                        _cat = traducir(sig)
                        if _cat in CATS_NO_ABUSO:
                            _d["ruido"] += 1       # se ve, pero no cuenta como abuso
                        else:
                            _d["sal"] += 1
                            if len(_d["cpes"]) < METRICAS_MAX_CPES:
                                _d["cpes"].add(src)
                            _d["cats"][_cat] += 1
                            if dport:
                                _d["puertos"][f"{dport}/{proto}"] += 1
                            _rid = rid_de(src)
                            if _rid:
                                _d["nodos"][_rid] += 1
                    elif _mio_dst and not _mio_src:        # internet golpeando tu red
                        dias_m[time.strftime("%Y-%m-%d", time.localtime(ts))]["ent"] += 1
            by_dst[dst] += 1
            by_src[src] += 1
            _cc = pais(dst)                    # pais del destino (mapa "a donde atacan")
            if _cc:
                pais_dst[_cc] += 1
                _cuenta_acotada(pais_ips[_cc], dst)    # detalle del mapa: a que IPs, puertos y desde que CPE
                _cuenta_acotada(pais_srcs[_cc], src)
                if dport != "":
                    _cuenta_acotada(pais_ports[_cc], f"{dport}/{proto}")
            if dport != "":
                by_dport[f"{dport}/{proto}"] += 1
            # --- senales de riesgo por CPE ---
            sv = g("sev")
            if sv:
                sv = int(sv)
                if src not in sev_by_src or sv < sev_by_src[src]:
                    sev_by_src[src] = sv     # menor numero = peor severidad
            if dst != "?" and len(dst_by_src[src]) < MAX_CARD:
                dst_by_src[src].add(dst)
            if dport and len(dpt_by_src[src]) < MAX_CARD:
                dpt_by_src[src].add(dport)
            if dport:
                _cuenta_acotada(dport_cnt_by_src[src], f"{dport}/{proto}")
            _cuenta_acotada(cat_cnt_by_src[src], traducir(sig))
            if dport and len(patron_src[(sig, dport)]) < MAX_CARD:
                patron_src[(sig, dport)].add(src)
            _sl = sig.lower()
            _es_cnc = any(k in _sl for k in CNC_KW)
            _es_dns = es_dns_sospechoso(sig, cat)
            if _es_cnc:                           # firma de infeccion (CnC/botnet/troyano)
                inf_hits[src] += 1
                inf_sids[src].add(g("sid") or sig)
                inf_sig[src] = sig
            if _es_dns:                            # consulta DNS a dominio malicioso
                dns_hits[src] += 1
                dns_sids[src].add(g("sid") or sig)
                dns_sig[src] = sig
            # evidencia por alerta (para la ficha): guardar hasta 8 registros por CPE
            if (_es_cnc or _es_dns) and len(pruebas_by_src[src]) < 8:
                pruebas_by_src[src].append({
                    "tipo": "cnc" if _es_cnc else "dns",
                    "sid": g("sid"), "rev": g("rev"), "sig": sig[:120],
                    "ts": int(ts) if ts else 0, "flow_id": g("flow_id"),
                    "dst": dst, "dport": dport,
                    "rrname": g("rrname") if _es_dns else "",
                })
            if ts:
                if ts >= NOW - 300:  n5_by_src[src] += 1
                if ts >= NOW - 3600: n1h_by_src[src] += 1
                by_hour[int(ts // BUCKET)] += 1
                if ts_min is None or ts < ts_min:
                    ts_min = ts
            k = (src, sport, dst, dport, proto, sig)
            f = flujos.get(k)
            if f is None:
                # tope de cardinalidad: si ya hay demasiados flujos unicos, no crear mas
                # (los pesados ya estan dentro); asi la RAM no crece sin limite.
                if len(flujos) < MAX_FLUJOS:
                    flujos[k] = [1, ts or 0, ts or 0]
            else:
                f[0] += 1
                if ts:
                    if not f[1] or ts < f[1]: f[1] = ts
                    if ts > f[2]: f[2] = ts
            total += 1
    except OSError:
        continue

# --- helpers de render (SVG inline, sin JS) ---
BLUE = "#2a78d6"; GRID = "#e7e6e2"; INK = "#0b0b0b"; INK2 = "#52514e"; SURF = "#fcfcfb"

def heat(f):
    """Color segun magnitud (0..1): a mas valor, mas critico -> mas rojo.
    Escala verde (bajo) -> ambar (medio) -> naranja -> rojo (alto)."""
    f = 0.0 if f < 0 else (1.0 if f > 1 else f)
    stops = [(0.0, (43, 120, 214)), (0.35, (27, 175, 122)),
             (0.65, (237, 161, 0)), (0.85, (235, 104, 52)), (1.0, (227, 73, 72))]
    for j in range(len(stops) - 1):
        a, ca = stops[j]; b, cb = stops[j + 1]
        if f <= b:
            t = (f - a) / (b - a) if b > a else 0.0
            r = int(ca[0] + (cb[0] - ca[0]) * t)
            g = int(ca[1] + (cb[1] - ca[1]) * t)
            bl = int(ca[2] + (cb[2] - ca[2]) * t)
            return f"#{r:02x}{g:02x}{bl:02x}"
    return "#e34948"

def esc(x): return html.escape(str(x))

def _cardq(tip):
    """Badge '?' con tooltip explicativo para la cabecera de un cuadro."""
    return f'<span class="chq">?<span class="chtip">{esc(tip)}</span></span>' if tip else ""

def hbar(titulo, pares, unidad="alertas", fmt=str, lblw=125, barw=470, card_class="card",
         label_above=False, tip="", piso=8, que="valor"):
    """Barras horizontales rankeadas, un solo tono, etiqueta de valor directa.
    label_above=True: el nombre va ENCIMA de la barra (a todo el ancho), no en una
    columna a la izquierda; asi los nombres largos (firmas) no se recortan nunca.
    Escala HONESTA: el largo y el color van contra `ref = max(mx, piso)`, no contra el
    maximo. Asi una sola alerta NO llena la barra ni la pinta de rojo (antes, con todo en
    1, salia todo full y rojo como si fueran ataques intensos). `que` = nombre singular
    de la fila (puerto/IP/firma) para el aviso de 'sin dominante'."""
    q = _cardq(tip)
    if not pares:
        return f'<section class="{card_class}"><h2>{esc(titulo)}{q}</h2><p class="muted">Sin datos.</p></section>'
    mx = max(v for _, v in pares) or 1
    ref = max(mx, piso)                       # escala minima: hace falta ~`piso` para llenar/enrojecer
    plano = len({v for _, v in pares}) <= 1   # todos iguales -> no hay un claro dominante
    rows = []
    if label_above:
        W = 900
        barh, labh, gap = 20, 18, 12
        rowh = labh + barh + gap
        h = len(pares) * rowh + 6
        barmax = W - 90
        maxch = 120
        for i, (name, v) in enumerate(pares):
            top = i * rowh + 4
            w = max(2, int(barmax * v / ref))
            etq = name if len(name) <= maxch else name[:maxch - 1] + "…"
            rows.append(
                f'<text x="2" y="{top+13}" class="lbl">{esc(etq)}</text>'
                f'<rect x="2" y="{top+labh}" width="{w}" height="{barh}" rx="4" fill="{heat(v/ref)}"/>'
                f'<text x="{w+8}" y="{top+labh+barh*0.7:.0f}" class="val">{esc(fmt(v))}</text>')
    else:
        rowh, gap = 26, 8
        maxch = max(8, int(lblw / 6.3))
        h = len(pares) * (rowh + gap) + 8
        W = lblw + barw + 80
        for i, (name, v) in enumerate(pares):
            y = i * (rowh + gap) + 4
            w = max(2, int(barw * v / ref))
            etq = name if len(name) <= maxch else name[:maxch - 1] + "…"
            rows.append(
                f'<text x="{lblw-8}" y="{y+rowh*0.68:.0f}" text-anchor="end" class="lbl">{esc(etq)}</text>'
                f'<rect x="{lblw}" y="{y}" width="{w}" height="{rowh}" rx="4" fill="{heat(v/ref)}"/>'
                f'<text x="{lblw+w+6}" y="{y+rowh*0.68:.0f}" class="val">{esc(fmt(v))}</text>')
    # aviso honesto cuando la muestra es plana/pequeña (no hay un dominante real)
    if plano:
        aviso = (f' &middot; <b>sin {esc(que)} dominante</b>: los {len(pares)} van empatados '
                 f'en {esc(fmt(mx))} {esc(unidad)} (muestra pequeña)')
    elif mx < piso:
        aviso = f' &middot; pocos datos todavia (maximo {esc(fmt(mx))} {esc(unidad)})'
    else:
        aviso = ""
    return (f'<section class="{card_class}"><h2>{esc(titulo)}{q}</h2>'
            f'<svg viewBox="0 0 {W} {h}" width="100%" role="img" aria-label="{esc(titulo)}">'
            f'{"".join(rows)}</svg>'
            f'<p class="muted leyenda">en {unidad} &middot; el color sube con la intensidad '
            f'(<span style="color:#1baf7a">bajo</span> &rarr; <span style="color:#eda100">medio</span> '
            f'&rarr; <span style="color:#e34948">alto</span>){aviso}</p></section>')

def timeline(by_hour):
    # Ventana FIJA de 24h en intervalos de BUCKET_MIN minutos (detalle hora:minuto),
    # terminando en el intervalo actual, rellenando con 0 los vacios. Tooltip por barra.
    n = int(VENTANA_MIN * 60 // BUCKET)             # nº de barras (~48) segun la ventana
    ahora_b = int(time.time() // BUCKET)
    lo = ahora_b - (n - 1)
    vals = [by_hour.get(lo + i, 0) for i in range(n)]
    mxreal = max(vals)      # maximo real (0 si no hay alertas aun; NO usar para index)
    mx = mxreal or 1        # escala para alturas/color (evita division por 0)
    W, H, pad = 1120, 190, 30
    bw = (W - 2 * pad) / n
    tick_every = max(1, n // 8)     # ~8 etiquetas de hora repartidas en la ventana
    bars, ticks = [], []
    for i, v in enumerate(vals):
        x = pad + i * bw
        bh = (H - 2 * pad) * v / mx
        t0 = datetime.fromtimestamp((lo + i) * BUCKET, TZ_EC)
        t1 = datetime.fromtimestamp((lo + i + 1) * BUCKET, TZ_EC)
        rango = t0.strftime("%H:%M") + "-" + t1.strftime("%H:%M")
        tip = f"{rango} · {v:,} alertas"
        bars.append(
            f'<rect class="tl-bar" x="{x:.1f}" y="{H-pad-bh:.1f}" width="{max(1,bw-1.5):.1f}" '
            f'height="{bh:.1f}" rx="1.5" fill="{heat(v/mx)}" style="animation-delay:{i*10}ms" '
            f'onmousemove="tlShow(evt,\'{tip}\')" onmouseleave="tlHide(evt)">'
            f'<title>{tip}</title></rect>')
        # etiquetas ancladas a la DERECHA: la ultima barra (intervalo actual) siempre
        # lleva su hora, para que se vea que el eje llega hasta "ahora" y no se corta antes
        if (n - 1 - i) % tick_every == 0:
            ticks.append(f'<text x="{x+bw/2:.1f}" y="{H-pad+14:.0f}" text-anchor="middle" class="tick">{t0.strftime("%H:%M")}</text>')
    pico_t = datetime.fromtimestamp((lo + vals.index(mxreal)) * BUCKET, TZ_EC).strftime("%H:%M") if mxreal else "-"
    _tl_tip = ("Numero de alertas en cada intervalo de 30 minutos a lo largo de la ventana. "
               "La altura y el color suben con la intensidad; pasa el raton por una barra para el conteo exacto.")
    return (f'<section class="card wide"><h2>Ataques por hora y minuto ({COB}){_cardq(_tl_tip)}</h2>'
            f'<div class="tlwrap"><div class="tltip"></div>'
            f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="alertas por intervalo" style="cursor:default">'
            f'<line x1="{pad}" y1="{H-pad}" x2="{W-pad}" y2="{H-pad}" stroke="{GRID}"/>'
            f'{"".join(bars)}{"".join(ticks)}</svg></div>'
            '<script>'
            'function tlShow(e,t){var c=e.currentTarget.closest(".tlwrap");if(!c)return;'
            'var p=c.querySelector(".tltip"),r=c.getBoundingClientRect();'
            'p.textContent=t;p.style.left=(e.clientX-r.left)+"px";p.style.top=(e.clientY-r.top)+"px";p.style.opacity=1;}'
            'function tlHide(e){var c=e.currentTarget.closest(".tlwrap");if(c){var p=c.querySelector(".tltip");if(p)p.style.opacity=0;}}'
            '</script>'
            f'<p class="muted">1 barra cada {BUCKET_MIN} min &middot; pasa el raton por una barra para ver el rango y el numero de peticiones &middot; pico: {mxreal:,} alertas a las {pico_t}</p></section>')

def dur(a, b):
    if not a or not b or b < a:
        return "-"
    s = int(b - a)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m"
    return f"{s//3600}h{(s%3600)//60:02d}m"

host = os.uname().nodename if hasattr(os, "uname") else "suricata"
gen = datetime.now(TZ_EC).strftime("%Y-%m-%d %H:%M")

# La ventana del reporte SIEMPRE es de HOURS (24 por defecto): la linea de tiempo
# tiene 48 barras de 30 min terminando "ahora", rellenando con 0 los intervalos sin
# alertas. Por eso la etiqueta es fija; que aun no haya datos en las primeras horas
# no cambia el tamano de la ventana.
if VENTANA_MIN < 60:
    COB = f"ultimos {VENTANA_MIN} min"
elif VENTANA_MIN == 60:
    COB = "ultima hora"
elif VENTANA_MIN % 60 == 0:
    COB = f"ultimas {VENTANA_MIN // 60} horas"
else:
    COB = f"ultimas {VENTANA_MIN / 60:.1f} horas"

def ipnum(s):
    # convierte una IPv4 en entero para ordenar bien (10 antes que 9 no; 9<10 numerico)
    p = s.split(".")
    if len(p) == 4 and all(x.isdigit() for x in p):
        try:
            return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
        except ValueError:
            return 0
    return 0

top_flujos = sorted(flujos.items(), key=lambda kv: kv[1][0], reverse=True)[:500]
filas = []
for (src, sport, dst, dport, proto, sig), (cnt, first, last) in top_flujos:
    hp = datetime.fromtimestamp(first, TZ_EC).strftime("%d/%m %H:%M") if first else "-"
    hu = datetime.fromtimestamp(last, TZ_EC).strftime("%H:%M") if last else "-"
    dursec = int((last - first)) if (first and last) else 0
    sig_es = traducir(sig)
    filas.append(
        f"<tr><td class='mono' data-s='{ipnum(ip_de(src))}'>{esc(ip_de(src))}</td>"
        f"<td class='mono num' data-s='{int(sport) if str(sport).isdigit() else -1}'>{esc(sport)}</td>"
        f"<td class='mono dst' data-s='{ipnum(dst)}'>{esc(dst)}</td>"
        f"<td class='mono num' data-s='{int(dport) if str(dport).isdigit() else -1}'>{esc(dport)}</td>"
        f"<td data-s='{esc(proto)}'>{esc(proto)}</td>"
        f"<td title='{esc(sig)}' data-s='{esc(sig_es)}'>{esc(sig_es)}</td>"
        f"<td class='num' data-s='{cnt}'>{cnt}</td>"
        f"<td class='mono' data-s='{int(first or 0)}'>{hp} &rarr; {hu}</td>"
        f"<td data-s='{dursec}'>{dur(first,last)}</td></tr>")

def top(counter, n=12, fmt=str):
    return [(fmt(k), v) for k, v in counter.most_common(n)]

by_sig = Counter()
for _k, _v in flujos.items():
    by_sig[traducir(_k[5])] += _v[0]   # agrupar por descripcion en espanol (sin duplicados)
firmas_top = [(s[:60], n) for s, n in by_sig.most_common(10)]

# ---- Dueno de cada IP destino (DNS inverso PTR -> marca conocida), cacheado ----
_IPINFO_CACHE = os.path.join(LOGDIR, "ipinfo-cache.json")
_IPINFO_TTL = 7 * 24 * 3600          # 7 dias: pasado eso se vuelve a resolver
_IPINFO_MAX_NUEVOS = 60              # tope de PTR nuevos por corrida (no colgar la generacion)
# dominio PTR conocido -> nombre humano de la empresa (trafico casi siempre legitimo)
_ORG_DOM = {
    "fbcdn.net": "Facebook", "facebook.com": "Facebook", "tfbnw.net": "Facebook",
    "instagram.com": "Instagram", "whatsapp.net": "WhatsApp",
    "1e100.net": "Google", "google.com": "Google", "googlevideo.com": "Google/YouTube",
    "googleusercontent.com": "Google", "gvt1.com": "Google",
    "amazonaws.com": "Amazon AWS", "amazon.com": "Amazon", "cloudfront.net": "Amazon CloudFront",
    "cloudflare.com": "Cloudflare", "cloudflare-dns.com": "Cloudflare",
    "akamaitechnologies.com": "Akamai", "akamai.net": "Akamai", "akamaiedge.net": "Akamai",
    "microsoft.com": "Microsoft", "azure.com": "Microsoft Azure", "windows.net": "Microsoft",
    "apple.com": "Apple", "icloud.com": "Apple", "aaplimg.com": "Apple",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix", "nflxso.net": "Netflix",
    "tiktokcdn.com": "TikTok", "tiktokv.com": "TikTok", "ttlivecdn.com": "TikTok",
    "twitter.com": "Twitter/X", "twimg.com": "Twitter/X", "fastly.net": "Fastly",
    "edgecastcdn.net": "Edgecast", "level3.net": "Lumen/Level3",
}

def _reg_dom(host):
    """Dominio registrable aproximado (2 ultimas etiquetas; 3 si es tipo co.uk)."""
    p = host.lower().rstrip(".").split(".")
    if len(p) < 2:
        return host.lower()
    if len(p) >= 3 and p[-2] in ("co", "com", "net", "org", "gov", "edu") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])

def _cargar_ipinfo():
    try:
        with open(_IPINFO_CACHE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

_ipinfo = _cargar_ipinfo()
_ipinfo_nuevos = 0
_ipinfo_sucio = False

def _rdap_org(ip):
    """Operador/red de una IP (util cuando NO tiene PTR) via RDAP publico (rdap.org, sin clave).
    Devuelve (etiqueta, pais) o ('', '') si falla. Timeout corto; el resultado se cachea en duenio."""
    try:
        req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                     headers={"User-Agent": "suricata-report/1.0",
                                              "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=2.5) as r:
            d = json.load(r)
    except Exception:
        return ("", "")
    name = (d.get("name") or "").strip()
    cc = (d.get("country") or "").strip()
    org = ""
    for e in (d.get("entities") or []):
        vc = e.get("vcardArray")
        if vc and len(vc) > 1:
            for it in vc[1]:
                if it and it[0] == "fn" and len(it) > 3 and it[3]:
                    org = str(it[3]).strip(); break
        if org:
            break
    etq = org or name
    return (etq[:44], cc)

def duenio(ip):
    """(etiqueta, legitimo) del dueno de una IP: PTR -> dominio -> marca conocida.
    Cachea a disco con TTL. Los CDN/grandes se marcan legitimo=True (verde)."""
    global _ipinfo_nuevos, _ipinfo_sucio
    if not ip or ip in ("?", "-"):
        return ("-", False)
    ent = _ipinfo.get(ip)
    now = time.time()
    if ent and now - ent.get("ts", 0) < _IPINFO_TTL:
        return (ent.get("org", "-"), ent.get("legit", False))
    if _ipinfo_nuevos >= _IPINFO_MAX_NUEVOS:
        return ("-", False)          # se resolvera en la proxima corrida
    _ipinfo_nuevos += 1
    org, legit, via = "sin PTR", False, ""
    try:
        socket.setdefaulttimeout(1.5)
        host = socket.gethostbyaddr(ip)[0]
        dom = _reg_dom(host)
        org, legit, via = (_ORG_DOM[dom], True, "ptr") if dom in _ORG_DOM else (dom, False, "ptr")
    except Exception:
        # sin DNS inverso: buscar el OPERADOR de red del bloque IP (RDAP, cacheado)
        aso, cc = _rdap_org(ip)
        if aso:
            org, legit, via = (aso + (f" · {cc}" if cc else ""), False, "rdap")
        else:
            org, legit, via = "sin PTR", False, ""
    finally:
        socket.setdefaulttimeout(None)
    _ipinfo[ip] = {"org": org, "legit": legit, "ts": now, "via": via}
    _ipinfo_sucio = True
    return (org, legit)

def _guardar_ipinfo():
    if not _ipinfo_sucio:
        return
    try:
        lim = time.time() - _IPINFO_TTL
        data = {k: v for k, v in _ipinfo.items() if v.get("ts", 0) >= lim}
        tmp = _IPINFO_CACHE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, _IPINFO_CACHE)
    except Exception:
        pass

# AbuseIPDB: lo que el PANEL ya consulto. Aqui solo se LEE la cache: el panel es el
# unico que llama a la API, porque la cuota es diaria y con dos procesos gastandola no
# la controlaria nadie. Si el archivo no existe, todo sigue como siempre.
_AIDB_CACHE_F = "/var/lib/suricata-feeds/abuseipdb.json"
try:
    _AIDB = json.load(open(_AIDB_CACHE_F, encoding="utf-8"))
except (OSError, ValueError):
    _AIDB = {}

def _aidb_chip(dst):
    """Que ataques se le denuncian a ese destino, si el panel ya lo consulto."""
    d = _AIDB.get(dst)
    if not isinstance(d, dict):
        return ""
    sc = int(d.get("score") or 0)
    if sc <= 0:
        return ""
    nom = ", ".join((d.get("cats_nom") or [])[:2])
    det = f"{d.get('reportes', 0):,} denuncias de {d.get('denunciantes', 0):,} denunciantes"
    ttl = f"AbuseIPDB: {sc}% de confianza de abuso; {det}" + (f". Denunciado por: {nom}" if nom else "")
    col = "#e34948" if sc >= 75 else ("#e07b39" if sc >= 25 else "#e58a00")
    return (f"<div><span class='obadge' style='background:{col};color:#fff;margin-top:4px' "
            f"title='{esc(ttl)}'>abuso {sc}%{(' · ' + esc(nom)) if nom else ''}</span></div>")

def _org_celda(dst):
    aidb = _aidb_chip(dst)
    # 1) si el destino esta en una lista de reputacion, eso manda (aunque no tenga PTR)
    fuente = es_malo(dst)
    if fuente:
        cat = (REP_META.get(fuente, {}) or {}).get("categoria", "")
        etq = ((cat + " · ") if cat else "") + fuente
        return (f"<td class='org'><span class='obadge bad' title='Destino en lista de reputacion "
                f"({esc(fuente)}{(', ' + esc(cat)) if cat else ''}) &mdash; ver ficha para el CIDR y la vigencia'>"
                f"&#9888; {esc(etq)}</span>{aidb}</td>")
    org, legit = duenio(dst)
    if org == "-":
        return f"<td class='org'>-{aidb}</td>"
    if legit:
        return (f"<td class='org'><span class='obadge ok' title='Servicio conocido "
                f"(CDN/gran empresa): trafico casi siempre legitimo'>{esc(org)}</span>{aidb}</td>")
    if org == "sin PTR":
        return ("<td class='org'><span class='obadge none' title='Sin DNS inverso ni operador identificable'>"
                f"sin PTR</span>{aidb}</td>")
    via = (_ipinfo.get(dst, {}) or {}).get("via", "")
    ttl = ("Operador de red del bloque IP (RDAP); no tiene DNS inverso" if via == "rdap"
           else "Dominio del dueño segun DNS inverso; no es un servicio grande conocido")
    marca = "&#127760; " if via == "rdap" else ""   # globo: viene del operador de red, no de PTR
    return (f"<td class='org'><span class='obadge unk' title='{ttl}'>{marca}{esc(org)}</span>{aidb}</td>")


# --- Reputacion: feeds de IPs/CIDR malos (suricata-feeds-update), con caducidad ---
FEEDS_DIR = "/var/lib/suricata-feeds"
REP_IPS = {}                    # ip -> fuente (procedencia)
REP_CIDR = defaultdict(list)    # primer octeto -> [(net_int, mask_int, fuente)]
REP_WIDE = []                   # CIDRs con prefijo <8 -> [(net, mask, fuente)]
REP_OK = False                  # hay al menos un feed vigente?
REP_INFO = "feeds no instalados"
REP_META = {}                   # meta por fuente (estado, vigencia, caducidad) para la ficha

def _ip4_int(ip):
    try:
        a, b, c, d = ip.split(".")
        return (int(a) << 24) | (int(b) << 16) | (int(c) << 8) | int(d)
    except Exception:
        return None

def _cargar_reputacion():
    global REP_OK, REP_INFO, REP_META
    try:
        meta = json.load(open(os.path.join(FEEDS_DIR, "reputation.meta"), encoding="utf-8"))
    except Exception:
        REP_INFO = "feeds no instalados"; return
    REP_META = meta.get("sources", {})
    # guarda gruesa: si el actualizador no corre hace mucho, no confiar (la caducidad fina
    # es por fuente y ya se aplico al rearmar reputation.lst -> solo trae fuentes vigentes)
    if time.time() - meta.get("generated", 0) > 3 * 86400:
        REP_INFO = "feeds sin refrescar (>3d; el actualizador no corre?)"; return
    try:
        for line in open(os.path.join(FEEDS_DIR, "reputation.lst"), encoding="utf-8"):
            line = line.rstrip("\n")
            if not line or line[0] in "#;":
                continue
            ind, _, src = line.partition("\t")
            ind = ind.strip(); src = src.strip() or "feed"
            if "/" in ind:
                try:
                    ipp, pl = ind.split("/"); pl = int(pl)
                    base = _ip4_int(ipp)
                    if base is None:
                        continue
                    mask = (0xffffffff << (32 - pl)) & 0xffffffff if pl else 0
                    net = base & mask
                    if pl >= 8:
                        REP_CIDR[(net >> 24) & 0xff].append((net, mask, src))
                    else:
                        REP_WIDE.append((net, mask, src))
                except Exception:
                    continue
            else:
                REP_IPS[ind] = src
    except Exception:
        pass
    n = len(REP_IPS) + sum(len(v) for v in REP_CIDR.values()) + len(REP_WIDE)
    vig = ", ".join(k for k, s in REP_META.items() if s.get("vigente"))
    REP_INFO = f"{n:,} IOCs ({vig})" if n else "feeds vacios"
    REP_OK = n > 0

_cargar_reputacion()

def es_malo(ip):
    """Devuelve la FUENTE que reporta la IP destino (str no vacio) o '' si ninguna."""
    s = REP_IPS.get(ip)
    if s:
        return s
    v = _ip4_int(ip)
    if v is None:
        return ""
    for net, mask, src in REP_CIDR.get((v >> 24) & 0xff, ()):
        if (v & mask) == net:
            return src
    for net, mask, src in REP_WIDE:
        if (v & mask) == net:
            return src
    return ""

def reputacion_de(ip):
    """(fuente, cidr_exacto) que reporta la IP, para la ficha de evidencia; ('','') si ninguna."""
    if ip in REP_IPS:
        return (REP_IPS[ip], ip)
    v = _ip4_int(ip)
    if v is None:
        return ("", "")
    for tabla in (REP_CIDR.get((v >> 24) & 0xff, ()), REP_WIDE):
        for net, mask, src in tabla:
            if (v & mask) == net:
                pl = bin(mask).count("1")
                return (src, f"{(net >> 24) & 255}.{(net >> 16) & 255}.{(net >> 8) & 255}.{net & 255}/{pl}")
    return ("", "")

def riesgo(src):
    """Puntaje de riesgo 0-100 del CPE (IP origen) combinando senales, en vez de
    clasificar por el texto de la firma. Devuelve (score, banda, color, desglose)."""
    sev = sev_by_src.get(src, 3)
    c_sev = {1: 30, 2: 18, 3: 8}.get(sev, 8)          # severidad Suricata (1=alta)
    c_dst = min(20, len(dst_by_src.get(src, ())) * 2)  # destinos unicos (barrido)
    c_pt  = min(15, len(dpt_by_src.get(src, ())) * 3)  # puertos unicos (port-sweep)
    p = 8 if n5_by_src.get(src, 0) > 0 else 0          # activo en los ultimos 5 min
    p += min(6, n1h_by_src.get(src, 0) / 20 * 6)       # sostenido en la ultima hora
    p += min(6, by_src.get(src, 0) / 60 * 6)           # persistente en la ventana
    c_per = min(20, p)
    otros = 0                                          # correlacion: otros CPE, mismo patron
    for k in flujos:
        if k[0] == src:
            n = len(patron_src.get((k[5], k[3]), ())) - 1
            if n > otros:
                otros = n
    c_cor = min(5, otros)
    rep_hits = 0                                       # destinos del CPE en feeds de reputacion
    if REP_OK:
        for d in dst_by_src.get(src, ()):
            if es_malo(d):
                rep_hits += 1
                if rep_hits >= 2:
                    break
    c_rep = min(10, rep_hits * 6)
    score = max(0, min(100, int(round(c_sev + c_dst + c_pt + c_per + c_cor + c_rep))))
    if score >= 70:
        banda, color = "ALTO", "#e34948"
    elif score >= 40:
        banda, color = "MEDIO", "#e58a00"
    else:
        banda, color = "bajo", "#3a9d5d"
    desg = (f"Severidad {c_sev}/30 &middot; Destinos unicos {c_dst}/20 &middot; "
            f"Puertos unicos {c_pt}/15 &middot; Persistencia {int(c_per)}/20 &middot; "
            f"Correlacion flota {c_cor}/5 &middot; Reputacion {c_rep}/10 [{REP_INFO}]")
    return score, banda, color, desg


def top_origenes_section(n_src=5, n_sub=8):
    """Top de IPs origen que mas peticionan, con el desglose de cada una:
    desde que puerto origen, hacia que IP destino y hacia que puerto destino.
    Se arma con by_src (totales reales) + flujos (ya trae sport/dport/proto)."""
    tops = by_src.most_common(n_src)
    if not tops:
        return ("<!--TOP_INI--><section class=\"card\"><h2>Top 5 IPs origen que mas peticionan</h2>"
                "<p class=\"muted\">Sin ataques en la ventana.</p></section><!--TOP_FIN-->")
    cards = []
    for i, (src, tot) in enumerate(tops, 1):
        agg = {}                       # (sport,dst,dport,proto) -> veces
        dsts, dports = set(), set()
        for (s, sp, dst, dp, pr, sig), v in flujos.items():
            if s != src:
                continue
            agg[(sp, dst, dp, pr)] = agg.get((sp, dst, dp, pr), 0) + v[0]
            dsts.add(dst); dports.add(dp)
        sub = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:n_sub]
        rows = "".join(
            f"<tr><td class='mono'>{esc(sp or '-')}</td>"
            f"<td class='mono' style='color:#184f95'>{esc(dst or '-')}</td>"
            f"{_org_celda(dst)}"
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (sp, dst, dp, pr), c in sub)
        rsc, rband, rcol, rdes = riesgo(src)
        if src in _MK_ENVIADOS:
            cuar = ("<span class='qsent' title='Este CPE ya esta en la lista de cuarentena del MikroTik'>"
                    "&#10003; En cuarentena</span>")
        else:
            # se manda la IDENTIDAD entera (router|IP): el panel la guarda tal cual y asi
            # el bloqueo sale hacia SU MikroTik y la marca "En cuarentena" vuelve a casar
            cuar = (f"<button class='qsend' title='Enviar este CPE a la address-list de cuarentena del MikroTik' "
                    f"onclick=\"qcuar(this,'{esc(src)}','{rsc}')\">&#9888; Cuarentena</button>")
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(ip_de(src))}</span>{_chip_nodo(src)}"
            f"<span class='risk' style='background:{rcol}' title='Puntaje de riesgo del CPE (0-100): {rdes}'>"
            f"Riesgo {rsc} &middot; {rband}</span>"
            f"<span class='tot'>{tot:,} alertas</span>{cuar}"
            f"<span class='meta'>&rarr; {len(dsts):,} IP destino &middot; {len(dports):,} puertos destino</span></div>"
            f"<div class='tablewrap'><table><thead><tr>"
            f"<th>Puerto origen</th><th>IP destino (a donde)</th><th class='org'>Dueño / organización</th>"
            f"<th class='num'>Puerto destino</th>"
            f"<th>Protocolo</th><th class='num'>Peticiones</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></div>")
    _guardar_ipinfo()
    return (
        "<!--TOP_INI-->"
        "<style>"
        ".topwrap .tcard{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 14px;overflow:hidden}"
        ".topwrap .thd{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:11px 15px;background:#f4f4f2;border-bottom:1px solid #e7e6e2}"
        ".topwrap .rank{font-weight:800;color:#2a78d6;font-size:15px}"
        ".topwrap .ipx{font-weight:700;font-size:15px}"
        ".topwrap .tot{background:#e34948;color:#fff;font-size:12px;font-weight:700;padding:3px 9px;border-radius:20px}"
        ".topwrap .risk{color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:20px;letter-spacing:.3px;cursor:help}"
        ".topwrap .qsend{font:11px system-ui;font-weight:700;color:#fff;background:#e34948;border:0;border-radius:20px;padding:3px 11px;cursor:pointer}"
        ".topwrap .qsend:hover{background:#c93b3a}"
        ".topwrap .qsent{font-size:11px;font-weight:700;color:#1a7f37;background:#e6f4ea;border:1px solid #b7e0c2;border-radius:20px;padding:2px 10px}"
        ".topwrap .meta{color:#52514e;font-size:12px;margin-left:auto}"
        ".topwrap table{table-layout:fixed;width:100%}"
        ".topwrap table th,.topwrap table td{text-align:center!important;padding:11px 8px;font-size:14px}"
        ".topwrap table thead th{font-size:13px;letter-spacing:.2px}"
        ".topwrap table tbody td{border-top:1px solid #eeece7}"
        ".topwrap table th.org{width:23%}"
        ".topwrap td.org{white-space:normal;word-break:break-word;overflow-wrap:anywhere}"
        ".topwrap .obadge{display:inline-block;font-size:12.5px;font-weight:700;padding:3px 10px;border-radius:12px;max-width:100%;white-space:normal;word-break:break-word;overflow-wrap:anywhere;line-height:1.35;vertical-align:middle}"
        ".topwrap .obadge.ok{background:#e6f4ea;color:#1a7f37;border:1px solid #b7e0c2}"
        ".topwrap .obadge.unk{background:#fdf0e6;color:#a15c12;border:1px solid #f2d3ad}"
        # etiqueta del nodo (solo aparece si hay varios MikroTik)
        ".nodochip{display:inline-block;background:#eef4fd;color:#2a5fa0;border:1px solid #cfe0f6;"
        "border-radius:20px;padding:1px 9px;font-size:11px;font-weight:700;white-space:nowrap;margin-left:6px}"
        ".topwrap .obadge.none{background:#f1f1ef;color:#6b6a66;border:1px solid #e0dfda}"
        ".topwrap .obadge.bad{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4}"
        "</style>"
        "<script>function qcuar(b,ip,sc){b.disabled=true;var o=b.innerHTML;b.textContent='enviando...';"
        "fetch('/cuarentena/enviar',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'ajax=1&ip='+encodeURIComponent(ip)+'&score='+encodeURIComponent(sc)})"
        ".then(function(r){return r.text();}).then(function(t){"
        "if(t.indexOf('OK')===0){b.outerHTML=\"<span class='qsent' title='Ya en cuarentena'>\\u2713 En cuarentena</span>\";}"
        "else{b.disabled=false;b.innerHTML=o;alert(t.replace(/^ERR: /,''));}})"
        ".catch(function(e){b.disabled=false;b.innerHTML=o;alert('Error: '+e);});}</script>"
        "<section class=\"card\"><h2>Top 5 IPs origen que mas peticionan</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">Quien ataca mas, hacia que IP destino, desde que puerto origen y hacia que puerto destino. "
        "La columna <b>Dueño / organización</b> viene del DNS inverso (PTR) de la IP destino: "
        "<span style='color:#1a7f37;font-weight:700'>verde</span> = servicio conocido (Facebook, Google, Cloudflare, etc., casi siempre legitimo); "
        "<span style='color:#a15c12;font-weight:700'>naranja</span> = dominio del dueño pero no es un gran servicio; "
        "<b>sin PTR</b> = IP sin nombre publico (frecuente en botnets/hosting sucio).</p>"
        f"<div class=\"topwrap\">{''.join(cards)}</div></section>"
        + top_destinos_section() + entrantes_section() +
        "<!--TOP_FIN-->")

# id numerico del TopoJSON (countries-110m) -> ISO2, y nombres, para el mapa del cliente.
_MAP_NUM2ISO = ("{4:'AF',8:'AL',10:'AQ',12:'DZ',24:'AO',31:'AZ',32:'AR',36:'AU',40:'AT',44:'BS',50:'BD',"
    "51:'AM',56:'BE',64:'BT',68:'BO',70:'BA',72:'BW',76:'BR',84:'BZ',90:'SB',96:'BN',100:'BG',"
    "104:'MM',108:'BI',112:'BY',116:'KH',120:'CM',124:'CA',140:'CF',144:'LK',148:'TD',152:'CL',"
    "156:'CN',158:'TW',170:'CO',178:'CG',180:'CD',188:'CR',191:'HR',192:'CU',196:'CY',203:'CZ',"
    "204:'BJ',208:'DK',214:'DO',218:'EC',222:'SV',226:'GQ',231:'ET',232:'ER',233:'EE',238:'FK',"
    "242:'FJ',246:'FI',250:'FR',260:'TF',262:'DJ',266:'GA',268:'GE',270:'GM',275:'PS',276:'DE',"
    "288:'GH',300:'GR',304:'GL',320:'GT',324:'GN',328:'GY',332:'HT',340:'HN',348:'HU',352:'IS',"
    "356:'IN',360:'ID',364:'IR',368:'IQ',372:'IE',376:'IL',380:'IT',384:'CI',388:'JM',392:'JP',"
    "398:'KZ',400:'JO',404:'KE',408:'KP',410:'KR',414:'KW',417:'KG',418:'LA',422:'LB',426:'LS',"
    "428:'LV',430:'LR',434:'LY',440:'LT',442:'LU',450:'MG',454:'MW',458:'MY',466:'ML',478:'MR',"
    "484:'MX',496:'MN',498:'MD',499:'ME',504:'MA',508:'MZ',512:'OM',516:'NA',524:'NP',528:'NL',"
    "540:'NC',548:'VU',554:'NZ',558:'NI',562:'NE',566:'NG',578:'NO',586:'PK',591:'PA',598:'PG',"
    "600:'PY',604:'PE',608:'PH',616:'PL',620:'PT',624:'GW',626:'TL',630:'PR',634:'QA',642:'RO',"
    "643:'RU',646:'RW',682:'SA',686:'SN',688:'RS',694:'SL',703:'SK',704:'VN',705:'SI',706:'SO',"
    "710:'ZA',716:'ZW',724:'ES',728:'SS',729:'SD',732:'EH',740:'SR',748:'SZ',752:'SE',756:'CH',"
    "760:'SY',762:'TJ',764:'TH',768:'TG',780:'TT',784:'AE',788:'TN',792:'TR',795:'TM',800:'UG',"
    "804:'UA',807:'MK',818:'EG',826:'GB',834:'TZ',840:'US',854:'BF',858:'UY',860:'UZ',862:'VE',"
    "887:'YE',894:'ZM'}")
_MAP_NAMES = ("{AF:'Afganistan',AR:'Argentina',AU:'Australia',AT:'Austria',BD:'Bangladesh',BE:'Belgica',"
    "BO:'Bolivia',BR:'Brasil',BG:'Bulgaria',CA:'Canada',CL:'Chile',CN:'China',CO:'Colombia',CR:'Costa Rica',"
    "CU:'Cuba',CZ:'Chequia',DK:'Dinamarca',DO:'Rep. Dominicana',EC:'Ecuador',EG:'Egipto',SV:'El Salvador',"
    "FI:'Finlandia',FR:'Francia',DE:'Alemania',GR:'Grecia',GT:'Guatemala',HN:'Honduras',HU:'Hungria',"
    "IN:'India',ID:'Indonesia',IR:'Iran',IQ:'Irak',IE:'Irlanda',IL:'Israel',IT:'Italia',JP:'Japon',"
    "KZ:'Kazajistan',KE:'Kenia',KR:'Corea del Sur',KP:'Corea del Norte',MX:'Mexico',MA:'Marruecos',"
    "NL:'Paises Bajos',NZ:'Nueva Zelanda',NI:'Nicaragua',NG:'Nigeria',NO:'Noruega',PK:'Pakistan',"
    "PA:'Panama',PY:'Paraguay',PE:'Peru',PH:'Filipinas',PL:'Polonia',PT:'Portugal',RO:'Rumania',"
    "RU:'Rusia',SA:'Arabia Saudita',RS:'Serbia',SG:'Singapur',ZA:'Sudafrica',ES:'Espana',SE:'Suecia',"
    "CH:'Suiza',SY:'Siria',TW:'Taiwan',TH:'Tailandia',TR:'Turquia',UA:'Ucrania',AE:'Emiratos AU',"
    "GB:'Reino Unido',US:'Estados Unidos',UY:'Uruguay',UZ:'Uzbekistan',VE:'Venezuela',VN:'Vietnam',"
    "HK:'Hong Kong',BY:'Bielorrusia',MD:'Moldavia',BZ:'Belice'}")

def _mapa_origen():
    """Punto de origen del mapa (tu red) como [lon, lat]. Configurable con MAPA_ORIGEN=lon,lat
    en el .conf; por defecto Ecuador. Es solo el punto de partida de los arcos, no un dato real."""
    try:
        v = (_conf_key("MAPA_ORIGEN", "") or "").split(",")
        return [float(v[0]), float(v[1])]
    except Exception:
        return [-78.1, -1.8]

def mapa_ataques_section():
    """Mapa mundial (coropleta por pais) de los DESTINOS de las alertas + arcos animados desde
    tu red hacia cada pais (de donde -> a donde). Con zoom por pais y detalle de que IPs,
    que puertos y que CPEs peticionan. Se dibuja en el navegador con el TopoJSON."""
    datos = {k: v for k, v in pais_dst.items() if k}
    total = sum(datos.values())
    # Detalle por pais para el tooltip y el panel: a que IPs destino, por que puertos y desde
    # que CPEs de tu red. Se recortan los top para no inflar el HTML (se indica cuantos faltan).
    det = {}
    for cc in datos:
        det[cc] = {
            "ips": [[ip, n] for ip, n in pais_ips[cc].most_common(6)],
            "ports": [[p, n] for p, n in pais_ports[cc].most_common(6)],
            "srcs": [[s, n] for s, n in pais_srcs[cc].most_common(4)],
            "nip": len(pais_ips[cc]), "npt": len(pais_ports[cc]), "nsr": len(pais_srcs[cc]),
        }
    intro = ("Los paises <b>destino</b> de las alertas (a donde va el trafico sospechoso de tus "
             "CPEs). El color sube con el nº de alertas; los <b>arcos animados</b> muestran el flujo "
             "desde tu red hacia cada pais. <b>Pasa el mouse</b> por un pais para ver a que IPs y "
             "puertos se peticiona, y <b>haz clic para acercar</b>. Geolocalizacion <b>offline</b>; "
             "las IPs privadas o sin pais no cuentan.")
    if not datos:
        aviso = ("<div class='mapempty'>Sin datos de pais todavia. Puede que la base GeoIP aun no este "
                 "instalada (<code>/var/lib/suricata-geoip/ipv4.bin</code>) o que los destinos recientes "
                 "sean IPs privadas / sin pais.</div>")
    else:
        aviso = ""
    return (
        "<style>"
        ".attmap .mapwrap{display:block}"
        ".attmap .mapsvg{position:relative;width:100%;background:#f7f9fc;border:1px solid #e7e6e2;border-radius:10px;overflow:hidden}"
        ".attmap #attackmap{width:100%;height:auto;display:block;cursor:grab}"
        ".attmap #attackmap.grab{cursor:grabbing}"
        ".attmap #attackmap path{transition:fill .2s}.attmap #attackmap path:hover{stroke:#0b0b0b;stroke-width:1}"
        ".attmap #attackmap path.sel{stroke:#0b0b0b;stroke-width:1.4}"
        # --- controles de zoom (esquina del mapa) ---
        ".attmap .mapctl{position:absolute;top:8px;right:8px;display:flex;gap:6px;z-index:3}"
        ".attmap .mapctl button{height:28px;min-width:28px;padding:0;border:1px solid #d7d6d2;background:#fff;color:#33322f;"
        "border-radius:7px;font:700 15px system-ui;line-height:1;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.12)}"
        ".attmap .mapctl button.wide{padding:0 10px;font:600 12px system-ui}"
        ".attmap .mapctl button:hover{background:#eef2f7;border-color:#2a78d6;color:#2a78d6}"
        # --- tooltip flotante con el detalle del pais ---
        ".attmap .maptip{position:absolute;z-index:4;display:none;width:266px;background:#fff;border:1px solid #d7d6d2;"
        "border-radius:10px;box-shadow:0 8px 26px rgba(0,0,0,.18);padding:10px 12px;font-size:12.5px;line-height:1.45;pointer-events:none}"
        ".attmap .maptip h4{margin:0 0 3px;font-size:13.5px;display:flex;align-items:center;gap:7px}"
        ".attmap .maptip .dir{color:#6b6a66;font-size:11.5px;margin:0 0 4px}"
        ".attmap .grp{margin:7px 0 0}"
        ".attmap .glbl{font-weight:700;font-size:10.5px;color:#8a8984;text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px}"
        ".attmap .it{display:flex;justify-content:space-between;gap:10px;font:12px ui-monospace,Consolas,monospace}"
        ".attmap .it span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        ".attmap .mas{color:#9a9a95;font-size:11px;margin-top:1px}"
        ".attmap .cc{font:700 11px ui-monospace,Consolas,monospace;background:#eef2f7;color:#33322f;border-radius:5px;padding:2px 6px}"
        # --- panel de detalle (al hacer clic en un pais): se queda fijo y se lee en movil ---
        ".attmap .mapdet{display:none;margin-top:10px;border:1px solid #e7e6e2;border-radius:10px;padding:12px 14px;background:#fbfcfe}"
        ".attmap .mapdethdr{display:flex;align-items:center;gap:9px;flex-wrap:wrap}"
        ".attmap .mapdethdr b{font-size:14.5px}"
        ".attmap .mapdethdr .dsub{color:#6b6a66;font-size:12px;flex:1;min-width:180px}"
        ".attmap .dclose{margin-left:auto;border:1px solid #d7d6d2;background:#fff;width:26px;height:26px;border-radius:50%;"
        "font-size:16px;line-height:1;cursor:pointer;color:#6b6a66}"
        ".attmap .dclose:hover{background:#f2f1ee;color:#0b0b0b}"
        ".attmap .mapdetgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px 20px;margin-top:10px}"
        ".attmap .maphint{color:#9a9a95;font-size:11.5px;margin:7px 0 0}"
        ".attmap .maptop{margin-top:12px}"
        ".attmap .maptophdr{font-weight:700;font-size:13px;margin:0 0 6px}"
        ".attmap .maptopgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:0 22px}"
        ".attmap .maprow{display:flex;align-items:center;gap:9px;padding:5px 0;border-bottom:1px solid #f2f1ee;font-size:13px;cursor:pointer}"
        ".attmap .maprow:hover{background:#f4f7fb}"
        ".attmap .maprow .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        ".attmap .maprow .ct{font-weight:700;font-variant-numeric:tabular-nums}"
        ".attmap .mapbar{height:6px;border-radius:4px;background:#e34948;min-width:6px}"
        ".attmap .mapempty{color:#6b6a66;font-size:13px;background:#faf9f6;border:1px dashed #e0dfda;border-radius:8px;padding:12px 14px;margin-top:8px}"
        "</style>"
        "<section class=\"card attmap\" style=\"margin-top:16px\"><h2>A donde atacan tus CPEs (destino por pais)</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">" + intro + "</p>" + aviso +
        "<div class=mapwrap><div class=mapsvg><svg id=attackmap viewBox=\"0 20 1000 392\" "
        "preserveAspectRatio=\"xMidYMid meet\" role=img aria-label=\"Mapa de destinos\"></svg>"
        "<div class=mapctl>"
        "<button type=button id=mzin title=\"Acercar\">+</button>"
        "<button type=button id=mzout title=\"Alejar\">&minus;</button>"
        "<button type=button id=mzrst class=wide title=\"Volver al mundo entero\">Vista completa</button>"
        "</div><div class=maptip id=maptip></div></div>"
        "<div class=mapdet id=mapdet></div>"
        "<p class=maphint>Clic en un pais para acercarlo y ver su detalle &middot; arrastra para mover "
        "&middot; <b>Ctrl + rueda</b> para zoom &middot; <b>Vista completa</b> para volver.</p>"
        "<div class=maptop id=attacktop></div></div>"
        "<script>window.__ATTACK_GEO=" + json.dumps(datos) + ";window.__ATTACK_TOTAL=" + str(total) +
        ";window.__ATTACK_DET=" + json.dumps(det) +
        ";window.__ATTACK_HOME=" + json.dumps(_mapa_origen()) + ";</script>"
        "<script src=\"/vendor/mapa/topojson-client.min.js\"></script>"
        "<script>(function(){"
        "var DATA=window.__ATTACK_GEO||{},DET=window.__ATTACK_DET||{},NUM2=" + _MAP_NUM2ISO + ",NAMES=" + _MAP_NAMES + ";"
        "var W=1000,H=500,svg=document.getElementById('attackmap');if(!svg)return;"
        "var tip=document.getElementById('maptip'),panel=document.getElementById('mapdet'),box=svg.parentNode;"
        "var BBOX={},NMAP={},sel='';"
        # nombre del pais: el traducido si lo tenemos, si no el del propio mapa (ingles), si no el codigo
        "function nombre(iso){return NAMES[iso]||NMAP[iso]||iso||'?';}"
        "function proj(lo,la){return [(lo+180)*(W/360),(90-la)*(H/180)];}"
        "function heat(f){f=f<0?0:(f>1?1:f);var st=[[0,[43,120,214]],[.35,[27,175,122]],[.65,[237,161,0]],[.85,[235,104,52]],[1,[227,73,72]]];"
        "for(var j=0;j<st.length-1;j++){var a=st[j][0],ca=st[j][1],b=st[j+1][0],cb=st[j+1][1];"
        "if(f<=b){var t=b>a?(f-a)/(b-a):0,r=Math.round(ca[0]+(cb[0]-ca[0])*t),g=Math.round(ca[1]+(cb[1]-ca[1])*t),bl=Math.round(ca[2]+(cb[2]-ca[2])*t);"
        "return 'rgb('+r+','+g+','+bl+')';}}return '#e34948';}"
        "function ringD(r){var d='',prev=null;for(var i=0;i<r.length;i++){var lo=r[i][0],p=proj(lo,r[i][1]);"
        # cruce del antimeridiano (salto de lon >180): cortar el trazo para evitar la banda horizontal
        "if(prev!==null&&Math.abs(lo-prev)>180){d+='ZM'+p[0].toFixed(1)+' '+p[1].toFixed(1);}"
        "else{d+=(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1);}prev=lo;}return d+'Z';}"
        "function geomD(g){var d='';if(!g)return d;if(g.type==='Polygon'){g.coordinates.forEach(function(r){d+=ringD(r);});}"
        "else if(g.type==='MultiPolygon'){g.coordinates.forEach(function(pl){pl.forEach(function(r){d+=ringD(r);});});}return d;}"
        "var mx=0;for(var k in DATA){if(DATA[k]>mx)mx=DATA[k];}if(mx<1)mx=1;"
        "function esc(s){return String(s).replace(/[&<>\"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c];});}"
        "function centroid(g){var best=null,bn=0;function c(r){if(r.length>bn){bn=r.length;best=r;}}"
        "if(!g)return null;if(g.type==='Polygon')g.coordinates.forEach(c);else if(g.type==='MultiPolygon')g.coordinates.forEach(function(pl){pl.forEach(c);});"
        "if(!best)return null;var sx=0,sy=0;for(var i=0;i<best.length;i++){var p=proj(best[i][0],best[i][1]);sx+=p[0];sy+=p[1];}return [sx/best.length,sy/best.length];}"
        # bbox del anillo MAS GRANDE (no de toda la geometria): asi el zoom de EEUU va al territorio
        # continental y no se estira hasta Alaska/Hawaii, ni Rusia cruza el antimeridiano.
        "function bboxMain(g){var best=null,bn=0;function c(r){if(r.length>bn){bn=r.length;best=r;}}"
        "if(!g)return null;if(g.type==='Polygon')g.coordinates.forEach(c);else if(g.type==='MultiPolygon')g.coordinates.forEach(function(pl){pl.forEach(c);});"
        "if(!best)return null;var x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;"
        "for(var i=0;i<best.length;i++){var p=proj(best[i][0],best[i][1]);"
        "if(p[0]<x0)x0=p[0];if(p[0]>x1)x1=p[0];if(p[1]<y0)y0=p[1];if(p[1]>y1)y1=p[1];}"
        "return {x:x0,y:y0,w:Math.max(x1-x0,4),h:Math.max(y1-y0,4)};}"
        # --- zoom / desplazamiento: se mueve el viewBox del SVG (nitido a cualquier escala) ---
        "var VB0={x:0,y:20,w:1000,h:392},AR=VB0.w/VB0.h,vb={x:VB0.x,y:VB0.y,w:VB0.w,h:VB0.h};"
        "function setVB(){svg.setAttribute('viewBox',vb.x.toFixed(1)+' '+vb.y.toFixed(1)+' '+vb.w.toFixed(1)+' '+vb.h.toFixed(1));}"
        "function fit(b){if(!b)return;var pad=Math.max(b.w,b.h)*0.30+8,w=b.w+pad*2,h=b.h+pad*2;"
        "if(w/h<AR)w=h*AR;else h=w/AR;if(w<60){w=60;h=w/AR;}"
        "vb={x:b.x+b.w/2-w/2,y:b.y+b.h/2-h/2,w:w,h:h};setVB();}"
        "function reset(){vb={x:VB0.x,y:VB0.y,w:VB0.w,h:VB0.h};setVB();}"
        "function zoom(f,cx,cy){var nw=vb.w*f,nh=vb.h*f;"
        "if(nw>VB0.w){nw=VB0.w;nh=VB0.h;}if(nw<60){nw=60;nh=nw/AR;}"
        "if(cx===undefined){cx=vb.x+vb.w/2;cy=vb.y+vb.h/2;}"
        "vb.x=cx-(cx-vb.x)*(nw/vb.w);vb.y=cy-(cy-vb.y)*(nh/vb.h);vb.w=nw;vb.h=nh;setVB();}"
        "function at(e){var r=svg.getBoundingClientRect();"
        "return [vb.x+(e.clientX-r.left)/r.width*vb.w,vb.y+(e.clientY-r.top)/r.height*vb.h];}"
        # --- detalle de un pais: a que IPs, por que puertos y desde que CPEs (direccion saliente) ---
        "function grupo(lbl,items,tot){if(!items||!items.length)return '';"
        "var h='<div class=grp><div class=glbl>'+lbl+'</div>';"
        "items.forEach(function(kv){h+='<div class=it><span>'+esc(kv[0])+'</span><b>'+kv[1]+'</b></div>';});"
        "if(tot>items.length)h+='<div class=mas>+'+(tot-items.length)+' mas</div>';return h+'</div>';}"
        "function dirTxt(iso){var nm=nombre(iso),c=DATA[iso]||0;"
        "return c?('Direccion <b>saliente</b>: tus CPEs &rarr; '+esc(nm)+' &middot; <b>'+c+'</b> alertas')"
        ":('Sin alertas hacia '+esc(nm)+' en la ventana.');}"
        "function grupos(iso){var d=DET[iso];if(!d)return '';"
        "return grupo('IPs destino (a donde)',d.ips,d.nip)+grupo('Puertos destino',d.ports,d.npt)"
        "+grupo('CPEs de tu red (de donde)',d.srcs,d.nsr);}"
        "function showTip(iso,e){if(!tip)return;"
        "tip.innerHTML='<h4><span class=cc>'+esc(iso)+'</span>'+esc(nombre(iso))+'</h4>'"
        "+'<div class=dir>'+dirTxt(iso)+'</div>'+grupos(iso);"
        "tip.style.display='block';var r=box.getBoundingClientRect();"
        "var x=e.clientX-r.left+16,y=e.clientY-r.top+16,tw=tip.offsetWidth,th=tip.offsetHeight;"
        "if(x+tw>r.width-6)x=e.clientX-r.left-tw-16;if(x<4)x=4;"
        "if(y+th>r.height-6)y=Math.max(4,e.clientY-r.top-th-16);"
        "tip.style.left=x+'px';tip.style.top=y+'px';}"
        "function hideTip(){if(tip)tip.style.display='none';}"
        # ojo: sin el guard de 'iso', marcar('') seleccionaba TODOS los paises sin codigo
        # (data-iso=\"\") y les pintaba el borde negro al pulsar 'Vista completa'.
        "function marcar(iso){sel=iso;Array.prototype.forEach.call(svg.querySelectorAll('path[data-iso]'),function(p){"
        "if(iso&&p.getAttribute('data-iso')===iso)p.classList.add('sel');else p.classList.remove('sel');});}"
        "function panelDe(iso){if(!panel)return;"
        "panel.innerHTML='<div class=mapdethdr><span class=cc>'+esc(iso)+'</span><b>'+esc(nombre(iso))+'</b>'"
        "+'<span class=dsub>'+dirTxt(iso)+'</span>'"
        "+'<button type=button class=dclose title=\"Cerrar\">&times;</button></div>'"
        "+'<div class=mapdetgrid>'+grupos(iso)+'</div>';"
        "panel.style.display='block';"
        "var b=panel.querySelector('.dclose');if(b)b.addEventListener('click',cerrar);}"
        "function abrir(iso){if(!panel)return;marcar(iso);fit(BBOX[iso]);panelDe(iso);guardarVista();}"
        "function cerrar(){if(panel)panel.style.display='none';marcar('');reset();guardarVista();}"
        # --- la pagina se recarga sola cada 5 min: sin esto el mapa volvia al mundo entero
        # y perdias el pais que estabas mirando ---
        "var MK='mapa:'+location.pathname,guardaPend=null;"
        "function guardarVista(){clearTimeout(guardaPend);guardaPend=setTimeout(function(){"
        "try{sessionStorage.setItem(MK,JSON.stringify({v:vb,s:sel}));}catch(e){}},300);}"
        "function restaurarVista(){try{var g=JSON.parse(sessionStorage.getItem(MK)||'null');"
        "if(!g||!g.v||!g.v.w)return;"
        "vb={x:+g.v.x,y:+g.v.y,w:+g.v.w,h:+g.v.h};setVB();"
        # se repone la vista exacta (incluido el desplazamiento), no se re-encuadra el pais
        "if(g.s&&DATA[g.s]){marcar(g.s);panelDe(g.s);}}catch(e){}}"
        "var HOME=window.__ATTACK_HOME||[-78.1,-1.8],home=proj(HOME[0],HOME[1]);"
        "fetch('/vendor/mapa/countries-110m.json').then(function(r){return r.json();}).then(function(topo){"
        "var feats=topojson.feature(topo,topo.objects.countries).features,frag='',cents={};"
        "feats.forEach(function(ft){var iso=NUM2[+ft.id]||'',pn=(ft.properties&&ft.properties.name)||'';"
        "if(!iso&&pn==='Kosovo')iso='XK';"   # Kosovo no trae id ISO en el mapa; GeoIP si lo reporta
        "if(iso&&pn)NMAP[iso]=pn;var c=DATA[iso]||0;"
        "var fill=c>0?heat(c/mx):'#e7ebf0';var nm=nombre(iso)||pn||'?';"
        "frag+='<path data-iso=\"'+esc(iso)+'\" d=\"'+geomD(ft.geometry)+'\" fill=\"'+fill+'\" stroke=\"#fff\" "
        "stroke-width=\"0.4\" vector-effect=\"non-scaling-stroke\">"
        "<title>'+esc(nm)+(c>0?': '+c+' alertas':'')+'</title></path>';"
        "if(iso){var bb=bboxMain(ft.geometry);if(bb)BBOX[iso]=bb;}"
        "if(c>0){var ce=centroid(ft.geometry);if(ce)cents[iso]=ce;}});"
        # --- flujo de donde -> a donde: arcos animados desde tu red hacia cada pais destino ---
        "var arcs='';Object.keys(cents).forEach(function(iso,idx){var ce=cents[iso],n=DATA[iso];"
        "var dx=ce[0]-home[0],dy=ce[1]-home[1],len=Math.sqrt(dx*dx+dy*dy);"
        "var mid=[(home[0]+ce[0])/2-dy*0.18,(home[1]+ce[1])/2+dx*0.18];"
        "var d='M'+home[0].toFixed(1)+' '+home[1].toFixed(1)+' Q'+mid[0].toFixed(1)+' '+mid[1].toFixed(1)+' '+ce[0].toFixed(1)+' '+ce[1].toFixed(1);"
        "var w=(0.8+1.8*(n/mx)).toFixed(2);"
        "arcs+='<path d=\"'+d+'\" fill=\"none\" stroke=\"#e34948\" stroke-opacity=\"0.5\" stroke-width=\"'+w+'\" "
        "vector-effect=\"non-scaling-stroke\" pointer-events=\"none\"/>';"
        "arcs+='<circle r=\"2.1\" fill=\"#e34948\" pointer-events=\"none\"><animateMotion dur=\"'+(1.6+len/900).toFixed(1)+'s\" repeatCount=\"indefinite\" path=\"'+d+'\"/></circle>';"
        # punta del arco: mismo latido que el origen, para ver de un vistazo donde cae cada
        # flujo. Se desfasa un poco cada uno (begin) para que no parpadeen todos a la vez.
        "var cx=ce[0].toFixed(1),cy=ce[1].toFixed(1),dl=((idx%7)*0.22).toFixed(2);"
        "arcs+='<circle cx=\"'+cx+'\" cy=\"'+cy+'\" r=\"2.6\" fill=\"#e34948\" pointer-events=\"none\"/>';"
        "arcs+='<circle cx=\"'+cx+'\" cy=\"'+cy+'\" r=\"2.6\" fill=\"none\" stroke=\"#e34948\" "
        "stroke-width=\"1.2\" vector-effect=\"non-scaling-stroke\" pointer-events=\"none\">"
        "<animate attributeName=\"r\" values=\"2.6;10\" dur=\"1.8s\" begin=\"'+dl+'s\" repeatCount=\"indefinite\"/>"
        "<animate attributeName=\"stroke-opacity\" values=\"0.7;0\" dur=\"1.8s\" begin=\"'+dl+'s\" repeatCount=\"indefinite\"/>"
        "</circle>';});"
        "if(Object.keys(cents).length){arcs+='<circle cx=\"'+home[0].toFixed(1)+'\" cy=\"'+home[1].toFixed(1)+'\" r=\"3\" fill=\"#0b0b0b\" pointer-events=\"none\"/>';"
        "arcs+='<circle cx=\"'+home[0].toFixed(1)+'\" cy=\"'+home[1].toFixed(1)+'\" r=\"3\" fill=\"none\" stroke=\"#0b0b0b\" pointer-events=\"none\">"
        "<animate attributeName=\"r\" values=\"3;12\" dur=\"1.8s\" repeatCount=\"indefinite\"/>"
        "<animate attributeName=\"stroke-opacity\" values=\"0.55;0\" dur=\"1.8s\" repeatCount=\"indefinite\"/></circle>';}"
        "svg.innerHTML=frag+arcs;if(sel)marcar(sel);pintarTop();restaurarVista();"
        "}).catch(function(e){var w=document.getElementById('attacktop');if(w)w.innerHTML='<div class=mapempty>No se pudo cargar el mapa.</div>';});"
        # --- interaccion: hover = detalle, clic = acercar el pais, arrastrar = mover, Ctrl+rueda = zoom ---
        "function isoDe(e){var t=e.target;return (t&&t.getAttribute)?(t.getAttribute('data-iso')||''):'';}"
        "var drag=null,movido=false;"
        "svg.addEventListener('mousedown',function(e){drag={x:e.clientX,y:e.clientY,vx:vb.x,vy:vb.y};movido=false;svg.classList.add('grab');});"
        "window.addEventListener('mouseup',function(){if(drag){drag=null;svg.classList.remove('grab');"
        "if(movido)guardarVista();}});"
        "svg.addEventListener('mousemove',function(e){"
        "if(drag){var r=svg.getBoundingClientRect(),dx=e.clientX-drag.x,dy=e.clientY-drag.y;"
        "if(Math.abs(dx)>3||Math.abs(dy)>3){movido=true;hideTip();"
        "vb.x=drag.vx-dx/r.width*vb.w;vb.y=drag.vy-dy/r.height*vb.h;setVB();}return;}"
        "var iso=isoDe(e);if(iso)showTip(iso,e);else hideTip();});"
        "svg.addEventListener('mouseleave',hideTip);"
        "svg.addEventListener('click',function(e){if(movido){movido=false;return;}"
        "var iso=isoDe(e);if(iso)abrir(iso);else cerrar();});"
        "svg.addEventListener('wheel',function(e){if(!(e.ctrlKey||e.metaKey))return;"
        "e.preventDefault();var p=at(e);zoom(e.deltaY<0?0.82:1.22,p[0],p[1]);guardarVista();},{passive:false});"
        "var bi=document.getElementById('mzin'),bo=document.getElementById('mzout'),br=document.getElementById('mzrst');"
        "if(bi)bi.addEventListener('click',function(){zoom(0.7);guardarVista();});"
        "if(bo)bo.addEventListener('click',function(){zoom(1.43);guardarVista();});"
        "if(br)br.addEventListener('click',cerrar);"
        "var w=document.getElementById('attacktop');"
        # se pinta ya (aunque el mapa tarde) y otra vez al cargarlo, cuando ya hay nombres de pais
        "function pintarTop(){if(!w)return;"
        "var rows=Object.keys(DATA).map(function(k){return [k,DATA[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,10);"
        "var tot=window.__ATTACK_TOTAL||0,html='';"
        "rows.forEach(function(kv){var iso=kv[0],c=kv[1],nm=nombre(iso),pct=tot?Math.max(6,Math.round(c/rows[0][1]*120)):6;"
        "html+='<div class=maprow data-iso=\"'+esc(iso)+'\" title=\"Ver detalle y acercar\"><span class=cc>'+esc(iso)+'</span><span class=nm>'+esc(nm)+'</span>"
        "<span class=mapbar style=\"width:'+pct+'px\"></span><span class=ct>'+c+'</span></div>';});"
        "w.innerHTML=html?('<div class=maptophdr>Top paises destino</div><div class=maptopgrid>'+html+'</div>'):'';}"
        "pintarTop();"
        # clic en una fila del top = mismo efecto que clic en el pais (acerca y abre el detalle)
        "if(w)w.addEventListener('click',function(e){var r=e.target.closest?e.target.closest('.maprow'):null;"
        "if(r&&r.getAttribute('data-iso')){abrir(r.getAttribute('data-iso'));"
        "var s=document.getElementById('attackmap');if(s&&s.scrollIntoView)s.scrollIntoView({behavior:'smooth',block:'nearest'});}});"
        "})();</script></section>")

def _dst_badge(dst):
    """Chip del dueño/reputacion de una IP destino, para la cabecera de su tarjeta."""
    fuente = es_malo(dst)
    if fuente:
        return (f"<span class='obadge bad' title='Destino en lista de reputacion ({esc(fuente)})'>"
                f"&#9888; {esc(fuente)}</span>")
    org, legit = duenio(dst)
    if org in ("-", "sin PTR"):
        return "<span class='obadge none'>sin PTR</span>"
    cls = "ok" if legit else "unk"
    return f"<span class='obadge {cls}'>{esc(org)}</span>"

def top_destinos_section(n_dst=5, n_sub=8):
    """Espejo del anterior: IPs DESTINO mas atacadas (las mas golpeadas) y QUE CPEs las
    atacan. Sirve para ver blancos comunes (un mismo C2/servidor tocado por varios CPEs)."""
    tops = [(d, c) for d, c in by_dst.most_common() if d and d != "?"][:n_dst]
    if not tops:
        return ("<section class=\"card\"><h2>Top IPs destino mas atacadas</h2>"
                "<p class=\"muted\">Sin ataques en la ventana.</p></section>")
    cards = []
    for i, (dst, tot) in enumerate(tops, 1):
        agg = {}                       # (src,sport,dport,proto) -> veces
        srcs = set()
        for (s, sp, d, dp, pr, sig), v in flujos.items():
            if d != dst:
                continue
            agg[(s, sp, dp, pr)] = agg.get((s, sp, dp, pr), 0) + v[0]
            srcs.add(s)
        sub = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:n_sub]
        rows = "".join(
            f"<tr><td class='mono' style='color:#184f95'>{esc(s or '-')}</td>"
            f"<td class='mono'>{esc(sp or '-')}</td>"
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (s, sp, dp, pr), c in sub)
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(dst)}</span>{_dst_badge(dst)}"
            f"<span class='tot'>{tot:,} alertas</span>"
            f"<span class='meta'>&larr; {len(srcs):,} CPE origen lo atacan</span></div>"
            f"<div class='tablewrap'><table><thead><tr>"
            f"<th>CPE origen (quien ataca)</th><th>Puerto origen</th>"
            f"<th class='num'>Puerto destino</th><th>Protocolo</th><th class='num'>Peticiones</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div></div>")
    _guardar_ipinfo()
    return (
        "<section class=\"card\" style=\"margin-top:16px\"><h2>Top IPs destino mas atacadas (y quien las ataca)</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">El espejo del cuadro anterior: los blancos que reciben mas alertas y "
        "los CPEs de tu red que los golpean. Util para detectar un <b>destino comun</b> (un mismo C2 o servidor tocado por "
        "varios CPEs a la vez). El chip muestra el dueño/reputacion del destino.</p>"
        f"<div class=\"topwrap\">{''.join(cards)}</div></section>")

def entrantes_section(n_src=8, n_sub=6, max_src=5000, max_det=60):
    """Ataques ENTRANTES: origenes de INTERNET golpeando IPs de TU red.

    Van aparte a proposito. No son abonados tuyos, asi que no se pueden mandar a la
    cuarentena de CPEs (ahi solo entran tus IPs): se cortan en el borde, o se cierra la
    exposicion del equipo golpeado. Mezclarlos con los CPEs hacia que un escaner de
    internet insistente apareciera como 'CPE infectado'."""
    agg = {}
    for (s, sp, d, dp, pr, sig), v in flujos.items():
        if es_mi_cpe(s) or not es_mi_cpe(d):
            continue                      # solo internet -> tu red
        e = agg.get(s)
        if e is None:
            if len(agg) >= max_src:       # cota de RAM, como el resto del script
                continue
            e = agg[s] = {"n": 0, "dst": set(), "det": {}}
        e["n"] += v[0]
        if len(e["dst"]) < 200:
            e["dst"].add(d)
        k = (d, dp, pr, sig)
        if k in e["det"] or len(e["det"]) < max_det:
            e["det"][k] = e["det"].get(k, 0) + v[0]
    if not agg:
        return ""                          # sin ataques entrantes: no se muestra el apartado
    tops = sorted(agg.items(), key=lambda kv: kv[1]["n"], reverse=True)[:n_src]
    cards = []
    for i, (src, e) in enumerate(tops, 1):
        sub = sorted(e["det"].items(), key=lambda kv: kv[1], reverse=True)[:n_sub]
        rows = "".join(
            f"<tr><td class='mono' style='color:#184f95'>{esc(d or '-')}</td>"
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='fw'>{esc((sig or '-')[:70])}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (d, dp, pr, sig), c in sub)
        _pa = pais(ip_de(src))
        _chip = f"<span class='obadge unk'>{esc(_pa)}</span>" if _pa else ""
        _ipa = ip_de(src)
        # que se le denuncia a ESTE atacante (si el panel ya lo consulto en AbuseIPDB)
        _aidb = _aidb_chip(_ipa)
        # denunciarlo de vuelta: solo si el admin lo habilito en Ajustes
        _den = ""
        if _AIDB_REPORTAR:
            _tf = sub[0][0] if sub else ("", "", "", "")
            _den = (f"<button class='qsend' title='Denunciar esta IP a AbuseIPDB "
                    f"(accion publica y a tu nombre)' onclick=\"qden(this,'{esc(_ipa)}',"
                    f"'{esc((_tf[3] or '')[:90])}','{esc(_tf[1] or '')}','{esc(_tf[2] or '')}',"
                    f"'{e['n']}')\">&#9873; Denunciar</button>")
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(_ipa)}</span>{_chip}{_dst_badge(_ipa)}{_chip_nodo(src)}"
            f"<span class='tot'>{e['n']:,} alertas</span>{_den}"
            f"<span class='meta'>&rarr; golpea {len(e['dst']):,} IP(s) de tu red</span></div>"
            + (f"<div style='padding:0 15px 10px'>{_aidb}</div>" if _aidb else "")
            + f"<div class='tablewrap'><table><thead><tr>"
            f"<th>IP de tu red (a quien golpea)</th><th>Puerto destino</th>"
            f"<th>Protocolo</th><th>Firma</th><th class='num'>Peticiones</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div></div>")
    return (
        "<section class=\"card\" style=\"margin-top:16px\"><h2>Ataques entrantes desde internet</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">Origenes de <b>fuera</b> golpeando IPs de tu red. "
        "<b>No son abonados tuyos</b>, asi que no entran al motor de cuarentena: mandarlos a la "
        "address-list de CPEs no bloquearia nada util. Lo que corresponde es <b>cortarlos en el borde</b> "
        "(firewall de entrada) o <b>cerrar la exposicion</b> del equipo golpeado: si algo tuyo recibe "
        "escaneo constante desde internet, casi siempre es que tiene un puerto publicado que no hacia falta.</p>"
        + ("<script>function qden(b,ip,f,dp,pr,n){if(!confirm('Denunciar '+ip+' a AbuseIPDB?\\n\\n"
           "Es publico y queda a tu nombre. No se envia ninguna IP tuya.'))return;"
           "b.disabled=true;var o=b.innerHTML;b.textContent='enviando...';"
           "fetch('/reputacion/denunciar',{method:'POST',credentials:'same-origin',"
           "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
           "body:'ip='+encodeURIComponent(ip)+'&firma='+encodeURIComponent(f)+'&dport='+"
           "encodeURIComponent(dp)+'&proto='+encodeURIComponent(pr)+'&n='+encodeURIComponent(n)})"
           ".then(function(r){return r.text();}).then(function(t){"
           "if(t.indexOf('OK')===0){b.outerHTML=\"<span class='qsent'>\\u2713 Denunciado</span>\";}"
           "else{b.disabled=false;b.innerHTML=o;alert(t.replace(/^ERR: /,''));}})"
           ".catch(function(e){b.disabled=false;b.innerHTML=o;alert('Error: '+e);});}</script>"
           if _AIDB_REPORTAR else "")
        + f"<div class=\"topwrap\">{''.join(cards)}</div></section>")

top_sec = top_origenes_section()

# --- Destinos de MALA REPUTACION que tus CPEs estan contactando --------------------
# Distinto de los atacantes entrantes: estos son destinos a los que sale trafico desde tu
# red y que estan fichados en los feeds. Bloquearlos corta el canal de control de las
# botnets, que es lo que mantiene vivo al equipo infectado.
DESTINOS_FILE = "/var/log/suricata-destinos-malos.json"
try:
    _dm = {}
    for (_s, _sp, _d, _dp, _pr, _sig), _v in flujos.items():
        _sip = ip_de(_s)
        if not es_mi_cpe(_sip) or es_mi_cpe(_d):
            continue                      # solo TU red -> internet
        _fuente, _cidr = reputacion_de(_d)
        if not _fuente:
            continue
        _e = _dm.get(_d)
        if _e is None:
            if len(_dm) >= 5000:
                continue
            _mm = REP_META.get(_fuente, {})
            _e = _dm[_d] = {"alertas": 0, "cpes": set(), "puertos": set(),
                            "fuente": _fuente, "categoria": _mm.get("categoria", ""),
                            "cidr": _cidr, "vigente": bool(_mm.get("vigente")),
                            "firma": "", "ultima": 0}
        _e["alertas"] += _v[0]
        if len(_e["cpes"]) < 200:
            _e["cpes"].add(_s)
        if _dp and len(_e["puertos"]) < 10:
            _e["puertos"].add(_dp)
        if not _e["firma"]:
            _e["firma"] = (_sig or "")[:90]
        if _v[2] > _e["ultima"]:
            _e["ultima"] = _v[2]
    _sal_dm = {k: {"alertas": v["alertas"], "cpes": len(v["cpes"]),
                   "cpes_ej": sorted(v["cpes"])[:8], "puertos": sorted(v["puertos"])[:10],
                   "fuente": v["fuente"], "categoria": v["categoria"], "cidr": v["cidr"],
                   "vigente": v["vigente"], "firma": v["firma"],
                   "ultima": int(v["ultima"] or 0), "pais": pais(k)}
               for k, v in sorted(_dm.items(), key=lambda kv: kv[1]["alertas"], reverse=True)}
    _tmpd = DESTINOS_FILE + ".tmp"
    with open(_tmpd, "w", encoding="utf-8") as _f:
        json.dump({"generado": int(time.time()), "ventana_min": VENTANA_MIN,
                   "destinos": _sal_dm}, _f)
    os.replace(_tmpd, DESTINOS_FILE)
except Exception:
    pass

# --- Quien nos ataca desde internet ------------------------------------------------
# Se guarda aparte porque el panel lo necesita para armar la lista de bloqueo del borde.
# La cadena es: el atacante de fuera infecta al CPE, el CPE infectado ensucia tu IP
# publica. Cortar la entrada es lo que corta infecciones NUEVAS.
ENTRANTES_FILE = "/var/log/suricata-entrantes.json"
try:
    _ent = {}
    for (_s, _sp, _d, _dp, _pr, _sig), _v in flujos.items():
        _sip = ip_de(_s)
        if es_mi_cpe(_sip) or not es_mi_cpe(_d):
            continue                      # solo internet -> tu red
        _e = _ent.get(_sip)
        if _e is None:
            if len(_ent) >= 20000:        # cota: un dia malo son decenas de miles de origenes
                continue
            _e = _ent[_sip] = {"alertas": 0, "dst": set(), "puertos": set(),
                               "firma": "", "ultima": 0}
        _e["alertas"] += _v[0]
        if len(_e["dst"]) < 50:
            _e["dst"].add(_d)
        if _dp and len(_e["puertos"]) < 20:
            _e["puertos"].add(_dp)
        if not _e["firma"]:
            _e["firma"] = (_sig or "")[:90]
        if _v[2] > _e["ultima"]:
            _e["ultima"] = _v[2]
    _sal_ent = {k: {"alertas": v["alertas"], "destinos": len(v["dst"]),
                    "puertos": sorted(v["puertos"])[:10], "firma": v["firma"],
                    "ultima": int(v["ultima"] or 0), "pais": pais(k)}
                for k, v in sorted(_ent.items(), key=lambda kv: kv[1]["alertas"],
                                   reverse=True)[:5000]}
    _tmpe = ENTRANTES_FILE + ".tmp"
    with open(_tmpe, "w", encoding="utf-8") as _f:
        json.dump({"generado": int(time.time()), "ventana_min": VENTANA_MIN,
                   "origenes": _sal_ent}, _f)
    os.replace(_tmpe, ENTRANTES_FILE)
except Exception:
    pass

# --- Cuarentena (Fase A, dry-run): CPEs INFECTADOS CONFIRMADOS (repeticion/contexto).
# Solo se ESCRIBE la lista de candidatos; NO se toca el MikroTik. El panel la muestra.
try:
    # correlacion de flota: CPEs que comparten un patron (misma firma+puerto) con >=3 CPEs
    correlacionados = set()
    for _k, _srcs in patron_src.items():
        if len(_srcs) >= 3:
            correlacionados |= _srcs

    def _reputacion_src(src):
        """Coincidencias de reputacion de los destinos del CPE: (fuente, CIDR exacto,
        categoria, vigencia). Para la ficha de evidencia."""
        out = []; vistos = set()
        for d in dst_by_src.get(src, ()):
            fuente, cidr = reputacion_de(d)
            if fuente and (fuente, cidr) not in vistos:
                vistos.add((fuente, cidr))
                mm = REP_META.get(fuente, {})
                out.append({"ip": d, "cidr": cidr, "fuente": fuente,
                            "categoria": mm.get("categoria", ""), "vigente": mm.get("vigente", False),
                            "fetched_valid": mm.get("fetched_valid", 0), "expira": mm.get("expira", 0)})
                if len(out) >= 8:
                    break
        return out

    def _evidencias_inf(src):
        """Evidencias INDEPENDIENTES (tipos distintos) que respaldan una infeccion. La
        repeticion o el volumen del MISMO conjunto de alertas NO son evidencia independiente;
        aqui se cuentan solo TIPOS distintos. Devuelve (n, lista de etiquetas)."""
        ev = []
        nsids = len(inf_sids.get(src, ()))
        if nsids >= 2:
            ev.append(f"{nsids} firmas CnC distintas")
        _dm = [d for d in dst_by_src.get(src, ()) if es_malo(d)]
        if _dm:
            ev.append(f"destino en lista de reputacion ({len(_dm)})")
        if (src in n5_by_src) and (n1h_by_src.get(src, 0) > n5_by_src.get(src, 0)):
            ev.append("actividad sostenida (5 min y 1 h)")
        if src in correlacionados:
            ev.append("patron compartido con otros CPE (campana)")
        if dns_hits.get(src, 0) >= 1:
            ev.append("consulto dominio malicioso (DNS)")
        return len(ev), ev

    cand = []
    for src in inf_hits:
        if not es_mi_cpe(ip_de(src)):
            continue            # atacante de internet, no un abonado: va al apartado de entrantes
        if nunca_bloquear(ip_de(src)):
            continue                                    # allowlist: nunca a cuarentena
        # gatillo minimo para siquiera considerarlo (repeticion o >=2 firmas)
        if not (inf_hits[src] >= UMBRAL_INFECTADO or len(inf_sids[src]) >= 2):
            continue
        n_ev, evid = _evidencias_inf(src)
        # nivel de confianza: la evidencia INDEPENDIENTE manda, no el volumen.
        #  - alta: >=2 tipos de evidencia independientes -> investigar / cuarentena
        #  - sospechoso: solo repeticion o una sola pista -> vigilar (no auto-cuarentena)
        confianza = "alta" if n_ev >= 2 else "sospechoso"
        sc, band, _c, _d = riesgo(src)
        cand.append({
            "ip": ip_de(src), "router": rid_de(src),
            "puertos_top": dict(dport_cnt_by_src.get(src, Counter()).most_common(8)),
            "cats_top": dict(cat_cnt_by_src.get(src, Counter()).most_common(6)),
            "riesgo": sc,
            "banda": band,
            "confianza": confianza,
            "n_evidencias": n_ev,
            "evidencias": evid,
            "alertas_cnc": inf_hits[src],
            "firmas_cnc": len(inf_sids[src]),
            "firma": inf_sig.get(src, ""),
            "destinos": len(dst_by_src.get(src, ())),
            "destinos_ip": sorted(dst_by_src.get(src, set()))[:12],   # para atribuir falsos positivos
            "puertos": len(dpt_by_src.get(src, ())),
            "total_alertas": by_src.get(src, 0),
            "pruebas": pruebas_by_src.get(src, []),
            "reputacion": _reputacion_src(src),
        })
    # ordenar: primero alta confianza, luego por riesgo
    cand.sort(key=lambda c: (c["confianza"] == "alta", c["riesgo"], c["alertas_cnc"]), reverse=True)
    # DNS sospechoso: CPEs que consultaron dominios de botnet/C2 (Camino A: alertas DNS)
    def _evidencias_dns(src):
        ev = []
        nd = len(dns_sids.get(src, ()))
        if nd >= 2:
            ev.append(f"{nd} firmas DNS distintas")
        _dm = [d for d in dst_by_src.get(src, ()) if es_malo(d)]
        if _dm:
            ev.append(f"destino en lista de reputacion ({len(_dm)})")
        if src in correlacionados:
            ev.append("patron compartido con otros CPE (campana)")
        if inf_hits.get(src, 0) >= 1:
            ev.append("tambien alertas CnC")
        return len(ev), ev
    cand_dns = []
    for src in dns_hits:
        if not es_mi_cpe(ip_de(src)):
            continue            # solo tus abonados consultan "tu" DNS; lo de fuera no se cuarentena
        if nunca_bloquear(ip_de(src)):
            continue                                    # allowlist: nunca a cuarentena
        if dns_hits[src] >= UMBRAL_DNS or len(dns_sids[src]) >= 2:
            n_ev, evid = _evidencias_dns(src)
            confianza = "alta" if n_ev >= 2 else "sospechoso"
            sc, band, _c, _d = riesgo(src)
            cand_dns.append({
                "ip": ip_de(src), "router": rid_de(src),
                "riesgo": sc,
                "banda": band,
                "confianza": confianza,
                "n_evidencias": n_ev,
                "evidencias": evid,
                "alertas_dns": dns_hits[src],
                "firmas_dns": len(dns_sids[src]),
                "firma": dns_sig.get(src, ""),
                "destinos": len(dst_by_src.get(src, ())),
                "destinos_ip": sorted(dst_by_src.get(src, set()))[:12],   # para atribuir falsos positivos
                "puertos": len(dpt_by_src.get(src, ())),
                "total_alertas": by_src.get(src, 0),
                "pruebas": pruebas_by_src.get(src, []),
                "reputacion": _reputacion_src(src),
            })
    cand_dns.sort(key=lambda c: (c["confianza"] == "alta", c["alertas_dns"], c["riesgo"]), reverse=True)
    # top con su banda de riesgo, para el motor de politicas del panel (tope 50 CPEs)
    top_r = []
    for _s, _t in by_src.most_common(80):
        if not es_mi_cpe(ip_de(_s)):
            continue            # el ranking de riesgo es de TUS CPEs; lo de fuera no se cuarentena
        if nunca_bloquear(ip_de(_s)):
            continue                                    # allowlist: fuera del motor de politicas
        _sc, _bd, _c2, _d2 = riesgo(_s)
        # Se guarda tambien POR QUE puntua asi: las politicas envian a cuarentena desde
        # esta lista (no desde 'candidatos'), y sin estos datos el bloqueo quedaba sin
        # motivo que mostrar y el panel lo rotulaba como "manual / sin motivo".
        top_r.append({"ip": ip_de(_s), "router": rid_de(_s),
                      # con que puertos y que tipo de trafico: es lo que permite cruzar
                      # la reputacion de la IP publica con el abonado que la ensucia
                      "puertos_top": dict(dport_cnt_by_src.get(_s, Counter()).most_common(8)),
                      "cats_top": dict(cat_cnt_by_src.get(_s, Counter()).most_common(6)),
                      "riesgo": _sc, "banda": _bd, "desglose": _d2, "alertas": _t,
                      "destinos": len(dst_by_src.get(_s, ())), "puertos": len(dpt_by_src.get(_s, ()))})
    _cq = {"generado": int(time.time()), "ventana_min": VENTANA_MIN,
           "umbral": UMBRAL_INFECTADO, "umbral_dns": UMBRAL_DNS,
           "candidatos": cand, "dns_candidatos": cand_dns, "top_riesgo": top_r}
    _tmpq = os.path.join(LOGDIR, "cuarentena.json.tmp")
    with open(_tmpq, "w", encoding="utf-8") as _f:
        json.dump(_cq, _f)
    os.replace(_tmpq, os.path.join(LOGDIR, "cuarentena.json"))
except Exception:
    pass

doc = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de ataques - {esc(host)}</title>
<style>
:root{{color-scheme:light}}
*{{box-sizing:border-box}}
body{{margin:0;background:{SURF};color:{INK};font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
header{{padding:22px 28px;border-bottom:2px solid {INK};display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px}}
h1{{margin:0;font-size:20px}} h2{{margin:0 0 10px;font-size:15px}}
.sub{{color:{INK2};font-size:13px}}
main{{padding:20px 28px;max-width:1200px;margin:0 auto}}
.tiles{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}}
.tile{{border:1px solid {GRID};border-radius:10px;padding:14px 16px;background:#fff;position:relative;cursor:help}}
.tile:hover{{border-color:#c9d4e3;box-shadow:0 2px 10px rgba(0,0,0,.06)}}
.tile .q{{position:absolute;right:11px;top:11px;width:16px;height:16px;border-radius:50%;border:1px solid {GRID};
color:{INK2};font:700 11px system-ui;text-align:center;line-height:15px}}
.tile .tip{{visibility:hidden;opacity:0;position:absolute;left:0;top:100%;margin-top:8px;z-index:40;
width:max-content;max-width:290px;background:#0b0b0b;color:#fff;font:400 12px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
padding:10px 12px;border-radius:9px;box-shadow:0 6px 18px rgba(0,0,0,.25);transition:opacity .12s;white-space:normal;text-align:left}}
.tile .tip b{{color:#8fc0ff}}
.tile .tip::before{{content:"";position:absolute;left:18px;top:-6px;border:6px solid transparent;border-bottom-color:#0b0b0b;border-top:0}}
.tile:hover .tip{{visibility:visible;opacity:1}}
@media print{{.tile .q,.tile .tip{{display:none}}}}
.chq{{position:relative;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;
border-radius:50%;border:1px solid {GRID};color:{INK2};font:700 11px system-ui;margin-left:8px;cursor:help;vertical-align:middle}}
.chq .chtip{{visibility:hidden;opacity:0;position:absolute;left:0;top:135%;z-index:50;width:max-content;max-width:300px;
background:#0b0b0b;color:#fff;font:400 12px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:9px 11px;border-radius:8px;
box-shadow:0 6px 18px rgba(0,0,0,.25);transition:opacity .12s;white-space:normal;text-align:left;font-weight:400}}
.chq .chtip::before{{content:"";position:absolute;left:5px;top:-6px;border:6px solid transparent;border-bottom-color:#0b0b0b;border-top:0}}
.chq:hover .chtip{{visibility:visible;opacity:1}}
h2{{position:relative}}
@media print{{.chq{{display:none}}}}
.tile .big{{font-size:30px;font-weight:700;line-height:1}}
.tile .lab{{font-size:12px;color:{INK2};margin-top:6px;display:flex;align-items:center;gap:6px}}
.dot{{width:11px;height:11px;border-radius:3px;display:inline-block}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.card{{border:1px solid {GRID};border-radius:10px;padding:16px;background:#fff;margin-bottom:16px;display:flex;flex-direction:column;min-width:0}}
.card>*{{min-width:0;max-width:100%}}  /* los hijos flex encogen y no desbordan la tarjeta (tablas anchas scrollean en su .tablewrap) */
.card.wide{{grid-column:1/-1}}
.lbl{{font-size:12.5px;fill:#2b2a27;font-weight:600}} .val{{font-size:12px;fill:{INK};font-weight:600}}
.tick{{font-size:11px;fill:{INK2}}}
.tlwrap{{position:relative}}
.tl-bar{{transform-box:fill-box;transform-origin:bottom;animation:tlgrow .6s cubic-bezier(.2,.75,.3,1) both;transition:filter .12s}}
.tl-bar:hover{{filter:brightness(1.18)}}
@keyframes tlgrow{{from{{transform:scaleY(0)}}to{{transform:scaleY(1)}}}}
.tltip{{position:absolute;left:0;top:0;transform:translate(-50%,-145%);background:#0b0b0b;color:#fff;
font-size:12px;font-weight:600;padding:5px 9px;border-radius:6px;pointer-events:none;white-space:nowrap;
opacity:0;transition:opacity .1s;z-index:6;box-shadow:0 2px 8px rgba(0,0,0,.25)}}
@media(prefers-reduced-motion:reduce){{.tl-bar{{animation:none}}}}
.muted{{color:{INK2};font-size:12px;margin:8px 0 0}}
.leyenda{{margin:16px -16px -16px;margin-top:auto;padding:9px 16px;border-top:1px solid {GRID};background:#fafafa;border-radius:0 0 10px 10px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid {GRID};vertical-align:top}}
th{{color:{INK2};font-weight:600;position:sticky;top:0;background:#fff}}
th.sortable{{cursor:pointer;user-select:none;white-space:nowrap}}
th.sortable:hover{{color:{BLUE}}}
th.sortable .ar{{opacity:.35;font-size:10px;margin-left:3px}}
th.sortable.asc .ar,th.sortable.desc .ar{{opacity:1;color:{BLUE}}}
td.num,td.mono{{white-space:nowrap}} .mono{{font-family:ui-monospace,Consolas,monospace}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
.tablewrap{{overflow-x:auto}}
.detbar{{display:flex;align-items:center;gap:12px;margin:2px 0 12px;flex-wrap:wrap}}
.detsearch{{padding:8px 12px;border:1px solid {GRID};border-radius:8px;font:13px system-ui;width:300px;max-width:100%}}
.detsearch:focus{{outline:none;border-color:{BLUE};box-shadow:0 0 0 3px rgba(42,120,214,.15)}}
@media print{{.detbar{{display:none}}}}
.pager{{display:flex;align-items:center;gap:12px;margin-top:12px;flex-wrap:wrap}}
.pager button{{font:13px system-ui;padding:6px 12px;border:1px solid {GRID};background:#fff;border-radius:8px;cursor:pointer;color:{INK}}}
.pager button:hover:not(:disabled){{background:#eef4fd;border-color:{BLUE}}}
.pager button:disabled{{opacity:.4;cursor:default}}
.pager #pgi{{font-weight:600;font-size:13px}}
.pgnote{{margin-left:auto}}
@media print{{.pager{{display:none!important}} #detalle tbody tr{{display:table-row!important}}}}
@media(max-width:820px){{.tiles{{grid-template-columns:repeat(2,1fr)}}.grid{{grid-template-columns:1fr}}}}
@media print{{.card,.tile{{break-inside:avoid}}header{{position:static}}}}
</style></head><body>
<header>
  <div><h1>Reporte de ataques - IDS {esc(host)}</h1>
  <div class="sub">{COB[0].upper() + COB[1:]} &middot; {total:,} alertas graves &middot; generado {gen}</div></div>
</header>
<main><!--COB:{COB}-->
  <div class="tiles">
    <div class="tile"><span class="q">?</span><div class="big">{total:,}</div><div class="lab">alertas graves</div>
      <span class="tip"><b>Total de alertas en {COB}</b>, ya sin el ruido informativo (ET INFO). Es la suma de todas las barras de la linea de tiempo de abajo.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(by_src):,}</div><div class="lab"><span class="dot" style="background:#e34948"></span>IPs origen (atacantes)</div>
      <span class="tip"><b>IPs de ORIGEN distintas</b> que dispararon al menos una alerta en {COB}. Ojo: muchas son equipos que solo hicieron una consulta DNS sospechosa, no ataque real. La grafica de abajo muestra solo el top.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(by_dst):,}</div><div class="lab"><span class="dot" style="background:#eb6834"></span>IPs destino (objetivos)</div>
      <span class="tip"><b>IPs de DESTINO distintas</b> hacia donde se dirigio el trafico alertado en {COB} (el objetivo). Suele ser tu propio DNS y unos pocos servidores.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(ips_vistas):,}{'+' if len(ips_vistas) >= MAX_IPS else ''}</div><div class="lab"><span class="dot" style="background:#2a78d6"></span>IPs unicas vistas (todo el trafico)</div>
      <span class="tip"><b>Todas las IPs distintas</b> que el MikroTik le envio al sensor en {COB}, no solo las que atacan: cuenta cualquier evento (TLS, HTTP, DNS, SNMP, alertas...), origen y destino, sin duplicar. Es el alcance real de lo que esta sensando.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(by_dport):,}</div><div class="lab"><span class="dot" style="background:#eda100"></span>puertos destino distintos</div>
      <span class="tip"><b>Puertos de destino distintos</b> que aparecieron en las alertas de {COB} (443, 80, 53, 22...). El top esta en la grafica "Puertos de destino mas atacados".</span></div>
  </div>
  {timeline(by_hour)}
  {mapa_ataques_section()}
  <div class="grid">
    {hbar("Puertos de destino mas atacados", top(by_dport), "alertas", que="puerto", tip="Puertos de destino con mas alertas (443 HTTPS, 80 HTTP, 53 DNS, 22 SSH...). Muestra a que servicios apunta el trafico sospechoso. Solo el top; el total de puertos distintos esta en el recuadro de arriba.")}
    {hbar("IPs origen (atacantes)", top(by_src), "alertas", que="IP", tip="IPs de ORIGEN que mas alertas dispararon (los equipos/CPE que generan el trafico). Ojo: muchas pueden ser solo consultas DNS sospechosas, no ataque real. Solo el top; el total esta arriba.")}
    {hbar("IPs destino (objetivos)", top(by_dst), "alertas", que="IP", tip="IPs de DESTINO mas frecuentes: hacia donde va el trafico alertado (el objetivo). Suele ser tu DNS y unos pocos servidores.")}
    {hbar("Firmas mas frecuentes (tipo de ataque)", firmas_top, "alertas", que="firma", tip="Tipos de ataque (firmas de Suricata) mas frecuentes, agrupados y traducidos al espanol. Indica que clase de amenaza predomina.")}
  </div>
  {top_sec}
  <section class="card">
    <h2>Detalle: quien ataca, a donde, por que puerto, cuando y por cuanto tiempo</h2>
    <div class="detbar"><input id="detbuscar" class="detsearch" placeholder="Filtrar por IP, puerto, protocolo, firma..."><span id="detcount" class="muted"></span></div>
    <div class="tablewrap"><table id="detalle">
      <thead><tr>
      <th class="sortable" data-col="0">IP origen<span class="ar">&#8597;</span></th>
      <th class="num sortable" data-col="1">Puerto<span class="ar">&#8597;</span></th>
      <th class="sortable" data-col="2">IP destino (atacada)<span class="ar">&#8597;</span></th>
      <th class="num sortable" data-col="3">Puerto<span class="ar">&#8597;</span></th>
      <th class="sortable" data-col="4">Protocolo<span class="ar">&#8597;</span></th>
      <th class="sortable" data-col="5">Firma (tipo de ataque)<span class="ar">&#8597;</span></th>
      <th class="num sortable" data-col="6">Veces<span class="ar">&#8597;</span></th>
      <th class="sortable" data-col="7">Primera &rarr; ultima<span class="ar">&#8597;</span></th>
      <th class="sortable" data-col="8">Duracion<span class="ar">&#8597;</span></th></tr></thead>
      <tbody>{"".join(filas) if filas else '<tr><td colspan="9" class="muted">Sin ataques en la ventana.</td></tr>'}</tbody>
    </table></div>
    <div class="pager" id="pager">
      <button id="prev" type="button">&larr; Anterior</button>
      <span id="pgi">Pagina 1</span>
      <button id="next" type="button">Siguiente &rarr;</button>
      <span class="pgnote muted">{len(filas)} flujos, 20 por pagina &middot; al imprimir salen todos</span>
    </div>
    <script>
    (function(){{
      var tbody=document.querySelector('#detalle tbody');
      var all=[].slice.call(tbody.querySelectorAll('tr'));
      var rows=all.slice();
      var per=20, p=1;
      var pager=document.getElementById('pager');
      var buscar=document.getElementById('detbuscar');
      var cnt=document.getElementById('detcount');
      function npag(){{return Math.max(1,Math.ceil(rows.length/per));}}
      function draw(){{
        for(var i=0;i<all.length;i++) all[i].style.display='none';
        var small=rows.length<=per;
        if(pager) pager.style.display=(small||rows.length===0)?'none':'';
        for(var i=0;i<rows.length;i++) rows[i].style.display=(small||(i>=(p-1)*per&&i<p*per))?'':'none';
        if(pager && !small){{
          document.getElementById('pgi').textContent='Pagina '+p+' de '+npag();
          document.getElementById('prev').disabled=(p<=1);
          document.getElementById('next').disabled=(p>=npag());
        }}
        if(cnt) cnt.textContent=(rows.length===all.length? '' : rows.length+' de '+all.length+' filas');
      }}
      function go(x){{p=Math.min(npag(),Math.max(1,x)); draw();}}
      function filtrar(){{
        var q=((buscar&&buscar.value)||'').toLowerCase().trim();
        try{{sessionStorage.setItem('detq',q);}}catch(e){{}}
        rows = q ? all.filter(function(tr){{return tr.textContent.toLowerCase().indexOf(q)>=0;}}) : all.slice();
        p=1; draw();
      }}
      // ordenar al pulsar un encabezado: 1er clic ascendente, 2do descendente (sobre lo filtrado)
      var ths=[].slice.call(document.querySelectorAll('#detalle thead th.sortable'));
      function val(tr,i){{
        var td=tr.children[i]; if(!td) return '';
        var s=td.getAttribute('data-s'); if(s===null) s=td.textContent;
        if(s!=='' && /^-?\\d/.test(s) && !isNaN(parseFloat(s))) return parseFloat(s);
        return String(s).toLowerCase();
      }}
      ths.forEach(function(th){{
        th.onclick=function(){{
          var col=+th.getAttribute('data-col');
          var asc=!th.classList.contains('asc');
          ths.forEach(function(o){{o.classList.remove('asc','desc'); var a=o.querySelector('.ar'); if(a) a.innerHTML='&#8597;';}});
          th.classList.add(asc?'asc':'desc');
          var ar=th.querySelector('.ar'); if(ar) ar.innerHTML=asc?'&#8593;':'&#8595;';
          rows.sort(function(a,b){{var x=val(a,col),y=val(b,col); if(x<y)return asc?-1:1; if(x>y)return asc?1:-1; return 0;}});
          rows.forEach(function(r){{tbody.appendChild(r);}});
          p=1; draw();
        }};
      }});
      if(pager){{
        document.getElementById('prev').onclick=function(){{go(p-1);}};
        document.getElementById('next').onclick=function(){{go(p+1);}};
      }}
      if(buscar){{
        buscar.oninput=filtrar;
        try{{var sq=sessionStorage.getItem('detq'); if(sq) buscar.value=sq;}}catch(e){{}}
      }}
      filtrar();
    }})();
    </script>
    <p class="muted">Top {len(filas)} flujos por numero de alertas. Se excluye ruido informativo (ET INFO).</p>
  </section>
</main></body></html>"""

out = os.path.join(LOGDIR, "report-" + datetime.now(TZ_EC).strftime("%Y%m%d-%H%M") + ".html")
# Escritura atomica (.tmp + replace), como el resto del script. Si no, el archivo existe
# con mtime nuevo desde el primer byte: el panel lo elige por mtime, no encuentra el
# <main> y sirve "En vivo" en blanco mientras se escribe; y si el generador muere a
# media escritura, ese HTML truncado queda como el mas reciente hasta el ciclo siguiente.
_tmp_out = out + ".tmp"
with open(_tmp_out, "w", encoding="utf-8") as _fo:
    _fo.write(doc)
os.replace(_tmp_out, out)

# Historico acotado: conservar los reportes de los ULTIMOS 3 DIAS, pero solo UNA
# instantanea por hora (el panel regenera cada ~5 min; sin adelgazar serian ~864
# archivos). Se conserva SIEMPRE el mas nuevo. Se corre en cada generacion.
try:
    RET_DIAS = 3
    ahora = time.time()
    hs = glob.glob(f"{LOGDIR}/report-*.html")
    nuevo = max(hs, key=os.path.getmtime) if hs else None
    vistos = set()
    if nuevo:
        vistos.add(int(os.path.getmtime(nuevo) // 3600))   # la hora del mas nuevo ya esta cubierta
    for f in sorted(hs, key=os.path.getmtime, reverse=True):
        if f == nuevo:
            continue
        try:
            mt = os.path.getmtime(f)
        except OSError:
            continue
        if ahora - mt > RET_DIAS * 86400:          # mas viejo que la retencion -> fuera
            try: os.remove(f)
            except OSError: pass
            continue
        bucket = int(mt // 3600)                    # 1 por hora: el primero (mas nuevo) manda
        if bucket in vistos:
            try: os.remove(f)                        # ya hay uno mas nuevo en esa hora
            except OSError: pass
        else:
            vistos.add(bucket)
except OSError:
    pass

# --- Metricas por dia: se SUMAN a lo ya guardado (el bucle solo conto lo nuevo) --------
# Esto es lo que permite responder "bajo el abuso?" con un numero, meses despues, cuando
# los reportes HTML de entonces ya no existen.
def fusionar_metricas(prev, nuevos, ts_max, hueco, ahora=None):
    """Suma lo contado en esta corrida a lo que ya habia. Devuelve el dict a guardar.

    Se SUMA en vez de sobrescribir porque el bucle solo conto lo posterior a la ultima
    corrida; recontar la ventana daria mal el total del dia en cuanto la ventana sea mas
    corta que 24 h."""
    ahora = time.time() if ahora is None else ahora
    dias = prev.get("dias")
    if not isinstance(dias, dict):
        dias = {}
    for d, v in (nuevos or {}).items():
        e = dias.get(d)
        if not isinstance(e, dict):
            e = {"sal": 0, "ent": 0, "ruido": 0, "cpes_n": 0, "cpes": [],
                 "puertos": {}, "cats": {}, "nodos": {}}
        e["sal"] = int(e.get("sal", 0)) + int(v.get("sal", 0))
        e["ent"] = int(e.get("ent", 0)) + int(v.get("ent", 0))
        e["ruido"] = int(e.get("ruido", 0)) + int(v.get("ruido", 0))
        # CPEs distintos del dia: se guarda el conjunto mientras el dia es reciente y
        # despues solo el numero (400 dias de listas no tendrian sentido).
        conj = set(e.get("cpes") or []) | set(v.get("cpes") or ())
        if len(conj) > METRICAS_MAX_CPES:
            conj = set(sorted(conj)[:METRICAS_MAX_CPES])
        e["cpes"] = sorted(conj)
        e["cpes_n"] = len(conj)
        for campo in ("puertos", "cats", "nodos"):
            acum = dict(e.get(campo) or {})
            for k, n in (v.get(campo) or {}).items():
                acum[k] = int(acum.get(k, 0)) + int(n)
            e[campo] = dict(sorted(acum.items(), key=lambda kv: kv[1], reverse=True)[:20])
        if hueco:
            e["hueco"] = True
        dias[d] = e
    corte_set = time.strftime("%Y-%m-%d", time.localtime(ahora - 3 * 86400))
    for k, v2 in dias.items():
        if k < corte_set and isinstance(v2, dict):
            v2.pop("cpes", None)
    lim = time.strftime("%Y-%m-%d", time.localtime(ahora - METRICAS_DIAS * 86400))
    dias = {k: v for k, v in dias.items() if k >= lim}
    return {"ultimo_ts": ts_max, "generado": int(ahora), "dias": dias}

try:
    # Si el generador estuvo parado mas que la ventana hay un agujero: se deja anotado en
    # vez de fingir que esos dias fueron tranquilos.
    _hueco = bool(METR_DESDE and ts_min and ts_min > METR_DESDE + 60)
    _nuevos = {d: {"sal": v["sal"], "ent": v["ent"], "ruido": v["ruido"], "cpes": v["cpes"],
                   "puertos": dict(v["puertos"]), "cats": dict(v["cats"]),
                   "nodos": dict(v["nodos"])}
               for d, v in dias_m.items()}
    _sal = fusionar_metricas(_mprev, _nuevos, ts_max or METR_DESDE, _hueco)
    _tmpm = METRICAS_FILE + ".tmp"
    with open(_tmpm, "w", encoding="utf-8") as _f:
        json.dump(_sal, _f)
    os.replace(_tmpm, METRICAS_FILE)
except OSError:
    pass

print(out)
HREP
chmod 755 /usr/local/bin/suricata-html-report

cat > /etc/systemd/system/suricata-report.service <<'UNIT'
[Unit]
Description=Informe diario de infractores de Suricata
[Service]
Type=oneshot
Nice=15
IOSchedulingClass=idle
ExecStart=/usr/local/bin/suricata-report
ExecStart=/usr/local/bin/suricata-html-report
# el auto-borrado (conservar 20) lo hace cada generador al terminar; aqui no hace falta
UNIT
cat > /etc/systemd/system/suricata-report.timer <<'UNIT'
[Unit]
Description=Informe diario de Suricata (top IPs origen)
[Timer]
OnCalendar=*-*-* 07:30:00
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now suricata-report.timer >/dev/null 2>&1 || true
ok "Informe diario 07:30 (suricata-report.timer): texto por Telegram + reporte HTML grafico."
ok "  Reporte HTML a mano: suricata-html-report  ->  /var/log/suricata/report-AAAAMMDD-HHMM.html"

# ----------------------------------------------------------------------------- panel de estadisticas
# Apartado web "Estadisticas": sirve el reporte grafico en vivo (se regenera si esta
# viejo) + historico, con login basico. Puerto propio, junto a EveBox.
cat > /usr/local/bin/suricata-dashboard <<'DASH'
#!/usr/bin/env python3
"""suricata-dashboard: panel web de estadisticas de Suricata (apartado "Estadisticas").

Sirve el reporte HTML grafico en vivo (lo regenera si esta viejo) y el historico de
reportes diarios, con login basico. Solo biblioteca estandar. Corre como servicio.

Config: /etc/suricata-dashboard.conf  (PORT, USER, PASS)
"""
import base64, glob, hashlib, html, json, os, re, secrets, socket, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
import traceback
import urllib.request, urllib.parse, urllib.error, ipaddress
from datetime import datetime, timezone, timedelta

TZ_EC = timezone(timedelta(hours=-5))   # hora de Ecuador (America/Guayaquil)

def hora_ec(ts):
    """Devuelve HH:MM:SS en hora de Ecuador desde una marca de eve.json (con offset)."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt).astimezone(TZ_EC).strftime("%H:%M:%S")
        except (ValueError, TypeError):
            pass
    return ts[11:19] if len(ts) >= 19 else ""
_up = urllib.parse      # alias corto. A NIVEL DE MODULO a proposito: ver abajo.
# Estuvo como "import urllib.parse as _up" DENTRO de un par de ramas del manejador GET, y
# eso convierte a _up en una variable LOCAL de todo el metodo. Las ramas que la importaban
# hacen return, asi que cualquier ruta posterior que usara _up reventaba con
# UnboundLocalError -> el hilo moria -> el proxy devolvia un "502 Bad Gateway" mudo.
# Le paso a /documentacion. Un import dentro de una rama no vale para las demas.

from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSIONS = {}          # token -> {user, role, exp}
SESSION_TTL = 12 * 3600
SESSIONS_FILE = "/etc/suricata-dashboard-sessions.json"   # persistir para no cerrar sesion al reiniciar

def _cargar_sesiones():
    """Carga las sesiones vigentes del disco (para que un reinicio del panel -p.ej. al
    actualizar- no eche a todos al login)."""
    try:
        d = json.load(open(SESSIONS_FILE, encoding="utf-8"))
        ahora = time.time()
        return {t: v for t, v in d.items() if isinstance(v, dict) and v.get("exp", 0) > ahora}
    except Exception:
        return {}

def _guardar_sesiones():
    try:
        ahora = time.time()
        data = {t: v for t, v in SESSIONS.items() if v.get("exp", 0) > ahora}
        tmp = SESSIONS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, SESSIONS_FILE)
        try: os.chmod(SESSIONS_FILE, 0o600)
        except OSError: pass
    except OSError:
        pass

SESSIONS = _cargar_sesiones()

# anti-fuerza-bruta del login: por IP de origen
LOGIN_FAILS = {}       # ip -> [intentos, primer_ts]
LOGIN_MAX = 8          # fallos permitidos por ventana
LOGIN_WINDOW = 600     # ventana y duracion del bloqueo (segundos)

def login_bloqueado(ip):
    """Segundos restantes de bloqueo para esa IP, o 0 si puede intentar."""
    r = LOGIN_FAILS.get(ip)
    if not r:
        return 0
    intentos, t0 = r
    if time.time() - t0 > LOGIN_WINDOW:
        LOGIN_FAILS.pop(ip, None)
        return 0
    return int(LOGIN_WINDOW - (time.time() - t0)) if intentos >= LOGIN_MAX else 0

def login_fallo(ip):
    now = time.time()
    r = LOGIN_FAILS.get(ip)
    if not r or now - r[1] > LOGIN_WINDOW:
        LOGIN_FAILS[ip] = [1, now]
    else:
        r[0] += 1
    if len(LOGIN_FAILS) > 5000:   # poda de entradas viejas
        for k in [k for k, v in LOGIN_FAILS.items() if now - v[1] > LOGIN_WINDOW]:
            LOGIN_FAILS.pop(k, None)

LOGIN_LOG = "/var/log/suricata-dashboard-login.log"

def login_registrar(ip, user, estado):
    """Deja constancia de cada intento: fecha, IP, usuario y estado (OK/FAIL/BLOQUEADO)."""
    user = (user or "")[:40].replace("\t", " ").replace("\n", " ").replace("\r", " ")
    ts = datetime.now(TZ_EC).strftime("%Y-%m-%d %H:%M:%S")
    try:
        # tope de tamano: si pasa de ~1 MB, conserva solo las ultimas 1000 lineas
        if os.path.exists(LOGIN_LOG) and os.path.getsize(LOGIN_LOG) > 1_000_000:
            with open(LOGIN_LOG, encoding="utf-8", errors="replace") as f:
                ult = f.readlines()[-1000:]
            with open(LOGIN_LOG, "w", encoding="utf-8") as f:
                f.writelines(ult)
        with open(LOGIN_LOG, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{(ip or '?')[:45]}\t{user}\t{estado}\n")
    except OSError:
        pass

def login_recientes(n=40):
    """Ultimos n intentos de login (mas reciente primero)."""
    try:
        with open(LOGIN_LOG, "rb") as f:
            f.seek(0, 2); size = f.tell(); f.seek(max(0, size - 80000)); data = f.read()
    except OSError:
        return []
    filas = []
    for l in reversed(data.decode("utf-8", "replace").splitlines()[-n:]):
        p = l.split("\t")
        if len(p) >= 4:
            filas.append(p[:4])
    return filas

def ips_bloqueadas():
    """IPs actualmente bloqueadas: (ip, segundos_restantes, intentos)."""
    res = []
    for ip in list(LOGIN_FAILS.keys()):
        s = login_bloqueado(ip)
        if s > 0:
            res.append((ip, s, LOGIN_FAILS[ip][0]))
    return sorted(res, key=lambda x: -x[1])

EVE = "/var/log/suricata/eve.json"

EXCL_FILE = "/etc/suricata-exclusiones.json"

def cargar_exclusiones(incluir_vencidas=False):
    """Lista de reglas de exclusion. Cada una: {tipo:'dst'|'src', ip, motivo, puertos:[int],
    sid, hasta, autor, creado}. puertos vacio = todos; sid vacio = cualquier firma;
    hasta=0 = permanente. Las vencidas se ocultan (salvo incluir_vencidas, para la UI).
    Tambien lee las lineas IGNORAR_* legacy del .conf."""
    reglas = []; ahora = time.time()
    try:
        data = json.load(open(EXCL_FILE, encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if not r.get("ip"):
                    continue
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                vencida = bool(hasta and ahora > hasta)
                if vencida and not incluir_vencidas:
                    continue
                reglas.append({"tipo": r.get("tipo", "dst"), "ip": r["ip"],
                               "motivo": r.get("motivo", ""),
                               "puertos": [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()],
                               "sid": str(r.get("sid") or ""), "hasta": hasta,
                               "autor": r.get("autor", ""), "creado": r.get("creado", 0),
                               "vencida": vencida})
    except Exception:
        pass
    try:
        for l in open("/etc/suricata-report.conf", encoding="utf-8"):
            l = l.strip()
            if l.startswith("IGNORAR_DESTINOS="):
                for ip in l.split("=", 1)[1].split(","):
                    if ip.strip():
                        reglas.append({"tipo": "dst", "ip": ip.strip(), "motivo": "(conf)", "puertos": []})
            elif l.startswith("IGNORAR_ORIGENES="):
                for ip in l.split("=", 1)[1].split(","):
                    if ip.strip():
                        reglas.append({"tipo": "src", "ip": ip.strip(), "motivo": "(conf)", "puertos": []})
    except OSError:
        pass
    return reglas

def guardar_exclusiones(reglas):
    _keys = ("tipo", "ip", "motivo", "puertos", "sid", "hasta", "autor", "creado")
    limpio = [{k: r[k] for k in _keys if k in r} for r in reglas if r.get("motivo") != "(conf)"]
    tmp = EXCL_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(limpio, f, ensure_ascii=False, indent=1)
    os.replace(tmp, EXCL_FILE)

def _excluido(reglas, src, dst, dport, sid=None):
    for r in reglas:
        quien = dst if r["tipo"] == "dst" else src
        if quien != r["ip"]:
            continue
        if r["puertos"] and not (dport is not None and int(dport) in r["puertos"]):
            continue
        if r.get("sid") and str(sid) != r["sid"]:        # regla ligada a una firma concreta
            continue
        return True
    return False
_RE = {k: re.compile(p) for k, p in {
    "ts": r'"timestamp":"([^"]+)"', "src_ip": r'"src_ip":"([^"]+)"',
    "dest_ip": r'"dest_ip":"([^"]+)"', "src_port": r'"src_port":(\d+)',
    "dest_port": r'"dest_port":(\d+)', "proto": r'"proto":"([^"]+)"',
    "sig": r'"signature":"((?:[^"\\]|\\.)*)"', "sid": r'"signature_id":(\d+)',
    # de que MikroTik vino la alerta (cada nodo espeja por su interfaz)
    "iface": r'"in_iface":"([^"]+)"',
}.items()}

def rid_por_iface(iface):
    """Id del router de esa interfaz. Con un solo nodo devuelve "" y todo queda
    indexado por IP, como siempre."""
    lst = cargar_routers()
    if len(lst) < 2:
        return ""
    for r in lst:
        if r.get("iface") == iface:
            return r.get("id", "")
    return ""

SEV = [  # (claves en la firma, color, etiqueta). Se evalua en orden; gana la primera.
    # ROJO = comunicacion real con el atacante (infeccion confirmada), no una simple
    # consulta a un dominio de mala fama. Por eso "malware" a secas NO es rojo aqui.
    (("cnc", "c2 ", "command and control", "checkin", "check-in", "botnet", "mirai",
      "katana", "trojan", "ransom", "coinmin", "cryptomin", "compromised"), "#e34948", "INFECTADO"),
    (("scan", "brute", "exploit", "attack", "recon", "sweep", "portscan"), "#eb6834", "ATAQUE"),
    (("malware", "dns query", "tld", "dyn_dns", "dynamic_dns", "duckdns", "dyndns", "no-ip",
      "adware", "pup", "suspicious", "hostile", "observed dns"), "#eda100", "SOSPECHOSO"),
]
def sev(sig):
    s = sig.lower()
    for claves, color, etq in SEV:
        if any(k in s for k in claves):
            return color, etq
    return "#8a8a86", "OTRO"

_SEVRANK = {"INFECTADO": 3, "ATAQUE": 2, "SOSPECHOSO": 1, "OTRO": 0}

def _ipnum(s):
    """IPv4 -> entero para ordenar bien (9 antes que 10). No-IP -> 0."""
    p = s.split(".")
    if len(p) == 4 and all(x.isdigit() for x in p):
        try:
            return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
        except ValueError:
            return 0
    return 0

# Traduccion de las firmas ET (ingles) a una descripcion en espanol. Se evalua en orden;
# lo especifico antes que lo generico. Si no casa, se deja la firma original.
_TRAD = [
    (("poor reputation", "cins", "compromised ip", "dshield", "spamhaus", "abuse.ch", "known attacker", "cinsscore"), "Mala reputacion"),
    (("tor exit", "tor node", "tor "), "Red Tor"),
    (("katana",), "Botnet Katana"),
    (("mirai",), "Botnet Mirai"),
    (("cnc", "c2 ", "command and control", "checkin", "check-in"), "Botnet CnC"),
    (("botnet",), "Botnet"),
    (("ransom",), "Ransomware"),
    (("trojan",), "Troyano"),
    (("coinmin", "cryptomin", "miner"), "Criptomineria"),
    (("ssh scan",), "Escaneo SSH"),
    (("brute", "password"), "Fuerza bruta"),
    (("rdp", "vnc"), "RDP/VNC"),
    (("telnet",), "Escaneo Telnet"),
    (("tr-069", "cwmp", "7547"), "Escaneo TR-069"),
    (("port scan", "portscan", "sweep", "recon", "barrido"), "Escaneo de puertos"),
    (("scan",), "Escaneo saliente"),
    (("exploit", "cve-", "shellcode", "attempted-admin"), "Exploit"),
    (("connectivity check", "connectivity-check"), "Chequeo de conectividad"),
    (("403 forbidden",), "Acceso denegado (403)"),
    (("go http client",), "Cliente HTTP Go"),
    (("fake wget", "wget 3.0"), "User-Agent falso"),
    (("user_agent", "user agent", "user-agent"), "User-Agent raro"),
    (("bittorrent", "p2p", "dht"), "BitTorrent / P2P"),
    (("stun ",), "STUN (video)"),
    (("snmp",), "Acceso SNMP"),
    (("dyn_dns", "dynamic_dns", "dyndns", "duckdns", "no-ip"), "DNS dinamico"),
    (("dns query", ".cc tld", ".su tld", ".top domain", " tld", "dns lookup"), "DNS sospechoso"),
    (("adware", "pup"), "Adware / PUP"),
    (("malware", "compromised"), "Trafico de malware"),
    (("quic",), "Anomalia QUIC"),
    (("tls", "ssl"), "Anomalia TLS/SSL"),
    (("http",), "Anomalia HTTP"),
    (("stream", "tcp "), "Anomalia TCP"),
]
def traducir(sig):
    s = sig.lower()
    for claves, txt in _TRAD:
        if any(k in s for k in claves):
            return txt
    # Sin traduccion salia la firma ENTERA, con su prefijo de ruleset, y la columna de
    # categorias quedaba ilegible ("ET HUNTING Terse Unencrypted Request for Google...").
    # Se le quita el prefijo y se acota.
    limpio = re.sub(r"^(?:ET|GPL)\s+(?:[A-Z_]{3,}\s+)?", "", sig).strip() or sig
    return (limpio[:44] + "\u2026") if len(limpio) > 45 else limpio

def tail_grupos(path=EVE, want=200, maxbytes=6_000_000, top=25):
    """Cola del eve.json agrupada por (origen, destino, puerto, firma) con contador."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); size = f.tell(); start = max(0, size - maxbytes)
            f.seek(start); data = f.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").split("\n")
    if start > 0 and lines:
        lines = lines[1:]
    reglas = cargar_exclusiones()
    g = {}
    vistos = 0
    for line in reversed(lines):
        if '"event_type":"alert"' not in line:
            continue
        get = lambda k: (_RE[k].search(line).group(1) if _RE[k].search(line) else "")
        sig = get("sig")
        if sig.startswith("ET INFO"):
            continue
        src = get("src_ip"); dst = get("dest_ip"); dp = get("dest_port"); pr = get("proto")
        if _excluido(reglas, src, dst, int(dp) if dp else None, get("sid")):   # exclusiones configuradas
            continue
        vistos += 1
        hh = hora_ec(get("ts"))
        key = (src, dst, f"{dp}/{pr}" if dp else pr, sig)
        r = g.get(key)
        if r is None:
            g[key] = [1, hh]      # primera vez que lo vemos (= mas reciente, vamos al reves)
        else:
            r[0] += 1
        if vistos >= want:
            break
    filas = [(hh, k[0], k[1], k[2], k[3], c) for k, (c, hh) in g.items()]
    filas.sort(key=lambda x: x[0], reverse=True)   # mas reciente primero
    return filas[:top]

def live_feed_html():
    filas = tail_grupos()
    if not filas:
        cuerpo = '<tr><td colspan="6" class="muted" style="padding:14px">Sin ataques recientes o esperando trafico...</td></tr>'
    else:
        tr = []
        for hh, src, dst, puerto, sig, cnt in filas:
            color, etq = sev(sig)
            veces = f'<span class="veces">&times;{cnt}</span>' if cnt > 1 else ""
            pnum = puerto.split("/", 1)[0]
            pnum = int(pnum) if pnum.isdigit() else -1
            sig_es = traducir(sig)
            tr.append(
                f'<tr data-r style="border-left:4px solid {color}">'
                f'<td class="mono t" data-s="{html.escape(hh)}">{html.escape(hh)}</td>'
                f'<td data-s="{_SEVRANK.get(etq, 0)}"><span class="badge" style="background:{color}">{etq}</span></td>'
                f'<td class="mono" data-s="{_ipnum(src)}">{html.escape(src)}</td>'
                f'<td class="mono dst" data-s="{_ipnum(dst)}">{html.escape(dst)}</td>'
                f'<td class="mono" data-s="{pnum}">{html.escape(puerto)}</td>'
                f'<td title="{html.escape(sig)}" data-s="{html.escape(sig_es)}">{html.escape(sig_es)} {veces}</td></tr>')
        cuerpo = "".join(tr)
    ahora = datetime.now(TZ_EC).strftime("%H:%M:%S")
    return (
        '<style>'
        '.feed{max-width:1360px;margin:20px auto;padding:0 28px}'
        '.feed h2{display:flex;align-items:center;gap:10px;margin:0 0 12px}'
        '.pulse{width:9px;height:9px;border-radius:50%;background:#e34948;display:inline-block;'
        'box-shadow:0 0 0 0 rgba(227,73,72,.6);animation:pulse 1.6s infinite}'
        '@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(227,73,72,.5)}70%{box-shadow:0 0 0 8px rgba(227,73,72,0)}100%{box-shadow:0 0 0 0 rgba(227,73,72,0)}}'
        '.feedwrap{max-height:420px;overflow:auto;border:1px solid #e7e6e2;border-radius:10px}'
        '.feed table{width:100%;border-collapse:collapse;font-size:12.5px}'
        '.feed thead th{position:sticky;top:0;background:#f4f4f2;color:#52514e;text-align:left;'
        'padding:9px 10px;font-weight:600;border-bottom:1px solid #e7e6e2;z-index:1}'
        '.feed thead th.sortable{cursor:pointer;user-select:none;white-space:nowrap}'
        '.feed thead th.sortable:hover{color:#2a78d6}'
        '.feed thead th .ar{opacity:.35;font-size:10px;margin-left:3px}'
        '.feed thead th.asc .ar,.feed thead th.desc .ar{opacity:1;color:#2a78d6}'
        '.feed tbody td{padding:7px 10px;border-bottom:1px solid #f0efec;vertical-align:middle}'
        '.feed tbody tr:nth-child(even){background:#fbfbfa}'
        '.feed tbody tr:hover{background:#eef4fd}'
        '.feed .mono{font-family:ui-monospace,Consolas,monospace}'
        '.feed .t{color:#52514e;white-space:nowrap}'
        '.feed .dst{color:#184f95}'
        '.badge{color:#fff;font-size:10px;font-weight:700;letter-spacing:.3px;'
        'padding:2px 7px;border-radius:20px;white-space:nowrap}'
        '.veces{background:#ecebe7;color:#52514e;font-size:11px;padding:1px 6px;border-radius:10px;margin-left:4px}'
        '</style>'
        f'<section class="feed">'
        f'<h2><span class="pulse"></span>Ultimos ataques en vivo'
        f'<span style="font-weight:400;color:#52514e;font-size:12px">se actualiza solo &middot; {ahora}</span></h2>'
        f'<div class="feedwrap"><table id="feedtbl">'
        f'<thead><tr>'
        f'<th class="sortable" data-col="0">Hora<span class="ar">&#8597;</span></th>'
        f'<th class="sortable" data-col="1">Tipo<span class="ar">&#8597;</span></th>'
        f'<th class="sortable" data-col="2">Origen (equipo)<span class="ar">&#8597;</span></th>'
        f'<th class="sortable" data-col="3">Destino<span class="ar">&#8597;</span></th>'
        f'<th class="sortable" data-col="4">Puerto<span class="ar">&#8597;</span></th>'
        f'<th class="sortable" data-col="5">Ataque<span class="ar">&#8597;</span></th></tr></thead>'
        f'<tbody>{cuerpo}</tbody></table></div>'
        f'<p class="muted" style="margin:8px 2px">Agrupado por equipo y tipo &middot; &times;N = veces repetido '
        f'&middot; pulsa un encabezado para ordenar</p>'
        '<script>(function(){'
        'var tb=document.getElementById("feedtbl");if(!tb)return;'
        'var tbody=tb.querySelector("tbody");'
        'var ths=[].slice.call(tb.querySelectorAll("thead th.sortable"));'
        'function val(tr,i){var td=tr.children[i];if(!td)return"";var s=td.getAttribute("data-s");'
        'if(s===null)s=td.textContent;if(s!==""&&/^-?\\d/.test(s)&&!isNaN(parseFloat(s)))return parseFloat(s);'
        'return String(s).toLowerCase();}'
        'function apply(col,asc){var rows=[].slice.call(tbody.querySelectorAll("tr[data-r]"));if(!rows.length)return;'
        'rows.sort(function(a,b){var x=val(a,col),y=val(b,col);if(x<y)return asc?-1:1;if(x>y)return asc?1:-1;return 0;});'
        'rows.forEach(function(r){tbody.appendChild(r);});'
        'ths.forEach(function(o){o.classList.remove("asc","desc");var a=o.querySelector(".ar");if(a)a.innerHTML="&#8597;";});'
        'var th=ths.filter(function(o){return +o.getAttribute("data-col")===col;})[0];'
        'if(th){th.classList.add(asc?"asc":"desc");var a=th.querySelector(".ar");if(a)a.innerHTML=asc?"&#8593;":"&#8595;";}}'
        'ths.forEach(function(th){th.onclick=function(){var col=+th.getAttribute("data-col");'
        'var asc=!th.classList.contains("asc");apply(col,asc);'
        'try{sessionStorage.setItem("feedsort",col+","+(asc?1:0));}catch(e){}};});'
        'try{var s=sessionStorage.getItem("feedsort");if(s){var p=s.split(",");apply(+p[0],p[1]==="1");}}catch(e){}'
        '})();</script>'
        f'</section>')

def top_origenes(path=EVE, maxbytes=12_000_000, topn=5, subn=8):
    """Top de IPs origen que mas alertan, con el desglose de cada una:
    desde que puerto origen, hacia que IP destino y hacia que puerto destino."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); size = f.tell(); start = max(0, size - maxbytes)
            f.seek(start); data = f.read()
    except OSError:
        return [], 0
    lines = data.decode("utf-8", "replace").split("\n")
    if start > 0 and lines:
        lines = lines[1:]              # descarta la primera linea, casi seguro cortada
    reglas = cargar_exclusiones()
    total, combos, dst_set, dp_set = {}, {}, {}, {}
    procesados = 0
    for line in lines:
        if '"event_type":"alert"' not in line:
            continue
        get = lambda k: (_RE[k].search(line).group(1) if _RE[k].search(line) else "")
        sig = get("sig")
        if sig.startswith("ET INFO"):
            continue
        src = get("src_ip"); dst = get("dest_ip")
        sp = get("src_port"); dp = get("dest_port"); pr = get("proto")
        if not src:
            continue
        if _excluido(reglas, src, dst, int(dp) if dp else None, get("sid")):
            continue
        procesados += 1
        total[src] = total.get(src, 0) + 1
        k = (src, sp, dst, dp, pr)
        combos[k] = combos.get(k, 0) + 1
        dst_set.setdefault(src, set()).add(dst)
        dp_set.setdefault(src, set()).add(dp)
    tops = sorted(total.items(), key=lambda x: x[1], reverse=True)[:topn]
    filas = []
    for src, cnt in tops:
        sub = [(sp, dst, dp, pr, c) for (s, sp, dst, dp, pr), c in combos.items() if s == src]
        sub.sort(key=lambda x: x[4], reverse=True)
        filas.append({"src": src, "total": cnt,
                      "n_dst": len(dst_set.get(src, ())),
                      "n_dp": len(dp_set.get(src, ())),
                      "sub": sub[:subn]})
    return filas, procesados

def _top_cards_tail():
    """Respaldo: arma las tarjetas del Top con la cola en vivo (mientras no hay reporte 24h)."""
    filas, procesados = top_origenes()
    if not filas:
        return ("<div class='topwrap'><div class='tcard'><p class='muted' style='margin:0;padding:12px'>"
                "Sin ataques recientes todavia; en cuanto entre trafico apareceran aqui.</p></div></div>", procesados)
    cards = []
    for i, r in enumerate(filas, 1):
        trs = "".join(
            f"<tr><td class='mono'>{html.escape(sp or '-')}</td>"
            f"<td class='mono' style='color:#184f95'>{html.escape(dst or '-')}</td>"
            f"<td class='mono'>{html.escape(dp or '-')}</td>"
            f"<td class='mono'>{html.escape((pr or '-').upper())}</td>"
            f"<td class='num'>{c:,}</td></tr>" for sp, dst, dp, pr, c in r["sub"])
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{html.escape(r['src'])}</span>"
            f"<span class='tot'>{r['total']:,} alertas</span>"
            f"<span class='meta'>&rarr; {r['n_dst']} IP destino &middot; {r['n_dp']} puertos destino</span></div>"
            f"<div class='tablewrap'><table><thead><tr>"
            f"<th>Puerto origen</th><th>IP destino (a donde)</th>"
            f"<th class='num'>Puerto destino</th><th>Protocolo</th><th class='num'>Peticiones</th>"
            f"</tr></thead><tbody>{trs}</tbody></table></div></div>")
    return "<div class='topwrap'>" + "".join(cards) + "</div>", procesados

def top_page():
    css_rep, top_html = partes_top()
    if top_html.strip():
        # el titulo/intro ya lo pone la pestana; quitar el h2+intro internos para no duplicar
        top_html = re.sub(r'<h2>Top 5 IPs origen que mas peticionan</h2>\s*<p class="muted"[^>]*>.*?</p>',
                          '', top_html, count=1, flags=re.S)
        cuerpo, nota = top_html, "Se actualiza junto con el resumen, cada 5 min (misma ventana que los cuadros)."
    else:
        cuerpo, procesados = _top_cards_tail()
        nota = (f"Muestra reciente ({procesados:,} alertas) mientras se genera el reporte de 24h; "
                "recarga en unos minutos para el ranking completo.")
    css = (css_rep +
           "<style>" + BASE_CSS +
           "main{padding:18px 22px}h1{font-size:20px;margin:0 0 2px}.subx{margin:0 0 18px}"
           ".topwrap .tcard{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 14px;overflow:hidden}"
           ".topwrap .thd{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:11px 15px;background:#f4f4f2;border-bottom:1px solid #e7e6e2}"
           ".topwrap .rank{font-weight:800;color:#2a78d6;font-size:15px}"
           ".topwrap .ipx{font-weight:700;font-size:15px;font-family:ui-monospace,Consolas,monospace}"
           ".topwrap .tot{background:#e34948;color:#fff;font-size:12px;font-weight:700;padding:3px 9px;border-radius:20px}"
           ".topwrap .meta{color:#52514e;font-size:12px;margin-left:auto}"
           ".topwrap table{width:100%;border-collapse:collapse;font-size:13px}"
           ".topwrap table{table-layout:fixed}"
           ".topwrap thead th{text-align:center;color:#52514e;font-weight:600;padding:8px 14px;border-bottom:1px solid #eee;background:#fbfbfa}"
           ".topwrap tbody td{padding:7px 14px;border-bottom:1px solid #f2f1ee;text-align:center}"
           ".topwrap tbody tr:hover{background:#eef4fd}"
           ".topwrap .num{text-align:center;white-space:nowrap;font-variant-numeric:tabular-nums}"
           ".topwrap .mono{font-family:ui-monospace,Consolas,monospace}"
           ".topwrap .tablewrap{overflow-x:auto}"
           "@media(max-width:820px){"                          # h1/main ya los baja BASE_CSS
           ".topwrap table{min-width:640px}"                  # el .tablewrap scrollea en vez de aplastar
           ".topwrap .thd{gap:8px}.topwrap .meta{margin-left:0}"
           "}"
           "</style>")
    body = (f"<!doctype html><html lang=es><head><meta charset=utf-8>"
            f"<link rel=icon type=image/png href=/favicon.ico>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv=refresh content=60><title>Suricata</title>{css}</head><body>"
            + nav("/top") +
            f"<main><h1>Top 5 IPs origen que mas peticionan</h1>"
            f"<p class='subx'>Quien ataca mas, hacia que IP destino, desde que puerto origen y hacia que puerto destino. "
            f"{nota}</p>{cuerpo}</main></body></html>")
    return body

LOGDIR = "/var/log/suricata"
GEN = "/usr/local/bin/suricata-html-report"
CONF = "/etc/suricata-dashboard.conf"
REFRESH_SECS = 300    # regeneracion del resumen en segundo plano: cada 5 min (tiles, graficos, linea de tiempo y Top 5)
FORCE_REGEN = False   # el selector de ventana lo pone True para regenerar el resumen ya
REGEN_MIN_SECS = 60   # separacion minima entre regeneraciones FORZADAS (ver pedir_regen)

def pedir_regen():
    """Pide regenerar el resumen cuanto antes. Es solo una marca: el hilo de fondo la
    atiende como mucho una vez cada REGEN_MIN_SECS. Importa porque un quitado masivo o
    una politica que mete y saca al mismo CPE pueden pedirlo decenas de veces seguidas, y
    generar el reporte es caro: mientras corre, ese mismo hilo no hace el barrido rapido
    ni mide la salud del sensor."""
    globals()["FORCE_REGEN"] = True

def conf():
    # PROXIES: IPs de los proxies inversos de confianza, separadas por coma. SOLO desde
    #   esas IPs se hace caso a X-Forwarded-For / X-Forwarded-Proto; de cualquier otro
    #   origen esas cabeceras las pone el cliente y se ignoran (si no, la lista de IPs
    #   de confianza y el bloqueo por intentos se saltan mandando una cabecera).
    # BIND: interfaz donde escucha el panel. 0.0.0.0 = todas (compatibilidad); si lo
    #   pones detras de un proxy HTTPS, 127.0.0.1 deja de exponerlo en claro a la red.
    d = {"PORT": "5637", "USER": "admin", "PASS": "", "PROXIES": "", "BIND": "0.0.0.0"}
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); d[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return d

CFG = conf()
# proxies inversos de confianza (ver conf()). Vacio = no se hace caso a X-Forwarded-*.
PROXIES_OK = {x.strip() for x in CFG.get("PROXIES", "").split(",") if x.strip()}

# ---------------------------------------------------------------- MikroTik (cuarentena Fase B)
# Empuja IPs de CPEs infectados a una address-list del MikroTik via API. El MikroTik
# decide que hacer con esa lista (drop/limitar) con las reglas que define el operador.
# La contrasena API es un SECRETO que se USA (no se verifica): se guarda con chmod 600.
import socket as _socket, ssl as _ssl, hashlib as _hashlib
MK_CONF = "/etc/suricata-mikrotik.conf"
MK_SENT = "/var/log/suricata-cuarentena-enviados.json"       # IPs enviadas a la lista de cuarentena
MK_SENT_DNS = "/var/log/suricata-dns-enviados.json"          # IPs enviadas a la lista de DNS sospechoso
MK_SENT_GRAD = "/var/log/suricata-graduada-enviados.json"     # CPEs con corte PARCIAL
MK_LOG  = "/var/log/suricata-cuarentena.log"                 # bitacora de acciones

# Los puertos que se le cortan a un CPE en cuarentena graduada. Fuera queda todo lo que
# el abonado usa de verdad (web, streaming, juegos, videollamadas): por eso no llama a
# soporte, y por eso el corte aguanta en el tiempo en vez de revertirse en cuanto llama.
GRAD_REGLAS = [
    # a un CPE YA comprometido se le corta todo el correo, tambien el autenticado
    ("tcp", "25,465,587", "correo saliente (spam)"),
    ("tcp", "22,2222,23,2323", "SSH y Telnet (escaneo y fuerza bruta)"),
    ("tcp", "445,139", "SMB (gusanos)"),
    ("tcp", "3389,5900", "RDP y VNC (fuerza bruta)"),
    ("tcp", "7547,37215", "TR-069 e IoT (botnets)"),
]

# --- Higiene de salida: reglas para TODOS los abonados -----------------------------
# Distinto de la cuarentena graduada: esto no señala a un CPE, cambia la politica del nodo.
# Por eso aqui el correo es SOLO el 25: cortar tambien el 587/465 romperia a los clientes
# de correo legitimos, que usan envio autenticado.
GRUPOS_SALIDA = [
    ("correo", "Correo saliente sin autenticar", ["25"], "tcp",
     "Es la causa numero uno de que un ISP acabe en Spamhaus. El estandar del sector es "
     "cortar el 25 saliente y dejar el 587 y 465 (envio autenticado), que es lo que usan "
     "los clientes de correo de verdad.",
     "Tu servidor de correo tiene que quedar excluido."),
    ("admin", "Administracion remota", ["22", "2222", "23", "2323", "3389", "5900"], "tcp",
     "Escaneo y fuerza bruta contra SSH, Telnet y RDP de todo internet. Es lo que mas "
     "denuncias genera despues del spam.",
     "Si algun abonado administra servidores propios, excluilo antes."),
    ("smb", "Compartir archivos de Windows", ["445", "139"], "tcp",
     "No tiene ningun uso legitimo saliendo a internet: es como se propagan los gusanos.",
     ""),
    ("iot", "TR-069 e IoT", ["7547", "37215", "5555"], "tcp",
     "Botnets tipo Mirai buscando routers y camaras ajenos.", ""),
    ("bd", "Bases de datos ajenas", ["3306", "1433", "5432", "6379", "27017"], "tcp",
     "Ataques contra bases de datos de terceros.", ""),
]

# --- Reglas por CONDUCTA ----------------------------------------------------------
# Un escaner NO se corta con una regla por puerto: prueba muchos, y el que hoy usa el 22
# manana usa el 23. Hay que detectarlo por como se comporta -muchos puertos en poco
# tiempo, o demasiadas conexiones nuevas- y meterlo en una address-list.
#
# Estas reglas se entregan con el DROP desactivado a proposito. El P2P, algunos juegos y
# ciertas apps abren muchas conexiones y darian falso positivo: primero se mira quien cae
# en la lista durante unos dias y despues se activa el corte. Entregarlas cortando de
# entrada seria dejar sin internet a gente que no hizo nada.
GRUPOS_CONDUCTA = [
    ("escaneo", "Escaneo de puertos y barridos",
     ["Escaneo de puertos", "Escaneo saliente", "Escaneo SSH", "Escaneo Telnet",
      "Escaneo TR-069"],
     "Es lo que mas denuncias genera y lo que mete tus publicas en las listas. No se "
     "puede cortar por puerto porque el escaner los prueba todos: se detecta por "
     "conducta (muchos puertos seguidos, o demasiadas conexiones nuevas) y se manda al "
     "que lo hace a una address-list."),
    ("fuerza", "Fuerza bruta de credenciales",
     ["Fuerza bruta", "RDP/VNC"],
     "Reintentos contra SSH, RDP, FTP o SIP ajenos. Se limita el ritmo de conexiones "
     "nuevas hacia esos puertos en vez de cortarlos del todo."),
]

def reglas_conducta_texto(clave, redes=None, permitidos="suricata-salida-permitida"):
    """Las reglas de MikroTik para una conducta. Texto listo para pegar."""
    redes = redes or [str(r) for r in mis_redes()]
    origen = " ".join(f"src-address={r}" for r in redes[:1]) or "src-address=0.0.0.0/0"
    if clave == "escaneo":
        return "\n".join([
            "/ip firewall filter",
            "# 1) el que prueba muchos puertos seguidos (psd = detector de escaneo de RouterOS)",
            f'add chain=forward protocol=tcp psd=21,3s,3,1 {origen} '
            f'src-address-list=!{permitidos} action=add-src-to-address-list '
            'address-list=suricata-escaneo address-list-timeout=1d '
            'comment="Suricata: escaneo de puertos saliente"',
            "",
            "# 2) el que abre demasiadas conexiones nuevas (barrido de muchas IPs)",
            f'add chain=forward connection-state=new {origen} '
            f'src-address-list=!{permitidos} action=jump jump-target=det-barrido '
            'comment="Suricata: medir ritmo de conexiones nuevas"',
            'add chain=det-barrido limit=50,100:packet action=return '
            'comment="Suricata: ritmo normal, seguir"',
            'add chain=det-barrido action=add-src-to-address-list '
            'address-list=suricata-escaneo address-list-timeout=1h '
            'comment="Suricata: barrido (demasiadas conexiones nuevas)"',
            "",
            "# 3) el corte. DESACTIVADO: mira unos dias quien cae en la lista",
            "#    (/ip firewall address-list print where list=suricata-escaneo)",
            "#    y cuando estes seguro, ponlo en disabled=no",
            'add chain=forward src-address-list=suricata-escaneo action=drop disabled=yes '
            'comment="Suricata: cortar a los que escanean"',
        ])
    return "\n".join([
        "/ip firewall filter",
        "# limitar el ritmo de intentos hacia puertos de acceso remoto y correo",
        f'add chain=forward connection-state=new protocol=tcp '
        f'dst-port=22,23,21,3389,5900,5060,25 {origen} '
        f'src-address-list=!{permitidos} action=jump jump-target=det-fuerza '
        'comment="Suricata: medir intentos de credenciales"',
        'add chain=det-fuerza limit=10,20:packet action=return '
        'comment="Suricata: ritmo normal, seguir"',
        'add chain=det-fuerza action=add-src-to-address-list '
        'address-list=suricata-fuerza-bruta address-list-timeout=1h '
        'comment="Suricata: fuerza bruta saliente"',
        "",
        "# el corte, DESACTIVADO hasta que revises la lista",
        'add chain=forward src-address-list=suricata-fuerza-bruta action=drop disabled=yes '
        'comment="Suricata: cortar la fuerza bruta saliente"',
    ])

# --- Trafico que NO es abuso pero igual se quiere controlar ------------------------
# El P2P no hace que te baneen una IP: por eso no cuenta como abuso saliente. Pero se
# come la banda y suele ser lo que mas alertas genera, asi que hay que poder VERLO y
# decidir aparte.
GRUPOS_CONTROL = [
    ("p2p", "BitTorrent y P2P",
     ["BitTorrent / P2P"],
     ["6881", "6882", "6883", "6884", "6885", "6886", "6887", "6888", "6889",
      "6969", "51413"],
     "No ensucia tus IPs publicas, asi que no cuenta como abuso. Pero suele ser el "
     "grueso del trafico y de las alertas."),
]

def analisis_control(rid=None, tope=12):
    """Que CPEs hacen P2P y cuanto. Sale de las categorias de firma, que SI lo cuentan."""
    cpes = _cpes_de_reporte(rid)
    out = []
    for clave, titulo, cats, puertos, porque in GRUPOS_CONTROL:
        quienes = []
        total = 0
        for c in cpes:
            suyo = sum(int(v) for cat, v in (c.get("cats_top") or {}).items() if cat in cats)
            if suyo:
                total += suyo
                quienes.append((clave_cpe(c.get("ip", ""), c.get("router", "")), suyo,
                                c.get("riesgo", 0)))
        if not total:
            continue
        quienes.sort(key=lambda x: x[1], reverse=True)
        out.append({"clave": clave, "titulo": titulo, "alertas": total,
                    "cpes": len(quienes), "top": quienes[:tope],
                    "puertos": puertos, "porque": porque})
    return out

def reglas_p2p_texto(puertos, redes=None, permitidos="suricata-salida-permitida"):
    """Reglas para el P2P, con lo que de verdad funciona y lo que no.

    Honestidad por delante: bloquear puertos conocidos caza al cliente perezoso, pero uno
    con cifrado y puertos aleatorios se escapa. Lo que si le duele a cualquier cliente de
    torrent es el tope de conexiones simultaneas, porque abre cientos."""
    redes = redes or [str(r) for r in mis_redes()]
    origen = f"src-address={redes[0]}" if redes else "src-address=0.0.0.0/0"
    pts = ",".join(puertos)
    return "\n".join([
        "/ip firewall filter",
        "# 1) puertos clasicos de BitTorrent. Caza al cliente por defecto; uno configurado",
        "#    a mano con puerto aleatorio y cifrado NO cae aqui.",
        f'add chain=forward protocol=tcp dst-port={pts} {origen} '
        f'src-address-list=!{permitidos} action=drop comment="Suricata: P2P (TCP)"',
        f'add chain=forward protocol=udp dst-port={pts} {origen} '
        f'src-address-list=!{permitidos} action=drop comment="Suricata: P2P (UDP/DHT)"',
        "",
        "# 2) esto es lo que de verdad le duele: un cliente de torrent abre CIENTOS de",
        "#    conexiones simultaneas. Un tope alto no molesta a quien navega.",
        f'add chain=forward protocol=tcp connection-state=new {origen} '
        f'src-address-list=!{permitidos} connection-limit=150,32 action=drop '
        'comment="Suricata: tope de conexiones simultaneas por abonado"',
        "",
        "# NOTA: bloquear P2P del todo es una pelea perdida (cifrado, puertos aleatorios,",
        "# DHT). Si lo que te molesta es la banda y no el trafico en si, sale mucho mejor",
        "# encolarlo con /queue que intentar cortarlo.",
    ])

def analisis_conducta(rid=None):
    """Cuanto abuso encaja con cada conducta, segun las categorias de firma reales."""
    cpes = _cpes_de_reporte(rid)
    total = 0
    for c in cpes:
        total += sum(int(v) for v in (c.get("cats_top") or {}).values())
    grupos = []
    for clave, titulo, cats, porque in GRUPOS_CONDUCTA:
        n = 0; quienes = set(); vistas = {}
        for c in cpes:
            suyo = 0
            for cat, v in (c.get("cats_top") or {}).items():
                if cat in cats:
                    suyo += int(v); vistas[cat] = vistas.get(cat, 0) + int(v)
            if suyo:
                n += suyo
                quienes.add(clave_cpe(c.get("ip", ""), c.get("router", "")))
        if not n:
            continue
        grupos.append({"clave": clave, "titulo": titulo, "alertas": n, "cpes": len(quienes),
                       "pct": (n * 100.0 / total) if total else 0.0,
                       "porque": porque,
                       "cats": sorted(vistas.items(), key=lambda kv: kv[1], reverse=True)})
    grupos.sort(key=lambda g: g["alertas"], reverse=True)
    return grupos

_CPES_CACHE = {"sello": None, "datos": []}

def _cpes_de_reporte(rid=None):
    """CPEs del reporte actual con su desglose de puertos, opcionalmente de un nodo.

    Con cache por mtime del archivo: la pagina de Abuso saliente lo pedia hasta SIETE
    veces por render (analisis de salida, de conducta, de control, y otra vez para saber
    si habia algo que mostrar), y cada una releia y reparseaba el JSON entero."""
    f = f"{LOGDIR}/cuarentena.json"
    try:
        st = os.stat(f)
    except OSError:
        return []
    # nanosegundos + tamaño: con getmtime a secas, un archivo reescrito dentro del mismo
    # tick se servia de cache VIEJA sin que nada lo delatara
    sello = (st.st_mtime_ns, st.st_size)
    if sello != _CPES_CACHE["sello"]:
        try:
            cq = json.load(open(f, encoding="utf-8"))
        except (OSError, ValueError):
            return []
        vistos = {}
        for k in ("top_riesgo", "candidatos", "dns_candidatos"):
            for c in cq.get(k, []):
                clave = clave_cpe(c.get("ip", ""), c.get("router", ""))
                if clave not in vistos or (c.get("puertos_top")
                                           and not vistos[clave].get("puertos_top")):
                    vistos[clave] = c
        _CPES_CACHE["datos"] = list(vistos.values())
        _CPES_CACHE["sello"] = sello
    if rid is None:
        return _CPES_CACHE["datos"]
    return [c for c in _CPES_CACHE["datos"] if (c.get("router") or "") == rid]

def analisis_salida(rid=None):
    """Cuanto abuso mataria cada regla de salida, con los datos REALES del sensor.

    Devuelve (total_alertas, total_cpes, [grupos]). Cada grupo dice cuantas alertas y
    cuantos CPEs cubre: sin esos dos numeros, proponer una regla es adivinar."""
    cpes = _cpes_de_reporte(rid)
    total = 0
    for c in cpes:
        total += sum(int(v) for v in (c.get("puertos_top") or {}).values())
    grupos = []
    for clave, titulo, puertos, proto, porque, cuidado in GRUPOS_SALIDA:
        n = 0; quienes = set(); detalle = {}
        for c in cpes:
            suyo = 0
            for pp, v in (c.get("puertos_top") or {}).items():
                num = str(pp).split("/", 1)[0]
                if num in puertos:
                    suyo += int(v)
                    detalle[num] = detalle.get(num, 0) + int(v)
            if suyo:
                n += suyo
                quienes.add(clave_cpe(c.get("ip", ""), c.get("router", "")))
        if not n:
            continue
        grupos.append({"clave": clave, "titulo": titulo, "proto": proto,
                       "puertos": [p for p in puertos if p in detalle],
                       "alertas": n, "cpes": len(quienes),
                       "pct": (n * 100.0 / total) if total else 0.0,
                       "porque": porque, "cuidado": cuidado, "detalle": detalle})
    grupos.sort(key=lambda g: g["alertas"], reverse=True)
    return total, len({clave_cpe(c.get("ip", ""), c.get("router", "")) for c in cpes}), grupos

def regla_salida(grupo, redes=None, permitidos="suricata-salida-permitida"):
    """La regla de MikroTik para un grupo, con TUS redes de abonado como origen."""
    redes = redes or [str(r) for r in mis_redes()]
    puertos = ",".join(grupo["puertos"])
    out = []
    for red in (redes or ["0.0.0.0/0"]):
        out.append(f'add chain=forward src-address={red} src-address-list=!{permitidos} '
                   f'protocol={grupo["proto"]} dst-port={puertos} action=drop '
                   f'comment="Suricata salida: {grupo["titulo"]}"')
    return "\n".join(out)

def reglas_salida_texto(grupos, redes=None):
    if not grupos:
        return ""
    cab = ["# Excepciones (servidor de correo propio, abonados con servidores, etc.):",
           "/ip firewall address-list",
           'add list=suricata-salida-permitida address=192.0.2.10 comment="ejemplo: cambialo"',
           "",
           "/ip firewall filter"]
    return "\n".join(cab + [regla_salida(g, redes) for g in grupos])

def grad_reglas_texto(lista):
    """Las reglas que hay que pegar en el MikroTik. Sin ellas la address-list no corta
    NADA: es el mismo fallo silencioso que tener la lista de cuarentena sin su drop."""
    out = ["/ip firewall filter"]
    for proto, puertos, por in GRAD_REGLAS:
        out.append(f'add chain=forward src-address-list={lista} protocol={proto} '
                   f'dst-port={puertos} action=drop comment="Suricata graduada: {por}"')
    return "\n".join(out)

def cargar_mk():
    # CERT_FP: huella SHA256 del certificado del router, fijada en la primera conexion
    # TLS (TOFU). Mientras no cambie, nadie puede colarse en medio; si cambia, la
    # conexion se rechaza y hay que borrar la clave a mano tras comprobar por que.
    # Forma de siempre (ajustes globales + UN router), para todo el codigo que aun no
    # distingue nodo. El router es el de por defecto; con multi-nodo, cada camino que
    # ya sabe de routers usa cargar_mk_de(router) en su lugar.
    return cargar_mk_de(router_defecto())

def cargar_mk_de(r):
    """Los ajustes tal y como los espera el codigo: politica global + este router."""
    d = {"HOST": "", "PORT": "8728", "TLS": "0", "USER": "", "PASS": "",
         "LIST": "suricata-cuarentena", "TTL": "1h",
         "LIST_DNS": "suricata-dns-sospechoso", "TTL_DNS": "1d",
         "LIST_GRAD": "suricata-graduada", "TTL_GRAD": "1d",
         "LIST_DST": "suricata-destinos-malos", "TTL_DST": "7d",
         "AUTO_MANTENER": "0", "ENABLED": "0", "CERT_FP": "",
         "POL_AUTO": "0", "POL_BAJO": "nada", "POL_MEDIO": "nada", "POL_ALTO": "nada"}
    d.update(_mk_globales())          # AUTO_MANTENER y POL_* son de toda la instalacion
    for k in ("HOST", "PORT", "TLS", "USER", "PASS", "LIST", "TTL",
              "LIST_DNS", "TTL_DNS", "LIST_GRAD", "TTL_GRAD", "LIST_DST", "TTL_DST",
              "CERT_FP", "ENABLED"):
        if k in (r or {}):
            d[k] = (r or {})[k]
    d["ROUTER_ID"] = (r or {}).get("id", "")
    d["ROUTER_NOMBRE"] = (r or {}).get("nombre", "") or d.get("HOST", "")
    return d

# ---------------------------------------------------------------------------------
# Varios MikroTik (multi-nodo)
# ---------------------------------------------------------------------------------
# Un sensor puede recibir el espejo de varios routers. Cada uno tiene su conexion, sus
# address-lists y SUS abonados, y ademas dos nodos suelen repetir el mismo rango privado
# (10.0.0.x en los dos), asi que una IP sola no identifica a nadie: hace falta el par
# (router, IP). La interfaz por la que entra el espejo de cada router es lo que permite
# saber de cual vino cada alerta (Suricata lo registra como in_iface).
#
# Los ajustes de POLITICA son globales (bandas de riesgo) y siguen en MK_CONF; lo que es
# por router vive aqui. Si este archivo no existe todavia se construye a partir del
# MK_CONF de siempre, asi que una instalacion existente sigue funcionando igual.
ROUTERS_CONF = "/etc/suricata-routers.json"
IFACE_BASE = "ids-mon"       # el primer router conserva el nombre de siempre
CAMPOS_ROUTER = ("id", "nombre", "iface", "HOST", "PORT", "TLS", "USER", "PASS",
                 "LIST", "TTL", "LIST_DNS", "TTL_DNS", "LIST_GRAD", "TTL_GRAD",
                 "LIST_DST", "TTL_DST", "CERT_FP", "ENABLED")

def _router_vacio(idx=1):
    return {"id": "r%d" % idx, "nombre": "", "iface": IFACE_BASE if idx == 1 else "%s%d" % (IFACE_BASE, idx),
            "HOST": "", "PORT": "8728", "TLS": "0", "USER": "", "PASS": "",
            "LIST": "suricata-cuarentena", "TTL": "1h",
            "LIST_DNS": "suricata-dns-sospechoso", "TTL_DNS": "1d",
            "LIST_GRAD": "suricata-graduada", "TTL_GRAD": "1d",
            "LIST_DST": "suricata-destinos-malos", "TTL_DST": "7d",
            "CERT_FP": "", "ENABLED": "0"}

def _mk_globales():
    """Lee MK_CONF crudo (conexion antigua + ajustes globales de politica)."""
    d = {"AUTO_MANTENER": "0", "ENABLED": "0", "POL_AUTO": "0",
         "POL_BAJO": "nada", "POL_MEDIO": "nada", "POL_ALTO": "nada"}
    try:
        for l in open(MK_CONF, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); d[k.strip()] = v.strip()
    except OSError:
        pass
    return d

def cargar_routers():
    """Lista de routers configurados. Si aun no hay archivo propio, se migra el unico
    router del MK_CONF de siempre (sin tocar nada en disco: la migracion se persiste
    la primera vez que se guarde)."""
    try:
        d = json.load(open(ROUTERS_CONF, encoding="utf-8"))
        lst = d.get("routers") if isinstance(d, dict) else d
        if isinstance(lst, list) and lst:
            salida = []
            for i, r in enumerate(lst, 1):
                base = _router_vacio(i)
                if isinstance(r, dict):
                    base.update({k: v for k, v in r.items() if k in CAMPOS_ROUTER})
                salida.append(base)
            return salida
    except Exception:
        pass
    g = _mk_globales()                      # migracion desde la configuracion de un solo router
    uno = _router_vacio(1)
    for k in ("HOST", "PORT", "TLS", "USER", "PASS", "LIST", "TTL",
              "LIST_DNS", "TTL_DNS", "LIST_GRAD", "TTL_GRAD", "LIST_DST", "TTL_DST",
              "CERT_FP", "ENABLED"):
        if g.get(k, "") != "":
            uno[k] = g[k]
    uno["nombre"] = uno["HOST"] or "MikroTik"
    return [uno]

def guardar_routers(lst):
    """Guarda la lista con permisos 600: lleva las claves de la API."""
    limpia = []
    for i, r in enumerate(lst, 1):
        base = _router_vacio(i)
        base.update({k: v for k, v in (r or {}).items() if k in CAMPOS_ROUTER})
        if not base.get("id"):
            base["id"] = "r%d" % i
        limpia.append(base)
    tmp = ROUTERS_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"routers": limpia}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, ROUTERS_CONF)
    try: os.chmod(ROUTERS_CONF, 0o600)
    except OSError: pass
    publicar_routers_map(limpia)
    return limpia

ROUTERS_MAP = "/var/log/suricata-routers-map.json"

def publicar_routers_map(lst=None):
    """Publica id, nombre e interfaz de cada router para que lo lea el generador del
    reporte. Va aparte a proposito: el archivo de routers lleva las CLAVES de la API y
    el generador no tiene por que verlas."""
    try:
        lst = lst if lst is not None else cargar_routers()
        datos = [{"id": r.get("id", ""), "nombre": r.get("nombre", "") or r.get("HOST", ""),
                  "iface": r.get("iface", "")} for r in lst]
        tmp = ROUTERS_MAP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False)
        os.replace(tmp, ROUTERS_MAP)
    except Exception:
        pass

def router_por_id(rid):
    for r in cargar_routers():
        if r.get("id") == rid:
            return r
    return None

def router_por_iface(iface):
    """De que router vino una alerta, segun la interfaz por la que entro su espejo."""
    if iface:
        for r in cargar_routers():
            if r.get("iface") == iface:
                return r
    return None

def router_defecto():
    """El primero habilitado; si ninguno lo esta, el primero. Es el que usan los caminos
    que todavia no distinguen router (compatibilidad mientras dure la migracion)."""
    lst = cargar_routers()
    for r in lst:
        if r.get("ENABLED") == "1":
            return r
    return lst[0] if lst else _router_vacio(1)

def guardar_mk(d):
    orden = ["HOST", "PORT", "TLS", "USER", "PASS", "LIST", "TTL", "LIST_DNS", "TTL_DNS",
             "AUTO_MANTENER", "ENABLED", "CERT_FP", "POL_AUTO", "POL_BAJO", "POL_MEDIO", "POL_ALTO"]
    txt = ("# Conexion API al MikroTik para la cuarentena. La clave se usa para autenticar\n"
           "# (no se puede hashear). Archivo con permisos 600.\n"
           + "".join(f"{k}={d.get(k,'')}\n" for k in orden))
    tmp = MK_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(txt)
    os.replace(tmp, MK_CONF)
    try: os.chmod(MK_CONF, 0o600)
    except OSError: pass

def mk_configurado():
    d = cargar_mk()
    return bool(d.get("HOST") and d.get("USER") and d.get("PASS"))

def mk_listo(d):
    """Si ESE router (no el de por defecto) esta configurado y habilitado para enviar.
    Con varios nodos, uno puede estar en dry-run y otro enviando."""
    return bool(d.get("HOST") and d.get("USER") and d.get("PASS") and d.get("ENABLED") == "1")

# --- cliente minimo de la API de RouterOS (v6.43+ y v7), stdlib pura ---
def _mk_len(n):
    if n < 0x80: return bytes([n])
    if n < 0x4000: return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000: return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000: return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xF0" + n.to_bytes(4, "big")

def _mk_word(sock, w):
    b = w.encode("utf-8")
    sock.sendall(_mk_len(len(b)) + b)

def _mk_send(sock, words):
    for w in words:
        _mk_word(sock, w)
    sock.sendall(b"\x00")

def _mk_rlen(sock):
    c = sock.recv(1)
    if not c: raise IOError("conexion cerrada")
    c = c[0]
    if c & 0x80 == 0: return c
    if c & 0xC0 == 0x80: return ((c & 0x3F) << 8) + sock.recv(1)[0]
    if c & 0xE0 == 0xC0:
        b = sock.recv(2); return ((c & 0x1F) << 16) + (b[0] << 8) + b[1]
    if c & 0xF0 == 0xE0:
        b = sock.recv(3); return ((c & 0x0F) << 24) + (b[0] << 16) + (b[1] << 8) + b[2]
    b = sock.recv(4); return int.from_bytes(b, "big")

def _mk_read(sock):
    """Lee una sentencia (lista de palabras hasta la palabra vacia)."""
    words = []
    while True:
        n = _mk_rlen(sock)
        if n == 0:
            return words
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk: raise IOError("conexion cerrada")
            data += chunk
        words.append(data.decode("utf-8", "replace"))

def _mk_reply(sock):
    """Junta sentencias hasta !done/!fatal. Devuelve (ok, sentencias, mensaje_error)."""
    frases, err = [], ""
    while True:
        w = _mk_read(sock)
        if not w:
            continue
        frases.append(w)
        tipo = w[0]
        if tipo == "!trap" or tipo == "!fatal":
            for a in w[1:]:
                if a.startswith("=message="):
                    err = a[len("=message="):]
        if tipo == "!done":
            return (err == "", frases, err)
        if tipo == "!fatal":
            return (False, frases, err or "conexion terminada")

def _mk_tls_wrap(host, port, timeout):
    """Envuelve en TLS probando cifrados en orden. RouterOS api-ssl SIN certificado usa
    cifrados ANONIMOS (ADH) -> hay que habilitarlos con @SECLEVEL=0 (Python los desactiva
    por defecto). Con certificado usa los normales. Se prueban ambos para no exigir cert."""
    ultimo = None
    for ciphers in ("ADH:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", None):
        try:
            raw = _socket.create_connection((host, port), timeout=timeout)
        except Exception as e:
            raise IOError(str(e))
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
        try: ctx.minimum_version = _ssl.TLSVersion.TLSv1
        except Exception: pass
        if ciphers:
            try: ctx.set_ciphers(ciphers)
            except Exception: pass
        try:
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception as e:
            ultimo = e
            try: raw.close()
            except Exception: pass
    raise IOError(f"TLS handshake fallo ({ultimo})")

def mk_conectar(d, timeout=6):
    """Abre el socket y hace login. Devuelve el socket o lanza excepcion."""
    host = d["HOST"]; port = int(d.get("PORT") or (8729 if d.get("TLS") == "1" else 8728))
    if d.get("TLS") == "1":
        sock = _mk_tls_wrap(host, port, timeout)
        # RouterOS trae un certificado autofirmado: no hay CA que valide la cadena, asi
        # que se fija su huella la primera vez (TOFU) y despues tiene que coincidir. Sin
        # esto cualquiera en medio acepta el handshake y se lleva la clave del router,
        # que es justo lo que se manda en el /login de aqui abajo.
        fp = _hashlib.sha256(sock.getpeercert(binary_form=True) or b"").hexdigest()
        esperada = (d.get("CERT_FP") or "").strip().lower().replace(":", "")
        if esperada and fp != esperada:
            sock.close()
            raise RuntimeError(
                "El certificado del MikroTik no coincide con el fijado (esperado "
                f"{esperada[:16]}..., recibido {fp[:16]}...). Puede ser un cambio "
                "legitimo del router o alguien en medio: comprueba el router y, si es "
                f"correcto, borra la linea CERT_FP de {MK_CONF}.")
        if not esperada:
            d["CERT_FP"] = fp
            try: guardar_mk(d)
            except OSError: pass
    else:
        sock = _socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    # login moderno (6.43+/v7): usuario y clave directos
    _mk_send(sock, ["/login", f"=name={d['USER']}", f"=password={d['PASS']}"])
    ok, frases, err = _mk_reply(sock)
    if ok:
        # login viejo (<6.43): !done trae =ret= (reto) -> responder con MD5
        reto = ""
        for f in frases:
            for a in f:
                if a.startswith("=ret="):
                    reto = a[len("=ret="):]
        if reto:
            md5 = _hashlib.md5(b"\x00" + d["PASS"].encode() + bytes.fromhex(reto)).hexdigest()
            _mk_send(sock, ["/login", f"=name={d['USER']}", f"=response=00{md5}"])
            ok, frases, err = _mk_reply(sock)
    if not ok:
        try: sock.close()
        except Exception: pass
        raise IOError(err or "login rechazado")
    return sock

def mk_probar():
    d = cargar_mk()
    if not (d.get("HOST") and d.get("USER") and d.get("PASS")):
        return (False, "Falta host, usuario o clave.")
    try:
        s = mk_conectar(d)
        _mk_send(s, ["/system/identity/print"])
        ok, frases, err = _mk_reply(s)
        nombre = ""
        for f in frases:
            for a in f:
                if a.startswith("=name="):
                    nombre = a[len("=name="):]
        s.close()
        return (True, f"Conexion OK con '{nombre or d['HOST']}'.")
    except Exception as e:
        return (False, f"No conecto: {e}")

def mk_add(ip, comment="", lista=None, ttl=None, router=None):
    # router=None -> el de por defecto, para todo el codigo que aun no distingue nodo
    d = cargar_mk_de(router) if router else cargar_mk()
    lst = lista or d.get("LIST", "suricata-cuarentena")
    tt = ttl if ttl is not None else d.get("TTL")
    s = mk_conectar(d)
    try:
        words = ["/ip/firewall/address-list/add", f"=list={lst}", f"=address={ip}"]
        if tt:
            words.append(f"=timeout={tt}")
        if comment:
            words.append(f"=comment={comment[:120]}")
        _mk_send(s, words)
        ok, frases, err = _mk_reply(s)
        if not ok and "already have such entry" in (err or "").lower():
            return (True, "ya estaba en la lista")   # add idempotente: ya estaba -> ok
        return (ok, err)
    finally:
        try: s.close()
        except Exception: pass

def mk_remove(ip, lista=None, router=None):
    """Quita TODAS las entradas de esa IP en la lista (busca .id y las borra)."""
    d = cargar_mk_de(router) if router else cargar_mk()
    lst = lista or d.get("LIST", "suricata-cuarentena")
    s = mk_conectar(d)
    try:
        _mk_send(s, ["/ip/firewall/address-list/print", "=.proplist=.id",
                     f"?list={lst}", f"?address={ip}"])
        ok, frases, err = _mk_reply(s)
        ids = [a[len("=.id="):] for f in frases if f and f[0] == "!re" for a in f if a.startswith("=.id=")]
        for _id in ids:
            _mk_send(s, ["/ip/firewall/address-list/remove", f"=.id={_id}"])
            _mk_reply(s)
        return (True, f"{len(ids)} entrada(s) quitada(s)")
    finally:
        try: s.close()
        except Exception: pass

# Un solo cerrojo para el registro de enviados. Lo tocan a la vez los hilos de las
# peticiones HTTP y el hilo de fondo (barrido rapido, reconciliador, politicas). Sin el,
# dos escrituras solapadas sobre el mismo temporal pueden publicar un JSON a medias, y
# como cargar_enviados() se traga cualquier error devolviendo {}, se perderia el registro
# ENTERO en silencio: los CPEs seguirian bloqueados en el router pero el panel ya no los
# veria (ni los liberaria).
_ENV_LOCK = threading.RLock()

def cargar_enviados(path=MK_SENT):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return {}

def quitar_enviados(ips, path=MK_SENT):
    """Saca IPs del registro releyendolo DENTRO del cerrojo. Importa porque entre que se
    decide quitar y se guarda pueden pasar minutos hablando con el router: guardar una
    foto vieja borraria lo que otro hilo anoto mientras tanto (p.ej. un CPE que el barrido
    rapido acaba de mandar a cuarentena), dejandolo bloqueado y fuera del panel."""
    quitadas = []
    with _ENV_LOCK:
        env = cargar_enviados(path)
        for ip in ips:
            if env.pop(ip, None) is not None:
                quitadas.append(ip)
        if quitadas:
            guardar_enviados(env, path)
    return quitadas

def guardar_enviados(d, path=MK_SENT):
    # El Top del resumen es una FOTO que se regenera cada 5 min y lee este archivo para
    # marcar "En cuarentena". Si cambia QUIEN esta en la lista y no se regenera, el Top
    # sigue marcando a un CPE que ya se quito (o no marca al que acaba de entrar).
    # El regen se fuerza aqui, el unico punto por el que pasan TODOS los cambios: hacerlo
    # ruta por ruta ya fallo (enviar lo hacia, quitar no).
    # Solo cuenta el alta/baja de IPs; el refresco de metadatos (last_eval/sigue) ocurre
    # en cada ciclo y regenerar por eso anularia la cache de 5 min.
    # El temporal lleva pid+hilo: con uno compartido, dos escrituras solapadas (una
    # peticion HTTP y el hilo de fondo) se pisan y pueden publicar un JSON a medias;
    # cargar_enviados() devolveria {} y se perderia el registro entero en silencio.
    tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
    with _ENV_LOCK:
        antes = set(cargar_enviados(path).keys())
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, path)
        except OSError:
            try: os.unlink(tmp)
            except OSError: pass
            return
    if antes != set(d.keys()):
        pedir_regen()

BITACORA_LOG = "/var/log/suricata-bitacora.log"   # auditoria: quien hizo que y cuando

def bitacora(accion, detalle="", quien=None, ip=None):
    """Registra una accion en la bitacora auditable (una linea por accion)."""
    q = quien if quien is not None else getattr(CTX, "user", "?") or "?"
    ipx = ip if ip is not None else (getattr(CTX, "ip", "") or "")
    try:
        with open(BITACORA_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{q}\t{ipx}\t{accion}\t{detalle}\n")
    except OSError:
        pass

# Acciones por dia (cuantos CPEs se pusieron en cuarentena y cuantos se liberaron).
# Va en un archivo PROPIO del panel: las metricas de deteccion las escribe el generador y
# dos procesos editando el mismo archivo se pisarian.
ACCIONES_FILE = "/var/log/suricata-acciones.json"
ACCIONES_DIAS = 400
_ACC_LOCK = threading.RLock()

def cargar_acciones():
    try:
        d = json.load(open(ACCIONES_FILE, encoding="utf-8"))
        return d.get("dias") or {}
    except (OSError, ValueError, AttributeError):
        return {}

def contar_accion(accion):
    """Suma 1 a esa accion en el dia de hoy. El log de cuarentena se poda a los 15 dias;
    esto es lo que permite decir dentro de seis meses cuantos CPEs se limpiaron."""
    hoy = time.strftime("%Y-%m-%d")
    try:
        with _ACC_LOCK:
            dias = cargar_acciones()
            dia = dias.get(hoy)
            if not isinstance(dia, dict):
                dia = {}
            dia[accion] = int(dia.get(accion, 0)) + 1
            dias[hoy] = dia
            lim = time.strftime("%Y-%m-%d", time.localtime(time.time() - ACCIONES_DIAS * 86400))
            dias = {k: v for k, v in dias.items() if k >= lim}
            tmp = "%s.%d.tmp" % (ACCIONES_FILE, os.getpid())
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"dias": dias}, f)
            os.replace(tmp, ACCIONES_FILE)
    except OSError:
        pass

def mk_log(accion, ip, quien, detalle=""):
    try:
        with open(MK_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {accion} {ip} por={quien} {detalle}\n")
    except OSError:
        pass
    contar_accion(accion)
    bitacora(accion, f"{ip} {detalle}".strip(), quien=quien)   # tambien a la bitacora general

def _ttl_efectivo(m, ttl_key):
    """Con auto-mantener, las entradas van SIN TTL (permanentes) y las libera el
    reconciliador cuando el CPE deja de atacar. Sin auto, se usa el TTL configurado."""
    return "" if m.get("AUTO_MANTENER") == "1" else m.get(ttl_key, "")

def reconciliar_cuarentena():
    """Mantiene la cuarentena: un CPE sigue en la lista mientras siga siendo candidato
    (sigue atacando); cuando deja de aparecer, se libera solo. Corre en segundo plano.
    Solo actua con MikroTik habilitado y AUTO_MANTENER activo."""
    m = cargar_mk()
    if not (mk_configurado() and m.get("ENABLED") == "1" and m.get("AUTO_MANTENER") == "1"):
        return
    try:
        data = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
    except Exception:
        return
    for cand_key, sent_path, list_key in (("candidatos", MK_SENT, "LIST"),
                                          ("dns_candidatos", MK_SENT_DNS, "LIST_DNS")):
        # El registro va por identidad (router, IP); los candidatos traen la IP y su nodo
        # por separado. Comparar IP contra identidad daba "ya no ataca" a TODOS los CPEs
        # de un sensor con varios routers.
        activas = {clave_cpe(c.get("ip", ""), c.get("router", "")) for c in data.get(cand_key, [])}
        env = cargar_enviados(sent_path); cambiado = False
        for k in list(env.keys()):
            if env[k].get("manual") or env[k].get("pol"):
                continue                       # manual o por politica -> los gestiona otro, no el auto
            if k in activas:
                continue                       # sigue atacando -> se queda (entrada permanente)
            r = router_de_clave(k); lst = cargar_mk_de(r).get(list_key, "")
            if not lst:
                continue
            try:
                mk_remove(ip_de(k), lista=lst, router=r)   # dejo de atacar -> liberar
            except Exception:
                continue                       # si el router no responde, reintenta el proximo ciclo
            env.pop(k, None); cambiado = True
            mk_log("AUTO-LIBERADO", ip_de(k), "auto", f"lista={lst} (dejo de atacar)" + _suf_nodo(k))
        if cambiado:
            guardar_enviados(env, sent_path)

def mk_lista_en_uso(lista, router=None):
    """True si alguna regla del firewall referencia esa address-list.

    Una address-list sin regla que la use no bloquea NADA: el panel diria "enviado" y el
    CPE seguiria atacando tan tranquilo. Es el fallo silencioso mas facil de cometer al
    montar esto, asi que se comprueba y se avisa."""
    d = cargar_mk_de(router) if router else cargar_mk()
    s_ = mk_conectar(d)
    try:
        _mk_send(s_, ["/ip/firewall/filter/print", "=.proplist=src-address-list"])
        ok, frases, err = _mk_reply(s_)
        for f in frases:
            if f and f[0] == "!re":
                for a in f:
                    if a.startswith("=src-address-list=") and a.split("=", 2)[2] == lista:
                        return True
        return False
    finally:
        try: s_.close()
        except OSError: pass

def _a_cidr(txt):
    """Normaliza lo que devuelve el router a algo consultable.

    Acepta "190.0.2.7/29" (se queda con la RED: una sola consulta cubre el pool),
    "190.0.2.7" y rangos "190.0.2.10-190.0.2.20" (se resumen a los CIDR que los cubren).
    Descarta lo privado, que es justo lo que NO hay que mandar a ningun sitio."""
    txt = (txt or "").strip()
    salida = []
    try:
        if "-" in txt:
            a, b = txt.split("-", 1)
            for red in ipaddress.summarize_address_range(
                    ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())):
                if red.is_global:
                    salida.append(str(red))
        elif "/" in txt:
            red = ipaddress.ip_network(txt, strict=False)
            if red.is_global:
                salida.append(str(red) if red.prefixlen <= 30 else str(red.network_address))
        else:
            ip = ipaddress.ip_address(txt)
            if ip.is_global:
                salida.append(str(ip))
    except ValueError:
        return []
    return salida

def mk_publicas_detectadas(router=None):
    """Las IPs publicas de salida segun el propio MikroTik.

    Dos fuentes: las direcciones configuradas en sus interfaces (de ahi sale el
    masquerade) y el to-addresses de las reglas de src-nat (de ahi salen los pools)."""
    d = cargar_mk_de(router) if router else cargar_mk()
    s_ = mk_conectar(d)
    encontradas = []
    try:
        for cmd, campo in (("/ip/address/print", "=address="),
                           ("/ip/firewall/nat/print", "=to-addresses=")):
            try:
                _mk_send(s_, [cmd, "=.proplist=" + campo.strip("=")])
                _ok, frases, _err = _mk_reply(s_)
            except Exception:
                continue
            for f in frases:
                if not (f and f[0] == "!re"):
                    continue
                for a in f:
                    if a.startswith(campo):
                        for c in _a_cidr(a[len(campo):]):
                            if c not in encontradas:
                                encontradas.append(c)
    finally:
        try: s_.close()
        except OSError: pass
    return sorted(encontradas)

# ---------------------------------------------------------------------------------
# Bloqueo en el BORDE: los que nos atacan desde internet
# ---------------------------------------------------------------------------------
ENTRANTES_FILE = "/var/log/suricata-entrantes.json"
BL_LISTA = "suricata-atacantes"
BL_MIN_ALERTAS = 20        # por debajo de esto es ruido de fondo de internet
BL_MIN_DESTINOS = 3        # que golpee a varios: uno solo puede ser un falso positivo
BL_TOPE = 20000            # cada entrada ocupa RAM en el router: no se manda una barbaridad

_REP_CACHE = {"mtime": 0, "ips": {}}
_REP_MAX = 300000          # tope duro: el archivo de feeds puede ser enorme

def rep_fuente(ip):
    """De que feed viene una IP, si es que viene de alguno. Solo IPs exactas: los CIDR
    los resuelve el generador, aqui solo hace falta una pista de confianza."""
    f = os.path.join(os.path.dirname(FEEDS_META), "reputation.lst")
    try:
        mt = os.path.getmtime(f)
    except OSError:
        return ""
    if mt != _REP_CACHE["mtime"]:
        ips = {}
        try:
            with open(f, encoding="utf-8") as fh:
                for n, linea in enumerate(fh):
                    if n >= _REP_MAX:
                        break
                    ind, _tab, fuente = linea.strip().partition("	")
                    if ind and "/" not in ind:
                        ips[ind] = fuente or "feed"
        except OSError:
            return ""
        _REP_CACHE["ips"] = ips
        _REP_CACHE["mtime"] = mt
    return _REP_CACHE["ips"].get(ip, "")

_REP_CAT_CACHE = {"mtime": 0, "cats": {}}

def rep_categoria(ip):
    """Que clase de infraestructura es esa IP segun el feed que la fichó.

    Devuelve la categoria ("c2-activo", "atacante-observado"...) o "". Importa la
    diferencia: hablar con un C2 ACTIVO es prueba de infeccion; hablar con una IP que
    alguna vez escaneo a alguien, no tanto."""
    f = rep_fuente(ip)
    if not f:
        return ""
    try:
        mt = os.path.getmtime(FEEDS_META)
    except OSError:
        return ""
    if mt != _REP_CAT_CACHE["mtime"]:
        meta = cargar_feeds_meta().get("sources") or {}
        _REP_CAT_CACHE["cats"] = {k: (v or {}).get("categoria", "") for k, v in meta.items()}
        _REP_CAT_CACHE["mtime"] = mt
    return _REP_CAT_CACHE["cats"].get(f, "")

# ---------------------------------------------------------------------------------
# Destinos de MALA REPUTACION: cortarlos en el router
# ---------------------------------------------------------------------------------
# Es la otra direccion del problema. La cuarentena corta al CPE; esto corta el DESTINO,
# que es lo que mantiene vivo al equipo infectado: sin canal de control, la botnet no
# manda nada. Y funciona para todos los abonados a la vez, sin tener que identificar a
# ninguno.
DESTINOS_FILE = "/var/log/suricata-destinos-malos.json"
MK_SENT_DST = "/var/log/suricata-destinos-enviados.json"
# Por confianza del feed. Un C2 activo es lo que es; una IP que alguna vez escaneo a
# alguien puede alojar ademas algo legitimo, y bloquearla deja sin servicio a un abonado
# que no hizo nada.
DST_CONFIABLES = ("c2-activo", "c2-ioc", "distribucion-malware", "infra-delictiva")

def cargar_destinos_malos():
    try:
        return (json.load(open(DESTINOS_FILE, encoding="utf-8")).get("destinos") or {})
    except (OSError, ValueError, AttributeError):
        return {}

def destino_bloqueable(ip):
    """SOLO IPs publicas. Una privada aqui seria una IP de tu propia red: bloquearla
    como destino dejaria sin servicio a tus abonados entre si."""
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False, "no es una IP"
    if not o.is_global:
        return False, "no es una IP publica"
    if es_mi_cpe(ip):
        return False, "es de tus redes"
    return True, ""

def destinos_malos(solo_confiables=True):
    """Destinos fichados que TUS CPEs estan contactando, listos para decidir."""
    env = cargar_enviados(MK_SENT_DST)
    dest_ok = _dest_ok_set()
    out = []
    for ip, d in cargar_destinos_malos().items():
        ok, _porque = destino_bloqueable(ip)
        if not ok or ip in dest_ok:
            continue                       # ya marcado como falso positivo: no se propone
        cat = d.get("categoria", "")
        if solo_confiables and cat not in DST_CONFIABLES:
            continue
        out.append({"ip": ip, "alertas": int(d.get("alertas", 0)),
                    "cpes": int(d.get("cpes", 0)), "cpes_ej": d.get("cpes_ej") or [],
                    "fuente": d.get("fuente", ""), "categoria": cat,
                    "pais": d.get("pais", ""), "firma": d.get("firma", ""),
                    "puertos": d.get("puertos") or [], "vigente": bool(d.get("vigente")),
                    "enviado": ip in env})
    out.sort(key=lambda x: (x["enviado"], -x["alertas"]))
    return out

# --- Bloqueo PREVENTIVO: los feeds enteros, antes de que nadie los visite -----------
# Lo de arriba es reactivo: bloquea destinos que un CPE YA contacto. Esto es lo contrario
# y es mejor: se corta la salida hacia infraestructura fichada ANTES de que nadie llegue,
# asi el equipo infectado ni siquiera consigue instrucciones.
#
# Solo entran los feeds en los que se puede confiar para cortar POR DESTINO. La
# diferencia importa: "esta IP alguna vez escaneo a alguien" (CINS, AbuseIPDB) describe a
# un atacante, pero esa misma IP puede alojar una web que un abonado visita. Un servidor
# de control de botnet o una red secuestrada, no.
DST_FEED_OK = ("c2-activo", "infra-delictiva")
DST_FEED_TOPE = 50000

def destinos_feed(tope=DST_FEED_TOPE):
    """Indicadores de los feeds de alta confianza, listos para una lista de DESTINO.

    Devuelve [(indicador, fuente)]. Incluye CIDRs: una address-list de MikroTik los
    acepta igual, y Spamhaus DROP son casi todo redes."""
    try:
        cats = {k: (v or {}).get("categoria", "")
                for k, v in (cargar_feeds_meta().get("sources") or {}).items()}
    except Exception:
        return []
    buenas = {k for k, c in cats.items() if c in DST_FEED_OK}
    if not buenas:
        return []
    dest_ok = _dest_ok_set()
    out = []
    f = os.path.join(os.path.dirname(FEEDS_META), "reputation.lst")
    try:
        with open(f, encoding="utf-8") as fh:
            for linea in fh:
                if len(out) >= tope:
                    break
                ind, _tab, fuente = linea.strip().partition("\t")
                if not ind or fuente not in buenas or ind in dest_ok:
                    continue
                # nunca lo propio: ni tus redes ni tus publicas declaradas
                base = ind.split("/", 1)[0]
                if es_mi_cpe(base) or es_publica_declarada(base):
                    continue
                out.append((ind, fuente))
    except OSError:
        return []
    return out

def destinos_rsc(lista="suricata-destinos-malos", ttl="1d"):
    """El script que el router se baja e importa para el bloqueo preventivo."""
    filas = destinos_feed()
    out = ["# Destinos de alta confianza (C2 activo e infraestructura delictiva).",
           "# Generado %s - %d entradas." % (time.strftime("%Y-%m-%d %H:%M"), len(filas)),
           "# Se reemplaza SOLO lo que puso el feed; lo que bloqueaste a mano no se toca.",
           "/ip firewall address-list",
           ':local viejas [find list=%s comment~"feed"]' % lista,
           ":foreach i in=$viejas do={remove $i}"]
    for ind, fuente in filas:
        out.append('add list=%s address=%s timeout=%s comment="feed %s"'
                   % (lista, ind, ttl, re.sub(r"[^A-Za-z0-9-]", "", fuente)[:20]))
    return "\n".join(out) + "\n"

def destinos_reglas(lista="suricata-destinos-malos"):
    return "\n".join([
        "# Cortar la salida hacia infraestructura fichada. Es dst-address-list, no src:",
        "# aqui no se bloquea a un abonado, se bloquea A DONDE va.",
        "/ip firewall filter",
        'add chain=forward dst-address-list=%s action=drop '
        'comment="Suricata: destinos de mala reputacion"' % lista,
        "",
        "# y que ni siquiera cree la conexion (mas barato con muchas entradas):",
        "/ip firewall raw",
        'add chain=prerouting dst-address-list=%s action=drop '
        'comment="Suricata: destinos de mala reputacion"' % lista,
    ])

def cargar_entrantes():
    try:
        return (json.load(open(ENTRANTES_FILE, encoding="utf-8")).get("origenes") or {})
    except (OSError, ValueError, AttributeError):
        return {}

def blocklist_borde(tope=BL_TOPE):
    """Las IPs a cortar en la entrada, con por que esta cada una.

    Solo entra lo OBSERVADO atacandonos, no los feeds enteros: un feed trae cientos de
    miles de IPs, llena la RAM del router y mete falsos positivos de sitios que tus
    abonados visitan. Lo que nos golpea a nosotros es corto y es el que importa."""
    out = []
    for ip, d in sorted(cargar_entrantes().items(),
                        key=lambda kv: int(kv[1].get("alertas", 0)), reverse=True):
        if len(out) >= tope:
            break
        try:
            o = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not o.is_global or es_mi_cpe(ip) or nunca_bloquear(ip):
            continue               # nunca lo propio ni la allowlist
        al = int(d.get("alertas", 0)); ds = int(d.get("destinos", 0))
        fuente = rep_fuente(ip)    # ademas en un feed de reputacion: confianza alta
        if not (fuente or (al >= BL_MIN_ALERTAS and ds >= BL_MIN_DESTINOS)):
            continue
        out.append({"ip": ip, "alertas": al, "destinos": ds,
                    "pais": d.get("pais", ""), "firma": d.get("firma", ""),
                    "fuente": fuente or ""})
    return out

def blocklist_rsc(lista=BL_LISTA, ttl="1d"):
    """El script que el router se descarga e importa.

    Se publica para que el MikroTik lo baje EL, en vez de meterle miles de entradas una
    a una por la API: por ahi tardaria horas."""
    hoy = time.strftime("%Y-%m-%d %H:%M")
    filas = blocklist_borde()
    out = ["# Atacantes vistos por el sensor Suricata. Generado %s" % hoy,
           "# %d direcciones. Se reemplaza la lista entera en cada importacion." % len(filas),
           "/ip firewall address-list",
           ":local viejas [find list=%s]" % lista,
           ":foreach i in=$viejas do={remove $i}"]
    for f in filas:
        por = f["fuente"] or ("%d alertas a %d destinos" % (f["alertas"], f["destinos"]))
        com = re.sub(r'[^A-Za-z0-9 ._:/()-]', " ", por)[:60]
        out.append('add list=%s address=%s timeout=%s comment="%s"' % (lista, f["ip"], ttl, com))
    return "\n".join(out) + "\n"

def blocklist_reglas(lista=BL_LISTA):
    """Las reglas. El detalle que decide si esto sirve o rompe clientes es
    connection-state=new: si se corta en raw o sin ese matcher, tambien se tiran las
    RESPUESTAS a conexiones que abrio tu abonado, y el cliente se queda sin poder entrar
    a un sitio legitimo sin que nadie entienda por que."""
    return "\n".join([
        "# 1) que el router se baje la lista solo, cada hora",
        "/system scheduler",
        'add name=suricata-atacantes interval=1h on-event="/tool fetch '
        'url=\\"http://IP_DEL_SENSOR:PUERTO/blocklist.rsc\\" dst-path=atacantes.rsc; '
        ':delay 5s; /import atacantes.rsc" comment="Suricata: lista de atacantes"',
        "",
        "# 2) cortar SOLO las conexiones NUEVAS que entran desde esas IPs.",
        "#    Sin connection-state=new se tiran tambien las respuestas a lo que pidio tu",
        "#    abonado, y el cliente se queda sin acceso a sitios legitimos.",
        "/ip firewall filter",
        'add chain=forward connection-state=new src-address-list=%s action=drop '
        'comment="Suricata: atacantes de internet"' % lista,
        'add chain=input connection-state=new src-address-list=%s action=drop '
        'comment="Suricata: atacantes contra el router"' % lista,
    ])

def _mk_print(s_, cmd, props):
    """Un print de la API como lista de diccionarios."""
    filas = []
    try:
        _mk_send(s_, [cmd, "=.proplist=" + ",".join(props)])
        _ok, frases, _err = _mk_reply(s_)
    except Exception:
        return filas
    for f in frases:
        if not (f and f[0] == "!re"):
            continue
        d = {}
        for a in f:
            if a.startswith("=") and "=" in a[1:]:
                k, v = a[1:].split("=", 1)
                d[k] = v
        filas.append(d)
    return filas

DIAG_FILE = "/var/log/suricata-diagnostico.json"

def guardar_diagnostico():
    """Consulta a cada router y deja el resultado en disco.

    Corre en el hilo de fondo A PROPOSITO: hacerlo dentro del render dejaba la pagina
    esperando CUATRO consultas a la API por router, con su conexion TCP y su login. Con
    el router al otro lado de una VPN eso son segundos, y si no responde, el timeout
    entero."""
    out = {}
    for r in cargar_routers():
        if not ((r.get("HOST") or "").strip() and r.get("ENABLED") == "1"):
            continue
        rid = r.get("id", "")
        try:
            out[rid] = {"ts": int(time.time()), "checks": mk_diagnostico(r)}
        except Exception as ex:
            out[rid] = {"ts": int(time.time()), "error": str(ex)[:140]}
    try:
        tmp = "%s.%d.tmp" % (DIAG_FILE, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f)
        os.replace(tmp, DIAG_FILE)
    except OSError:
        pass
    return len(out)

def diagnostico_de(rid):
    """Lo ultimo que se midio de ese router, o None si aun no se midio."""
    try:
        return (json.load(open(DIAG_FILE, encoding="utf-8")) or {}).get(rid)
    except (OSError, ValueError, AttributeError):
        return None

def mk_diagnostico(router=None):
    """Que le falta al router para poder cortar de verdad. [(estado, titulo, detalle, arreglo)]
    estado: ok | falta | aviso."""
    d = cargar_mk_de(router) if router else cargar_mk()
    s_ = mk_conectar(d)
    try:
        filtros = _mk_print(s_, "/ip/firewall/filter/print",
                            ["chain", "action", "src-address-list", "dst-port",
                             "protocol", "psd", "disabled", "connection-limit"])
        crudas = _mk_print(s_, "/ip/firewall/raw/print", ["action", "src-address-list"])
        ajustes = _mk_print(s_, "/ip/settings/print", ["rp-filter"])
        sniffer = _mk_print(s_, "/tool/sniffer/print",
                            ["running", "streaming-enabled", "streaming-server",
                             "filter-interface"])
    finally:
        try: s_.close()
        except OSError: pass

    activos = [f for f in filtros if f.get("disabled") != "true"]
    def usa_lista(nombre):
        return any(f.get("src-address-list") == nombre for f in activos + crudas)

    out = []
    # 1) sin espejo no hay nada que analizar
    sn = sniffer[0] if sniffer else {}
    if sn.get("running") == "true" and sn.get("streaming-enabled") == "true":
        out.append(("ok", "El espejo esta activo",
                    "Enviando a %s desde %s." % (sn.get("streaming-server", "?"),
                                                 sn.get("filter-interface") or "todas las interfaces"), ""))
    else:
        out.append(("falta", "El espejo NO esta enviando",
                    "Sin esto el sensor esta ciego y todo lo demas da igual.",
                    "/tool sniffer set streaming-enabled=yes "
                    "streaming-server=IP_DEL_SENSOR:37008 filter-stream=yes\n/tool sniffer start"))

    # 2) las address-lists tienen que tener una regla que las use
    for lista, que in ((d.get("LIST", ""), "cuarentena"),
                       (d.get("LIST_GRAD", ""), "cuarentena graduada")):
        if not lista:
            continue
        if usa_lista(lista):
            out.append(("ok", f"La lista de {que} corta", f"Hay una regla usando '{lista}'.", ""))
        else:
            out.append(("falta", f"La lista de {que} NO corta nada",
                        f"El panel mete CPEs en '{lista}', pero ninguna regla del firewall la "
                        "usa: el abonado sigue atacando y el panel dice 'enviado'.",
                        f"/ip firewall filter add chain=forward src-address-list={lista} "
                        f'action=drop comment="Suricata: {que}"'))

    # 3) el origen falsificado no lo ve NINGUN IDS
    rp = (ajustes[0].get("rp-filter") if ajustes else "") or "no"
    if rp == "strict":
        out.append(("ok", "Origen falsificado bloqueado (rp-filter strict)",
                    "Tus abonados no pueden salir con una IP que no es suya.", ""))
    else:
        out.append(("falta", "Se puede salir con IP falsificada (rp-filter = %s)" % rp,
                    "Es la base de los ataques de amplificacion y de las quejas que no se "
                    "pueden rastrear. Ningun IDS lo detecta, porque el trafico parece venir "
                    "de otro sitio. OJO: con rutas asimetricas o varios proveedores, "
                    "'strict' tira trafico legitimo; probalo primero con 'loose'.",
                    "/ip settings set rp-filter=strict"))

    # 4) deteccion de escaneo en el propio router (instantanea, sin esperar al sensor)
    if any(f.get("psd") for f in activos):
        out.append(("ok", "El router detecta escaneos por si solo",
                    "Hay una regla con el matcher psd.", ""))
    else:
        out.append(("falta", "El router no detecta escaneos",
                    "Suricata los ve, pero tarda: el router puede marcarlos al instante y "
                    "sin depender del sensor. Las reglas estan mas abajo.", ""))

    # 5) limite de conexiones: frena botnets sin saber nada de firmas
    if any(f.get("connection-limit") for f in activos):
        out.append(("ok", "Hay limite de conexiones por abonado", "", ""))
    else:
        out.append(("aviso", "Sin limite de conexiones por abonado",
                    "Un CPE infectado puede abrir miles de conexiones. Un tope alto no "
                    "molesta a nadie y le corta las piernas a un escaner.",
                    "/ip firewall filter add chain=forward protocol=tcp "
                    "connection-state=new connection-limit=200,32 "
                    'action=drop comment="Suricata: tope de conexiones por abonado"'))

    # 6) los drops masivos son mas baratos en raw (no pasan por conntrack)
    if crudas:
        out.append(("ok", "Hay reglas en raw", "Los cortes masivos no gastan conntrack.", ""))
    else:
        out.append(("aviso", "Los cortes van por filter, no por raw",
                    "Con muchas IPs en cuarentena conviene cortar en raw: se descarta antes "
                    "de crear la conexion y la tabla de conntrack no se llena.",
                    "/ip firewall raw add chain=prerouting "
                    f"src-address-list={d.get('LIST', 'suricata-cuarentena')} "
                    'action=drop comment="Suricata: cortar antes de conntrack"'))
    return out

def mk_list_ips(lista, router=None):
    """Devuelve el conjunto de direcciones que estan AHORA en esa address-list del MikroTik."""
    d = cargar_mk_de(router) if router else cargar_mk()
    s = mk_conectar(d)
    try:
        _mk_send(s, ["/ip/firewall/address-list/print", "=.proplist=address", f"?list={lista}"])
        ok, frases, err = _mk_reply(s)
        ips = set()
        for f in frases:
            if f and f[0] == "!re":
                for a in f:
                    if a.startswith("=address="):
                        ips.add(a[len("=address="):])
        return ips
    finally:
        try: s.close()
        except Exception: pass

# --- Cliente -> abonado: mapear IP interna a PPPoE/DHCP del MikroTik (para la ficha) ---
ABONADOS_FILE = "/var/log/suricata-abonados.json"

def _mk_re_dicts(frases):
    """Convierte las sentencias !re de una respuesta API en lista de dicts {clave: valor}."""
    out = []
    for f in frases:
        if f and f[0] == "!re":
            r = {}
            for a in f:
                if a.startswith("="):
                    k, _, v = a[1:].partition("=")
                    r[k] = v
            out.append(r)
    return out

def mk_abonados(router=None):
    """Consulta PPPoE activos + leases DHCP y arma {ip: {nombre, tipo, mac, extra}}."""
    d = cargar_mk_de(router) if router else cargar_mk()
    s = mk_conectar(d)
    mapa = {}
    try:
        _mk_send(s, ["/ppp/active/print", "=.proplist=name,address,caller-id,uptime"])
        _ok, frases, _e = _mk_reply(s)
        for r in _mk_re_dicts(frases):
            ip = r.get("address")
            if ip:
                mapa[ip] = {"nombre": r.get("name", ""), "tipo": "PPPoE",
                            "mac": r.get("caller-id", ""), "extra": ("uptime " + r.get("uptime", "")).strip()}
        _mk_send(s, ["/ip/dhcp-server/lease/print",
                     "=.proplist=address,active-address,mac-address,host-name,comment,status"])
        _ok, frases, _e = _mk_reply(s)
        for r in _mk_re_dicts(frases):
            ip = r.get("active-address") or r.get("address")
            if ip and ip not in mapa:                      # PPPoE tiene prioridad
                mapa[ip] = {"nombre": (r.get("comment") or r.get("host-name") or ""), "tipo": "DHCP",
                            "mac": r.get("mac-address", ""), "extra": r.get("status", "")}
        return mapa
    finally:
        try: s.close()
        except Exception: pass

def refrescar_abonados():
    """Refresca el mapa IP->abonado desde el MikroTik (solo si esta configurado). En 2do plano."""
    routers = [r for r in cargar_routers() if r.get("ENABLED") == "1" and (r.get("HOST") or "")]
    if not routers:
        return
    multi = len(cargar_routers()) > 1
    # Cada router conoce SOLO a sus abonados. Con varios nodos hay que preguntarle a
    # todos y guardar la asignacion con su nodo: si no, los CPEs de los demas saldrian
    # sin nombre, o peor, se les pondria el del cliente que tiene esa misma IP en otro.
    mapa = {}
    for r in routers:
        try:
            parcial = mk_abonados(router=r)
        except Exception:
            continue                       # ese router no responde: se conserva lo demas
        for ip, datos in (parcial or {}).items():
            datos = dict(datos)
            datos["router"] = r["id"]
            datos["router_nombre"] = r.get("nombre") or r.get("HOST", "")
            mapa[clave_cpe(ip, r["id"] if multi else "")] = datos
    if not mapa:
        return
    try:
        tmp = ABONADOS_FILE + ".tmp"
        json.dump({"ts": int(time.time()), "mapa": mapa}, open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, ABONADOS_FILE)
    except OSError:
        pass
    _registrar_hist_abonados(mapa)

ABON_HIST_FILE = "/var/log/suricata-abonados-hist.jsonl"
_ABON_HIST_MAX = 40000                     # lineas a conservar tras rotar

def _registrar_hist_abonados(mapa):
    """Anexa a un JSONL SOLO los cambios de asignacion (ip -> nombre/mac/tipo) para poder
    saber quien tenia una IP en el momento de un evento (historial punto-en-el-tiempo)."""
    prev = {}
    try:
        for ln in open(ABON_HIST_FILE, encoding="utf-8"):
            try: r = json.loads(ln)
            except Exception: continue
            if r.get("ip"): prev[r["ip"]] = r          # ultimo estado por ip
    except FileNotFoundError:
        pass
    except Exception:
        return
    now = int(time.time()); nuevos = []
    for ip, v in mapa.items():
        firma = (v.get("nombre", ""), v.get("mac", ""), v.get("tipo", ""))
        p = prev.get(ip)
        if not p or (p.get("nombre", ""), p.get("mac", ""), p.get("tipo", "")) != firma:
            nuevos.append({"ts": now, "ip": ip, "nombre": v.get("nombre", ""),
                           "mac": v.get("mac", ""), "tipo": v.get("tipo", "")})
    if not nuevos:
        return
    try:
        with open(ABON_HIST_FILE, "a", encoding="utf-8") as f:
            for r in nuevos:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    except OSError:
        return
    try:                                                # rotacion simple por tamaño
        if os.path.getsize(ABON_HIST_FILE) > 6_000_000:
            lineas = open(ABON_HIST_FILE, encoding="utf-8").readlines()
            if len(lineas) > _ABON_HIST_MAX:
                tmp = ABON_HIST_FILE + ".tmp"
                open(tmp, "w", encoding="utf-8").writelines(lineas[-_ABON_HIST_MAX // 2:])
                os.replace(tmp, ABON_HIST_FILE)
    except OSError:
        pass

def historial_abonado(ip, ts):
    """Quien tenia esa IP en el instante ts (ultimo cambio registrado con ts <= evento)."""
    if not ip or not ts:
        return {}
    best = {}
    try:
        for ln in open(ABON_HIST_FILE, encoding="utf-8"):
            try: r = json.loads(ln)
            except Exception: continue
            if r.get("ip") == ip and r.get("ts", 0) <= ts and r.get("ts", 0) >= best.get("ts", 0):
                best = r
    except Exception:
        return {}
    return best

def cargar_abonados():
    try:
        return json.load(open(ABONADOS_FILE, encoding="utf-8"))
    except Exception:
        return {}

def abonado_de(ip, rid=""):
    """Abonado de una IP. Con varios nodos hay que decir en CUAL, porque la misma IP
    puede ser de dos clientes distintos; si no se dice, se busca por la IP sola (que es
    lo correcto con un solo router)."""
    mapa = cargar_abonados().get("mapa") or {}
    if rid:
        v = mapa.get(clave_cpe(ip, rid))
        if v is not None:
            return v
    v = mapa.get(ip)
    if v is not None:
        return v
    # registro antiguo (guardado cuando aun no se distinguian nodos)
    for k, datos in mapa.items():
        if ip_de(k) == ip and not rid:
            return datos
    return {}

def mk_sync_enviados():
    """Sincroniza el registro del panel con lo que REALMENTE hay en el MikroTik, para que el
    indicador 'En cuarentena' sea fiable y no se reintente enviar algo que ya esta. Agrega los
    que estan en el router y faltan (marcados manual), y quita los que ya no estan."""
    routers = [r for r in cargar_routers() if r.get("ENABLED") == "1" and (r.get("HOST") or "")]
    if not routers:
        return
    multi = len(cargar_routers()) > 1
    for list_key, sent_path in (("LIST", MK_SENT), ("LIST_DNS", MK_SENT_DNS)):
        # Se consulta CADA router y se compara solo contra SUS entradas. Mirar un solo
        # router borraria del registro los CPEs de los demas, que seguirian bloqueados y
        # ya invisibles para el panel (no habria forma de liberarlos).
        reales = {}          # id de router -> ips en esa lista
        fallo = set()
        for r in routers:
            d = cargar_mk_de(r)
            lst = d.get(list_key, "")
            if not lst:
                continue
            try:
                reales[r["id"]] = set(mk_list_ips(lst, router=r))
            except Exception:
                fallo.add(r["id"])         # ese router no responde -> no tocar lo suyo
        if not reales:
            continue
        env = cargar_enviados(sent_path); cambiado = False; nowt = int(time.time())
        for rid, ips in reales.items():
            for ip in ips:
                k = clave_cpe(ip, rid if multi else "")
                if k not in env:           # esta en el router pero no en el panel -> registrarlo
                    env[k] = {"cuando": nowt, "score": "", "por": "mikrotik", "manual": True,
                              "router": rid}
                env[k]["en_router"] = True; env[k]["sync_ts"] = nowt
                env[k].setdefault("router", rid)
                cambiado = True
        for k in list(env.keys()):
            rid = rid_de(k) or (env[k].get("router") or (routers[0]["id"] if routers else ""))
            if rid in fallo or rid not in reales:
                continue                   # de ese router no sabemos nada ahora mismo
            if ip_de(k) not in reales[rid]:   # ya no esta en SU router -> soltar
                env.pop(k, None); cambiado = True
        if cambiado:
            guardar_enviados(env, sent_path)

# --- allowlist "nunca bloquear": IPs/CIDR que jamas van a cuarentena (infra, clientes clave) ---
NUNCA_FILE = "/etc/suricata-nunca-bloquear.lst"

def cargar_nunca():
    try:
        return open(NUNCA_FILE, encoding="utf-8").read()
    except OSError:
        return ""

def guardar_nunca(texto):
    """Guarda la allowlist; conserva solo lineas validas (IP o CIDR) o comentarios."""
    limpio = []
    for l in (texto or "").splitlines():
        s = l.split("#", 1)[0].strip()
        if not s:
            if l.strip().startswith("#"):
                limpio.append(l.strip()[:120])
            continue
        try:
            ipaddress.ip_network(s, strict=False) if "/" in s else ipaddress.ip_address(s)
            limpio.append(s)
        except ValueError:
            pass
    try:
        tmp = NUNCA_FILE + ".tmp"
        open(tmp, "w", encoding="utf-8").write("\n".join(limpio) + ("\n" if limpio else ""))
        os.replace(tmp, NUNCA_FILE)
    except OSError:
        pass

def _chip_nodo_panel(clave):
    """Etiqueta con el nodo. Vacia si la instalacion tiene un solo MikroTik."""
    r = rid_de(clave)
    if not r:
        return ""
    nom = (router_por_id(r) or {}).get("nombre") or r
    return ("<span class='nodochip' title='Este CPE cuelga de este MikroTik'>"
            + html.escape(nom) + "</span>")

def _suf_nodo(clave):
    """Sufijo para la bitacora: deja constancia de en que nodo se actuo."""
    r = rid_de(clave)
    if not r:
        return ""
    return " nodo=" + ((router_por_id(r) or {}).get("nombre") or r)

def clave_cpe(ip, rid):
    """Identidad de un CPE: con varios nodos es (router, IP). Tiene que coincidir con la
    que usa el generador, porque el panel lee sus candidatos."""
    return (rid + "|" + ip) if rid else ip

def ip_de(clave):
    """La IP pelada, que es lo que se manda al router."""
    return clave.split("|", 1)[1] if "|" in clave else clave

def rid_de(clave):
    """A que router pertenece ("" si la instalacion tiene un solo nodo)."""
    return clave.split("|", 1)[0] if "|" in clave else ""

def router_de_clave(clave):
    """El router al que hay que hablarle para bloquear o liberar este CPE."""
    r = rid_de(clave)
    return (router_por_id(r) or router_defecto()) if r else router_defecto()

def mis_redes():
    """Redes que son TUYAS (abonados). MIS_REDES=CIDR,CIDR en el .conf; por defecto las
    privadas RFC1918 + CGNAT. Debe coincidir con lo que usa el generador."""
    redes = []
    for t in (conf().get("MIS_REDES", "") or "").replace(";", ",").split(","):
        t = t.strip()
        if not t:
            continue
        try:
            redes.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            pass
    if not redes:
        for t in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
            redes.append(ipaddress.ip_network(t))
    return redes

def es_mi_cpe(ip):
    """False para una IP de internet: esas no van a la cuarentena de CPEs (no bloquea
    nada util y ensucia la address-list). Se cortan en el borde."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in mis_redes())

def nunca_bloquear(ip):
    ips = set(); nets = []
    for l in cargar_nunca().splitlines():
        s = l.split("#", 1)[0].strip()
        if not s:
            continue
        try:
            if "/" in s:
                nets.append(ipaddress.ip_network(s, strict=False))
            else:
                ips.add(s)
        except ValueError:
            pass
    if ip in ips:
        return True
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except ValueError:
        return False

# --- destinos confiables (falsos positivos): un DNS u otro destino que dispara alertas en
# muchos CPEs. Al marcarlo, el generador deja de contar sus alertas y se liberan los CPEs
# que fueron a la lista por su culpa. ---
DEST_OK_FILE = "/etc/suricata-destinos-confianza.lst"

def cargar_dest_ok():
    try:
        return open(DEST_OK_FILE, encoding="utf-8").read()
    except OSError:
        return ""

def _dest_ok_set():
    s = set()
    for l in cargar_dest_ok().splitlines():
        x = l.split("#", 1)[0].strip()
        if x:
            s.add(x)
    return s

def guardar_dest_ok_set(conjunto):
    try:
        tmp = DEST_OK_FILE + ".tmp"
        open(tmp, "w", encoding="utf-8").write("\n".join(sorted(conjunto)) + ("\n" if conjunto else ""))
        os.replace(tmp, DEST_OK_FILE)
    except OSError:
        pass

def excluir_destino(d):
    """Marca un destino como confiable (falso positivo) y libera de la cuarentena TODOS los
    CPEs cuyo bloqueo se debe a ese destino. Devuelve (n_liberados, mensaje)."""
    d = (d or "").strip()
    try:
        ipaddress.ip_address(d)
    except ValueError:
        return 0, "IP de destino invalida"
    cur = _dest_ok_set(); cur.add(d)
    guardar_dest_ok_set(cur)                       # 1) destino a la lista de confiables
    liberados = 0
    try:                                           # destinos por CPE del reporte actual (respaldo)
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
        cand_dst = {}
        for key in ("candidatos", "dns_candidatos"):
            for c in cq.get(key, []):
                cand_dst[clave_cpe(c.get("ip", ""), c.get("router", ""))] = c.get("destinos_ip", [])
    except Exception:
        cand_dst = {}
    for list_key, sent_path in (("LIST", MK_SENT), ("LIST_DNS", MK_SENT_DNS)):
        env = cargar_enviados(sent_path); cambiado = False
        for k in list(env.keys()):
            dips = (env[k].get("motivo") or {}).get("destinos_ip") or cand_dst.get(k) or []
            if d in dips:                          # 2) atribuible a ese destino -> liberar
                # cada CPE se libera en SU router y en la lista que ese router tenga
                r = router_de_clave(k); dr = cargar_mk_de(r); lst = dr.get(list_key, "")
                try:
                    if lst and dr.get("ENABLED") == "1":
                        mk_remove(ip_de(k), lista=lst, router=r)
                except Exception:
                    pass
                env.pop(k, None); cambiado = True; liberados += 1
                mk_log("LIBERADO-FALSO-POSITIVO", ip_de(k), getattr(CTX, "user", "?"),
                       f"destino={d} lista={lst}" + _suf_nodo(k))
        if cambiado:
            guardar_enviados(env, sent_path)
    globals()["FORCE_REGEN"] = True                # 3) recalcular candidatos sin ese destino
    bitacora("EXCLUIR-DESTINO", f"{d} -> {liberados} CPE liberado(s)")
    return liberados, f"Destino {d} marcado confiable; {liberados} CPE liberado(s) por falso positivo."

# --- cuarentena explicable: por que se bloqueo y cuando se reviso por ultima vez ---
# --- Una address-list por CATEGORIA de abuso ---------------------------------------
# (clave, nombre visible, categorias de firma que la disparan, lista por defecto)
# El orden MANDA: se clasifica por la primera que casa, de lo mas grave a lo mas leve.
# Un CPE con botnet Y P2P es un CPE con botnet.
CAT_CPE = [
    ("botnet", "Botnet / CnC",
     ["Botnet CnC", "Botnet", "Botnet Mirai", "Botnet Katana", "Troyano", "Ransomware",
      "Trafico de malware"], "clientes-botnet"),
    ("dns", "DNS de malware",
     ["DNS sospechoso"], "clientes-dns-malware"),
    ("escaneo", "Escaneo",
     ["Escaneo de puertos", "Escaneo SSH", "Escaneo Telnet", "Escaneo TR-069",
      "Escaneo saliente"], "clientes-escaneo"),
    ("fuerza", "Fuerza bruta",
     ["Fuerza bruta", "RDP/VNC"], "clientes-fuerza-bruta"),
    ("spam", "Spam",
     ["Spam"], "clientes-spam"),
    ("minado", "Criptominado",
     ["Criptomineria"], "clientes-minado"),
    ("p2p", "P2P",
     ["BitTorrent / P2P"], "clientes-p2p"),
]
CAT_OTROS = ("otros", "Otros", [], "clientes-otros")

def lista_de_categoria(cat):
    """Nombre de la address-list de esa categoria. Se puede cambiar en MK_CONF con
    LISTA_<CATEGORIA>=nombre, por si el ISP ya tiene su propia nomenclatura."""
    for c, _nom, _cats, por_defecto in CAT_CPE + [CAT_OTROS]:
        if c == cat:
            return (_mk_globales().get("LISTA_" + c.upper(), "") or por_defecto).strip()
    return CAT_OTROS[3]

def nombre_categoria(cat):
    for c, nom, _cats, _l in CAT_CPE + [CAT_OTROS]:
        if c == cat:
            return nom
    return CAT_OTROS[1]

def categoria_cpe(clave):
    """En que categoria cae ese CPE, segun el tipo de trafico que hace de verdad.

    Se decide por la PRIMERA categoria que casa, y la tabla va de lo mas grave a lo mas
    leve: quien tiene una botnet y ademas usa BitTorrent es, a efectos de que hacer con
    el, un CPE con botnet."""
    c = None
    for x in _cpes_de_reporte(None):
        if clave_cpe(x.get("ip", ""), x.get("router", "")) == clave:
            c = x
            break
    if not c:
        return CAT_OTROS[0]
    suyas = set((c.get("cats_top") or {}).keys())
    for cat, _nom, cats, _l in CAT_CPE:
        if suyas & set(cats):
            return cat
    return CAT_OTROS[0]

def listas_cpe_reglas():
    """Las reglas de cada lista. No todas se tratan igual, que es el motivo de separarlas."""
    def L(c):
        return lista_de_categoria(c)
    return "\n".join([
        "# ORDEN: estas reglas de drop van ANTES de la regla de fasttrack-connection y",
        "# antes de los accept. Con fasttrack activo una conexion ya establecida deja de",
        "# pasar por filter, asi que el drop parece no aplicarse aunque este bien escrito.",
        "/ip firewall filter",
        "# Lo que hay que cortar: el equipo esta comprometido y ataca a terceros.",
        'add chain=forward src-address-list=%s action=drop comment="Suricata: botnet"' % L("botnet"),
        'add chain=forward src-address-list=%s action=drop comment="Suricata: escaneo"' % L("escaneo"),
        'add chain=forward src-address-list=%s action=drop comment="Suricata: fuerza bruta"' % L("fuerza"),
        "",
        "# Meter un CPE en la address-list NO corta lo que ya tiene abierto: la regla solo",
        "# mira los paquetes que pasan por ella. Hay que soltar las conexiones vivas:",
        '#   /ip firewall connection remove [find src-address~"^192.0.2.25:"]',
        "",
        "# Spam: basta con cerrarle el correo saliente, no hace falta dejarlo sin internet.",
        'add chain=forward src-address-list=%s protocol=tcp dst-port=25,465,587 '
        'action=drop comment="Suricata: spam"' % L("spam"),
        "",
        "# DNS de malware: en vez de cortar, se le fuerza a TU resolutor, que ya filtra.",
        "# OJO: redirect manda al resolutor DEL PROPIO ROUTER. Si el router no resuelve, el",
        "# cliente se queda sin DNS y parece que le cortaste internet. O lo habilitas con",
        "#   /ip dns set allow-remote-requests=yes",
        "# o mandas el trafico a tu resolutor cambiando la accion de la regla de abajo por",
        "#   action=dst-nat to-addresses=192.0.2.53 to-ports=53",
        "/ip firewall nat",
        'add chain=dstnat src-address-list=%s protocol=udp dst-port=53 '
        'action=redirect to-ports=53 comment="Suricata: DNS de malware al resolutor propio"' % L("dns"),
        "",
        "# P2P y minado: no son un ataque, son consumo. Encolar rinde mas que cortar.",
        "# La cadena completa es: marca de CONEXION -> marca de PAQUETE -> cola de arbol",
        "# que consume esa marca. Faltando cualquiera de los tres pasos no se limita nada",
        "# y ademas no da error: una simple queue con target=\"\" no engancha trafico, y",
        "# una marca de paquete que ninguna cola consume no la usa nadie.",
        "# Cada categoria lleva SU marca y SU cola: si comparten cola, el minado se come",
        "# el limite del P2P y no hay forma de saber cual de los dos esta consumiendo.",
        "# (ejemplo; ajusta los limites a tu plan)",
        "/ip firewall mangle",
        'add chain=forward src-address-list=%s action=mark-connection '
        'new-connection-mark=p2p-con passthrough=yes comment="Suricata: P2P"' % L("p2p"),
        'add chain=forward connection-mark=p2p-con action=mark-packet '
        'new-packet-mark=p2p passthrough=no comment="Suricata: P2P"',
        'add chain=forward src-address-list=%s action=mark-connection '
        'new-connection-mark=minado-con passthrough=yes comment="Suricata: minado"' % L("minado"),
        'add chain=forward connection-mark=minado-con action=mark-packet '
        'new-packet-mark=minado passthrough=no comment="Suricata: minado"',
        "/queue tree",
        'add name=p2p-limite parent=global packet-mark=p2p max-limit=2M '
        'comment="Suricata: P2P acotado"',
        'add name=minado-limite parent=global packet-mark=minado max-limit=1M '
        'comment="Suricata: minado acotado"',
    ])

def _motivo_bloqueo(clave):
    """Busca por que un CPE es candidato (firma, banda, score, conteos) en cuarentena.json,
    para guardarlo AL bloquear y poder explicar el bloqueo aunque despues deje de atacar.
    Recibe la IDENTIDAD (router, IP): con varios nodos dos CPEs distintos pueden tener la
    misma IP y se guardaria el motivo del vecino."""
    try:
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
    except Exception:
        return {}
    for key, tipo, cnt, cntlbl, fir in (
            ("candidatos", "infeccion", "alertas_cnc", "alertas CnC", "firmas_cnc"),
            ("dns_candidatos", "dns", "alertas_dns", "alertas DNS", "firmas_dns")):
        for c in cq.get(key, []):
            if clave_cpe(c.get("ip", ""), c.get("router", "")) == clave:
                return {"tipo": tipo, "banda": c.get("banda", ""), "score": c.get("riesgo", 0),
                        "firma": (c.get("firma", "") or "")[:120],
                        "conteo": f"{c.get(cnt, 0)} {cntlbl}, {c.get(fir, 0)} firma(s)",
                        "destinos_ip": c.get("destinos_ip", [])}   # para liberar por falso positivo
    # Las POLITICAS por banda no envian desde 'candidatos' sino desde 'top_riesgo': si el
    # CPE no es candidato confirmado, el motivo se arma con lo que uso la politica para
    # decidir (banda, puntaje y su desglose). Sin esto el bloqueo se quedaba sin motivo.
    for c in cq.get("top_riesgo", []):
        if clave_cpe(c.get("ip", ""), c.get("router", "")) == clave:
            return {"tipo": "politica", "banda": c.get("banda", ""), "score": c.get("riesgo", 0),
                    "firma": "", "desglose": c.get("desglose", ""),
                    "conteo": (f"{c.get('alertas', 0)} alertas, {c.get('destinos', 0)} destino(s) "
                               f"distintos, {c.get('puertos', 0)} puerto(s)"),
                    "destinos_ip": []}
    return {}

def evaluar_bloqueos():
    """Sella en cada entrada de cuarentena la ultima evaluacion (last_eval) y si el CPE
    SIGUE activo. Barato (solo lee cuarentena.json); corre cada ciclo del hilo de fondo."""
    try:
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
    except Exception:
        return
    activos = ({clave_cpe(c.get("ip", ""), c.get("router", "")) for c in cq.get("candidatos", [])}
               | {clave_cpe(c.get("ip", ""), c.get("router", "")) for c in cq.get("dns_candidatos", [])})
    now = int(time.time())
    for path in (MK_SENT, MK_SENT_DNS):
        env = cargar_enviados(path)
        if not env:
            continue
        for k, e in env.items():
            e["last_eval"] = now
            e["sigue"] = k in activos
        guardar_enviados(env, path)

# --- salud del sensor: distinguir "sin amenazas" de "sin trafico / perdidas / reporte viejo" ---
SENSOR_FILE = "/var/log/suricata-sensor.json"
REPORT_CONF = "/etc/suricata-report.conf"   # comparte TELEGRAM_TOKEN/CHAT_ID con el informe

def _hostname():
    try:
        return os.uname().nodename
    except Exception:
        return "suricata"

def enviar_telegram(texto):
    """Envia un aviso por Telegram si esta configurado en /etc/suricata-report.conf.
    No lanza: si no hay token o falla la red, no pasa nada (el aviso igual queda en el panel)."""
    tok = chat = None
    try:
        for ln in open(REPORT_CONF, encoding="utf-8"):
            ln = ln.strip()
            if ln.startswith("TELEGRAM_TOKEN="):
                tok = ln.split("=", 1)[1].strip()
            elif ln.startswith("TELEGRAM_CHAT_ID="):
                chat = ln.split("=", 1)[1].strip()
    except OSError:
        return False
    if not (tok and chat):
        return False
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": texto[:4000]}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data=data, timeout=15)
        return True
    except Exception:
        return False

NOTIF_CUAR_FILE = "/var/log/suricata-notif-cuarentena.json"   # dedupe de avisos de cuarentena

def notificar_cuarentena(ip, tipo, lista, quien=""):
    """Aviso ACCIONABLE (Telegram) cuando un CPE va a cuarentena: cliente/abonado, confianza,
    evidencia, accion aplicada y enlace a la ficha. Dedupe por IP: no re-notifica dentro de 6h."""
    now = time.time()
    try:
        d = json.load(open(NOTIF_CUAR_FILE, encoding="utf-8"))
    except Exception:
        d = {}
    if now - d.get(ip, 0) < 6 * 3600:
        return
    ab = abonado_de(ip)
    cliente = f"{ab.get('nombre')} ({ip})" if ab.get("nombre") else ip
    conf = ""; ev = ""
    try:
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
        for k in ("candidatos", "dns_candidatos"):
            for c in cq.get(k, []):
                if c.get("ip") == ip:
                    conf = c.get("confianza", "")
                    ev = "; ".join((c.get("evidencias") or [])[:3])
                    break
    except Exception:
        pass
    base = conf_dash_get("PANEL_URL", "").rstrip("/")
    link = f"{base}/cuarentena/ficha?ip={ip}" if base else f"panel -> Cuarentena -> Ver evidencia ({ip})"
    txt = (f"\U0001f6a8 Cuarentena [{_hostname()}]: {cliente}\n"
           f"Accion: enviado a lista '{lista}' ({tipo})" + (f" | confianza {conf}" if conf else "") + "\n"
           + (f"Evidencia: {ev}\n" if ev else "")
           + (f"Por: {quien}\n" if quien else "")
           + f"Ficha: {link}")
    if enviar_telegram(txt):
        d[ip] = int(now)
        try:
            json.dump(d, open(NOTIF_CUAR_FILE, "w", encoding="utf-8"))
        except OSError:
            pass

def _suricatasc(cmd):
    try:
        r = subprocess.run(["suricatasc", "-c", cmd], capture_output=True, text=True, timeout=8)
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None

def _svc_activo(nombre):
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", nombre],
                              timeout=5).returncode == 0
    except Exception:
        return False

def medir_sensor():
    """Mide el estado real del sensor (captura, perdidas, servicios, frescura del reporte).
    Corre en el hilo de fondo y cachea en SENSOR_FILE; el request solo lee el cache."""
    prev = {}
    try:
        prev = json.load(open(SENSOR_FILE, encoding="utf-8"))
    except Exception:
        pass
    now = time.time()
    o = {"ts": int(now)}
    o["suricata"] = _svc_activo("suricata")
    o["tzsp_mode"] = os.path.exists("/etc/systemd/system/tzsp-decap.service")
    o["tzsp"] = _svc_activo("tzsp-decap") if o["tzsp_mode"] else None
    # interfaces capturadas + contadores acumulados
    ifl = _suricatasc("iface-list")
    ifaces = ((ifl or {}).get("message", {}) or {}).get("ifaces", []) or []
    o["ifaces"] = ifaces
    pkts = drop = 0
    for i in ifaces:
        st = _suricatasc(f"iface-stat {i}")
        msg = (st or {}).get("message", {}) or {}
        try:
            pkts += int(msg.get("pkts", 0)); drop += int(msg.get("drop", 0))
        except (TypeError, ValueError):
            pass
    o["pkts"] = pkts; o["drop"] = drop
    # tasas: delta desde la medicion anterior
    dt = now - prev.get("ts", 0) if prev.get("ts") else 0
    dpkts = pkts - prev.get("pkts", pkts)
    o["pps"] = round(dpkts / dt, 1) if dt > 0 and dpkts >= 0 else None
    ddrop = drop - prev.get("drop", drop)
    o["drop_ratio"] = round(ddrop / dpkts, 4) if dt > 0 and dpkts > 0 and ddrop >= 0 else 0.0
    # crecimiento de eve.json (respaldo por si iface-stat no da paquetes)
    try:
        sz = os.path.getsize(f"{LOGDIR}/eve.json")
    except OSError:
        sz = prev.get("eve_size", 0)
    o["eve_size"] = sz
    o["eve_bps"] = round((sz - prev.get("eve_size", sz)) / dt, 0) if dt > 0 and sz >= prev.get("eve_size", sz) else None
    # frescura del reporte
    nr = newest_report()
    o["reporte_edad"] = int(now - os.path.getmtime(nr)) if nr and os.path.exists(nr) else None
    # amenazas activas (para separar "sano sin amenazas" de "con CPEs en riesgo")
    try:
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
        o["candidatos"] = len(cq.get("candidatos", [])) + len(cq.get("dns_candidatos", []))
    except Exception:
        o["candidatos"] = 0
    # clasificacion en un nivel + titulo legible
    hay_trafico = (o["pps"] is not None and o["pps"] >= 1) or (o["eve_bps"] is not None and o["eve_bps"] >= 1)
    if not o["suricata"]:
        o["nivel"], o["titulo"] = "down", "Sensor detenido"
    elif o["tzsp_mode"] and not o["tzsp"]:
        o["nivel"], o["titulo"] = "warn", "Receptor TZSP caido"
    elif not ifaces:
        o["nivel"], o["titulo"] = "warn", "Sin interfaz de captura"
    elif dt > 0 and not hay_trafico:
        o["nivel"], o["titulo"] = "warn", "Sin trafico"
    elif o["drop_ratio"] and o["drop_ratio"] > 0.02:
        o["nivel"], o["titulo"] = "warn", "Captura con perdidas"
    elif o["reporte_edad"] is not None and o["reporte_edad"] > 2 * REFRESH_SECS:
        o["nivel"], o["titulo"] = "warn", "Reporte desactualizado"
    else:
        o["nivel"] = "ok"
        o["titulo"] = "Viendo trafico" + (" · sin amenazas" if o["candidatos"] == 0 else f" · {o['candidatos']} CPE en riesgo")
    # avisos proactivos: notificar cuando el estado EMPEORA (ok->warn/down), cuando cambia el
    # motivo del problema, o re-recordar cada 6h si sigue mal; y avisar la recuperacion.
    o["alert_estado"] = prev.get("alert_estado", "ok")
    o["alert_titulo"] = prev.get("alert_titulo", "")
    o["alert_ts"] = prev.get("alert_ts", 0)
    mal = o["nivel"] in ("warn", "down")
    era_mal = prev.get("alert_estado", "ok") in ("warn", "down")
    aviso = None
    if mal and (not era_mal or o["titulo"] != o["alert_titulo"] or now - o["alert_ts"] > 6 * 3600):
        ico = "⛔" if o["nivel"] == "down" else "⚠️"
        det = []
        if o.get("pps") is not None: det.append(f"{o['pps']:,.0f} pkts/s")
        if o.get("drop_ratio"): det.append(f"perdidas {o['drop_ratio']*100:.1f}%")
        if o.get("reporte_edad") is not None: det.append(f"reporte hace {o['reporte_edad']//60} min")
        aviso = f"{ico} Suricata [{_hostname()}]: {o['titulo']}" + (" (" + ", ".join(det) + ")" if det else "")
    elif era_mal and not mal:
        aviso = f"✅ Suricata [{_hostname()}]: sensor recuperado ({o['titulo']})"
    if aviso:
        enviar_telegram(aviso)
        o["alert_estado"] = o["nivel"]; o["alert_titulo"] = o["titulo"]; o["alert_ts"] = int(now)
    try:
        tmp = SENSOR_FILE + ".tmp"
        json.dump(o, open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, SENSOR_FILE)
    except OSError:
        pass

def estado_sensor():
    try:
        return json.load(open(SENSOR_FILE, encoding="utf-8"))
    except Exception:
        return {}

POL_NOTIF = "/var/log/suricata-politica-notif.json"   # dedupe de la accion 'notificar'
POL_ACCIONES = ("nada", "cuarentena", "dns", "notificar")

def aplicar_politicas():
    """Aplica las politicas por banda de riesgo del Top a los CPEs: envia a cuarentena/DNS,
    solo notifica, o nada. Las entradas 'pol' las gestiona ESTA funcion (entran cuando el CPE
    califica por banda, salen cuando deja de calificar). Solo con MikroTik habilitado y POL_AUTO."""
    m = cargar_mk()
    if not (mk_configurado() and m.get("ENABLED") == "1" and m.get("POL_AUTO") == "1"):
        return
    pol = {"BAJO": m.get("POL_BAJO", "nada"), "MEDIO": m.get("POL_MEDIO", "nada"),
           "ALTO": m.get("POL_ALTO", "nada")}
    try:
        top = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8")).get("top_riesgo", [])
    except Exception:
        return
    deseado_lst = {}; deseado_dns = {}; a_notificar = {}
    for c in top:
        act = pol.get((c.get("banda", "") or "").upper(), "nada")
        ip = c.get("ip"); sc = c.get("riesgo", "")
        if not ip:
            continue
        k = clave_cpe(ip, c.get("router", ""))   # a que nodo pertenece este CPE
        if act == "cuarentena":
            deseado_lst[k] = sc
        elif act == "dns":
            deseado_dns[k] = sc
        elif act == "notificar":
            a_notificar[k] = (sc, c.get("banda", ""))
    # --- accion notificar (dedupe: 1 aviso cada 6h por IP) ---
    if a_notificar:
        try:
            nv = json.load(open(POL_NOTIF, encoding="utf-8"))
        except Exception:
            nv = {}
        ahora = time.time(); cambio_n = False
        for k, (sc, band) in a_notificar.items():
            if ahora - nv.get(k, 0) > 6 * 3600:
                mk_log("POLITICA-NOTIFICAR", ip_de(k), "politica",
                       f"riesgo={sc} banda={band}" + _suf_nodo(k))
                nv[k] = ahora; cambio_n = True
        nv = {k: v for k, v in nv.items() if ahora - v < 7 * 86400}   # limpiar viejos
        if cambio_n:
            try:
                with open(POL_NOTIF + ".tmp", "w", encoding="utf-8") as f:
                    json.dump(nv, f)
                os.replace(POL_NOTIF + ".tmp", POL_NOTIF)
            except OSError:
                pass
    # --- acciones que tocan el router (cuarentena / dns) ---
    for list_key, deseado, sent_path in (("LIST", deseado_lst, MK_SENT),
                                         ("LIST_DNS", deseado_dns, MK_SENT_DNS)):
        env = cargar_enviados(sent_path); cambiado = False
        for k, sc in deseado.items():
            if k in env:
                continue
            # cada CPE se bloquea en SU router y en la lista que ese router tenga
            r = router_de_clave(k); dr = cargar_mk_de(r); lst = dr.get(list_key, "")
            if not lst or dr.get("ENABLED") != "1":
                continue
            try:
                ok, err = mk_add(ip_de(k), comment=f"suricata politica riesgo {sc} {time.strftime('%Y-%m-%d %H:%M')}",
                                 lista=lst, ttl="", router=r)
            except Exception:
                ok = False
            if ok:
                env[k] = {"cuando": int(time.time()), "score": sc, "por": "politica", "manual": False, "pol": True,
                          "router": r.get("id", ""), "motivo": _motivo_bloqueo(k)}
                notificar_cuarentena(ip_de(k), "politica de riesgo", lst, quien="politica")
                mk_log("POLITICA-ENVIADO", ip_de(k), "politica",
                       f"lista={lst} riesgo={sc}" + _suf_nodo(k)); cambiado = True
        for k in list(env.keys()):        # sacar los que entraron por politica y ya no califican
            if env[k].get("pol") and k not in deseado:
                r = router_de_clave(k); dr = cargar_mk_de(r); lst = dr.get(list_key, "")
                if not lst:
                    continue
                try:
                    mk_remove(ip_de(k), lista=lst, router=r)
                except Exception:
                    continue
                env.pop(k, None)
                mk_log("POLITICA-LIBERADO", ip_de(k), "politica", f"lista={lst}" + _suf_nodo(k))
                cambiado = True
        if cambiado:
            guardar_enviados(env, sent_path)

# --- barrido rapido de ALTO: envio casi inmediato de infecciones confirmadas ---
# El ciclo normal (reporte + aplicar_politicas) corre cada REFRESH_SECS (5 min), asi que
# un CPE puede tardar hasta ~5 min en ir a cuarentena. Este barrido corre cada ~60s y envia
# YA a los que confirman INFECCION (comunicacion CnC/botnet repetida), sin esperar el reporte.
# Es conservador: solo firmas de infeccion confirmada (mismo umbral que los candidatos del
# reporte), respeta allowlist / destinos de confianza / exclusiones, y solo actua si el ALTO
# esta configurado para ir a cuarentena. MEDIO/BAJO siguen en el ciclo de 5 min.
_FAST_LAST = {}            # ip -> ts de la ultima accion (anti-rebote por CPE)
_FAST_CNC = ("cnc", "c2 ", "command and control", "checkin", "check-in", "botnet", "mirai",
             "katana", "trojan", "ransom", "coinmin", "cryptomin", "compromised")
# Contacto con infraestructura FICHADA en los feeds. Por niveles, porque no todas las
# listas dicen lo mismo: un C2 activo (Feodo, ThreatFox) es prueba de que el equipo esta
# infectado y basta UNA vez; una IP que alguna vez escaneo a alguien (CINS) puede ser
# coincidencia, y ahi se exige insistencia.
_FAST_REP_C2 = ("c2-activo", "c2-ioc")
_FAST_REP_OTRAS = 3
try:                      # umbral de confirmacion; alinear con el del reporte (report.conf)
    _u = 3
    for _l in open("/etc/suricata-report.conf", encoding="utf-8"):
        if _l.strip().startswith("UMBRAL_INFECTADO="):
            _u = int(_l.split("=", 1)[1].strip() or "3"); break
    _FAST_UMBRAL = max(1, _u)
except Exception:
    _FAST_UMBRAL = 3

def barrido_alto_rapido(maxbytes=4_000_000):
    """Envia a cuarentena, casi al instante, los CPEs con INFECCION confirmada (CnC/botnet
    repetida) sin esperar el ciclo de 5 min. Idempotente y con anti-rebote de 60s por CPE."""
    m = cargar_mk()
    if not (mk_configurado() and m.get("ENABLED") == "1" and m.get("POL_AUTO") == "1"):
        return
    if m.get("POL_ALTO", "nada") != "cuarentena":
        return                                  # el barrido solo actua si ALTO -> cuarentena
    lst = m.get("LIST", "")
    if not lst:
        return
    try:
        with open(EVE, "rb") as f:
            f.seek(0, 2); size = f.tell(); start = max(0, size - maxbytes); f.seek(start); data = f.read()
    except OSError:
        return
    lines = data.decode("utf-8", "replace").split("\n")
    if start > 0 and lines:
        lines = lines[1:]                        # la 1a linea casi seguro viene cortada
    reglas = cargar_exclusiones(); dest_ok = _dest_ok_set()
    hits = {}; sids = {}; rep_hits = {}
    for line in lines:
        if '"event_type":"alert"' not in line:
            continue
        get = lambda k: (_RE[k].search(line).group(1) if _RE[k].search(line) else "")
        low = get("sig").lower()
        src_ip = get("src_ip"); dst = get("dest_ip"); dp = get("dest_port"); sid = get("sid")
        _es_cnc = any(k in low for k in _FAST_CNC)
        # el destino esta fichado? se mira SOLO si la firma no bastaba ya
        _cat = "" if _es_cnc else (rep_categoria(dst) if dst else "")
        if not _es_cnc and not _cat:
            continue                             # ni firma de infeccion ni destino fichado
        if not src_ip or nunca_bloquear(src_ip) or dst in dest_ok:
            continue
        if es_publica_declarada(src_ip):
            continue                             # es tu propia salida NAT, no un abonado
        if not es_mi_cpe(src_ip):
            continue                             # atacante de internet: no va a la cuarentena de CPEs
        if _excluido(reglas, src_ip, dst, int(dp) if dp else None, sid):
            continue
        src = clave_cpe(src_ip, rid_por_iface(get("iface")))   # identidad (router, IP)
        if _es_cnc:
            hits[src] = hits.get(src, 0) + 1
            sids.setdefault(src, set()).add(sid or low)
        else:
            rep_hits.setdefault(src, {"c2": 0, "otras": 0, "quien": "", "cat": ""})
            _r = rep_hits[src]
            if _cat in _FAST_REP_C2:
                _r["c2"] += 1
            else:
                _r["otras"] += 1
            if not _r["quien"]:
                _r["quien"] = dst; _r["cat"] = _cat
    ahora = time.time()
    env = cargar_enviados(MK_SENT); cambiado = False
    motivos = {}
    for src, r in rep_hits.items():
        # hablar con un C2 activo basta una vez; con el resto de listas, insistencia
        if r["c2"] >= 1:
            motivos[src] = "contacto con C2 activo (%s, %s)" % (r["quien"], r["cat"])
        elif r["otras"] >= _FAST_REP_OTRAS:
            motivos[src] = "%d contactos con infraestructura fichada (%s, %s)" % (
                r["otras"], r["quien"], r["cat"])
    for src in hits:
        if hits[src] >= _FAST_UMBRAL or len(sids[src]) >= 2:
            motivos[src] = "infeccion confirmada (%d alertas CnC, %d firmas)" % (
                hits[src], len(sids[src]))
    for src in motivos:
        if src in env or ahora - _FAST_LAST.get(src, 0) < 60:
            continue                             # ya en la lista, o anti-rebote 60s
        _FAST_LAST[src] = ahora
        try:
            _r = router_de_clave(src)
            _cat = categoria_cpe(src)
            lst = lista_de_categoria(_cat)      # cada categoria, a su lista
            ok, _err = mk_add(ip_de(src), comment=f"suricata ALTO inmediato {time.strftime('%Y-%m-%d %H:%M')}",
                              lista=lst, ttl="", router=_r)
        except Exception:
            ok = False
        if ok:
            env[src] = {"cuando": int(ahora), "score": "", "por": "politica-rapida", "manual": False,
                        "pol": True, "router": _r.get("id", ""), "categoria": _cat, "lista": lst,
                        "motivo": _motivo_bloqueo(src)}
            try: notificar_cuarentena(ip_de(src), "ALTO (envio inmediato)", lst, quien="politica-rapida")
            except Exception: pass
            mk_log("POLITICA-RAPIDA", ip_de(src), "politica",
                   f"lista={lst} {motivos.get(src, '')}" + _suf_nodo(src))
            cambiado = True
    if cambiado:
        guardar_enviados(env, MK_SENT)
    # limpiar anti-rebote viejo para no crecer sin fin
    for k in [k for k, v in _FAST_LAST.items() if ahora - v > 3600]:
        _FAST_LAST.pop(k, None)

# --- log de actividad unificado (accesos + acciones de cuarentena) + retencion ---
LOG_RETENCION_DIAS = 15   # los registros mas viejos que esto se borran solos

def _ev_ts(s):
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return 0.0

def _cola_lineas(path, nbytes=200000):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); sz = f.tell(); f.seek(max(0, sz - nbytes)); data = f.read()
        return data.decode("utf-8", "replace").splitlines()
    except OSError:
        return []

def actividad_reciente(n=800):
    """Eventos recientes (mas nuevo primero): accesos al panel + acciones de cuarentena.
    Devuelve tuplas (ts, tipo, ip, usuario, accion, detalle)."""
    evs = []
    for l in _cola_lineas(LOGIN_LOG):                      # accesos (TAB separado)
        p = l.split("\t")
        if len(p) >= 4:
            evs.append((p[0], "Acceso", p[1], p[2], p[3], ""))
    for l in _cola_lineas(MK_LOG):                         # cuarentena (espacio separado)
        t = l.split(" ")
        if len(t) >= 5:
            ts = t[0] + " " + t[1]; accion = t[2]; ip = t[3]
            quien = ""; det = []
            for x in t[4:]:
                if x.startswith("por="):
                    quien = x[4:]
                else:
                    det.append(x)
            evs.append((ts, "Cuarentena", ip, quien, accion, " ".join(det)))
    evs.sort(key=lambda e: e[0], reverse=True)
    return evs[:n]

def podar_logs():
    """Borra del log de accesos y del de cuarentena las lineas mas viejas que LOG_RETENCION_DIAS."""
    corte = time.time() - LOG_RETENCION_DIAS * 86400
    for path, sep in ((LOGIN_LOG, "\t"), (MK_LOG, " "), (BITACORA_LOG, "\t")):
        try:
            if not os.path.exists(path):
                continue
            keep = []
            for l in open(path, encoding="utf-8", errors="replace"):
                s = l.rstrip("\n")
                if not s:
                    continue
                if sep == "\t":
                    ts = s.split("\t", 1)[0]
                else:
                    parts = s.split(" ")
                    ts = (parts[0] + " " + parts[1]) if len(parts) >= 2 else s
                t = _ev_ts(ts)
                if t == 0.0 or t >= corte:     # conserva lo reciente (y lo no-parseable, por si acaso)
                    keep.append(l if l.endswith("\n") else l + "\n")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp, path)
        except OSError:
            pass

REPORTES_RETENCION_DIAS = 3   # reportes HTML guardados: se borra lo mas viejo que esto

def podar_reportes():
    """Borra los reportes HTML de mas de REPORTES_RETENCION_DIAS dias, conservando SIEMPRE
    el mas nuevo (En vivo sirve ese archivo, no debe quedarse sin ninguno)."""
    corte = time.time() - REPORTES_RETENCION_DIAS * 86400
    fs = glob.glob(f"{LOGDIR}/report-*.html")
    if not fs:
        return
    nuevo = max(fs, key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
    for f in fs:
        if f == nuevo:
            continue
        try:
            if os.path.getmtime(f) < corte:
                os.remove(f)
        except OSError:
            pass

# ---------------------------------------------------------------- usuarios y roles
USERS_FILE = "/etc/suricata-dashboard-users.json"
CTX = threading.local()   # contexto por peticion: user/role del que la hace
ROLES = ("admin", "operador", "lectura")   # operador: gestiona incidentes y cuarentenas; no toca usuarios/conexiones/updates

def _hash_pw(pw, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()
    return salt, h

def _blank_conf_pass():
    """Deja PASS= vacio en el .conf: la clave real ya vive hasheada en users.json.
    Evita la contrasena en texto plano en disco (y que el instalador la reimprima)."""
    try:
        lineas = open(CONF, encoding="utf-8").read().splitlines()
    except OSError:
        return
    out = []
    for l in lineas:
        out.append("PASS=" if l.strip().startswith("PASS=") else l)
    tmp = CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)
    CFG["PASS"] = ""

VENTANAS = [(30, "30 min"), (60, "1 hora"), (180, "3 horas"),
            (360, "6 horas"), (720, "12 horas"), (1440, "24 horas")]

def ventana_actual():
    try:
        return int(CFG.get("VENTANA_MIN", "1440") or "1440")
    except ValueError:
        return 1440

def set_ventana(minutos):
    """Persiste VENTANA_MIN en el .conf (agrega la linea si no existe) y actualiza CFG."""
    try:
        lineas = open(CONF, encoding="utf-8").read().splitlines()
    except OSError:
        lineas = []
    out, hecho = [], False
    for l in lineas:
        if l.strip().startswith("VENTANA_MIN="):
            out.append(f"VENTANA_MIN={minutos}"); hecho = True
        else:
            out.append(l)
    if not hecho:
        out.append(f"VENTANA_MIN={minutos}")
    tmp = CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)
    CFG["VENTANA_MIN"] = str(minutos)

def conf_dash_get(key, default=""):
    try:
        for l in open(CONF, encoding="utf-8"):
            if l.strip().startswith(key + "="):
                return l.split("=", 1)[1].strip()
    except OSError:
        pass
    return default

def conf_dash_set(key, val):
    """Escribe/actualiza una clave en /etc/suricata-dashboard.conf (lo lee el generador)."""
    try:
        lineas = open(CONF, encoding="utf-8").read().splitlines()
    except OSError:
        lineas = []
    out, hecho = [], False
    for l in lineas:
        if l.strip().startswith(key + "="):
            out.append(f"{key}={val}"); hecho = True
        else:
            out.append(l)
    if not hecho:
        out.append(f"{key}={val}")
    try:
        tmp = CONF + ".tmp"
        open(tmp, "w", encoding="utf-8").write("\n".join(out) + "\n")
        os.chmod(tmp, 0o600); os.replace(tmp, CONF)
    except OSError:
        pass

# --- feeds de reputacion: Auth-Key (abuse.ch) y estado por fuente ---
FEEDS_CONF = "/etc/suricata-feeds.conf"
FEEDS_META = "/var/lib/suricata-feeds/reputation.meta"

def _feeds_conf_get(clave):
    """Valor de una clave del .conf de feeds. Solo lo usa el codigo que HACE la peticion;
    nunca se devuelve a una pagina."""
    try:
        for l in open(FEEDS_CONF, encoding="utf-8"):
            l = l.strip()
            if l.startswith(clave + "=") and not l.startswith("#"):
                return l.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""

def _feeds_conf_set(clave, val):
    """Guarda/actualiza (o borra) una clave en /etc/suricata-feeds.conf (permisos 600).
    Solo-escritura: el valor NO se muestra despues. Conserva los comentarios/plantilla."""
    try:
        lineas = open(FEEDS_CONF, encoding="utf-8").read().splitlines()
    except OSError:
        lineas = []
    out = [l for l in lineas if not l.strip().startswith(clave + "=")]   # quita la activa vieja
    v = (val or "").strip()
    if v:
        out.append(f"{clave}={v}")
    try:
        tmp = FEEDS_CONF + ".tmp"
        open(tmp, "w", encoding="utf-8").write("\n".join(out) + "\n")
        os.chmod(tmp, 0o600); os.replace(tmp, FEEDS_CONF); os.chmod(FEEDS_CONF, 0o600)
        return True
    except OSError:
        return False

def feeds_auth_configurada():
    """La Auth-Key de abuse.ch esta puesta? (nunca se devuelve el valor, solo si existe)."""
    return bool(_feeds_conf_get("ABUSE_CH_AUTH_KEY"))

def feeds_auth_set(val):
    return _feeds_conf_set("ABUSE_CH_AUTH_KEY", val)

def feeds_auth_probar(key):
    """Valida una Auth-Key contra abuse.ch (URLhaus). Devuelve (estado, msg):
    True=valida, False=invalida (rechazada/HTML), None=no se pudo comprobar (sin red)."""
    key = (key or "").strip()
    if not key:
        return False, "vacia"
    try:
        req = urllib.request.Request("https://urlhaus.abuse.ch/downloads/hostfile/",
                                     headers={"Auth-Key": key, "User-Agent": "suricata-feeds/2.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read(2048).decode("utf-8", "replace")
        low = body.lstrip()[:200].lower()
        if low.startswith("<!doctype html") or "<html" in low or "<title" in low:
            return False, "abuse.ch respondio una pagina HTML (clave invalida o login requerido)"
        return True, "valida"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, f"abuse.ch rechazo la clave (HTTP {e.code})"
        return None, f"no se pudo comprobar (HTTP {e.code})"
    except Exception:
        return None, "no se pudo comprobar ahora (sin red?)"

def cargar_feeds_meta():
    try:
        return json.load(open(FEEDS_META, encoding="utf-8"))
    except Exception:
        return {}

def actualizar_feeds_async():
    try:
        subprocess.Popen(["/usr/local/bin/suricata-feeds-update"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------------
# AbuseIPDB: que hace REALMENTE una IP publica
# ---------------------------------------------------------------------------------
# Los feeds dicen "esta IP es mala". AbuseIPDB dice ademas POR QUE: las categorias de las
# denuncias de la comunidad (escaneo de puertos, fuerza bruta SSH, ataque a aplicacion
# web...). Eso es lo que permite pasar de "la bloqueo" a "se que hay que corregir".
#
# El plan gratuito da 1.000 consultas AL DIA, asi que NO se puede enriquecer todo solo:
# hay cache, presupuesto diario y una reserva que lo automatico no puede tocar (para que
# un barrido no deje al operador sin consultas). Y el UNICO proceso que llama a la API es
# el panel: el generador del reporte solo LEE la cache, porque dos procesos gastando la
# misma cuota se la comen sin que nadie lleve la cuenta.
AIDB_CACHE = "/var/lib/suricata-feeds/abuseipdb.json"
AIDB_ESTADO = "/var/lib/suricata-feeds/abuseipdb-estado.json"
AIDB_TTL_LIMPIA = 7 * 24 * 3600    # sin denuncias: cambia poco
AIDB_TTL_SUCIA = 12 * 3600         # con denuncias: cambia rapido
AIDB_CUOTA = 1000                  # consultas por IP al dia (plan gratuito "Standard")
AIDB_CUOTA_BLOQUE = 100            # consultas por RED al dia: es una cuota APARTE
AIDB_PREFIJO_MIN = 16              # /16 = 65.536 direcciones; por debajo no lo acepta nadie
AIDB_RESERVA_MANUAL = 300          # consultas que SOLO puede gastar el operador a mano
AIDB_MAX_LOTE = 25                 # IPs por consulta manual
AIDB_MAX_CACHE = 20000
_AIDB_LOCK = threading.RLock()

# Taxonomia oficial (https://www.abuseipdb.com/categories) en castellano, y que implica
# cada cosa cuando la IP denunciada es TUYA (el caso que de verdad hay que corregir).
AIDB_CATS = {
    1: "DNS comprometido", 2: "Envenenamiento de DNS", 3: "Pedidos fraudulentos",
    4: "Ataque DDoS", 5: "Fuerza bruta FTP", 6: "Ping de la muerte", 7: "Phishing",
    8: "Fraude VoIP", 9: "Proxy abierto o Tor", 10: "Spam web", 11: "Spam de correo",
    12: "Spam en blogs", 13: "IP de VPN", 14: "Escaneo de puertos", 15: "Hackeo",
    16: "Inyeccion SQL", 17: "Suplantacion de remitente", 18: "Fuerza bruta",
    19: "Bot web abusivo", 20: "Host comprometido", 21: "Ataque a aplicacion web",
    22: "SSH", 23: "Dirigido a IoT",
}
AIDB_REMEDIO = {
    4: "Equipo dentro participando en una botnet: buscar el CPE y ponerlo en cuarentena.",
    5: "Hay un FTP expuesto a internet. Cerrarlo o limitarlo por origen.",
    7: "Alojamiento de phishing: revisar hosting/servidor propio en esa IP.",
    9: "Proxy abierto: revisar NAT y puertos redirigidos sin querer.",
    11: "Salida de spam: bloquear 25/tcp saliente salvo tu servidor de correo.",
    14: "Alguien detras de esa IP escanea internet: casi siempre un equipo infectado.",
    16: "Aplicacion web expuesta siendo usada para atacar: revisar el servidor.",
    18: "Fuerza bruta de credenciales: cerrar el acceso remoto o limitarlo por origen.",
    20: "Equipo comprometido: aislarlo y limpiarlo, no solo bloquearlo.",
    21: "Servicio web expuesto (router, camara, panel) usado para atacar.",
    22: "SSH abierto a internet: cerrarlo desde la WAN o mover/limitar el puerto.",
    23: "Camara, DVR o IoT expuesto: firmware y credenciales por defecto.",
}

def aidb_key():
    return _feeds_conf_get("ABUSEIPDB_KEY")

def aidb_configurada():
    return bool(aidb_key())

def aidb_set(val):
    return _feeds_conf_set("ABUSEIPDB_KEY", val)

def _aidb_estado():
    """Gasto del dia. La cuota de AbuseIPDB se reinicia a medianoche UTC, no local."""
    try:
        d = json.load(open(AIDB_ESTADO, encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    hoy = time.strftime("%Y-%m-%d", time.gmtime())
    if d.get("dia") != hoy:
        d = {"dia": hoy, "gastadas": 0, "auto": 0, "bloques": 0, "bloqueada_hasta": 0}
    d.setdefault("bloques", 0)     # instalaciones que ya tenian el archivo sin este campo
    return d

def _aidb_guardar_estado(d):
    try:
        tmp = "%s.%d.tmp" % (AIDB_ESTADO, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, AIDB_ESTADO)
    except OSError:
        pass

def aidb_restantes():
    e = _aidb_estado()
    return max(0, AIDB_CUOTA - int(e.get("gastadas", 0)))

def aidb_restantes_bloque():
    e = _aidb_estado()
    return max(0, AIDB_CUOTA_BLOQUE - int(e.get("bloques", 0)))

def _aidb_cache():
    try:
        return json.load(open(AIDB_CACHE, encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def _aidb_guardar_cache(c):
    try:
        os.makedirs(os.path.dirname(AIDB_CACHE), exist_ok=True)
        tmp = "%s.%d.%d.tmp" % (AIDB_CACHE, os.getpid(), threading.get_ident())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(c, f)
        os.replace(tmp, AIDB_CACHE)
    except OSError:
        pass

def aidb_ip_valida(ip):
    """Solo IPs PUBLICAS. Las privadas ni se envian: son las de tus abonados y ademas
    AbuseIPDB las rechaza."""
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False, "no es una IP"
    if not o.is_global:
        return False, "no es una IP publica"
    return True, ""

def aidb_red_valida(cidr):
    """Una RED publica en notacion CIDR. Se rechazan las privadas por lo mismo que las
    IPs sueltas, y las descomunales porque ningun plan las acepta (y la respuesta seria
    enorme)."""
    try:
        red = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None, "no es una red valida (ej: 200.0.0.0/24)"
    if red.version != 4:
        return None, "solo redes IPv4"
    if not red.is_global:
        return None, "no es una red publica"
    if red.prefixlen < AIDB_PREFIJO_MIN:
        return None, f"demasiado grande: como mucho /{AIDB_PREFIJO_MIN}"
    return red, ""

def _aidb_pedir_red(cidr, dias=30):
    """Una llamada a /check-block: devuelve QUE direcciones de esa red estan denunciadas.
    Una peticion cubre las 256 de un /24, en vez de 256 consultas sueltas."""
    key = aidb_key()
    if not key:
        return None, "sin clave", False
    url = ("https://api.abuseipdb.com/api/v2/check-block?network=" + urllib.parse.quote(cidr)
           + "&maxAgeInDays=%d" % dias)
    req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json",
                                               "User-Agent": "suricata-panel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            try:
                espera = int(e.headers.get("Retry-After", "0") or 0)
            except (TypeError, ValueError):
                espera = 0
            return None, "cuota:%d" % (espera or 3600), True
        if e.code == 402:
            # el plan no llega a ese tamaño: gratis es /24, y de pago /20 o /16
            return None, ("tu plan de AbuseIPDB no permite una red tan grande "
                          "(el gratuito llega a /24)"), True
        if e.code in (401, 403):
            return None, "AbuseIPDB rechazo la clave (HTTP %d)" % e.code, True
        if e.code == 422:
            return None, "AbuseIPDB no acepta esa red", True
        return None, "HTTP %d" % e.code, True
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, "sin respuesta de AbuseIPDB", False
    except ValueError:
        return None, "respuesta ilegible de AbuseIPDB", True
    return (d or {}).get("data") or {}, "", True

def _aidb_resumen_red(cidr, d):
    den = []
    for r in (d.get("reportedAddress") or []):
        try:
            den.append([r.get("ipAddress", ""), int(r.get("abuseConfidenceScore") or 0),
                        int(r.get("numReports") or 0), (r.get("mostRecentReport") or "")[:10],
                        (r.get("countryCode") or "")[:2]])
        except (TypeError, ValueError):
            continue
    den.sort(key=lambda x: (x[1], x[2]), reverse=True)
    return {"red": cidr, "tipo": "red",
            "hosts": int(d.get("numPossibleHosts") or 0),
            "desc": (d.get("addressSpaceDesc") or "")[:60],
            "denunciadas": den[:512], "n_den": len(den), "ts": int(time.time())}

def aidb_consultar_red(cidr, refrescar=False):
    """Ficha de una red. Devuelve (datos|None, origen, error). Nunca lanza."""
    red, porque = aidb_red_valida(cidr)
    if red is None:
        return None, "", porque
    clave = str(red)
    ahora = time.time()
    with _AIDB_LOCK:
        ent = _aidb_cache().get(clave)
        if ent and not refrescar and ahora - ent.get("ts", 0) < AIDB_TTL_SUCIA:
            return ent, "cache", ""
        est = _aidb_estado()
        if est.get("bloqueada_hasta", 0) > ahora or int(est.get("bloques", 0)) >= AIDB_CUOTA_BLOQUE:
            return (ent, "cache", "") if ent else (None, "", "cuota de redes agotada por hoy")
    d, err, gastada = _aidb_pedir_red(clave)
    with _AIDB_LOCK:
        est = _aidb_estado()
        if gastada:
            est["bloques"] = int(est.get("bloques", 0)) + 1
        if err.startswith("cuota:"):
            est["bloqueada_hasta"] = ahora + int(err.split(":", 1)[1])
            est["bloques"] = AIDB_CUOTA_BLOQUE
            _aidb_guardar_estado(est)
            return (ent, "cache", "") if ent else (None, "", "cuota de redes agotada por hoy")
        _aidb_guardar_estado(est)
        if err:
            return (ent, "cache", err) if ent else (None, "", err)
        res = _aidb_resumen_red(clave, d)
        cache = _aidb_cache()
        cache[clave] = res
        _aidb_guardar_cache(cache)
    return res, "api", ""

def aidb_lote(texto, refrescar=False):
    """Reparte lo que pego el usuario: lo que lleva '/' va al endpoint de REDES (una
    peticion por red) y el resto a consultas por IP. Devuelve (resultados, aviso)."""
    pedidas = [t.strip() for t in re.split(r"[\s,;]+", texto or "") if t.strip()]
    vistas = []
    for t in pedidas:
        if t not in vistas:
            vistas.append(t)        # repetir gasta cuota para nada
    sobran = max(0, len(vistas) - AIDB_MAX_LOTE)
    res = []
    for t in vistas[:AIDB_MAX_LOTE]:
        if "/" in t:
            res.append((t,) + aidb_consultar_red(t, refrescar=refrescar))
        else:
            res.append((t,) + aidb_consultar(t, refrescar=refrescar))
    if not vistas:
        return res, "No pusiste ninguna IP ni red."
    if sobran:
        return res, f"Se consultaron {AIDB_MAX_LOTE}; quedan {sobran} sin consultar (repite la operacion)."
    return res, ""

def _aidb_pedir(ip, dias=90):
    """Una llamada a /check con detalle. Devuelve (datos, error, gastada).

    No hay un 'except Exception' a lo ancho a proposito: 'sin clave', 'cuota agotada' y
    'sin red' se arreglan de formas distintas, y un fallo mudo aqui seria invisible."""
    key = aidb_key()
    if not key:
        return None, "sin clave", False
    url = ("https://api.abuseipdb.com/api/v2/check?ipAddress=" + urllib.parse.quote(ip)
           + "&maxAgeInDays=%d&verbose" % dias)
    req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json",
                                               "User-Agent": "suricata-panel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            try:
                espera = int(e.headers.get("Retry-After", "0") or 0)
            except (TypeError, ValueError):
                espera = 0
            return None, "cuota:%d" % (espera or 3600), True
        if e.code in (401, 403):
            return None, "AbuseIPDB rechazo la clave (HTTP %d)" % e.code, True
        if e.code == 422:
            return None, "AbuseIPDB no acepta esa IP", True
        return None, "HTTP %d" % e.code, True
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, "sin respuesta de AbuseIPDB", False
    except ValueError:
        return None, "respuesta ilegible de AbuseIPDB", True
    return (d or {}).get("data") or {}, "", True

def _aidb_resumen(d):
    """Se queda con lo util y, sobre todo, con QUE ataques se le denuncian."""
    cats = {}; ejemplos = []
    for r in (d.get("reports") or [])[:80]:
        for c in (r.get("categories") or []):
            try:
                cats[int(c)] = cats.get(int(c), 0) + 1
            except (TypeError, ValueError):
                continue
        com = (r.get("comment") or "").strip()
        if com and len(ejemplos) < 3:
            ejemplos.append(com[:160])
    orden = sorted(cats.items(), key=lambda kv: kv[1], reverse=True)[:8]
    return {"ip": d.get("ipAddress", ""), "score": int(d.get("abuseConfidenceScore") or 0),
            "pais": (d.get("countryCode") or "")[:2], "isp": (d.get("isp") or "")[:70],
            "dominio": (d.get("domain") or "")[:60], "uso": (d.get("usageType") or "")[:50],
            "tor": bool(d.get("isTor")), "blanca": bool(d.get("isWhitelisted")),
            "reportes": int(d.get("totalReports") or 0),
            "denunciantes": int(d.get("numDistinctUsers") or 0),
            "ultimo": (d.get("lastReportedAt") or "")[:19],
            "cats": [[c, n] for c, n in orden],
            # ya traducidas: el generador del reporte las pinta sin conocer la taxonomia
            "cats_nom": [AIDB_CATS.get(c, "categoria %d" % c) for c, _n in orden],
            "ejemplos": ejemplos, "ts": int(time.time())}

def aidb_consultar(ip, auto=False, refrescar=False):
    """Ficha de una IP publica. Devuelve (datos|None, origen, error);
    origen es 'cache' o 'api'. Nunca lanza."""
    ok, porque = aidb_ip_valida(ip)
    if not ok:
        return None, "", porque
    ahora = time.time()
    with _AIDB_LOCK:
        ent = _aidb_cache().get(ip)
        if ent and not refrescar:
            ttl = AIDB_TTL_SUCIA if ent.get("score", 0) else AIDB_TTL_LIMPIA
            if ahora - ent.get("ts", 0) < ttl:
                return ent, "cache", ""
        est = _aidb_estado()
        if est.get("bloqueada_hasta", 0) > ahora:
            return (ent, "cache", "") if ent else (None, "", "cuota diaria agotada")
        # lo automatico no puede comerse la reserva del operador
        tope = AIDB_CUOTA - (AIDB_RESERVA_MANUAL if auto else 0)
        if int(est.get("gastadas", 0)) >= tope:
            falta = "sin cuota para lo automatico" if auto else "cuota diaria agotada"
            return (ent, "cache", "") if ent else (None, "", falta)
    d, err, gastada = _aidb_pedir(ip)
    with _AIDB_LOCK:
        est = _aidb_estado()
        if gastada:
            est["gastadas"] = int(est.get("gastadas", 0)) + 1
            if auto:
                est["auto"] = int(est.get("auto", 0)) + 1
        if err.startswith("cuota:"):
            est["bloqueada_hasta"] = ahora + int(err.split(":", 1)[1])
            est["gastadas"] = AIDB_CUOTA
            _aidb_guardar_estado(est)
            return (ent, "cache", "") if ent else (None, "", "cuota diaria agotada")
        _aidb_guardar_estado(est)
        if err:
            return (ent, "cache", err) if ent else (None, "", err)
        res = _aidb_resumen(d)
        cache = _aidb_cache()
        cache[ip] = res
        if len(cache) > AIDB_MAX_CACHE:       # poda: no crecer sin fin en un espejo de ISP
            for k, _v in sorted(cache.items(), key=lambda kv: kv[1].get("ts", 0))[:5000]:
                cache.pop(k, None)
        _aidb_guardar_cache(cache)
    return res, "api", ""

def precargar_abuseipdb(max_por_ciclo=4):
    """Va llenando la cache con los destinos de los CPEs candidatos, de a pocos.

    Solo mira DESTINOS (publicos): la IP del abonado es privada y no sale de aqui. Usa
    auto=True, asi que nunca puede comerse la reserva de consultas del operador, y si se
    queda sin cuota o sin red deja de insistir hasta el ciclo siguiente."""
    if not aidb_configurada():
        return 0
    try:
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    destinos = []
    for key in ("candidatos", "dns_candidatos"):
        for c in cq.get(key, []):
            for d in (c.get("destinos_ip") or []):
                if d not in destinos:
                    destinos.append(d)
    hechas = 0
    for ip in destinos:
        if hechas >= max_por_ciclo:
            break
        ok, _porque = aidb_ip_valida(ip)
        if not ok:
            continue
        _d, origen, err = aidb_consultar(ip, auto=True)
        if origen == "api":
            hechas += 1
        elif err:
            break               # sin cuota o sin red: no machacar en este ciclo
    return hechas

# --- Denunciar de vuelta -----------------------------------------------------------
# Es la unica funcion del panel que PUBLICA algo hacia fuera y con tu nombre, asi que:
# viene apagada, no se dispara sola (siempre la pulsa una persona), solo acepta atacantes
# ENTRANTES (IPs publicas que golpean TU red, nunca tus abonados) y el comentario va sin
# datos de nadie. AbuseIPDB pide expresamente que no se manden datos personales.
AIDB_DENUNCIAS = "/var/lib/suricata-feeds/abuseipdb-denuncias.json"
AIDB_REDENUNCIA = 24 * 3600      # no repetir la misma IP antes de esto
PANEL_FLAGS = "/var/log/suricata-panel-flags.json"   # sin secretos: lo lee el reporte

# Firma de Suricata -> categorias de AbuseIPDB. Se SUMAN todas las que casan; no manda la
# primera. "ET SCAN Potential SSH Scan" es un escaneo Y es SSH: con la primera ganando se
# denunciaba como FUERZA BRUTA algo que solo era un escaneo, y esto se publica a tu nombre.
AIDB_FIRMA_CAT = [
    (("ssh", "sshd"), [22]),
    (("sql injection", "sqli"), [16]),
    (("wordpress", "phpmyadmin", "web application", "web app", "web_server",
      "shellshock", "struts", "joomla", "drupal"), [21]),
    (("telnet", "mirai", "iot", "dvr", "hikvision"), [23]),
    (("scan", "nmap", "masscan", "sweep", "probe"), [14]),
    (("brute", "fuerza bruta", "login", "credential", "password"), [18]),
    (("rdp", "remote desktop", "vnc"), [18]),
    (("ftp",), [5]),
    (("sip", "voip", "asterisk"), [8]),
    (("ddos", "denial of service", "flood", "amplification"), [4]),
    (("spam", "smtp"), [11]),
    (("proxy", "tor exit"), [9]),
    # ojo con las claves cortas: "rce" casaba dentro de "brute force" y denunciaba
    # como Hackeo cualquier ataque de credenciales. Mejor la frase entera.
    (("exploit", "cve-", "remote code execution", "overflow"), [15]),
]

def aidb_reportar_activo():
    return _feeds_conf_get("ABUSEIPDB_REPORTAR") == "1"

def aidb_set_reportar(v):
    ok = _feeds_conf_set("ABUSEIPDB_REPORTAR", "1" if v else "")
    publicar_flags()
    return ok

def publicar_flags():
    """Publica para el generador del reporte lo que necesita saber del panel. Va aparte
    del .conf a proposito: ese archivo lleva las CLAVES y aqui no hace falta ninguna."""
    try:
        tmp = PANEL_FLAGS + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"aidb_reportar": aidb_reportar_activo()}, f)
        os.replace(tmp, PANEL_FLAGS)
    except OSError:
        pass

def aidb_cats_de_firma(firma, dport=""):
    """Categorias que mejor describen el ataque. Si no se reconoce la firma se denuncia
    como 'Hackeo', que es lo que honestamente sabemos: un IDS salto."""
    low = (firma or "").lower()
    cats = []
    for claves, cs in AIDB_FIRMA_CAT:
        if any(k in low for k in claves):
            for c in cs:
                if c not in cats:
                    cats.append(c)
    if cats:
        return cats[:4]                    # acepta varias; con 4 ya queda descrito de sobra
    if str(dport) in ("22", "2222"):
        return [18, 22]
    if str(dport) in ("23", "2323"):
        return [23, 15]
    return [15]

def aidb_comentario(firma, dport="", proto="", n=0):
    """Texto de la denuncia SIN datos de nadie: fuera cualquier IP (la del atacante ya va
    en su campo y la de la victima no tiene por que publicarse) y fuera caracteres raros."""
    f = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "", firma or "")
    f = re.sub(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}", "", f)   # IPv6, tambien con ::
    f = re.sub(r"[^A-Za-z0-9 ._:/()\-]", " ", f)
    f = re.sub(r"\s+", " ", f).strip()[:140]
    partes = ["Suricata IDS"]
    if f:
        partes.append(f)
    if str(dport).isdigit():
        partes.append("puerto %s/%s" % (dport, (proto or "tcp").lower()[:4]))
    if n:
        partes.append("%d alertas" % int(n))
    return " | ".join(partes)[:180]

def _aidb_denuncias():
    try:
        return json.load(open(AIDB_DENUNCIAS, encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def _aidb_guardar_denuncias(d):
    try:
        os.makedirs(os.path.dirname(AIDB_DENUNCIAS), exist_ok=True)
        tmp = "%s.%d.tmp" % (AIDB_DENUNCIAS, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, AIDB_DENUNCIAS)
    except OSError:
        pass

def aidb_denunciar(ip, firma="", dport="", proto="", n=0, quien="?"):
    """Denuncia UN atacante entrante. Devuelve (ok, mensaje). Nunca lanza."""
    if not aidb_reportar_activo():
        return False, "las denuncias estan apagadas (Ajustes -> Reputacion)"
    if not aidb_configurada():
        return False, "falta la clave de AbuseIPDB"
    ok, porque = aidb_ip_valida(ip)
    if not ok:
        return False, porque
    if es_mi_cpe(ip):
        # denunciar tu propio rango te mete a VOS en las listas negras
        return False, f"{ip} es de TUS redes: eso se corrige adentro, no se denuncia"
    if nunca_bloquear(ip):
        return False, f"{ip} esta en la lista 'Nunca bloquear'"
    ahora = time.time()
    with _AIDB_LOCK:
        reg = _aidb_denuncias()
        prev = reg.get(ip, {})
        if ahora - prev.get("ts", 0) < AIDB_REDENUNCIA:
            cuando = time.strftime("%d/%m %H:%M", time.localtime(prev.get("ts", 0)))
            return False, f"{ip} ya se denuncio el {cuando} (se espera 24 h para repetir)"
    cats = aidb_cats_de_firma(firma, dport)
    datos = urllib.parse.urlencode({"ip": ip, "categories": ",".join(str(c) for c in cats),
                                    "comment": aidb_comentario(firma, dport, proto, n)})
    req = urllib.request.Request(
        "https://api.abuseipdb.com/api/v2/report", data=datos.encode("utf-8"),
        headers={"Key": aidb_key(), "Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "suricata-panel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return False, "cuota de denuncias agotada por hoy"
        if e.code in (401, 403):
            return False, f"AbuseIPDB rechazo la clave (HTTP {e.code})"
        if e.code == 422:
            return False, "AbuseIPDB no acepto la denuncia (IP propia o ya denunciada)"
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError):
        return False, "sin respuesta de AbuseIPDB"
    except ValueError:
        return False, "respuesta ilegible de AbuseIPDB"
    sc = ((d or {}).get("data") or {}).get("abuseConfidenceScore")
    with _AIDB_LOCK:
        reg = _aidb_denuncias()
        reg[ip] = {"ts": int(ahora), "por": quien, "cats": cats}
        lim = ahora - 30 * 86400
        for k in [k for k, v in reg.items() if v.get("ts", 0) < lim]:
            reg.pop(k, None)
        _aidb_guardar_denuncias(reg)
    bitacora("DENUNCIA-ABUSEIPDB", f"{ip} cats={','.join(str(c) for c in cats)}", quien=quien)
    nom = ", ".join(AIDB_CATS.get(c, str(c)) for c in cats)
    return True, f"{ip} denunciado como {nom}" + (f" (ahora {sc}% de abuso)" if sc is not None else "")

# ---------------------------------------------------------------------------------
# Las IPs PUBLICAS del cliente (el NAT de salida)
# ---------------------------------------------------------------------------------
# El espejo del MikroTik es PRE-NAT: Suricata ve 10.x, nunca la IP publica por la que
# salio el ataque. Por eso las publicas se DECLARAN aqui, por nodo. A partir de ahi:
#
#   la reputacion de la publica dice QUE tipo de abuso sale por ella,
#   Suricata dice QUIEN, dentro de ese nodo, hace ese tipo de trafico,
#   y el cruce de las dos cosas es el abonado al que hay que meter en cuarentena.
#
# Sin el cruce solo se sabe "algo sale mal por esta IP", que no sirve para actuar.
PUBLICAS_CONF = "/etc/suricata-publicas.json"
PUB_HIST = "/var/log/suricata-publicas-reputacion.json"
PUB_HIST_DIAS = 180
PUB_UMBRAL_AVISO = 25          # a partir de aqui la IP ya esta ensuciada: avisar
_PUB_LOCK = threading.RLock()

def cargar_publicas():
    """{id_router: [ "200.0.0.0/24", "190.0.2.7", ... ]}"""
    try:
        d = json.load(open(PUBLICAS_CONF, encoding="utf-8"))
        n = d.get("nodos")
        if isinstance(n, dict):
            return {k: [str(x) for x in (v or [])] for k, v in n.items()}
    except (OSError, ValueError, AttributeError):
        pass
    return {}

def guardar_publicas(d):
    tmp = PUBLICAS_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"nodos": d}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, PUBLICAS_CONF)
    return d

def es_publica_declarada(ip):
    """La IP es una de las publicas que declaraste (o cae en una de sus redes)?

    Existe por el modo POST-NAT: si el sensor mira la WAN, HOME_NET son tus rangos
    publicos y el panel las trata como CPEs. Mandar tu IP de NAT a la cuarentena dejaria
    sin internet a TODOS los abonados que salen por ella."""
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for rid, entradas in cargar_publicas().items():
        for e in entradas:
            try:
                if "/" in e:
                    if o in ipaddress.ip_network(e, strict=False):
                        return e
                elif str(o) == e:
                    return e
            except ValueError:
                continue
    return ""

def publicas_texto(rid):
    return "\n".join(cargar_publicas().get(rid, []))

def guardar_publicas_de(rid, texto):
    """Guarda las entradas de un nodo. Devuelve (guardadas, rechazadas)."""
    ok, mal = [], []
    for t in re.split(r"[\s,;]+", texto or ""):
        t = t.strip()
        if not t:
            continue
        if "/" in t:
            red, porque = aidb_red_valida(t)
            (ok.append(str(red)) if red is not None else mal.append(f"{t} ({porque})"))
        else:
            v, porque = aidb_ip_valida(t)
            (ok.append(t) if v else mal.append(f"{t} ({porque})"))
    d = cargar_publicas()
    if ok:
        d[rid] = sorted(set(ok))
    else:
        d.pop(rid, None)
    guardar_publicas(d)
    return ok, mal

def _pub_hist():
    try:
        return json.load(open(PUB_HIST, encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def _guardar_pub_hist(d):
    try:
        tmp = "%s.%d.tmp" % (PUB_HIST, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, PUB_HIST)
    except OSError:
        pass

def _peor_de(dat):
    """Puntaje representativo de una entrada: el de la IP, o el peor de la red."""
    if not dat:
        return 0
    if dat.get("tipo") == "red":
        den = dat.get("denunciadas") or []
        return max([int(x[1]) for x in den] or [0])
    return int(dat.get("score") or 0)

def _cats_de(dat):
    """Categorias denunciadas de una entrada, como lista de ids."""
    if not dat or dat.get("tipo") == "red":
        return []          # el endpoint de bloques no trae categorias (hay que mirar la IP)
    return [int(c) for c, _n in (dat.get("cats") or []) if str(c).isdigit()]

def vigilar_publicas(forzar=False):
    """Revisa la reputacion de las publicas declaradas y guarda la serie por dia.
    Corre en el hilo de fondo; si no hay nada declarado, no hace nada ni gasta cuota."""
    decl = cargar_publicas()
    if not decl or not aidb_configurada():
        return 0
    hoy = time.strftime("%Y-%m-%d")
    hist = _pub_hist()
    n = 0
    for rid, entradas in decl.items():
        for ent in entradas:
            if "/" in ent:
                dat, origen, err = aidb_consultar_red(ent, refrescar=forzar)
            else:
                dat, origen, err = aidb_consultar(ent, refrescar=forzar)
            if not dat:
                continue
            if origen == "api":
                n += 1
            sc = _peor_de(dat)
            h = hist.get(ent)
            if not isinstance(h, dict):
                h = {"router": rid, "dias": {}}
            antes = int(h.get("ultimo_score", 0))
            h["router"] = rid
            h["dias"] = h.get("dias") or {}
            h["dias"][hoy] = sc
            lim = time.strftime("%Y-%m-%d", time.localtime(time.time() - PUB_HIST_DIAS * 86400))
            h["dias"] = {k: v for k, v in h["dias"].items() if k >= lim}
            h["ultimo_score"] = sc
            h["ultimo_ts"] = int(time.time())
            hist[ent] = h
            # aviso solo al CRUZAR el umbral: si no, avisaria en cada vuelta
            if sc >= PUB_UMBRAL_AVISO and antes < PUB_UMBRAL_AVISO:
                nom = (router_por_id(rid) or {}).get("nombre") or rid
                try:
                    enviar_telegram(f"\u26a0\ufe0f IP publica ensuciada [{_hostname()}]: {ent} "
                                    f"({nom}) esta denunciada ({sc} % de abuso). "
                                    f"Panel -> Consultar IP para ver que abonado lo causa.")
                except Exception:
                    pass
                bitacora("PUBLICA-DENUNCIADA", f"{ent} score={sc} nodo={nom}", quien="auto")
    with _PUB_LOCK:
        _guardar_pub_hist(hist)
    return n

# --- de la categoria denunciada a la señal que SI ve Suricata ----------------------
# Cada categoria de AbuseIPDB se traduce a los puertos de salida y a las categorias de
# firma con las que ese abuso se manifiesta puertas adentro. Es una traduccion, no una
# certeza: sirve para ORDENAR sospechosos, no para condenar a nadie sola.
AIDB_SENAL = {
    4:  {"cats": ["Botnet", "Botnet CnC", "Botnet Mirai", "Botnet Katana"]},
    5:  {"puertos": ["21"], "cats": ["Fuerza bruta"]},
    8:  {"puertos": ["5060", "5061"], "cats": ["Fuerza bruta"]},
    9:  {"puertos": ["3128", "8080", "1080", "9050"]},
    11: {"puertos": ["25", "465", "587"], "cats": ["Spam"]},
    14: {"cats": ["Escaneo de puertos", "Escaneo saliente", "Escaneo SSH",
                  "Escaneo Telnet", "Escaneo TR-069"]},
    15: {"cats": ["Exploit", "Trafico de malware"]},
    16: {"puertos": ["80", "443", "3306", "1433"], "cats": ["Exploit"]},
    18: {"puertos": ["22", "23", "21", "3389", "5060", "2222"], "cats": ["Fuerza bruta"]},
    19: {"puertos": ["80", "443"], "cats": ["Anomalia HTTP", "User-Agent raro", "Cliente HTTP Go"]},
    20: {"cats": ["Botnet CnC", "Troyano", "Trafico de malware", "Ransomware", "Criptomineria"]},
    21: {"puertos": ["80", "443", "8080", "8443"], "cats": ["Exploit", "Anomalia HTTP"]},
    22: {"puertos": ["22", "2222"], "cats": ["Escaneo SSH", "Fuerza bruta"]},
    23: {"puertos": ["23", "2323", "7547", "37215"],
         "cats": ["Escaneo Telnet", "Escaneo TR-069", "Botnet Mirai"]},
}

def senal_de_categorias(cats):
    """Puertos y categorias de firma a buscar, a partir de las categorias denunciadas."""
    puertos, firmas = set(), set()
    for c in cats or []:
        sen = AIDB_SENAL.get(int(c)) or {}
        puertos |= set(sen.get("puertos") or [])
        firmas |= set(sen.get("cats") or [])
    return puertos, firmas

def _cpes_del_nodo(rid):
    """CPEs con actividad del reporte actual, con lo que hace falta para el cruce."""
    try:
        cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
    except (OSError, ValueError):
        return []
    fuera = {}
    for clave in ("candidatos", "dns_candidatos", "top_riesgo"):
        for c in cq.get(clave, []):
            if (c.get("router") or "") != (rid or ""):
                continue
            k = clave_cpe(c.get("ip", ""), c.get("router", ""))
            prev = fuera.get(k) or {}
            # 'candidatos' trae mas contexto que 'top_riesgo': que no lo pise
            fuera[k] = {**c, **{x: y for x, y in prev.items() if y and not c.get(x)}}
    return list(fuera.items())

def culpables_de(rid, cats, tope=12):
    """Ordena los CPEs de ese nodo por cuanto encajan con lo que se denuncia de su IP
    publica. Devuelve [(clave, cpe, puntos, [motivos])]."""
    puertos, firmas = senal_de_categorias(cats)
    if not puertos and not firmas:
        return []
    env = set(cargar_enviados(MK_SENT)) | set(cargar_enviados(MK_SENT_DNS))
    out = []
    for k, c in _cpes_del_nodo(rid):
        pts = 0; motivos = []
        pt = c.get("puertos_top") or {}
        for p_, n_ in pt.items():
            if str(p_).split("/", 1)[0] in puertos:
                pts += int(n_); motivos.append(f"{int(n_):,} alertas por {p_}")
        ct = c.get("cats_top") or {}
        for cat, n_ in ct.items():
            if cat in firmas:
                pts += int(n_); motivos.append(f"{int(n_):,} de {cat}")
        if not pts:
            continue
        out.append((k, c, pts, motivos[:4], k in env))
    out.sort(key=lambda x: x[2], reverse=True)
    return out[:tope]

# ---------------------------------------------------------------------------------
# Listas negras (DNSBL): lo que REALMENTE hace que baneen a un ISP
# ---------------------------------------------------------------------------------
# AbuseIPDB es una base de denuncias: util para saber QUE hace una IP, pero casi nadie
# bloquea correo o trafico mirandola. Lo que rebota los correos y corta servicios son las
# DNSBL. Consultarlas es gratis y son solo consultas DNS, asi que aqui se revisan todas
# las publicas declaradas.
#
# Detalle que evita dar sustos: que un rango RESIDENCIAL este en la PBL de Spamhaus es lo
# NORMAL y lo correcto (dice "esta IP no deberia mandar correo directo"). Solo es problema
# si por ahi sale tu servidor de correo. Por eso se cuenta aparte y no se pinta en rojo.
DNSBL = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("psbl.surriel.com", "PSBL"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT-1"),
]
DNSBL_HIST = "/var/log/suricata-publicas-dnsbl.json"
DNSBL_MAX_IPS = 256            # un /24 entero; por encima se revisa el principio y se dice
DNSBL_HILOS = 8
DNSBL_DIAS = 180
# Que significa cada respuesta de Spamhaus ZEN
ZEN_COD = {
    "127.0.0.2": "SBL: origen de spam",
    "127.0.0.3": "SBL CSS: origen de spam",
    "127.0.0.4": "XBL: equipo infectado o proxy abierto",
    "127.0.0.5": "XBL: equipo infectado o proxy abierto",
    "127.0.0.6": "XBL: equipo infectado o proxy abierto",
    "127.0.0.7": "XBL: equipo infectado o proxy abierto",
    "127.0.0.9": "DROP: red secuestrada",
    "127.0.0.10": "PBL: rango dinamico (normal en residencial)",
    "127.0.0.11": "PBL: rango dinamico (normal en residencial)",
}
_PBL = ("127.0.0.10", "127.0.0.11")

def _invertida(ip):
    return ".".join(reversed(ip.split(".")))

def dnsbl_una(ip, zona):
    """Consulta una IP en una lista. Devuelve (estado, [codigos]).
    estado: limpia | listada | rechazada | error.

    'rechazada' importa: Spamhaus responde 127.255.255.x cuando no acepta la consulta
    (resolutor publico tipo 8.8.8.8, o demasiadas consultas). Eso NO es "esta limpia", y
    confundirlo daria una falsa tranquilidad."""
    try:
        res = socket.gethostbyname_ex(_invertida(ip) + "." + zona)[2]
    except socket.gaierror:
        return "limpia", []            # NXDOMAIN = no esta en la lista
    except OSError:
        return "error", []
    if any(str(r).startswith("127.255.255.") for r in res):
        return "rechazada", [str(r) for r in res]
    return "listada", [str(r) for r in res]

def dnsbl_revisar(entrada, tope=DNSBL_MAX_IPS):
    """Revisa en todas las listas las direcciones de una entrada declarada."""
    if "/" in entrada:
        red, _porque = aidb_red_valida(entrada)
        if red is None:
            return None
        ips = []
        for h in red.hosts():
            ips.append(str(h))
            if len(ips) >= tope:
                break
        truncado = red.num_addresses - 2 > tope
    else:
        ok, _porque = aidb_ip_valida(entrada)
        if not ok:
            return None
        ips, truncado = [entrada], False

    tareas = [(ip, z, nom) for ip in ips for z, nom in DNSBL]
    porip = {}
    rechazadas = set()
    def _uno(t):
        ip, z, nom = t
        est, cods = dnsbl_una(ip, z)
        return ip, nom, est, cods
    with ThreadPoolExecutor(max_workers=DNSBL_HILOS) as pool:
        for ip, nom, est, cods in pool.map(_uno, tareas):
            if est == "rechazada":
                rechazadas.add(nom)
                continue
            if est != "listada":
                continue
            e = porip.setdefault(ip, {"listas": [], "solo_pbl": True})
            if nom == "Spamhaus ZEN":
                for c in cods:
                    txt = ZEN_COD.get(c, "listada (%s)" % c)
                    e["listas"].append("Spamhaus ZEN - " + txt)
                    if c not in _PBL:
                        e["solo_pbl"] = False
            else:
                e["listas"].append(nom)
                e["solo_pbl"] = False
    graves = {k: v for k, v in porip.items() if not v["solo_pbl"]}
    return {"ts": int(time.time()), "n_ips": len(ips), "truncado": truncado,
            "rechazadas": sorted(rechazadas), "ips": porip,
            "n_listadas": len(graves), "n_pbl": len(porip) - len(graves)}

def _dnsbl_hist():
    try:
        return json.load(open(DNSBL_HIST, encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def vigilar_dnsbl():
    """Revisa las listas negras de todo lo declarado. Solo son consultas DNS: no gasta
    cuota de AbuseIPDB ni depende de tener clave."""
    decl = cargar_publicas()
    if not decl:
        return 0
    hist = _dnsbl_hist()
    hoy = time.strftime("%Y-%m-%d")
    n = 0
    for rid, entradas in decl.items():
        for ent in entradas:
            r = dnsbl_revisar(ent)
            if r is None:
                continue
            n += 1
            h = hist.get(ent)
            if not isinstance(h, dict):
                h = {"dias": {}}
            antes = int(h.get("n_listadas", 0))
            h["router"] = rid
            h["dias"] = h.get("dias") or {}
            h["dias"][hoy] = r["n_listadas"]
            lim = time.strftime("%Y-%m-%d", time.localtime(time.time() - DNSBL_DIAS * 86400))
            h["dias"] = {k: v for k, v in h["dias"].items() if k >= lim}
            h.update(r)
            hist[ent] = h
            if r["n_listadas"] and not antes:
                nom = (router_por_id(rid) or {}).get("nombre") or rid
                try:
                    enviar_telegram(f"\u26d4 Lista negra [{_hostname()}]: {r['n_listadas']} "
                                    f"direccion(es) de {ent} ({nom}) estan en listas de bloqueo. "
                                    f"Panel -> Consultar IP.")
                except Exception:
                    pass
                bitacora("PUBLICA-EN-LISTA-NEGRA", f"{ent} listadas={r['n_listadas']}", quien="auto")
    with _PUB_LOCK:
        try:
            tmp = "%s.%d.tmp" % (DNSBL_HIST, os.getpid())
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(hist, f)
            os.replace(tmp, DNSBL_HIST)
        except OSError:
            pass
    return n

def aidb_probar(key):
    """Valida una clave ANTES de guardarla. (True|False|None, mensaje)."""
    key = (key or "").strip()
    if not key:
        return False, "vacia"
    # 1.1.1.1 es el resolutor publico de Cloudflare: sirve de sonda y no es de nadie tuyo
    req = urllib.request.Request(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1",
        headers={"Key": key, "Accept": "application/json", "User-Agent": "suricata-panel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            json.load(r)
        return True, "valida"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, f"AbuseIPDB rechazo la clave (HTTP {e.code})"
        if e.code == 429:
            return True, "valida (hoy ya no quedan consultas)"
        return None, f"no se pudo comprobar (HTTP {e.code})"
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, "no se pudo comprobar ahora (sin red?)"
    except ValueError:
        return None, "respuesta ilegible de AbuseIPDB"

def aidb_cats_txt(cats, sep=", "):
    """Nombres de categoria en castellano, con cuantas denuncias hay de cada una."""
    out = []
    for par in (cats or []):
        try:
            c, n = int(par[0]), int(par[1])
        except (TypeError, ValueError, IndexError):
            continue
        out.append("%s (%d)" % (AIDB_CATS.get(c, "categoria %d" % c), n))
    return sep.join(out)

def guardar_usuarios(lst):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(lst, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, USERS_FILE)

def cargar_usuarios():
    """Lista de {user, salt, hash, role}. Si no existe, migra el usuario del .conf
    (USER/PASS) como admin, hasheando su clave. Si el .conf no tiene PASS -> [] (sin auth)."""
    try:
        data = json.load(open(USERS_FILE, encoding="utf-8"))
        if isinstance(data, list) and data:
            return data
    except (OSError, ValueError):
        pass
    u = CFG.get("USER", "admin"); p = CFG.get("PASS", "")
    if p:
        salt, h = _hash_pw(p)
        lst = [{"user": u, "salt": salt, "hash": h, "role": "admin"}]
        try:
            guardar_usuarios(lst)
            _blank_conf_pass()   # ya migrada y hasheada: borrar la clave en claro del .conf
        except OSError:
            pass
        return lst
    return []

def buscar_usuario(user):
    for r in cargar_usuarios():
        if r.get("user") == user:
            return r
    return None

# ---- datos de la empresa (nombre + logo que se muestra en la barra) ----
EMPRESA_FILE = "/etc/suricata-dashboard-empresa.json"

def cargar_empresa():
    try:
        d = json.load(open(EMPRESA_FILE, encoding="utf-8"))
        if isinstance(d, dict):
            return {"nombre": d.get("nombre", ""), "logo": d.get("logo", "")}
    except (OSError, ValueError):
        pass
    return {"nombre": "", "logo": ""}

def panel_actualizado():
    """Fecha de la ultima actualizacion del panel desde GitHub, o None."""
    try:
        return open("/etc/suricata-dashboard.updated", encoding="utf-8").read().strip() or None
    except OSError:
        return None

def firma_panel():
    """Firma corta del codigo instalado (hash del panel + generador de reportes).
    Si cambia tras 'Actualizar panel', es prueba de que se aplico codigo nuevo."""
    h = hashlib.md5()
    for f in ("/usr/local/bin/suricata-dashboard", "/usr/local/bin/suricata-html-report"):
        try:
            h.update(open(f, "rb").read())
        except OSError:
            pass
    return h.hexdigest()[:10]

# --- deteccion de actualizacion disponible (SHA instalado vs ultimo commit de GitHub) ---
COMMIT_FILE = "/etc/suricata-dashboard.commit"      # SHA del commit aplicado (lo escribe el updater)
UPDCHK_FILE = "/var/log/suricata-update-check.json"  # cache del ultimo chequeo contra GitHub
_UPD_REPO = "mtandazo35/suricata-ids-lab"
PANEL_VERSION = "1.1"   # version visible del panel (se sube a mano en cada release); el SHA es el 'build' exacto

def _sha_local():
    try:
        return open(COMMIT_FILE, encoding="utf-8").read().strip() or None
    except OSError:
        return None

def chequear_update(timeout=15):
    """Consulta la API de GitHub (best-effort) y cachea si hay commits nuevos y cuales.
    No lanza: si no hay red o la API falla, deja el cache como estaba (con el motivo)."""
    local = _sha_local()
    def _err(motivo):   # deja rastro del fallo en vez de salir mudo (rate limit, sin red, etc.)
        try:
            prev = {}
            try:
                prev = json.load(open(UPDCHK_FILE, encoding="utf-8"))
            except Exception:
                pass
            prev.update({"disponible": bool(prev.get("disponible")), "local": local,
                         "error": str(motivo)[:200], "checked": int(time.time())})
            json.dump(prev, open(UPDCHK_FILE, "w", encoding="utf-8"))
        except OSError:
            pass
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{_UPD_REPO}/commits?sha=main&per_page=20",
            headers={"User-Agent": "suricata-panel", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        _err("limite de la API de GitHub (403)" if e.code == 403 else f"HTTP {e.code}")
        return
    except Exception as e:
        _err(e)
        return
    if not isinstance(data, list) or not data:
        _err("respuesta inesperada de GitHub")
        return
    def _subj(c):
        return (c.get("commit", {}).get("message", "") or "").split("\n", 1)[0].strip()
    def _fecha(c):
        d = (c.get("commit", {}).get("committer", {}) or {}).get("date") \
            or (c.get("commit", {}).get("author", {}) or {}).get("date") or ""
        return f"{d[8:10]}/{d[5:7]}/{d[0:4]}" if len(d) >= 10 else ""
    latest = data[0].get("sha", "") or ""
    mejoras = []
    changelog = []
    seen_local = False
    for c in data[:12]:
        sha = c.get("sha", "")
        if sha == local:
            seen_local = True
        s = _subj(c)
        if not s or s.lower().startswith("merge"):
            continue
        nuevo = bool(local) and not seen_local and sha != local
        if nuevo:
            mejoras.append(s)
        changelog.append({"subject": s, "fecha": _fecha(c), "nuevo": nuevo})
    disponible = bool(local) and latest != local and (len(mejoras) > 0 or local not in [c.get("sha") for c in data])
    out = {"disponible": bool(disponible), "latest": latest, "local": local,
           "ultimo": _subj(data[0]), "mejoras": mejoras[:12], "n": len(mejoras),
           "changelog": changelog[:12], "checked": int(time.time())}
    try:
        json.dump(out, open(UPDCHK_FILE, "w", encoding="utf-8"))
    except OSError:
        pass
    if not local and latest:
        # caja sin SHA registrado (instalacion previa a esta funcion): fijar linea base
        # para no marcar un falso "disponible" sin poder listar las mejoras. El primer
        # 'Actualizar panel' registrara el SHA real y a partir de ahi el chequeo es exacto.
        try:
            open(COMMIT_FILE, "w", encoding="utf-8").write(latest)
        except OSError:
            pass

UPDLAST_FILE = "/var/log/suricata-update-last.json"  # ultimo evento de actualizacion (de->a, por quien)

def registrar_update_inicio(usuario):
    """Antes de lanzar el updater: guarda desde que SHA y quien dispara la actualizacion.
    El 'a' (SHA nuevo) se lee luego de COMMIT_FILE, que escribe el updater al terminar."""
    try:
        json.dump({"from": _sha_local() or "", "by": usuario or "", "at": int(time.time())},
                  open(UPDLAST_FILE, "w", encoding="utf-8"))
    except OSError:
        pass

def update_last():
    try:
        return json.load(open(UPDLAST_FILE, encoding="utf-8"))
    except Exception:
        return {}

def update_info():
    """Lee el cache completo del chequeo (haya o no update), para la tarjeta de Ajustes."""
    try:
        return json.load(open(UPDCHK_FILE, encoding="utf-8"))
    except Exception:
        return {}

def update_estado():
    """Lee el cache del chequeo; devuelve dict o None. Solo se muestra si 'disponible'."""
    try:
        d = json.load(open(UPDCHK_FILE, encoding="utf-8"))
        return d if d.get("disponible") else None
    except Exception:
        return None

_UPD_KICK_TS = 0.0
_UPD_KICK_LOCK = threading.Lock()

def _kick_update_check():
    """Refresca el chequeo en segundo plano cuando un admin navega, como mucho cada 30 min,
    para que el aviso aparezca poco despues de subir un cambio (sin esperar el ciclo de 6h)
    y sin bloquear el request (la llamada de red va en un hilo aparte)."""
    global _UPD_KICK_TS
    now = time.time()
    if now - _UPD_KICK_TS < 1800:
        return
    if not _UPD_KICK_LOCK.acquire(blocking=False):
        return
    _UPD_KICK_TS = now
    def _run():
        try:
            chequear_update()
        finally:
            _UPD_KICK_LOCK.release()
    threading.Thread(target=_run, daemon=True).start()

TRUST_FILE = "/etc/suricata-dashboard-trust.json"

def cargar_confianza():
    """Lista de IPs/CIDR de confianza. Vacia = acceso abierto (con bloqueo por fallos)."""
    try:
        d = json.load(open(TRUST_FILE, encoding="utf-8"))
        if isinstance(d, list):
            return [str(x) for x in d if x]
    except (OSError, ValueError):
        pass
    return []

def guardar_confianza(lst):
    tmp = TRUST_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(lst, f, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, TRUST_FILE)

def ip_en_lista(ip, lst):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in lst:
        try:
            if a in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            pass
    return False

def ip_confiable(ip):
    """True si la IP puede acceder: con lista vacia todos; con lista, solo las incluidas."""
    lst = cargar_confianza()
    return True if not lst else ip_en_lista(ip, lst)

def guardar_empresa(d):
    tmp = EMPRESA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"nombre": d.get("nombre", ""), "logo": d.get("logo", "")}, f, ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, EMPRESA_FILE)

def verificar_login(user, pw):
    """Devuelve el rol si user/clave son correctos y la cuenta esta activa; si no None."""
    r = buscar_usuario(user)
    if not r or r.get("activo", True) is False:
        return None
    try:
        _, h = _hash_pw(pw, r.get("salt", ""))
    except ValueError:
        return None
    if secrets.compare_digest(h, r.get("hash", "")):
        return r.get("role", "admin")
    return None

def newest_report():
    fs = sorted(glob.glob(f"{LOGDIR}/report-*.html"), key=os.path.getmtime, reverse=True)
    return fs[0] if fs else None

_DETALLE_RE = re.compile(r'<section class="card">\s*<h2>Detalle:.*?</section>', re.S)
_TOP_RE = re.compile(r'<!--TOP_INI-->.*?<!--TOP_FIN-->', re.S)

def partes_reporte():
    """Divide el ultimo reporte en (estilos, resumen-sin-detalle-ni-top, seccion-detalle)."""
    f = newest_report()
    if not f:
        return "", "", ""
    try:
        doc = open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        return "", "", ""
    mh = re.search(r"<style>(.*?)</style>", doc, re.S)
    css = f"<style>{mh.group(1)}</style>" if mh else ""
    mm = re.search(r"<main[^>]*>(.*?)</main>", doc, re.S)
    inner = mm.group(1) if mm else ""
    md = _DETALLE_RE.search(inner)
    detalle = md.group(0) if md else ""
    # el resumen de "En vivo" no lleva ni la tabla de detalle ni el Top (van en sus pestanas)
    resumen = _TOP_RE.sub("", _DETALLE_RE.sub("", inner))
    return css, resumen, detalle

def partes_top():
    """(estilos, seccion Top-origenes) del ultimo reporte, para la pestana /top (24h)."""
    f = newest_report()
    if not f:
        return "", ""
    try:
        doc = open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        return "", ""
    mh = re.search(r"<style>(.*?)</style>", doc, re.S)
    css = f"<style>{mh.group(1)}</style>" if mh else ""
    mt = _TOP_RE.search(doc)
    return css, (mt.group(0) if mt else "")

# --- Auto-aprovisionamiento del mapa (assets + base GeoIP) ---
# Para las cajas que actualizaron con un updater VIEJO (sin la logica de bajar el mapa): el
# propio panel se auto-cura al arrancar. Best-effort, una sola vez, en 2do plano.
_MAPA_DIR = "/var/lib/suricata-mapa"
_GEOIP_BIN2 = "/var/lib/suricata-geoip/ipv4.bin"
_REPO_RAW2 = "https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main"
_MAPA_ASSETS = {
    "countries-110m.json": "a73ecc17bac82de28af19fa593f9e1a2e76619c51855490da735b7883ec48715",
    "topojson-client.min.js": "ec362ac1599ef406ea9e79616a4ad47d4a3b3939882d47da7e4bc827a56f629c",
}
_GEO_CSV_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"

def _provisionar_geo():
    """Asegura los assets del mapa y la base GeoIP si faltan. No bloquea el panel."""
    # 1) assets del mapa (TopoJSON + topojson-client), verificando SHA256
    try:
        os.makedirs(_MAPA_DIR, exist_ok=True)
        for fn, want in _MAPA_ASSETS.items():
            dst = os.path.join(_MAPA_DIR, fn)
            try:
                if os.path.exists(dst) and hashlib.sha256(open(dst, "rb").read()).hexdigest() == want:
                    continue
                data = urllib.request.urlopen(f"{_REPO_RAW2}/vendor/mapa/{fn}", timeout=30).read()
                if hashlib.sha256(data).hexdigest() == want:
                    tmp = dst + ".tmp"
                    with open(tmp, "wb") as f:
                        f.write(data)
                    os.replace(tmp, dst)
            except Exception:
                pass
    except OSError:
        pass
    # 2) base GeoIP IP->pais (DB-IP lite via ip-location-db, CC-BY-4.0) -> binario compacto
    try:
        if os.path.exists(_GEOIP_BIN2) and os.path.getsize(_GEOIP_BIN2) > 0:
            return
        import array, struct
        raw = urllib.request.urlopen(_GEO_CSV_URL, timeout=180).read().decode("utf-8", "replace")
        rows = []
        for ln in raw.splitlines():
            p = ln.split(",")
            if len(p) < 3:
                continue
            cc = p[2].strip().upper()
            if len(cc) != 2 or not cc.isalpha():
                continue
            try:
                s = int(ipaddress.IPv4Address(p[0].strip())); e = int(ipaddress.IPv4Address(p[1].strip()))
            except Exception:
                continue
            if e >= s:
                rows.append((s, e, cc))
        if len(rows) < 1000:
            return
        rows.sort()
        st = array.array("I", [r[0] for r in rows]); en = array.array("I", [r[1] for r in rows])
        if st.itemsize != 4:
            return
        ccb = b"".join(r[2].encode("ascii") for r in rows)
        os.makedirs(os.path.dirname(_GEOIP_BIN2), exist_ok=True)
        tmp = _GEOIP_BIN2 + ".tmp"
        with open(tmp, "wb") as f:
            f.write(struct.pack("<I", len(rows))); st.tofile(f); en.tofile(f); f.write(ccb)
        os.replace(tmp, _GEOIP_BIN2)
        globals()["FORCE_REGEN"] = True   # regenerar el reporte para pintar el mapa con el nuevo geoip
    except Exception:
        pass

def refrescador():
    """Hilo de fondo: regenera el reporte periodicamente, NUNCA en el request.
    Asi 'En vivo' sirve siempre el ultimo archivo al instante aunque generar tarde."""
    threading.Thread(target=_provisionar_geo, daemon=True).start()   # auto-cura mapa/GeoIP 1 vez
    publicar_routers_map()   # que el generador sepa que interfaz es de que router
    publicar_flags()         # y si las denuncias a AbuseIPDB estan activadas
    ult_poda = 0.0
    ult_updchk = 0.0
    ult_sensor = 0.0
    ult_fast = 0.0
    ult_dur = 0.0       # lo que tardo la ultima generacion (para el freno de abajo)
    ult_fin = 0.0       # cuando termino
    ult_aidb = 0.0
    ult_pub = 0.0
    ult_diag = 0.0
    ult_forzado = 0.0   # ultima regeneracion pedida a mano/por cambios (ver REGEN_MIN_SECS)
    while True:
        global FORCE_REGEN
        if time.time() - ult_fast > 60:        # cada ~60s: enviar YA los ALTO/infeccion confirmada
            try: barrido_alto_rapido()
            except Exception: pass
            ult_fast = time.time()
        if time.time() - ult_poda > 86400:     # 1x/dia: podar logs (15d) y reportes guardados (3d)
            try: podar_logs()
            except Exception: pass
            try: podar_reportes()
            except Exception: pass
            ult_poda = time.time()
        if time.time() - ult_updchk > 3600:    # cada 1h: mirar si hay actualizacion en GitHub
            try: chequear_update()
            except Exception: pass
            ult_updchk = time.time()
        if time.time() - ult_sensor > 60:      # cada ~60s: medir salud del sensor (trafico/perdidas)
            try: medir_sensor()
            except Exception: pass
            ult_sensor = time.time()
        if time.time() - ult_aidb > 300:       # cada ~5 min: unos pocos destinos a AbuseIPDB
            try: precargar_abuseipdb()
            except Exception as _e: sys.stderr.write("precarga abuseipdb: %s\n" % _e)
            ult_aidb = time.time()
        if time.time() - ult_diag > 600:       # cada ~10 min: que le falta al router
            try: guardar_diagnostico()
            except Exception as _e: sys.stderr.write("diagnostico mikrotik: %s\n" % _e)
            ult_diag = time.time()
        if time.time() - ult_pub > 6 * 3600:   # cada ~6 h: reputacion de TUS IPs publicas
            try: vigilar_publicas()
            except Exception as _e: sys.stderr.write("vigilancia de publicas: %s\n" % _e)
            try: vigilar_dnsbl()     # y las listas negras, que son las que de verdad banean
            except Exception as _e: sys.stderr.write("vigilancia dnsbl: %s\n" % _e)
            ult_pub = time.time()
        nr = newest_report()
        # una regeneracion FORZADA se atiende como mucho cada REGEN_MIN_SECS; la marca no
        # se pierde, solo se agrupa (un lote de cambios = una sola generacion)
        forzado = FORCE_REGEN and (time.time() - ult_forzado >= REGEN_MIN_SECS)
        stale = forzado or (nr is None) or (time.time() - os.path.getmtime(nr) >= REFRESH_SECS)
        # FRENO: si una corrida tardo mas que el propio ciclo, esperar al menos lo que
        # tardo antes de lanzar la siguiente. Sin esto, en una caja donde generar lleva
        # 9 minutos y el ciclo son 5, se encadenan una tras otra y queda un nucleo al
        # 100 % de forma permanente; el reporte no sale antes por eso, y la maquina que
        # tiene que analizar el trafico se queda sin CPU. Como mucho, medio nucleo.
        if stale and ult_dur > REFRESH_SECS and (time.time() - ult_fin) < ult_dur:
            stale = False
        if stale:
            if forzado:
                ult_forzado = time.time()
            try:
                mk_sync_enviados()   # el registro del panel refleja la lista real del MikroTik
            except Exception:
                pass
            # se limpia DESPUES del sync: lo que cambie el sync ya entra en esta misma
            # generacion, asi no queda pidiendo otra identica para el ciclo siguiente
            FORCE_REGEN = False
            try:
                refrescar_abonados()  # mapa IP->abonado (PPPoE/DHCP) para la ficha de evidencia
            except Exception:
                pass
            try:
                # ventana del resumen en minutos (config VENTANA_MIN; por defecto 24h)
                vmin = str(ventana_actual())
                _t_gen = time.time()
                subprocess.run(["nice", "-n", "15", GEN, vmin], timeout=600,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                ult_dur = time.time() - _t_gen
                ult_fin = time.time()
                if ult_dur > REFRESH_SECS:
                    # que quede dicho: si tarda mas que el ciclo, el operador tiene que
                    # saberlo (suele ser un eve.json/dns.json enorme)
                    sys.stderr.write("generar el reporte tardo %d s (ciclo %d s): se espaciaran las corridas\n"
                                     % (ult_dur, REFRESH_SECS))
            except Exception:
                ult_fin = time.time()
            try:
                reconciliar_cuarentena()   # libera de la cuarentena a los que dejaron de atacar
            except Exception:
                pass
            try:
                evaluar_bloqueos()         # sella ultima evaluacion + si el CPE sigue activo
            except Exception:
                pass
            try:
                aplicar_politicas()        # aplica las politicas por banda de riesgo del Top
            except Exception:
                pass
        time.sleep(10)   # poll corto para atender un cambio de ventana casi al instante

_NAV_LINKS = [("/", "En vivo"), ("/top", "Top origenes"), ("/detalle", "Detalle"),
              ("/cuarentena", "Cuarentena"), ("/reputacion", "Consultar IP"),
              ("/historico", "Historico"), ("/exclusiones", "Exclusiones"),
              ("/ajustes", "Ajustes")]   # Log y Documentacion viven dentro de Ajustes
_NAV_CSS = """<style>
html{scrollbar-gutter:stable}  /* reservar el hueco del scroll: paginas cortas (Exclusiones) y largas (Ajustes) no desplazan el contenido */
.nav{position:sticky;top:0;z-index:20;background:linear-gradient(180deg,#12161c,#0b0b0b);color:#fff;
font:15px system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 2px 10px rgba(0,0,0,.25)}
.nav .navwrap{max-width:1360px;margin:0 auto;padding:0 28px;height:58px;display:flex;align-items:center;gap:4px;flex-wrap:nowrap}
.nav .brand{font-weight:700;font-size:16px;margin-right:14px;display:flex;align-items:center;gap:11px;letter-spacing:.2px}
.nav .brand .applogo{height:30px;width:auto;display:block;filter:drop-shadow(0 1px 2px rgba(0,0,0,.4))}
.nav .brand .elogo{height:34px;width:auto;max-width:150px;object-fit:contain;border-radius:5px;background:#fff;padding:3px;display:block}
.nav .brand .bn{white-space:nowrap;max-width:240px;overflow:hidden;text-overflow:ellipsis}
.nav a.tab{position:relative;color:#c9d2dd;text-decoration:none;padding:11px 15px;margin:9px 1px;border-radius:8px;
font-size:15px;font-weight:500;transition:background .15s,color .15s}
.nav a.tab:hover{color:#fff;background:rgba(255,255,255,.08)}
.nav a.tab.on{color:#fff;background:rgba(42,120,214,.22)}  /* sin cambiar el grosor: evita que la pestana activa ensanche y recoloque la barra */
.nav a.tab.on::after{content:"";position:absolute;left:15px;right:15px;bottom:-9px;height:3px;background:#2a78d6;border-radius:2px}
.nav .push{margin-left:auto}
.nav .out{margin-left:14px;color:#f3b0b0;text-decoration:none;font-weight:600;padding:9px 17px;border-radius:8px;font-size:15px;
border:1px solid rgba(243,176,176,.35);transition:background .15s,color .15s,border-color .15s}
.nav .out:hover{background:#e34948;color:#fff;border-color:#e34948}
.nav .updbtn{display:inline-flex;align-items:center;gap:7px;margin-left:14px;cursor:pointer;background:#e67e22;color:#fff;
border:0;padding:9px 15px;border-radius:8px;font:600 14px system-ui;box-shadow:0 2px 8px rgba(230,126,34,.4)}
.nav .updbtn:hover{background:#d3691a}
.nav .updbtn .uddot{width:9px;height:9px;border-radius:50%;background:#fff;animation:udpulse 1.6s infinite}
@keyframes udpulse{0%{box-shadow:0 0 0 0 rgba(255,255,255,.6)}70%{box-shadow:0 0 0 8px rgba(255,255,255,0)}100%{box-shadow:0 0 0 0 rgba(255,255,255,0)}}
.updov{display:none;position:fixed;inset:0;background:rgba(11,11,11,.5);z-index:120;align-items:center;justify-content:center;padding:24px}
.updov .updbox{position:relative;background:#fff;color:#0b0b0b;border-radius:14px;max-width:560px;width:100%;max-height:calc(100vh - 48px);overflow:auto;padding:22px 24px;box-shadow:0 14px 50px rgba(0,0,0,.4)}
.updov .updx{position:absolute;top:8px;right:8px;border:0;background:#eceae6;width:30px;height:30px;border-radius:50%;font-size:19px;line-height:1;cursor:pointer;z-index:3}
.updov h3{margin:2px 0 6px;font-size:20px}
.updov .updsub{color:#52514e;margin:0 0 14px;font-size:14px;line-height:1.5}
.updov .updlist{margin:0 0 18px;padding-left:20px;max-height:44vh;overflow:auto}
.updov .updlist li{margin:5px 0;font-size:14px;line-height:1.45}
.updov .updgo{background:#2a78d6;color:#fff;border:0;padding:11px 18px;border-radius:9px;font:600 15px system-ui;cursor:pointer}
.updov .updgo:hover{background:#1c5cab}
.updask{display:none;position:fixed;inset:0;background:rgba(11,11,11,.55);z-index:150;align-items:center;justify-content:center;padding:24px}
.updask .updaskbox{background:#fff;color:#0b0b0b;border-radius:14px;max-width:440px;width:100%;padding:22px 24px;box-shadow:0 16px 54px rgba(0,0,0,.45)}
.updask h3{margin:0 0 8px;font-size:19px}
.updask p{margin:0 0 18px;color:#52514e;font-size:14px;line-height:1.5}
.updask .updaskacts{display:flex;gap:10px;justify-content:flex-end}
.updask .updaskno{background:#eef0f2;color:#33322f;border:1px solid #d7d6d2;padding:10px 16px;border-radius:9px;font:600 14px system-ui;cursor:pointer}
.updask .updaskno:hover{background:#e2e5e8}
.updask .updaskok{background:#2a78d6;color:#fff;border:0;padding:10px 18px;border-radius:9px;font:600 14px system-ui;cursor:pointer}
.updask .updaskok:hover{background:#1c5cab}
.empbar{background:#fff;border-bottom:1px solid #ececec}
.empbar .empwrap{max-width:1360px;margin:0 auto;padding:7px 28px;display:flex;justify-content:flex-end;align-items:center;gap:10px}
.empbar .elogo{height:30px;width:auto;max-width:150px;object-fit:contain;display:block}
.empbar .en{color:#33322f;font-size:14px;font-weight:700;white-space:nowrap;max-width:280px;overflow:hidden;text-overflow:ellipsis}
/* --- responsive de la barra: en pantallas angostas las pestanas se apilan en vez de desbordarse --- */
@media(max-width:820px){
 .nav .navwrap{height:auto;flex-wrap:wrap;padding:6px 14px;gap:2px}
 .nav .brand{width:100%;margin:0 0 2px;padding:4px 0;font-size:15px}
 .nav a.tab{padding:8px 11px;margin:3px 1px;font-size:14px}
 .nav a.tab.on::after{display:none}         /* el subrayado inferior no encaja al envolver */
 .nav .push{margin-left:auto}
 .nav .out{margin-left:8px;padding:7px 12px;font-size:14px}
 .nav .updbtn{margin-left:8px;padding:7px 11px;font-size:13px}
 .updov,.updask{padding:14px}
 .empbar .empwrap{padding:6px 14px}
 /* base compartida: margen lateral comodo en movil para TODOS los apartados
    (_NAV_CSS se inyecta despues del <style> de cada pagina, asi que manda) */
 main{padding-left:14px!important;padding-right:14px!important}
}
@media(max-width:420px){
 .nav .navwrap{padding:5px 10px}
 .nav a.tab{padding:7px 9px;font-size:13px}
 .nav .brand .bn{max-width:150px}
}
/* --- tablas ordenables: click en la cabecera ordena asc/desc (JS en _SORT_JS) --- */
table.orden th[data-sort]{cursor:pointer;user-select:none;white-space:nowrap;position:relative;padding-right:20px}
table.orden th[data-sort]:hover{color:#2a78d6}
table.orden th[data-sort]::after{content:"⇅";position:absolute;right:6px;opacity:.32;font-size:11px;font-weight:700}
table.orden th[data-sort][aria-sort="ascending"]::after{content:"▲";opacity:.9;color:#2a78d6}
table.orden th[data-sort][aria-sort="descending"]::after{content:"▼";opacity:.9;color:#2a78d6}
@media(max-width:820px){table.orden th[data-sort]::after{display:none}}
</style>"""

# Ordenamiento de tablas del lado del cliente. Se aplica a cualquier <table class="orden">:
# al pulsar una cabecera con data-sort ordena su columna (asc/desc alterno). La clave de
# orden es data-sort de la celda si existe (util para fechas: epoch), si no su texto; si
# todas las claves son numericas ordena por numero. Se inyecta una sola vez por pagina.
_SORT_JS = ("<script>(function(){function key(td){var d=td.getAttribute('data-sort');"
            "return d!==null?d:(td.textContent||'').trim();}"
            "function isnum(v){return v!==''&&!isNaN(parseFloat(v))&&isFinite(v);}"
            "function sortBy(tb,i,dir){var rows=Array.prototype.slice.call(tb.rows);"
            "var num=rows.every(function(r){return !r.cells[i]||isnum(key(r.cells[i]));});"
            "rows.sort(function(a,b){var x=a.cells[i]?key(a.cells[i]):'',y=b.cells[i]?key(b.cells[i]):'';"
            "var c=num?(parseFloat(x)||0)-(parseFloat(y)||0):x.localeCompare(y,'es',{numeric:true,sensitivity:'base'});"
            "return dir*c;});rows.forEach(function(r){tb.appendChild(r);});}"
            "function marca(ths,th,asc){Array.prototype.forEach.call(ths,function(o){o.removeAttribute('aria-sort');});"
            "th.setAttribute('aria-sort',asc?'ascending':'descending');}"
            "function init(){document.querySelectorAll('table.orden').forEach(function(t,ti){"
            "var tb=t.tBodies[0];if(!tb)return;var ths=t.tHead?t.tHead.rows[0].cells:[];"
            "var K='orden:'+location.pathname+':'+ti;"
            "function aplicar(i,asc,guardar){sortBy(tb,i,asc?1:-1);marca(ths,ths[i],asc);"
            "if(guardar){try{sessionStorage.setItem(K,i+','+(asc?1:0));}catch(e){}}}"
            "Array.prototype.forEach.call(ths,function(th,i){"
            "if(th.hasAttribute('data-nosort'))return;th.setAttribute('data-sort','');"
            "th.addEventListener('click',function(){aplicar(i,th.getAttribute('aria-sort')!=='ascending',1);});});"
            # tras recargar (p.ej. al pulsar Quitar) se vuelve a aplicar el orden elegido,
            # para que la tabla no se desordene sola
            "try{var g=sessionStorage.getItem(K);if(g){var p=g.split(',');var i=+p[0];"
            "if(ths[i]&&!ths[i].hasAttribute('data-nosort'))aplicar(i,p[1]==='1',0);}}catch(e){}"
            "});}"
            # este <script> va al PRINCIPIO del <body> (lo inyecta nav()), asi que al
            # ejecutarse todavia no existe ninguna tabla: hay que esperar al DOM.
            "if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);"
            "else init();})();</script>")

# Conserva la POSICION de la pagina al recargar. Sin esto, cada accion (Quitar, Enviar...)
# hace un POST y la pagina vuelve arriba del todo, perdiendo de vista la fila en la que
# estabas. Solo se restaura tras una accion de la propia pagina o una recarga (incluida la
# automatica cada 5 min): al cambiar de pestana NO se toca, para no confundir.
_POS_JS = ("<script>(function(){"
           "var K='pos:'+location.pathname,F='posact:'+location.pathname;"
           "function y(){return window.scrollY||window.pageYOffset||0;}"
           "function guardar(){try{sessionStorage.setItem(K,String(y()));}catch(e){}}"
           "document.addEventListener('submit',function(){guardar();"
           "try{sessionStorage.setItem(F,'1');}catch(e){}},true);"
           "window.addEventListener('beforeunload',guardar);"
           "function esRecarga(){try{var n=performance.getEntriesByType('navigation')[0];"
           "if(n)return n.type==='reload';"
           "return !!(performance.navigation&&performance.navigation.type===1);}catch(e){return false;}}"
           "function rest(){try{"
           "if(sessionStorage.getItem(F))sessionStorage.removeItem(F);"
           "else if(!esRecarga())return;"
           "var v=sessionStorage.getItem(K);if(v===null)return;"
           "var p=parseInt(v,10);if(p>0)window.scrollTo(0,p);}catch(e){}}"
           "if(document.readyState==='complete')rest();else window.addEventListener('load',rest);"
           "})();</script>")

# Base de estilos COMPARTIDA por los apartados del panel (fuente unica de tokens y
# componentes). Se incluye al PRINCIPIO del <style> de cada pagina migrada; las reglas
# propias de la pagina van despues y la sobreescriben (p.ej. su max-width de main). Asi
# se quita el CSS duplicado y todo se ve consistente. Migracion pagina-a-pagina.
BASE_CSS = (
    "*{box-sizing:border-box}"
    "body{margin:0;background:#fcfcfb;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#0b0b0b}"
    "main{max-width:1000px;margin:0 auto;padding:20px 24px}"
    "h1{font-size:21px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}"
    ".sub,.subx,.sub2{color:#52514e;font-size:13px}"
    ".mono{font-family:ui-monospace,Consolas,monospace}"
    ".muted{color:#9a9a95;font-size:12px}"
    "code{background:#f1f1ef;padding:1px 5px;border-radius:4px}"
    ".card{border:1px solid #e7e6e2;border-radius:12px;background:#fff}"
    "table{width:100%;border-collapse:collapse;font-size:13px}"
    "thead th{background:#f4f4f2;text-align:left;padding:9px 12px;border-bottom:1px solid #e7e6e2;color:#52514e;font-weight:600}"
    "tbody td{padding:9px 12px;border-bottom:1px solid #f2f1ee;vertical-align:top}"
    "tbody tr:hover{background:#faf9f6}"
    ".num{text-align:right;font-variant-numeric:tabular-nums}"
    ".banner{border:1px solid #f2d3ad;background:#fff7ed;color:#7a4a12;border-radius:10px;padding:11px 14px;margin:0 0 12px;font-size:13px}"
    ".banner.ok{border-color:#b7e0c2;background:#e6f4ea;color:#1a7f37}"
    ".banner.err{border-color:#f3c4c4;background:#fdecec;color:#b52a2a}"
    ".banner.msg{border-color:#cfe0f6;background:#eef4fd;color:#2a5fa0}"
    "@media(max-width:820px){main{padding:16px 14px}h1{font-size:19px}}"
)

def nav(active=""):
    _rl = getattr(CTX, "role", None)
    es_admin_nav = _rl in (None, "admin")   # exclusiones/tuning: solo admin (ni operador ni lectura)
    parts = []
    for h, t in _NAV_LINKS:
        if h == "/exclusiones" and not es_admin_nav:
            continue   # exclusiones (ajuste de deteccion) es solo de admin
        cls = "tab on" if h == active else "tab"
        parts.append(f'<a href="{h}" class="{cls}">{t}</a>')
    brand = '<span class="brand"><img class="applogo" src="/logo.png" alt="Suricata">Estadisticas Suricata</span>'
    # boton + modal de 'actualizacion disponible' (solo admin y solo si el chequeo lo marca)
    upd_btn = ""; upd_modal = ""
    if getattr(CTX, "role", None) == "admin":
        # si el cache esta viejo/ausente, consultar GitHub EN EL MOMENTO (timeout corto)
        # para que el aviso salga en el primer load; como mucho 1 vez cada 10 min por caja
        # (un chequeo fallido tambien actualiza 'checked', asi no repite la espera).
        _info = update_info()
        if (not _info) or (time.time() - _info.get("checked", 0) > 600):
            try: chequear_update(timeout=6)
            except Exception: pass
        ue = update_estado()
        if ue:
            mej = ue.get("mejoras") or []
            if mej:
                items = "".join(f"<li>{html.escape(m)}</li>" for m in mej)
            else:
                items = "<li>Varias mejoras acumuladas del panel y los reportes.</li>"
            upd_btn = ('<button type=button class=updbtn '
                       "onclick=\"document.getElementById('updov').style.display='flex'\">"
                       '<span class=uddot></span>Actualizacion</button>')
            upd_modal = (
                "<div id=updov class=updov onclick=\"if(event.target===this)this.style.display='none'\">"
                "<div class=updbox>"
                "<button type=button class=updx onclick=\"document.getElementById('updov').style.display='none'\">&times;</button>"
                "<h3>Actualizacion disponible</h3>"
                "<p class=updsub>Hay una version nueva del panel en GitHub. Solo se actualiza el codigo "
                "(no toca tu configuracion). Mejoras incluidas:</p>"
                f"<ul class=updlist>{items}</ul>"
                "<form id=updform_nav method=post action=/update-panel>"
                "<button class=updgo type=button onclick=\"updaskShow('updform_nav')\">&#8681; Actualizar ahora</button>"
                "</form></div></div>")
    # modal propio de confirmacion (reemplaza el confirm() del navegador); solo admin
    updask = ""
    if getattr(CTX, "role", None) == "admin":
        updask = (
            "<div id=updask class=updask onclick=\"if(event.target===this)updaskHide()\">"
            "<div class=updaskbox><h3>Actualizar el panel</h3>"
            "<p>Se bajara y aplicara la ultima version del panel desde GitHub. "
            "El panel se reiniciara en unos segundos.</p>"
            "<div class=updaskacts>"
            "<button type=button class=updaskno onclick=updaskHide()>Cancelar</button>"
            "<button type=button class=updaskok id=updaskok>&#8681; Actualizar</button>"
            "</div></div></div>"
            "<script>function updaskShow(f){var m=document.getElementById('updask');m.dataset.f=f;m.style.display='flex';}"
            "function updaskHide(){var m=document.getElementById('updask');if(m)m.style.display='none';}"
            "document.getElementById('updaskok').addEventListener('click',function(){"
            "var m=document.getElementById('updask');var f=document.getElementById(m.dataset.f||'');if(f)f.submit();});"
            "document.addEventListener('keydown',function(e){if(e.key==='Escape')updaskHide();});</script>")
    navbar = ('<div class="nav"><div class="navwrap">' + brand + '<span class="push"></span>'
              + "".join(parts) + '<span class="push"></span>' + upd_btn
              + '<a href="/logout" class="out">Salir</a></div></div>' + upd_modal + updask)
    # marca de la empresa (logo + nombre) en una franja debajo, alineada a la derecha (bajo Salir)
    emp = cargar_empresa()
    tiene_logo = emp.get("logo", "").startswith("data:image/")
    empbar = ""
    if tiene_logo or emp.get("nombre"):
        elogo = f'<img class="elogo" src="{html.escape(emp["logo"])}" alt="">' if tiene_logo else ""
        enom = f'<span class="en">{html.escape(emp["nombre"])}</span>' if emp.get("nombre") else ""
        empbar = f'<div class="empbar"><div class="empwrap">{elogo}{enom}</div></div>'
    return _NAV_CSS + _SORT_JS + _POS_JS + navbar + empbar

# compat: algunas plantillas todavia interpolan {NAV} (barra sin pestana activa marcada)
NAV = nav()

# cabecera de pagina (titulo con presencia + subtitulo + indicador en vivo)
_PAGEH_CSS = """<style>
.pageh{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;flex-wrap:wrap;
max-width:1360px;margin:0 auto;padding:18px 28px 8px}
.pageh h1{margin:0;font-size:21px;font-weight:700;letter-spacing:-.2px;color:#0b0b0b}
.pageh .ph-sub{margin:4px 0 0;color:#6b6a66;font-size:13px}
.pageh .ph-live{display:inline-flex;align-items:center;gap:7px;color:#c0392b;font-size:12px;font-weight:700;
background:#fdecea;border:1px solid #f7c9c4;padding:4px 10px;border-radius:20px;margin-left:8px;vertical-align:middle}
.pageh .dotlive{width:8px;height:8px;border-radius:50%;background:#e34948;
box-shadow:0 0 0 0 rgba(227,73,72,.6);animation:phpulse 1.6s infinite}
@keyframes phpulse{0%{box-shadow:0 0 0 0 rgba(227,73,72,.5)}70%{box-shadow:0 0 0 8px rgba(227,73,72,0)}100%{box-shadow:0 0 0 0 rgba(227,73,72,0)}}
.pageh .wsel{display:flex;align-items:center;gap:8px;margin:0}
.pageh .wsel .wlbl{color:#6b6a66;font-size:12.5px;font-weight:600}
.pageh .wsel select{padding:7px 11px;border:1px solid #d7d6d2;border-radius:8px;font:13px system-ui;background:#fff;cursor:pointer}
.pageh .wsel select:focus{outline:none;border-color:#2a78d6;box-shadow:0 0 0 3px rgba(42,120,214,.15)}
</style>"""

def wrap(body_html, refresh=True, active=""):
    meta = '<meta http-equiv="refresh" content="300">' if refresh else ""
    # inserta la barra de navegacion justo despues de <body ...>
    def ins(m):
        return m.group(0) + nav(active)
    out = re.sub(r"<body[^>]*>", ins, body_html, count=1)
    if meta:
        out = re.sub(r"</head>", meta + "</head>", out, count=1)
    return out

def save_conf(user, pw):
    """Reescribe /etc/suricata-dashboard.conf con el usuario/clave nuevos (conserva PORT)."""
    port = CFG.get("PORT", "5637")
    txt = ("# Panel de estadisticas de Suricata. Editado desde el apartado Perfil.\n"
           "# Reiniciar tras cambios manuales: systemctl restart suricata-dashboard\n"
           f"PORT={port}\nUSER={user}\nPASS={pw}\n")
    tmp = CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(txt)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)
    CFG["USER"], CFG["PASS"], CFG["PORT"] = user, pw, port

def _rol_badge(rl):
    if rl == "admin":
        return '<span class="rbadge adm">Administrador</span>'
    if rl == "operador":
        return '<span class="rbadge ope">Operador</span>'
    if rl == "lectura":
        return '<span class="rbadge lec">Solo lectura</span>'
    return '<span class="rbadge">—</span>'

_AV_COLORS = ["#c0392b", "#8e44ad", "#2980b9", "#16a085", "#27ae60", "#d35400",
              "#2c3e50", "#e67e22", "#7f8c8d", "#c2185b", "#00838f", "#5d4037"]

def _iniciales(nombre, user):
    base = (nombre or user or "?").strip()
    parts = base.split()
    if len(parts) >= 2:
        return (parts[0][:1] + parts[1][:1]).upper()
    return base[:2].upper()

def _avatar(nombre, user, foto=None):
    if foto and foto.startswith("data:image/"):
        return f'<img class="av" src="{html.escape(foto)}" alt="">'
    ini = html.escape(_iniciales(nombre, user))
    col = _AV_COLORS[sum(ord(c) for c in (user or nombre or "?")) % len(_AV_COLORS)]
    return f'<span class="av" style="background:{col}">{ini}</span>'

_IC_EDIT = ('<svg viewBox="0 0 24 24" width="15" height="15"><path fill="currentColor" '
            'd="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1 1 0 0 0 0-1.41'
            'l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>')
_IC_DEL = ('<svg viewBox="0 0 24 24" width="15" height="15"><path fill="currentColor" '
           'd="M6 19a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>')

def _ic(d):   # icono redondo del hub de Ajustes (32px, blanco)
    return f'<svg viewBox="0 0 24 24" width="32" height="32"><path fill="currentColor" d="{d}"/></svg>'
_IC_USER  = _ic("M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z")
_IC_BLD   = _ic("M12 7V3H2v18h20V7H12zM6 19H4v-2h2v2zm0-4H4v-2h2v2zm0-4H4V9h2v2zm0-4H4V5h2v2zm4 12H8v-2h2v2zm0-4H8v-2h2v2zm0-4H8V9h2v2zm0-4H8V5h2v2zm10 12h-8v-2h2v-2h-2v-2h2v-2h-2V9h8v10zm-2-8h-2v2h2v-2zm0 4h-2v2h2v-2z")
_IC_USERS = _ic("M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5s-3 1.34-3 3 1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z")
_IC_SHIELD= _ic("M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z")
_IC_RTR   = _ic("M19 15h-1v-3a1 1 0 0 0-1-1h-4V9h1a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v4a1 1 0 0 0 1 1h1v2H7a1 1 0 0 0-1 1v3H5a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2H8v-2h8v2h-1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2z")
_IC_DL    = _ic("M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z")
_IC_LOG   = _ic("M3 5h18v2H3V5zm0 6h18v2H3v-2zm0 6h12v2H3v-2z")
_IC_BOOK  = _ic("M18 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM6 4h5v8l-2.5-1.5L6 12V4z")
_IC_AUDIT = _ic("M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm-2 14l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z")
_IC_FEED  = _ic("M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 4.5a2.5 2.5 0 0 1 2.5 2.5c0 1-.6 1.9-1.5 2.3V17h-2v-4.7A2.5 2.5 0 0 1 9.5 8 2.5 2.5 0 0 1 12 5.5z")

def _card_politicas(m):
    """Sub-bloque de la tarjeta MikroTik: politicas por banda de riesgo del Top origenes."""
    esc = html.escape
    ops = [("nada", "Nada (solo mostrar)"), ("cuarentena", "Enviar a cuarentena"),
           ("dns", "Enviar a lista DNS"), ("notificar", "Solo notificar (Log)")]
    def _sel(name, actual):
        o = "".join(f"<option value='{v}'{' selected' if v == actual else ''}>{esc(t)}</option>" for v, t in ops)
        return f"<select name='{name}'>{o}</select>"
    auto = m.get("POL_AUTO") == "1"
    return ("<div class=polbox><h3 class=ch>Politicas por riesgo (Top origenes)</h3>"
            "<p class=sub2 style='margin:2px 0 10px'>Que hacer automaticamente con cada CPE del Top segun su banda de riesgo. "
            "<b>Ojo:</b> riesgo alto no siempre es infeccion (un torrent puede dar alto). Por eso viene apagado.</p>"
            "<div class=grid2>"
            f"<div class=field><label>Riesgo BAJO (0-39)</label>{_sel('pol_bajo', m.get('POL_BAJO','nada'))}</div>"
            f"<div class=field><label>Riesgo MEDIO (40-69)</label>{_sel('pol_medio', m.get('POL_MEDIO','nada'))}</div>"
            f"<div class=field><label>Riesgo ALTO (70-100)</label>{_sel('pol_alto', m.get('POL_ALTO','nada'))}</div>"
            "</div>"
            "<div class=field><label class=chk>"
            f"<input type=checkbox name=pol_auto value=1 {'checked' if auto else ''}> "
            "Aplicar politicas automaticamente</label>"
            "<div class=hint>Activado: el panel envia/saca del MikroTik solo, segun la banda de cada CPE. "
            "Apagado: las politicas no hacen nada (usa los botones a mano).</div></div></div>")

def _form_nodo(r, nuevo=False):
    """Formulario compacto de un nodo. La clave nunca se devuelve al navegador: si se
    deja vacia se conserva la que ya estaba."""
    esc = html.escape
    rid = r.get("id", "")
    tit = ("Nuevo nodo" if nuevo else esc(r.get("nombre", "") or r.get("HOST", "") or rid))
    return (
        "<form method=post action='/routers/guardar' class=nodoform>"
        f"<input type=hidden name=rid value='{esc(rid)}'>"
        f"<div class=nodohd><b>{tit}</b>"
        + ("" if nuevo else f"<span class=nodoif title='Interfaz por la que entra su espejo'>{esc(r.get('iface',''))}</span>")
        + "</div>"
        "<div class=grid2>"
        f"<div class=field><label>Nombre del nodo</label>"
        f"<input type=text name=nombre maxlength=40 value=\"{esc(r.get('nombre',''))}\" placeholder='Nodo Centro'></div>"
        f"<div class=field><label>IP del MikroTik</label>"
        f"<input type=text name=host value=\"{esc(r.get('HOST',''))}\" placeholder='192.168.88.1'></div>"
        f"<div class=field><label>Puerto API</label>"
        f"<input type=text name=port value=\"{esc(r.get('PORT','8728'))}\" placeholder='8728 (8729 si TLS)'></div>"
        f"<div class=field><label>Usuario API</label>"
        f"<input type=text name=user value=\"{esc(r.get('USER',''))}\" autocomplete=off></div>"
        f"<div class=field><label>Clave API</label>"
        f"<input type=password name=pass autocomplete=new-password placeholder=\""
        + ("dejar vacio para no cambiarla" if r.get("PASS") else "clave del usuario API") + "\"></div>"
        f"<div class=field><label>Address-list de infectados</label>"
        f"<input type=text name=list value=\"{esc(r.get('LIST','suricata-cuarentena'))}\"></div>"
        f"<div class=field><label>Address-list de DNS sospechoso</label>"
        f"<input type=text name=list_dns value=\"{esc(r.get('LIST_DNS','suricata-dns-sospechoso'))}\"></div>"
        f"<div class=field><label>Caducidad (infectados / DNS)</label>"
        f"<input type=text name=ttl value=\"{esc(r.get('TTL','1h'))}\" style='width:48%' placeholder='1h'> "
        f"<input type=text name=ttl_dns value=\"{esc(r.get('TTL_DNS','1d'))}\" style='width:48%' placeholder='1d'></div>"
        "</div>"
        "<label class=chk><input type=checkbox name=tls" + (" checked" if r.get("TLS") == "1" else "") + "> API-SSL (TLS)</label>"
        "<label class=chk><input type=checkbox name=enabled" + (" checked" if r.get("ENABLED") == "1" else "") + "> Permitir enviar a este nodo</label>"
        "<div class=nodoacts><button class=savebtn type=submit>Guardar nodo</button>"
        + ("" if nuevo else
           "<button class=cancelbtn type=submit formaction='/routers/quitar' "
           "onclick=\"return confirm('Quitar este nodo del panel? Sus CPEs en cuarentena seguiran "
           "bloqueados en ese MikroTik.')\">Quitar nodo</button>")
        + "</div></form>")

def _card_nodos():
    """Tarjeta para gestionar VARIOS MikroTik. Solo aparece cuando tiene sentido: con un
    unico nodo la tarjeta de arriba ya lo configura todo."""
    esc = html.escape
    rs = cargar_routers()
    filas = "".join(
        f"<tr><td class=mono>{esc(r.get('nombre','') or r.get('HOST',''))}</td>"
        f"<td class=mono>{esc(r.get('HOST',''))}</td>"
        f"<td class=mono>{esc(r.get('iface',''))}</td>"
        f"<td>{'envia' if r.get('ENABLED') == '1' else 'solo observa'}</td></tr>" for r in rs)
    otros = "".join(_form_nodo(r) for r in rs[1:])
    return (
        "<section class=card><h2>Varios MikroTik (multi-nodo)</h2>"
        "<p class=sub2>Un sensor puede vigilar <b>varios routers</b>. Cada uno espeja por "
        "<b>su propia interfaz</b>, y de ahi sale de que nodo es cada CPE: por eso dos nodos que "
        "usan el mismo rango privado (10.0.0.x en los dos) no se confunden, y cada bloqueo sale "
        "hacia el router que corresponde.</p>"
        "<div class=twrap><table class=nodost><thead><tr><th>Nodo</th><th>MikroTik</th>"
        "<th>Interfaz del espejo</th><th>Cuarentena</th></tr></thead>"
        f"<tbody>{filas}</tbody></table></div>"
        "<p class=sub2 style='margin-top:10px'><b>Importante:</b> dar de alta el nodo aqui solo "
        "configura la conexion para bloquear. Para que su trafico se <b>capture</b> hay que "
        "re-ejecutar el instalador incluyendo su IP en <code>-m</code> "
        "(ej. <code>-m 10.0.0.1,10.9.9.1</code>), que es lo que crea su interfaz.</p>"
        "<p class=sub2>El <b>primer nodo</b> se configura en la tarjeta de arriba.</p>"
        + otros +
        "<details class=nodonew><summary>Agregar otro MikroTik</summary>"
        + _form_nodo(_router_vacio(len(rs) + 1), nuevo=True) +
        "</details></section>")

def perfil_page(msg="", ok=False, edit_user=None):
    esc = html.escape
    yo = getattr(CTX, "user", None)
    mirol = getattr(CTX, "role", None)
    es_admin = mirol in (None, "admin")   # operador NO ve tarjetas de admin (usuarios/mikrotik/updates/bitacora)
    mi = buscar_usuario(yo) if yo else None
    mi_foto = (mi or {}).get("avatar", "")
    big_av = (f'<img class=avatar src="{esc(mi_foto)}" alt="">' if mi_foto.startswith("data:image/")
              else f'<div class=avatar>{esc(yo[0].upper()) if yo else "?"}</div>')
    # --- tarjeta: cambiar mi clave (solo para lectura; el admin lo hace desde su fila) ---
    if yo and not es_admin:
        card_pw = (
            "<section class=card>"
            "<div class=acct>"
            f"{big_av}"
            f"<div><div class=aname>{esc(yo)}</div><div class=arole>{_rol_badge(mirol)}</div></div></div>"
            "<h3 class=ch>Mi foto</h3>"
            "<form method=post action='/perfil' class=fotoform>"
            "<input type=hidden name=accion value=mi_foto><input type=hidden name=avatar id=mavatar>"
            "<input type=file accept=image/* onchange=\"foto(this,'m')\">"
            + ("<button class=cancelbtn type=button onclick=\"document.getElementById('mavatar').value='__BORRAR__';this.form.submit();\">Quitar foto</button>" if mi_foto else "")
            + "<button class=primary type=submit>Guardar foto</button></form>"
            "<h3 class=ch>Cambiar mi clave</h3>"
            "<form method=post action='/perfil'>"
            "<input type=hidden name=accion value=mi_clave>"
            "<div class=field><label>Clave actual</label>"
            "<input type=password name=actual autocomplete=current-password required></div>"
            "<div class=grid2>"
            "<div class=field><label>Clave nueva</label>"
            "<input type=password name=nueva autocomplete=new-password required>"
            "<div class=hint>Minimo 6 caracteres.</div></div>"
            "<div class=field><label>Repetir clave nueva</label>"
            "<input type=password name=nueva2 autocomplete=new-password required></div></div>"
            "<div class=actions><button class=primary type=submit>Actualizar mi clave</button></div>"
            "</form></section>")
    elif not yo:
        card_pw = "<section class=card><p>Autenticacion desactivada (sin usuarios configurados en el servidor).</p></section>"
    else:
        card_pw = ""   # admin: cambia su clave con el lapiz de su fila
    usuarios = cargar_usuarios() if (es_admin and yo) else []
    # --- tarjeta: gestion de empresa (nombre + logo en la barra; solo admin) ---
    card_empresa = ""
    if es_admin and yo:
        emp = cargar_empresa()
        elogo = emp.get("logo", "")
        tiene_logo = elogo.startswith("data:image/")
        card_empresa = (
            "<section class=card><h2>Empresa</h2>"
            "<p class=sub2>El nombre y el logo aparecen en la barra superior, al lado de las pestañas.</p>"
            "<form method=post action='/empresa'>"
            "<div class=grid2>"
            f"<div class=field><label>Nombre de la empresa</label>"
            f"<input type=text name=nombre maxlength=60 value=\"{esc(emp.get('nombre',''))}\"></div>"
            "<div class=field><label>Logo</label><div class=avup>"
            f"<img id=lpreview class='avprev logo' src=\"{esc(elogo)}\" alt=''{'' if tiene_logo else ' style=display:none'}>"
            "<input id=lfile type=file accept=image/* onchange=\"foto(this,'l')\">"
            "<button class=cancelbtn type=button onclick=\"quitarimg('l')\">Quitar imagen</button></div>"
            "<input type=hidden name=logo id=lavatar></div></div>"
            "<div class=actions><button class=primary type=submit>Guardar</button></div>"
            "</form></section>")
    # --- tarjeta: actualizar el panel desde GitHub (solo codigo, no config; solo admin) ---
    card_update = ""
    if es_admin and yo:
        info = update_info()
        local = _sha_local()
        disp = bool(info.get("disponible"))
        upd_err = info.get("error") if not disp else None
        try:
            _ures = json.load(open("/var/log/suricata-update-result.json", encoding="utf-8"))
        except Exception:
            _ures = {}
        rollback_aviso = ("<div style='background:#fdecec;border:1px solid #f3c4c4;color:#b52a2a;"
                          "border-radius:9px;padding:10px 13px;margin:0 0 12px;font-size:13px'>"
                          "&#9888; La ultima actualizacion se <b>revirtio automaticamente</b>: el codigo nuevo no "
                          "levanto y se restauro la version previa. Reintenta mas tarde o revisa el cambio."
                          "</div>") if (_ures and not _ures.get("ok") and _ures.get("rollback")) else ""
        sha_corto = (local[:7] if local else None)
        ultimo = info.get("ultimo") or ""
        mejoras = info.get("mejoras") or []
        changelog = info.get("changelog") or []
        last = update_last()
        _vcss = ("<style>"
                 ".verhead{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap;margin:4px 0 14px}"
                 ".verlbl{font-size:12px;color:#8a8a86;font-weight:600}"
                 ".versha{font:700 20px ui-monospace,Menlo,Consolas,monospace;color:#0b0b0b;margin-top:2px}"
                 ".verbadge{padding:5px 12px;border-radius:20px;font-size:12.5px;font-weight:700;white-space:nowrap}"
                 ".verbadge.new{background:#1a7f37;color:#fff}.verbadge.ok{background:#e8ece9;color:#4a4a46}"
                 ".verblk{margin:0 0 12px}.vermsg{font-size:14px;color:#33322f;margin-top:3px}"
                 ".versep{border:0;border-top:1px solid #ececea;margin:14px 0}"
                 ".verstatus{display:flex;align-items:center;justify-content:center;gap:8px;font-weight:700;font-size:15px;margin:2px 0 14px}"
                 ".vermej{list-style:none;margin:0 auto 14px;padding:0;max-width:640px;display:flex;flex-direction:column;gap:6px}"
                 ".vermej li{background:#eef7f1;border:1px solid #cfe8d9;border-radius:8px;padding:8px 12px 8px 32px;position:relative;font-size:13.5px;color:#245c3c;line-height:1.4}"
                 ".vermej li::before{content:'\\2713';position:absolute;left:12px;top:8px;color:#1a7f37;font-weight:700}"
                 ".verstatus.new{color:#1a7f37}.verstatus.ok{color:#52514e}.verstatus.warn{color:#b06a00}"
                 ".verbadge.warn{background:#fdf1dc;color:#8a5a00}"
                 ".veractions{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:12px}.veractions form{margin:0}"
                 ".verbtn2{background:#eef0f2;color:#33322f;border:1px solid #d7d6d2;padding:11px 16px;border-radius:9px;font:600 14px system-ui;cursor:pointer}"
                 ".verbtn2:hover{background:#e2e5e8}"
                 ".verlast{text-align:center;color:#3f7d55;font-size:13px;margin:0 0 16px}"
                 ".verchg{border:1px solid #e7e6e2;border-radius:10px;overflow:hidden}"
                 ".verchgh{background:#12161c;color:#fff;text-align:center;font-weight:700;font-size:13.5px;padding:8px}"
                 ".verchgt{width:100%;border-collapse:collapse;font-size:13.5px}"
                 ".verchgt td{padding:9px 12px;border-top:1px solid #f0efec;vertical-align:top}"
                 ".verchgt td.c1{width:66px}.verchgt td.c3{width:94px;color:#8a8a86;white-space:nowrap;text-align:right}"
                 ".vnew{color:#1a7f37;font-weight:700}"
                 ".verbuild{font:12px ui-monospace,Consolas,monospace;color:#9a9a95;margin-top:3px}"
                 "</style>")
        if disp:
            badge = "<span class='verbadge new'>hay una version nueva</span>"
            estado = "<div class='verstatus new'>&#9432; Hay actualizaciones disponibles</div>"
        elif upd_err:
            badge = "<span class='verbadge warn'>sin verificar</span>"
            estado = f"<div class='verstatus warn'>&#9888; No se pudo consultar GitHub: {esc(upd_err)}</div>"
        else:
            badge = "<span class='verbadge ok'>estas al dia</span>"
            estado = "<div class='verstatus ok'>&#10003; Estas en la ultima version</div>"
        # el boton de aplicar esta SIEMPRE disponible (para poder forzar la actualizacion a
        # mano), no solo cuando el chequeo marca 'disponible': primario si hay update,
        # secundario ('Actualizar de todos modos') si ya se esta al dia.
        _lbl = "&#8681; Actualizar ahora" if disp else "&#8681; Actualizar de todos modos"
        _cls = "primary" if disp else "verbtn2"
        btn_upd = ("<form id=updform_hub method=post action='/update-panel'>"
                   f"<button class={_cls} type=button onclick=\"updaskShow('updform_hub')\">{_lbl}</button></form>")
        btn_buscar = ("<form method=post action='/buscar-update'>"
                      "<button class=verbtn2 type=submit>Buscar actualizaciones</button></form>")
        btn_hist = ("<button type=button class=verbtn2 "
                    "onclick=\"var e=document.getElementById('histwrap');e.hidden=!e.hidden\">Historial de cambios</button>")
        acciones = "<div class=veractions>" + btn_upd + btn_buscar + btn_hist + "</div>"
        linea_last = ""
        if last.get("from") and local:
            linea_last = (f"<div class=verlast>&#10003; Actualizado de <b>{esc(last['from'][:7])}</b> a "
                          f"<b>{esc(local[:7])}</b>" + (f" por {esc(last.get('by',''))}" if last.get('by') else "") + ".</div>")
        # historial de cambios (colapsable, se abre con el boton 'Historial de cambios')
        if changelog:
            filas = ""
            for c in changelog:
                et = "<span class=vnew>Nuevo</span>" if c.get("nuevo") else ""
                filas += (f"<tr><td class=c1>{et}</td><td>{esc(c.get('subject',''))}</td>"
                          f"<td class=c3>{esc(c.get('fecha',''))}</td></tr>")
            cuerpo_hist = f"<table class=verchgt><tbody>{filas}</tbody></table>"
        else:
            cuerpo_hist = ("<p class=sub2 style='padding:12px;margin:0'>Sin historial cargado todavia. "
                           "Pulsa <b>Buscar actualizaciones</b> para traerlo desde GitHub.</p>")
        tabla = ("<div id=histwrap hidden style='margin-top:12px'>"
                 "<div class=verchg><div class=verchgh>Registro de cambios</div>"
                 f"{cuerpo_hist}</div></div>")
        card_update = (
            _vcss + "<section class=card><h2>Version y actualizaciones</h2>" + rollback_aviso +
            "<div class=verhead><div><div class=verlbl>Version desplegada</div>"
            f"<div class=versha>{PANEL_VERSION}</div>"
            f"<div class=verbuild>build {esc(sha_corto) if sha_corto else '&mdash;'}</div></div>{badge}</div>"
            f"<div class=verblk><div class=verlbl>Ultimo cambio</div>"
            f"<div class=vermsg>{esc(ultimo) if ultimo else 'Pulsa <b>Buscar actualizaciones</b> para consultar GitHub.'}</div></div>"
            "<hr class=versep>" + estado
            + (("<ul class=vermej>" + "".join(f"<li>{esc(m)}</li>" for m in mejoras) + "</ul>")
               if (disp and mejoras) else "")
            + acciones + linea_last + tabla +
            "<p class=sub2 style='margin-top:14px;color:#8a8a86'>Solo actualiza el codigo del panel y de los reportes; "
            "no toca tu configuracion (usuarios, exclusiones, empresa, IPs de confianza, clave, ni HOME_NET/Suricata).</p>"
            "</section>")
    # --- tarjeta: reputacion / feeds (Auth-Key abuse.ch + estado por fuente; solo admin) ---
    card_feeds = ""
    if es_admin and yo:
        meta = cargar_feeds_meta()
        srcs = meta.get("sources", {})
        auth_ok = feeds_auth_configurada()
        def _estb(e):
            c = {"valido": "#1a7f37", "vacio": "#e58a00", "error": "#b52a2a",
                 "sin-clave": "#7a4a12", "caducado": "#b52a2a"}.get(e, "#8a8a86")
            return (f"<span style='background:{c};color:#fff;font-size:10.5px;font-weight:700;"
                    f"padding:2px 8px;border-radius:20px'>{esc(e)}</span>")
        filas = ""
        for name, s in srcs.items():
            fv = s.get("fetched_valid", 0)
            ult = time.strftime("%d/%m %H:%M", time.localtime(fv)) if fv else "&mdash;"
            exp = time.strftime("%d/%m %H:%M", time.localtime(s.get("expira", 0))) if s.get("expira") else "&mdash;"
            vig = "si" if s.get("vigente") else "no"
            filas += (f"<tr><td class=mono>{esc(name)}</td><td>{_estb(s.get('estado', '?'))}</td>"
                      f"<td>{vig}</td><td class=num>{s.get('count', 0):,}</td>"
                      f"<td class=mono>{ult}</td><td class=mono>{exp}</td></tr>")
        if not filas:
            filas = ("<tr><td colspan=6 class=hint style='padding:12px'>Sin datos de feeds todavia. "
                     "Pulsa 'Actualizar feeds ahora'.</td></tr>")
        gen = meta.get("generated", 0)
        genT = time.strftime("%d/%m %H:%M", time.localtime(gen)) if gen else "nunca"
        card_feeds = (
            "<style>.feedt{width:100%;border-collapse:collapse;font-size:13px;margin:10px 0 2px}"
            ".feedt th,.feedt td{padding:7px 10px;border-top:1px solid #f0efec;text-align:left}"
            ".feedt th{color:#8a8a86;font-size:12px;border-top:0}.feedt .num{text-align:right}</style>"
            "<section class=card><h2>Reputacion / feeds</h2>"
            "<p class=sub2>Fuentes de reputacion (IPs y dominios de C2/malware) que respaldan el riesgo. "
            "URLhaus y ThreatFox de abuse.ch exigen una <b>Auth-Key</b> gratis "
            "(<a href='https://auth.abuse.ch/' target=_blank>auth.abuse.ch</a>). La clave se guarda solo "
            "en este servidor (permisos 600) y <b>no se vuelve a mostrar</b>.</p>"
            "<form method=post action='/feeds'>"
            "<div class=field><label>Auth-Key de abuse.ch "
            + ("<span style='color:#3a9d5d'>(configurada)</span>" if auth_ok else "<span style='color:#b06a00'>(sin configurar)</span>")
            + "</label>"
            "<input type=password name=authkey autocomplete=new-password placeholder='"
            + ("dejar vacio para conservar" if auth_ok else "pega tu Auth-Key") + "'>"
            "<div class=hint>Al guardar se <b>valida contra abuse.ch</b> (una clave invalida se rechaza). "
            "Solo escritura. Para <b>quitarla</b>, escribe <code>BORRAR</code>.</div></div>"
            "<div class=actions><button class=primary type=submit>Guardar clave</button></div></form>"
            "<form method=post action='/feeds/aidb'>"
            "<div class=field><label>Clave de AbuseIPDB "
            + ("<span style='color:#3a9d5d'>(configurada)</span>" if aidb_configurada() else "<span style='color:#b06a00'>(sin configurar)</span>")
            + "</label>"
            "<input type=password name=aidbkey autocomplete=new-password placeholder='"
            + ("dejar vacio para conservar" if aidb_configurada() else "pega tu clave de AbuseIPDB") + "'>"
            "<div class=hint>Gratis en <a href='https://www.abuseipdb.com/account/api' target=_blank "
            "rel=noopener>abuseipdb.com</a>. Sirve para <b>dos</b> cosas: la lista masiva de atacantes "
            "(fuente <code>abuseipdb</code> de la tabla) y la pestana <b>Consultar IP</b>, que dice que "
            f"ataques se le denuncian a una IP. El plan gratuito da <b>{AIDB_CUOTA:,}</b> consultas al dia. "
            "Se valida al guardar. Para <b>quitarla</b>, escribe <code>BORRAR</code>.</div></div>"
            "<div class=actions><button class=primary type=submit>Guardar clave de AbuseIPDB</button></div></form>"
            "<form method=post action='/feeds/reportar'>"
            "<label class=chk><input type=checkbox name=reportar"
            + (" checked" if aidb_reportar_activo() else "")
            + "> Permitir <b>denunciar</b> atacantes entrantes a AbuseIPDB</label>"
            "<div class=hint>Apagado por defecto. Con esto activado, cada atacante de la seccion "
            "<b>Ataques entrantes</b> muestra un boton <b>Denunciar</b>; <b>nunca</b> se denuncia solo, "
            "siempre lo pulsa una persona. Es una accion <b>publica y a tu nombre</b>. Nunca se denuncian "
            "IPs de tus redes ni de la lista 'Nunca bloquear', el comentario va <b>sin ninguna IP</b> "
            "(ni la tuya) y la misma IP no se repite antes de 24 h.</div>"
            "<div class=actions><button class=primary type=submit>Guardar</button></div></form>"
            "<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:6px'>"
            "<form method=post action='/feeds/actualizar' style='margin:0'>"
            "<button class=cancelbtn type=submit>Actualizar feeds ahora</button></form>"
            f"<span class=hint>Ultima corrida del actualizador: {genT}</span></div>"
            "<table class=feedt><thead><tr><th>Fuente</th><th>Estado</th><th>Vigente</th>"
            "<th class=num>Indicadores</th><th>Ultima valida</th><th>Caduca</th></tr></thead>"
            f"<tbody>{filas}</tbody></table></section>")
    # --- tarjeta: conexion al MikroTik para la cuarentena (solo admin) ---
    card_mk = ""
    if es_admin and yo:
        m = cargar_mk()
        tiene_pass = bool(m.get("PASS"))
        en = m.get("ENABLED") == "1"
        tls = m.get("TLS") == "1"
        card_mk = (
            "<section class=card><h2>MikroTik (cuarentena)</h2>"
            "<p class=sub2>Conexion por <b>API</b> para enviar las IPs de CPEs infectados a una "
            "<b>address-list</b> del MikroTik. El MikroTik decide que hacer con esa lista (drop, limitar) "
            "con <b>tus</b> reglas de firewall. La clave se guarda solo en este servidor (permisos 600).</p>"
            "<form method=post action='/mikrotik'>"
            "<div class=grid2>"
            f"<div class=field><label>Host / IP del MikroTik</label>"
            f"<input type=text name=host value=\"{esc(m.get('HOST',''))}\" placeholder='192.168.88.1'></div>"
            f"<div class=field><label>Puerto API</label>"
            f"<input id=mkport type=text name=port value=\"{esc(m.get('PORT','8728'))}\" placeholder='8728 (8729 si TLS)'></div>"
            f"<div class=field><label>Usuario API</label>"
            f"<input type=text name=user value=\"{esc(m.get('USER',''))}\" autocomplete=off></div>"
            f"<div class=field><label>Clave API {'<span style=color:#3a9d5d>(guardada)</span>' if tiene_pass else ''}</label>"
            "<input type=password name=pass autocomplete=new-password placeholder='"
            + ("dejar vacio para conservar" if tiene_pass else "clave del usuario API") + "'></div>"
            f"<div class=field><label>Address-list de cuarentena (infectados)</label>"
            f"<input type=text name=list value=\"{esc(m.get('LIST','suricata-cuarentena'))}\"></div>"
            f"<div class=field><label>TTL cuarentena (timeout)</label>"
            f"<input type=text name=ttl value=\"{esc(m.get('TTL','1h'))}\" placeholder='1h, 30m, 1d (vacio = permanente)'></div>"
            f"<div class=field><label>Address-list de DNS sospechoso</label>"
            f"<input type=text name=list_dns value=\"{esc(m.get('LIST_DNS','suricata-dns-sospechoso'))}\"></div>"
            f"<div class=field><label>TTL DNS sospechoso (timeout)</label>"
            f"<input type=text name=ttl_dns value=\"{esc(m.get('TTL_DNS','1d'))}\" placeholder='1d, 12h (vacio = permanente)'></div>"
            "</div>"
            "<div class=field style='margin-top:6px'><label class=chk>"
            f"<input type=checkbox name=tls value=1 {'checked' if tls else ''} "
            "onchange=\"var p=document.getElementById('mkport');if(this.checked){if(!p.value||p.value=='8728')p.value='8729';}else{if(!p.value||p.value=='8729')p.value='8728';}\">"
            " Usar API-SSL (TLS, puerto 8729)</label></div>"
            "<div class=field><label class=chk>"
            f"<input type=checkbox name=enabled value=1 {'checked' if en else ''}> "
            "Permitir enviar IPs al MikroTik</label>"
            "<div class=hint>Activado: aparece el boton para poner CPEs en cuarentena (el panel escribe en el router). "
            "Apagado: la pestana Cuarentena solo muestra sugerencias y no toca el MikroTik.</div></div>"
            "<div class=field><label class=chk>"
            f"<input type=checkbox name=auto value=1 {'checked' if m.get('AUTO_MANTENER') == '1' else ''}> "
            "Mantener la cuarentena automaticamente</label>"
            "<div class=hint>Activado: la IP entra SIN caducidad y se <b>libera sola</b> cuando el CPE deja de atacar "
            "(mientras siga enviando virus, sigue en cuarentena). Apagado: la IP caduca sola con el TTL de arriba.</div></div>"
            "<div class=field style='margin-top:6px'><label class=chk>"
            f"<input type=checkbox name=doble value=1 {'checked' if conf_dash_get('DOBLE_SENAL','1') == '1' else ''}> "
            "Doble senal para confirmar infeccion</label>"
            "<div class=hint>Exige <b>2 indicios independientes</b> (repeticion, varias firmas, fan-out, volumen) "
            "o una senal abrumadora antes de marcar un CPE como infectado. Menos falsos positivos.</div></div>"
            "<div class=field><label>Nunca bloquear (una IP o CIDR por linea)</label>"
            "<textarea name=nunca rows=3 style='width:100%;box-sizing:border-box;font:12px ui-monospace,Consolas,monospace;"
            "padding:8px;border:1px solid #d7d6d2;border-radius:8px' "
            f"placeholder='192.0.2.10&#10;198.51.100.0/24'>{esc(cargar_nunca())}</textarea>"
            "<div class=hint>Estas IPs/redes <b>jamas</b> entran a cuarentena (infra, DNS, clientes criticos), "
            "ni por politica ni a mano.</div></div>"
            + _card_politicas(m) +
            "<div class=actions>"
            "<button class=primary type=submit>Guardar</button>"
            "<button class=cancelbtn type=button onclick=\"mktest(this)\">Probar conexion</button>"
            "</div></form>"
            "<div id=mkwait class=mkwait onclick=\"if(event.target===this)this.style.display='none'\">"
            "<div class=mkbox><div class=mkspin></div><div><b>Probando conexion&hellip;</b></div></div></div>"
            "<style>.mkwait{display:none;position:fixed;inset:0;background:rgba(11,11,11,.5);z-index:100;"
            "align-items:center;justify-content:center}"
            ".mkwait .mkbox{background:#fff;border-radius:14px;padding:24px 28px;display:flex;align-items:center;gap:16px;"
            "max-width:440px;box-shadow:0 10px 40px rgba(0,0,0,.3)}"
            ".nodoform{border:1px solid #e7e6e2;border-radius:10px;padding:12px 14px;margin:12px 0;background:#fbfcfe}"
            ".nodohd{display:flex;align-items:center;gap:10px;margin:0 0 8px;font-size:14px}"
            ".nodoif{font:11px ui-monospace,Consolas,monospace;background:#eef2f7;color:#33322f;border-radius:5px;padding:2px 7px}"
            ".nodoacts{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}"
            ".nodost td,.nodost th{font-size:13px}"
            ".nodonew{margin-top:10px}"
            ".nodonew summary{cursor:pointer;font-weight:700;font-size:13.5px;color:#2a5fa0}"
            ".mkwait .mkspin{width:30px;height:30px;flex:0 0 auto;border:3px solid #e7e6e2;border-top-color:#2a78d6;"
            "border-radius:50%;animation:mkspin .8s linear infinite}"
            "@keyframes mkspin{to{transform:rotate(360deg)}}</style>"
            "<script>function mkclose(){document.getElementById('mkwait').style.display='none';}"
            "function mktest(btn){var f=btn.form,mo=document.getElementById('mkwait'),bx=mo.querySelector('.mkbox');"
            "bx.innerHTML=\"<div class='mkspin'></div><div><b>Probando conexion&hellip;</b><br><span style='color:#52514e;font-size:13px'>Espera unos segundos.</span></div>\";"
            "mo.style.display='flex';"
            "var d=new URLSearchParams(new FormData(f));d.set('ajax','1');"
            "fetch('/mikrotik/test',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:d.toString()})"
            ".then(function(r){return r.text();}).then(function(t){var ok=t.indexOf('OK')===0;"
            "var msg=t.replace(/^OK /,'').replace(/^ERR: /,'').replace(/</g,'&lt;');"
            "bx.innerHTML=\"<div style='font-size:30px;line-height:1'>\"+(ok?'\\u2705':'\\u26D4')+\"</div>\"+"
            "\"<div><b>\"+(ok?'Conexion OK':'No conecto')+\"</b><br>\"+"
            "\"<span style='color:#52514e;font-size:13px'>\"+msg+\"</span><br>\"+"
            "\"<button type=button class=cancelbtn style='margin-top:12px' onclick='mkclose()'>Cerrar</button></div>\";})"
            ".catch(function(e){bx.innerHTML=\"<div><b>Error</b><br>\"+e+"
            "\"<br><button type=button class=cancelbtn style='margin-top:10px' onclick='mkclose()'>Cerrar</button></div>\";});}</script>"
            "</section>")
    # --- tarjeta: gestion de usuarios estilo tabla (solo admin) ---
    card_users = ""
    if es_admin and yo:
        rows = []
        for i, r in enumerate(usuarios, 1):
            uraw = r.get("user", ""); un = esc(uraw); rl = r.get("role", "admin")
            nombre = r.get("nombre", ""); correo = r.get("correo", "")
            disp = esc(nombre) if nombre else un
            activo = r.get("activo", True)
            est_cls = "on" if activo else "off"; est_txt = "ACTIVADO" if activo else "DESACTIVADO"
            tu = ' <span class=me>tu</span>' if uraw == yo else ''
            filtro = esc(((nombre + " " + uraw + " " + correo).lower()))
            correo_c = esc(correo) if correo else "<span class=dash>&mdash;</span>"
            rows.append(
                f"<tr data-f=\"{filtro}\"><td class=idc>{i}</td>"
                f"<td><div class=nmcell>{_avatar(nombre, uraw, r.get('avatar'))}<span class=nm>{disp}</span>{tu}</div></td>"
                f"<td class=mono>{un}</td><td class=mono cmail>{correo_c}</td>"
                f"<td>{_rol_badge(rl)}</td>"
                "<td><form method=post action='/perfil' class=inl>"
                f"<input type=hidden name=accion value=toggle_user><input type=hidden name=user value='{un}'>"
                f"<button class='estado {est_cls}' type=submit title='clic para activar/desactivar'>{est_txt}</button></form></td>"
                "<td class=acts>"
                f"<button class=ic title=Editar type=button onclick=\"abrirEdit(this)\" "
                f"data-user='{un}' data-nombre=\"{esc(nombre)}\" data-correo=\"{esc(correo)}\" "
                f"data-role='{rl}'>{_IC_EDIT}</button>"
                "<form method=post action='/perfil' class=inl "
                f"onsubmit=\"return confirm('Eliminar al usuario {un}?')\">"
                f"<input type=hidden name=accion value=del_user><input type=hidden name=user value='{un}'>"
                f"<button class='ic danger' title=Eliminar type=submit>{_IC_DEL}</button></form>"
                "</td></tr>")
        modal_new = (
            "<div id=ovlNew class=ovl hidden onclick=\"if(event.target===this)cerrar('ovlNew')\">"
            "<div class=modal><div class=mhead><h3>Nuevo usuario</h3>"
            "<button class=mx type=button onclick=\"cerrar('ovlNew')\" aria-label=Cerrar>&times;</button></div>"
            "<form method=post action='/perfil'><input type=hidden name=accion value=add_user>"
            "<div class=mbody>"
            "<div class=grid2><div class=field><label>Nombre</label><input type=text name=nnombre autocomplete=off></div>"
            "<div class=field><label>Usuario</label><input type=text name=nuser autocomplete=off required></div></div>"
            "<div class=grid2><div class=field><label>Correo</label><input type=email name=ncorreo autocomplete=off></div>"
            "<div class=field><label>Rol</label><select name=nrole>"
            "<option value=lectura>Solo lectura</option><option value=operador>Operador (cuarentenas/incidentes)</option>"
            "<option value=admin>Administrador</option></select></div></div>"
            "<div class=field><label>Clave</label><input type=password name=npass autocomplete=new-password required>"
            "<div class=hint>Minimo 6 caracteres. Nombre y correo son opcionales.</div></div>"
            "<div class=field><label>Foto (opcional)</label><div class=avup>"
            "<img id=npreview class=avprev alt='' style=display:none>"
            "<input id=nfile type=file accept=image/* onchange=\"foto(this,'n')\">"
            "<button class=cancelbtn type=button onclick=\"quitarimg('n')\">Quitar</button></div>"
            "<input type=hidden name=avatar id=navatar></div>"
            "</div>"
            "<div class=mfoot><button class=cancelbtn type=button onclick=\"cerrar('ovlNew')\">Cancelar</button>"
            "<button class=primary type=submit>Crear usuario</button></div></form></div></div>")
        modal_edit = (
            "<div id=ovlEdit class=ovl hidden onclick=\"if(event.target===this)cerrar('ovlEdit')\">"
            "<div class=modal><div class=mhead><h3>Editar usuario</h3>"
            "<button class=mx type=button onclick=\"cerrar('ovlEdit')\" aria-label=Cerrar>&times;</button></div>"
            "<form method=post action='/perfil'><input type=hidden name=accion value=edit_user>"
            "<input type=hidden name=user id=eu>"
            "<div class=mbody>"
            "<div class=grid2><div class=field><label>Nombre</label><input type=text name=nombre id=en></div>"
            "<div class=field><label>Correo</label><input type=email name=correo id=ec></div></div>"
            "<div class=field><label>Rol</label><select name=role id=er>"
            "<option value=admin>Administrador</option><option value=operador>Operador (cuarentenas/incidentes)</option>"
            "<option value=lectura>Solo lectura</option></select></div>"
            "<div class=field><label>Clave nueva (opcional)</label>"
            "<input type=password name=npass autocomplete=new-password placeholder='dejar vacio para no cambiar'>"
            "<div class=hint>Si la escribes, minimo 6 caracteres.</div></div>"
            "<div class=field><label>Foto (opcional)</label><div class=avup>"
            "<img id=epreview class=avprev alt='' style=display:none>"
            "<input id=efile type=file accept=image/* onchange=\"foto(this,'e')\">"
            "<button class=cancelbtn type=button onclick=\"quitarimg('e')\">Quitar</button></div>"
            "<div class=hint>Sube una imagen para cambiarla, o Quitar para borrarla.</div>"
            "<input type=hidden name=avatar id=eavatar></div>"
            "</div>"
            "<div class=mfoot><button class=cancelbtn type=button onclick=\"cerrar('ovlEdit')\">Cancelar</button>"
            "<button class=primary type=submit>Guardar cambios</button></div></form></div></div>")
        card_users = (
            "<section class=card>"
            "<div class=uhead><h2>Usuarios</h2>"
            "<div class=tools>"
            "<button class='primary sm' type=button onclick=\"abrir('ovlNew')\">+ Nuevo</button>"
            "<input class=search id=usearch placeholder='Buscar...' oninput='ufiltrar()'></div></div>"
            "<p class=sub2>Los de <b>solo lectura</b> ven paneles y reportes pero no editan exclusiones, "
            "ni actualizan reglas, ni gestionan usuarios.</p>"
            "<div class=twrap><table class=ut><thead><tr>"
            "<th>ID</th><th>Nombre</th><th>Usuario</th><th>Correo</th><th>Rol</th><th>Estado</th><th></th>"
            f"</tr></thead><tbody id=ubody>{''.join(rows)}</tbody></table></div>"
            "</section>" + modal_new + modal_edit)
    # --- tarjeta: accesos y seguridad (log de login + desbloqueo; solo admin) ---
    card_acceso = ""
    if es_admin and yo:
        bloq = ips_bloqueadas()
        if bloq:
            brows = "".join(
                f"<tr><td class=mono>{esc(ip)}</td><td>{intentos} fallos</td><td>{seg//60 + 1} min</td>"
                "<td class=acts><form method=post action='/perfil' class=inl>"
                "<input type=hidden name=accion value=unlock_ip>"
                f"<input type=hidden name=ip value='{esc(ip)}'>"
                "<button class=mini type=submit>Desbloquear</button></form></td></tr>"
                for ip, seg, intentos in bloq)
            blq = ("<div class=twrap><table class=ut><thead><tr><th>IP bloqueada</th><th>Motivo</th>"
                   f"<th>Expira en</th><th></th></tr></thead><tbody>{brows}</tbody></table></div>")
        else:
            blq = "<p class=sub2>No hay IPs bloqueadas ahora.</p>"
        # IPs de confianza (allowlist del panel)
        trust = cargar_confianza()
        myip = getattr(CTX, "ip", "?")
        if trust:
            crows = "".join(
                f"<tr><td class=mono>{esc(t)}</td>"
                "<td class=acts><form method=post action='/perfil' class=inl>"
                "<input type=hidden name=accion value=del_trust>"
                f"<input type=hidden name=ip value='{esc(t)}'>"
                "<button class='mini danger' type=submit>Quitar</button></form></td></tr>"
                for t in trust)
            ctab = ("<div class=twrap><table class=ut><thead><tr><th>IP / CIDR de confianza</th><th></th>"
                    f"</tr></thead><tbody>{crows}</tbody></table></div>"
                    "<p class=sub2 style='color:#12805a'><b>Activo:</b> solo estas IPs pueden entrar al panel.</p>")
        else:
            ctab = ("<p class=sub2>Sin IPs de confianza: <b>cualquiera</b> puede intentar entrar y se "
                    "<b>bloquea tras 8 fallos</b>. Si agregas IPs aqui, <b>solo esas</b> podran acceder.</p>")
        addc = (
            "<form method=post action='/perfil' class=fotoform style='margin-top:4px'>"
            "<input type=hidden name=accion value=add_trust>"
            "<input type=text name=ip placeholder='IP o CIDR (ej. 200.10.20.30 o 192.168.1.0/24)' style='flex:1;min-width:200px'>"
            "<button class=primary type=submit>Agregar</button></form>"
            f"<p class=sub2>Tu IP actual es <b class=mono>{esc(myip)}</b>. "
            "Agregala (o un rango que la incluya) antes de restringir, o quedarias fuera.</p>")
        card_acceso = (
            "<section class=card><h2>Accesos y seguridad</h2>"
            "<p class=sub2>Controla quien puede entrar al panel. El historial de intentos esta en la pestana "
            "<b>Log</b>.</p>"
            "<h3 class=ch>IPs de confianza</h3>" + ctab + addc +
            "<h3 class=ch>IPs bloqueadas ahora</h3>" + blq +
            "</section>")
    css = (
        BASE_CSS +
        "body{background:#f6f6f4}main{max-width:900px;padding:26px 20px 40px}"
        "h1{font-size:22px;margin:0 0 2px}h2{margin:0}"
        ".psub{color:#6b6a66;font-size:13px;margin:0 0 18px}.sub2{color:#6b6a66;font-size:12.5px;margin:6px 0 12px}"
        ".card{border:1px solid #e7e6e2;border-radius:14px;padding:22px 22px 20px;background:#fff;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.03)}"
        ".ch{font-size:13px;color:#52514e;margin:18px 0 6px;padding-top:16px;border-top:1px solid #f0efec}"
        ".acct{display:flex;align-items:center;gap:14px}"
        ".avatar{width:46px;height:46px;border-radius:50%;background:linear-gradient(135deg,#2a78d6,#1c5cab);color:#fff;font:700 20px system-ui;display:flex;align-items:center;justify-content:center;flex:none}"
        ".aname{font-size:17px;font-weight:700}.arole{margin-top:3px}"
        ".rbadge{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;background:#ecebe7;color:#52514e}"
        ".rbadge.adm{background:#e7f0fb;color:#1c5cab}.rbadge.lec{background:#eceae6;color:#6b6a66}"
        ".rbadge.ope{background:#e6f4ea;color:#1a7f37}"
        ".field{margin:12px 0 0}label{display:block;font-size:12.5px;color:#52514e;margin:0 0 5px;font-weight:600}"
        "input,select{width:100%;padding:9px 11px;border:1px solid #d7d6d2;border-radius:8px;font:14px system-ui;box-sizing:border-box;background:#fff}"
        "label.chk{display:flex;align-items:center;gap:9px;font-weight:500;color:#33322f;margin:0;cursor:pointer}"
        "label.chk input{width:auto;flex:0 0 auto;margin:0;padding:0;box-shadow:none}"
        "input:focus,select:focus{outline:none;border-color:#2a78d6;box-shadow:0 0 0 3px rgba(42,120,214,.15)}"
        ".grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}"
        ".addgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}"
        "@media(max-width:640px){.grid2,.addgrid{grid-template-columns:1fr}}"
        ".hint{color:#9a9a95;font-size:12px;margin-top:6px}.actions{margin-top:18px;display:flex;gap:12px;align-items:center}"
        "button.primary{padding:10px 18px;background:#2a78d6;color:#fff;border:0;border-radius:9px;font:600 14px system-ui;cursor:pointer}"
        "button.primary:hover{background:#1c5cab}button.primary.sm{padding:8px 14px;font-size:13px}"
        ".cancel{color:#6b6a66;font-size:13px;text-decoration:none}.cancel:hover{color:#0b0b0b}"
        ".uhead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}"
        ".tools{display:flex;gap:10px;align-items:center}"
        ".search{width:220px;padding:8px 12px}"
        ".twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px;margin:6px 0 4px}"
        ".ut{width:100%;border-collapse:collapse;font-size:13px;white-space:nowrap}"
        ".ut th{text-align:left;color:#8a8a86;font-weight:600;padding:10px 12px;background:#fafafa;border-bottom:1px solid #eee}"
        ".ut td{padding:9px 12px;border-bottom:1px solid #f2f1ee;vertical-align:middle}"
        ".ut tbody tr:last-child td{border-bottom:0}.ut tbody tr:hover{background:#fafbfd}"
        ".idc{color:#9a9a95;font-variant-numeric:tabular-nums}"
        ".nmcell{display:flex;align-items:center;gap:9px}.nm{font-weight:600}"
        ".av{width:30px;height:30px;border-radius:50%;color:#fff;font:700 11px system-ui;display:inline-flex;align-items:center;justify-content:center;flex:none}"
        ".mono{font-family:ui-monospace,Consolas,monospace}.cmail{color:#52514e}.dash{color:#c3c2be}"
        ".me{background:#e7f0fb;color:#1c5cab;font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px;margin-left:2px}"
        ".estado{font-size:10px;font-weight:800;letter-spacing:.3px;padding:4px 9px;border-radius:6px;border:0;cursor:pointer}"
        ".estado.on{background:#12b886;color:#fff}.estado.off{background:#eceae6;color:#8a8a86}"
        ".estado:hover{filter:brightness(1.06)}"
        ".acts{display:flex;gap:8px;justify-content:flex-end}.inl{display:inline-flex;margin:0}"
        ".ic{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:8px;"
        "border:1px solid #e0dfda;background:#fff;color:#52514e;cursor:pointer;text-decoration:none}"
        ".ic:hover{background:#eef2f7;color:#2a78d6;border-color:#cddaea}"
        ".ic.danger:hover{background:#e34948;color:#fff;border-color:#e34948}"
        ".banner{padding:11px 14px;border-radius:9px;margin-bottom:16px;font-size:13px;color:#fff}"
        ".banner.err{background:#e34948}"
        ".banner.ok{background:#1baf7a;animation:bfade 2.8s ease forwards}"
        "@keyframes bfade{0%,68%{opacity:1;transform:translateY(0)}"
        "100%{opacity:0;transform:translateY(-8px);visibility:hidden;height:0;margin:0;padding:0}}"
        ".ovl{position:fixed;inset:0;background:rgba(11,11,11,.45);display:flex;align-items:center;justify-content:center;z-index:100;padding:18px}"
        ".ovl[hidden]{display:none}"
        ".modal{background:#fff;border-radius:14px;width:100%;max-width:470px;box-shadow:0 20px 55px rgba(0,0,0,.32);animation:mpop .16s ease}"
        "@keyframes mpop{from{transform:translateY(10px);opacity:.5}to{transform:none;opacity:1}}"
        ".mhead{display:flex;align-items:center;justify-content:space-between;padding:15px 20px;border-bottom:1px solid #f0efec}"
        ".mhead h3{margin:0;font-size:16px}"
        ".mx{background:none;border:0;font-size:24px;line-height:1;color:#8a8a86;cursor:pointer;padding:0 2px}.mx:hover{color:#0b0b0b}"
        ".mbody{padding:2px 20px 16px}"
        ".mfoot{display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:14px 20px;border-top:1px solid #f0efec;background:#fafafa;border-radius:0 0 14px 14px}"
        ".mfoot button.primary{margin:0}"
        ".cancelbtn{padding:9px 16px;background:#fff;border:1px solid #d7d6d2;border-radius:9px;color:#52514e;font:600 13px system-ui;cursor:pointer}.cancelbtn:hover{background:#f4f4f2}"
        "img.av{object-fit:cover}img.avatar{object-fit:cover;padding:0}"
        ".avup{display:flex;align-items:center;gap:12px;margin-top:2px;flex-wrap:wrap}"
        ".avup input[type=file]{flex:1;min-width:150px;padding:7px}"
        ".avprev{width:46px;height:46px;border-radius:50%;object-fit:cover;border:1px solid #e0dfda;background:#fafafa;flex:none}"
        ".avprev.logo{width:auto;height:40px;max-width:150px;border-radius:6px;object-fit:contain;padding:2px;background:#fff}"
        ".fotoform{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.fotoform input[type=file]{flex:1;min-width:160px}"
        ".fotoform .primary,.fotoform .cancelbtn{margin-top:0}")
    script = ("<script>"
              "function foto(inp,p){var f=inp.files&&inp.files[0];if(!f)return;var r=new FileReader();"
              "r.onload=function(){var im=new Image();im.onload=function(){var mx=160,w=im.width,h=im.height;"
              "if(w>h){if(w>mx){h=h*mx/w;w=mx;}}else{if(h>mx){w=w*mx/h;h=mx;}}"
              "var c=document.createElement('canvas');c.width=w;c.height=h;c.getContext('2d').drawImage(im,0,0,w,h);"
              "var d=c.toDataURL('image/png');var hid=document.getElementById(p+'avatar');if(hid)hid.value=d;"
              "var pv=document.getElementById(p+'preview');if(pv){pv.src=d;pv.style.display='';}};im.src=r.result;};"
              "r.readAsDataURL(f);}"
              "function quitarimg(p){var h=document.getElementById(p+'avatar');if(h)h.value='__BORRAR__';"
              "var pv=document.getElementById(p+'preview');if(pv){pv.removeAttribute('src');pv.style.display='none';}"
              "var fi=document.getElementById(p+'file');if(fi)fi.value='';}"
              "function abrir(id){document.getElementById(id).hidden=false;}"
              "function cerrar(id){document.getElementById(id).hidden=true;}"
              "function abrirEdit(b){document.getElementById('eu').value=b.getAttribute('data-user');"
              "document.getElementById('en').value=b.getAttribute('data-nombre')||'';"
              "document.getElementById('ec').value=b.getAttribute('data-correo')||'';"
              "document.getElementById('er').value=b.getAttribute('data-role')||'lectura';"
              "var p=document.querySelector('#ovlEdit input[name=npass]');if(p)p.value='';abrir('ovlEdit');}"
              "function ufiltrar(){var q=(document.getElementById('usearch').value||'').toLowerCase();"
              "var rs=document.querySelectorAll('#ubody tr');for(var i=0;i<rs.length;i++){"
              "var f=rs[i].getAttribute('data-f')||'';rs[i].style.display=f.indexOf(q)>=0?'':'none';}}"
              "document.addEventListener('keydown',function(e){if(e.key==='Escape'){cerrar('ovlNew');cerrar('ovlEdit');}});"
              "</script>")
    # --- hub de accesos: cada apartado abre en su MODAL (Log y Documentacion incluidos) ---
    def _tile(sid, label, icon, show=True):
        if not show:
            return ""
        return (f"<a class=hubt href='#' onclick=\"return openm('{sid}')\">"
                f"<span class=hubc>{icon}</span><span class=hubl>{esc(label)}</span></a>")
    tiles = (_tile("perfil", "Perfil", _IC_USER, bool(card_pw))
             + _tile("empresa", "Empresa", _IC_BLD, bool(card_empresa))
             + _tile("usuarios", "Usuarios y roles", _IC_USERS, bool(card_users))
             + _tile("acceso", "IPs de confianza", _IC_SHIELD, bool(card_acceso))
             + _tile("mikrotik", "MikroTik", _IC_RTR, bool(card_mk))
             + _tile("feeds", "Reputacion", _IC_FEED, bool(card_feeds))
             + _tile("update", "Actualizaciones", _IC_DL, bool(card_update))
             + _tile("log", "Log", _IC_LOG, es_admin)
             + _tile("bitacora", "Bitacora", _IC_AUDIT, es_admin)
             + _tile("doc", "Documentacion", _IC_BOOK, True))
    hub = f"<div class=hubgrid>{tiles}</div>"
    def _modal(sid, contenido):
        return (f"<div class=aptmodal id=m-{sid} onclick=\"if(event.target===this)closem()\">"
                f"<div class=aptbox><button type=button class=aptx onclick=closem() title=Cerrar>&times;</button>"
                f"<div class=aptscroll>{contenido}</div></div></div>")
    def _mcard(sid, card):
        return _modal(sid, card) if card else ""
    modals = (_mcard("perfil", card_pw) + _mcard("empresa", card_empresa) + _mcard("usuarios", card_users)
              + _mcard("acceso", card_acceso) + _mcard("mikrotik", card_mk + (_card_nodos() if card_mk else "")) + _mcard("feeds", card_feeds)
              + _mcard("update", card_update))
    if es_admin:
        modals += _modal("log", "<iframe class=aptframe data-src='/log?embed=1'></iframe>")
        modals += _modal("bitacora", "<iframe class=aptframe data-src='/bitacora?embed=1'></iframe>")
    modals += _modal("doc", "<iframe class=aptframe data-src='/documentacion?embed=1'></iframe>")
    hubcss = ("<style>.hubgrid{display:flex;flex-wrap:wrap;gap:22px;margin:18px 0}"
              ".hubt{display:flex;flex-direction:column;align-items:center;gap:9px;width:118px;text-decoration:none;color:#33322f;cursor:pointer}"
              ".hubc{width:90px;height:90px;border-radius:50%;background:#109c8e;color:#fff;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(16,156,142,.28);transition:transform .12s,box-shadow .12s}"
              ".hubt:hover .hubc{transform:translateY(-3px);box-shadow:0 9px 20px rgba(16,156,142,.4)}"
              ".hubl{font-size:13px;font-weight:600;text-align:center;line-height:1.2}"
              ".aptmodal{display:none;position:fixed;inset:0;background:rgba(11,11,11,.5);z-index:90;align-items:center;justify-content:center;padding:24px;overflow:auto}"
              ".aptmodal .aptbox{position:relative;margin:auto;background:#fcfcfb;border-radius:14px;max-width:980px;width:100%;max-height:calc(100vh - 48px);overflow:hidden;box-shadow:0 12px 48px rgba(0,0,0,.35)}"
              ".aptmodal .aptscroll{max-height:calc(100vh - 48px);overflow:auto;padding:16px 20px 24px}"
              ".aptmodal .aptx{position:absolute;top:8px;right:8px;border:0;background:#eceae6;color:#33322f;width:30px;height:30px;border-radius:50%;font-size:19px;line-height:1;cursor:pointer;z-index:3}"
              ".aptmodal .aptx:hover{background:#e34948;color:#fff}"
              ".aptmodal .aptframe{width:100%;height:74vh;border:0;border-radius:8px;background:#fff}"
              ".notifm{position:fixed;top:18px;left:50%;transform:translateX(-50%) translateY(-16px);z-index:140;"
              "display:flex;align-items:center;gap:10px;max-width:560px;padding:12px 16px;border-radius:12px;"
              "font-size:14px;box-shadow:0 8px 30px rgba(0,0,0,.25);opacity:0;transition:opacity .25s,transform .25s;pointer-events:none}"
              ".notifm.show{opacity:1;transform:translateX(-50%) translateY(0)}"
              ".notifm.ok{background:#e6f4ea;color:#1a7f37;border:1px solid #b7e0c2}"
              ".notifm.err{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4}"
              ".notifm .ni{font-size:18px}"
              "</style>")
    ntf = ("<div id=notif class='notifm " + ("ok" if ok else "err") + "'>"
           "<span class=ni>" + ("✅" if ok else "⛔") + "</span><span>" + esc(msg) + "</span></div>") if msg else ""
    hubjs = ("<script>function openm(id){var mo=document.getElementById('m-'+id);if(!mo)return false;"
             "var fr=mo.querySelector('iframe[data-src]');if(fr&&!fr.src){fr.src=fr.getAttribute('data-src');}"
             "mo.style.display='flex';document.body.style.overflow='hidden';"
             "try{sessionStorage.setItem('apt',id);}catch(e){}return false;}"
             "function closem(){var a=document.querySelectorAll('.aptmodal');for(var i=0;i<a.length;i++)a[i].style.display='none';"
             "document.body.style.overflow='';try{sessionStorage.removeItem('apt');}catch(e){}}"
             "document.addEventListener('keydown',function(e){if(e.key==='Escape')closem();});"
             "(function(){var n=document.getElementById('notif');if(!n)return;"
             "var la=null;try{la=sessionStorage.getItem('apt');}catch(e){}if(la)openm(la);"
             "setTimeout(function(){n.classList.add('show');},60);"
             "setTimeout(function(){n.classList.remove('show');},3400);})();</script>")
    return ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>Suricata</title>"
            f"<style>{css}</style>" + hubcss + "</head><body>"
            + nav("/ajustes") +
            "<main><h1>Ajustes</h1>"
            "<p class=psub>Toca cada apartado para abrirlo.</p>"
            + hub + modals + ntf + script + hubjs +
            "</main></body></html>")

def exclusiones_page(msg="", ok=False, edit_idx=None):
    reglas = cargar_exclusiones(incluir_vencidas=True)
    ahora = time.time()
    def _vig_txt(r):
        h = r.get("hasta") or 0
        if not h:
            return "permanente"
        if r.get("vencida") or ahora > h:
            return "vencida " + time.strftime("%d/%m %H:%M", time.localtime(h))
        rest = int(h - ahora)
        if rest >= 86400:
            q = f"{rest // 86400} d"
        elif rest >= 3600:
            q = f"{rest // 3600} h"
        else:
            q = f"{max(1, rest // 60)} min"
        return f"vence en {q} ({time.strftime('%d/%m %H:%M', time.localtime(h))})"
    banner = ""
    if msg:
        col = "#1baf7a" if ok else "#e34948"
        anim = "animation:fadeout 2.7s ease forwards;" if ok else ""   # exito visible ~2s y se desvanece suave
        banner = f'<div class="banner" style="background:{col};color:#fff;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px;{anim}">{html.escape(msg)}</div>'
    # regla a editar (solo si es propia, no legacy)
    ed = None
    if edit_idx is not None and 0 <= edit_idx < len(reglas) and reglas[edit_idx].get("motivo") != "(conf)":
        ed = reglas[edit_idx]
    filas = []
    for i, r in enumerate(reglas):
        pts = ", ".join(str(p) for p in r["puertos"]) if r["puertos"] else "todos"
        tipo = "Destino" if r["tipo"] == "dst" else "Origen"
        legacy = r.get("motivo") == "(conf)"
        firma = html.escape(r.get("sid") or "cualquiera")
        vig = _vig_txt(r)
        vig_col = "#b52a2a" if (r.get("vencida") or (r.get("hasta") and ahora > r["hasta"])) else ("#6b6a66" if not r.get("hasta") else "#7a4a12")
        vig_html = f'<span style="color:{vig_col}">{html.escape(vig)}</span>'
        autor = r.get("autor") or ""
        mot = html.escape(r.get("motivo", "")) + (f'<div class="muted">por {html.escape(autor)}</div>' if autor else "")
        if legacy:
            accion = '<span class="muted">en .conf</span>'
        else:
            accion = (f'<div style="display:flex;gap:6px;align-items:center">'
                      f'<a class="edit" href="/exclusiones?edit={i}">Editar</a>'
                      f'<form method=post action="/exclusiones" style="margin:0">'
                      f'<input type=hidden name=accion value=del><input type=hidden name=idx value="{i}">'
                      f'<button class="del" type=submit>Eliminar</button></form></div>')
        resalta = ' style="background:#eef4fd"' if (ed is not None and i == edit_idx) else ''
        filas.append(f'<tr{resalta}><td>{tipo}</td><td class="mono">{html.escape(r["ip"])}</td>'
                     f'<td>{html.escape(pts)}</td><td class="mono">{firma}</td><td>{vig_html}</td>'
                     f'<td>{mot}</td><td>{accion}</td></tr>')
    tabla = ("".join(filas) if filas else
             '<tr><td colspan=7 class="muted">No hay exclusiones. Todo el trafico se analiza.</td></tr>')
    titulo_form = "Editar exclusion" if ed else "Agregar exclusion"
    val_ip = html.escape(ed["ip"]) if ed else ""
    val_pts = ", ".join(str(p) for p in ed["puertos"]) if ed else ""
    val_mot = html.escape(ed.get("motivo", "")) if ed else ""
    val_sid = html.escape(ed.get("sid", "")) if ed else ""
    sel_src = "selected" if ed and ed["tipo"] == "src" else ""
    sel_dst = "selected" if not ed or ed["tipo"] == "dst" else ""
    # vigencia: al editar, si ya venia con hasta se ofrece "mantener"
    _vig_opts = [("0", "Permanente"), ("24", "24 horas"), ("168", "7 dias"), ("720", "30 dias")]
    if ed and ed.get("hasta"):
        _rest_h = max(1, int((ed["hasta"] - time.time()) // 3600))
        vig_select = (f'<select name=vigencia><option value=keep selected>Mantener (~{_rest_h} h restantes)</option>'
                      + "".join(f'<option value="{v}">{t}</option>' for v, t in _vig_opts) + "</select>")
    else:
        vig_select = ("<select name=vigencia>"
                      + "".join(f'<option value="{v}"{" selected" if v == "0" else ""}>{t}</option>' for v, t in _vig_opts)
                      + "</select>")
    hid_edit = f'<input type=hidden name=editar value="{edit_idx}">' if ed else ""
    btn_txt = "Guardar cambios" if ed else "Agregar"
    cancelar = '<a class="cancel" href="/exclusiones">Cancelar</a>' if ed else ""
    body = f"""<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>
<meta name=viewport content='width=device-width,initial-scale=1'><title>Suricata</title>
<style>{BASE_CSS}
main{{max-width:820px;padding:24px 20px}}.sub{{margin:0 0 18px}}h2{{font-size:15px;margin:24px 0 10px}}
.card{{padding:18px}}
form.add{{display:grid;grid-template-columns:130px 1fr;gap:10px 12px;align-items:center}}
label{{font-size:13px;color:#52514e;font-weight:600}}
input,select{{padding:9px 11px;border:1px solid #d7d6d2;border-radius:8px;font:14px system-ui;width:100%;box-sizing:border-box}}
.hint{{grid-column:2;color:#8a8a86;font-size:12px;margin-top:-4px}}
button{{padding:9px 16px;border:0;border-radius:8px;font:600 13px system-ui;cursor:pointer}}
button[type=submit].primary{{background:#2a78d6;color:#fff;grid-column:2;justify-self:start;margin-top:4px}}
button.del{{background:#fbeaea;color:#c0392b;border:1px solid #f0c9c9;padding:5px 10px}}
button.del:hover{{background:#f5d5d5}}
a.edit{{background:#eef4fd;color:#1c5cab;border:1px solid #cfe0fb;padding:5px 12px;border-radius:8px;
text-decoration:none;font-size:13px;font-weight:600}}a.edit:hover{{background:#dceafb}}
a.cancel{{color:#8a8a86;text-decoration:none;font-size:13px}}a.cancel:hover{{color:#52514e}}
.eximp-row{{display:flex;gap:14px;align-items:center;flex-wrap:wrap}}
.eximp-imp{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0}}
.eximp-sep{{width:1px;align-self:stretch;background:#eceae6}}
.ebtn{{display:inline-flex;align-items:center;padding:9px 16px;border-radius:9px;font:600 13px system-ui;
cursor:pointer;text-decoration:none;border:1px solid transparent;transition:background .15s,border-color .15s}}
.ebtn.exp{{background:#f2f6fc;color:#1c5cab;border-color:#d6e2f2}}.ebtn.exp:hover{{background:#e6eef9;border-color:#c2d5ee}}
.ebtn.imp{{background:#2a78d6;color:#fff}}.ebtn.imp:hover{{background:#1c5cab}}
.filepick{{display:inline-flex;align-items:center;gap:10px;border:1px dashed #cdd3da;border-radius:9px;
padding:5px 10px 5px 5px;background:#fafbfc;cursor:pointer;max-width:100%}}
.filepick:hover{{border-color:#9db4d6;background:#f5f8fc}}
.filepick .filebtn{{background:#eceae6;color:#33322f;border-radius:7px;padding:6px 12px;font:600 13px system-ui;white-space:nowrap}}
.filepick .fname{{font-size:12.5px;color:#8a8a86;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:190px}}
.filepick input[type=file]{{position:absolute;width:1px;height:1px;opacity:0;overflow:hidden}}
@media(max-width:520px){{.eximp-sep{{display:none}}.eximp-row,.eximp-imp{{width:100%}}.filepick{{flex:1}}}}
@keyframes fadeout{{0%,74%{{opacity:1;transform:translateY(0)}}100%{{opacity:0;transform:translateY(-10px);visibility:hidden;margin:0;padding:0;height:0}}}}
@media(max-width:820px){{
 main{{padding:16px 14px}}
 .card{{overflow-x:auto}}
 table{{min-width:720px}}
 form.add{{grid-template-columns:1fr;gap:6px}}
 label{{margin-top:6px}}
 .hint,button[type=submit].primary{{grid-column:1}}
}}</style></head><body>{nav("/exclusiones")}<main>
<h1>Exclusiones</h1><p class=sub>IPs que no quieres que aparezcan en el panel ni en los reportes
(tus DNS, tu monitoreo SNMP, etc.). Se aplica al instante.</p>
{banner}
<div class=card><table><thead><tr><th>Tipo</th><th>IP</th><th>Puertos</th><th>Firma (SID)</th><th>Vigencia</th><th>Motivo</th><th></th></tr></thead>
<tbody>{tabla}</tbody></table></div>
<h2>{titulo_form}</h2>
<div class=card><form class=add method=post action="/exclusiones">
<input type=hidden name=accion value=add>{hid_edit}
<label>Tipo</label><select name=tipo><option value=dst {sel_dst}>Destino (a donde va)</option><option value=src {sel_src}>Origen (de donde sale)</option></select>
<label>IP</label><input name=ip placeholder="10.66.66.2" value="{val_ip}" required>
<label>Puertos</label><input name=puertos placeholder="53, 161  (vacio = todos)" value="{val_pts}">
<div class=hint>Para un DNS suele ser 53; para monitoreo SNMP, 161. Deja vacio para ignorar toda la IP.</div>
<label>Firma (SID)</label><input name=sid placeholder="p.ej. 2027865  (vacio = cualquier firma)" value="{val_sid}">
<div class=hint>Excluye SOLO esa firma para esta IP (util para un falso positivo puntual de un CPE). Vacio = todas.</div>
<label>Vigencia</label>{vig_select}
<div class=hint>Exclusion temporal: se ignora hasta que venza y luego vuelve a analizarse sola. "Permanente" no vence.</div>
<label>Motivo</label><input name=motivo placeholder="Falso positivo / DNS interno / monitoreo SNMP" value="{val_mot}">
<div style="grid-column:2;display:flex;gap:10px;align-items:center;margin-top:4px">
<button type=submit class=primary>{btn_txt}</button>{cancelar}</div>
</form></div>
<p class=sub style="margin-top:16px">Ejemplos: tu DNS interno como <b>Destino</b> puerto <b>53</b>; tu servidor de
monitoreo como <b>Origen</b> puerto <b>161</b>. Asi quitas el ruido sin perder de vista lo demas que hagan esas IPs.</p>
<h2 style="margin-top:30px">Copia de seguridad</h2>
<div class="card eximp">
<p class=sub style="margin:0 0 14px">Guarda tus exclusiones en un archivo <code>.json</code> (respaldo o para pasarlas a otro
sensor) o cargalas desde uno. Al importar, <b>reemplazan</b> todas las exclusiones actuales.</p>
<div class=eximp-row>
<a class="ebtn exp" href="/exclusiones/export" download="exclusiones.json">&#8681;&nbsp; Exportar JSON</a>
<span class=eximp-sep></span>
<form class=eximp-imp method=post action="/exclusiones"
 onsubmit="if(!document.getElementById('impjson').value){{alert('Elige un archivo JSON primero.');return false;}}">
<input type=hidden name=accion value=import>
<input type=hidden name=json id=impjson>
<label class=filepick><span class=filebtn>Elegir archivo</span><span id=fname class=fname>ningun archivo</span>
<input type=file accept="application/json,.json" onchange="leerJSON(this)"></label>
<button type=submit class="ebtn imp">&#8679;&nbsp; Importar</button>
</form>
</div>
</div>
<script>function leerJSON(i){{var f=i.files&&i.files[0];var n=document.getElementById('fname');
if(!f){{if(n)n.textContent='ningun archivo';return;}}if(n)n.textContent=f.name;
var r=new FileReader();r.onload=function(){{document.getElementById('impjson').value=r.result;}};r.readAsText(f);}}</script>
</main></body></html>"""
    return body

LOGO_IMG = "data:image/png;base64,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"
LOGO_BYTES = base64.b64decode(LOGO_IMG.split(",", 1)[1])
FAVICON_BYTES = base64.b64decode("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")  # logo cuadrado 64x64 para el favicon (no se estira)

def login_page(msg=""):
    err = f'<div class="err">{html.escape(msg)}</div>' if msg else ""
    return f"""<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>
<meta name=viewport content='width=device-width,initial-scale=1'><title>Entrar - Suricata IDS</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
font:15px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#0b0b0b;position:relative;overflow:hidden;
background:
 radial-gradient(1100px 520px at 50% -8%, rgba(42,120,214,.28), transparent 60%),
 radial-gradient(760px 420px at 88% 112%, rgba(27,175,122,.20), transparent 60%),
 linear-gradient(140deg,#0a0f1a 0%,#0d1a2e 55%,#0a0f1a 100%)}}
body::before{{content:"";position:absolute;inset:0;z-index:0;
background-image:radial-gradient(rgba(255,255,255,.05) 1px, transparent 1px);background-size:24px 24px;
-webkit-mask-image:radial-gradient(70% 60% at 50% 45%,#000,transparent 80%);
mask-image:radial-gradient(70% 60% at 50% 45%,#000,transparent 80%)}}
.wrap{{position:relative;z-index:1;width:360px;max-width:94vw;text-align:center}}
.logo{{width:132px;height:auto;margin:0 auto 20px;display:block;filter:drop-shadow(0 8px 22px rgba(0,0,0,.5))}}
.box{{background:#fff;border-radius:18px;padding:26px 30px 26px;
box-shadow:0 30px 70px rgba(0,0,0,.5);text-align:left}}
.sub{{color:#8a8a86;font-size:13px;margin:0 0 6px;text-align:center}}
label{{display:block;font-size:13px;color:#52514e;font-weight:600;margin:13px 0 6px}}
input{{width:100%;padding:11px 13px;border:1px solid #d7d6d2;border-radius:10px;font:15px system-ui}}
input:focus{{outline:none;border-color:#2a78d6;box-shadow:0 0 0 3px rgba(42,120,214,.18)}}
button{{width:100%;margin-top:22px;padding:12px;background:linear-gradient(160deg,#2a78d6,#1f65bd);color:#fff;
border:0;border-radius:10px;font:600 15px system-ui;cursor:pointer;transition:filter .15s}}
button:hover{{filter:brightness(1.08)}}
.err{{background:#fbeaea;color:#c0392b;border:1px solid #f0c9c9;border-radius:9px;padding:9px 12px;
font-size:13px;margin-bottom:8px}}
.foot{{color:#b8b7b2;font-size:11px;text-align:center;margin-top:16px}}
</style></head><body>
<div class="wrap">
<img class="logo" src="/logo.png" alt="Suricata">
<div class="box">
<div class="sub">Panel de deteccion de ataques</div>
<form method=post action="/login">
{err}
<label>Usuario</label><input name=usuario autocomplete=username autofocus required>
<label>Clave</label><input name=clave type=password autocomplete=current-password required>
<button type=submit>Entrar</button>
</form>
<div class="foot">Acceso restringido</div>
</div></div></body></html>"""

RULES_FILE = "/var/lib/suricata/rules/suricata.rules"
UPDATE = {"running": False, "started": 0.0, "msg": ""}   # estado del boton "actualizar reglas"

def ultima_actualizacion_reglas():
    """Cuando se escribio por ultima vez el archivo de reglas (= ultima actualizacion)."""
    try:
        return datetime.fromtimestamp(os.path.getmtime(RULES_FILE), TZ_EC)
    except OSError:
        return None

def _run_rules_update():
    try:
        r = subprocess.run(["/usr/local/bin/suricata-rules-update"], timeout=600,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        UPDATE["msg"] = "ok" if r.returncode == 0 else "err"
    except Exception:
        UPDATE["msg"] = "err"
    finally:
        UPDATE["running"] = False

def update_box():
    """Recuadro con el estado de las reglas y el boton de actualizacion manual."""
    ult = ultima_actualizacion_reglas()
    ult_txt = ult.strftime("%d/%m/%Y %H:%M") if ult else "desconocida"
    if UPDATE["running"]:
        h = datetime.fromtimestamp(UPDATE["started"], TZ_EC).strftime("%H:%M:%S")
        estado = (f'<div style="background:#eda100;color:#fff;padding:9px 13px;border-radius:8px;'
                  f'font-size:13px;margin:0 0 10px">Actualizacion en curso desde las {h}&hellip; '
                  f'esta pagina se refresca sola; termina en ~1 min.</div>')
        boton = ('<button type="button" disabled style="background:#9aa;color:#fff;border:0;'
                 'padding:10px 16px;border-radius:8px;font:600 14px system-ui;cursor:default">'
                 'Actualizando&hellip;</button>')
    else:
        estado = ""
        if UPDATE["msg"] == "ok":
            estado = ('<div style="background:#1baf7a;color:#fff;padding:9px 13px;border-radius:8px;'
                      'font-size:13px;margin:0 0 10px">Base de conocimiento actualizada correctamente.</div>')
        elif UPDATE["msg"] == "err":
            estado = ('<div style="background:#e34948;color:#fff;padding:9px 13px;border-radius:8px;'
                      'font-size:13px;margin:0 0 10px">La actualizacion fallo. Revisa '
                      '<code>/tmp/suricata-update.log</code> en el servidor.</div>')
        boton = ('<form method="post" action="/update-reglas" style="display:inline">'
                 '<button type="submit" style="background:#2a78d6;color:#fff;border:0;'
                 'padding:10px 16px;border-radius:8px;font:600 14px system-ui;cursor:pointer">'
                 '&#8635; Actualizar base de conocimiento</button></form>')
    return (
        '<div id="reglas" style="border:1px solid #e7e6e2;border-radius:10px;background:#fff;padding:16px;margin:6px 0 14px;scroll-margin-top:70px">'
        f'{estado}'
        f'<p style="margin:0 0 4px"><b>Ultima actualizacion de reglas:</b> {ult_txt} '
        '<span style="color:#52514e">(hora de Ecuador)</span></p>'
        '<p style="margin:0 0 12px;color:#52514e;font-size:13px">Es <b>automatica cada dia a las 04:30</b>. '
        'Con este boton la fuerzas ahora sin esperar; descarga ET Open y recarga en caliente.</p>'
        f'{boton}</div>')

def documentacion_page(embed=False, pagina=""):
    port = CFG.get("PORT", "5637")
    ubox = update_box()
    refresh_meta = "<meta http-equiv=refresh content='15;url=/documentacion#reglas'>" if UPDATE["running"] else ""
    art = f"""<!--CAT:Primeros pasos--><h2>Las pestañas del menu</h2>
<table><tr><th>Pestaña</th><th>Que hace</th></tr>
<tr><td><b>En vivo</b></td><td>Vista principal. Arriba, el <b>resumen de las ultimas 24h</b>:
puertos de destino mas atacados, IPs origen (atacantes), IPs destino (objetivos) y la
linea de tiempo por intervalos de 30 minutos. Abajo, el <b>feed de los ultimos ataques</b>,
que se actualiza solo cada 20 segundos.</td></tr>
<tr><td><b>Top origenes</b></td><td>Ranking del <b>Top 5 de CPEs que mas alertan</b> (quien ataca mas),
con el desglose de cada uno: puerto origen, IP destino, dueño/organizacion del destino, puerto y
protocolo. Debajo, el <b>espejo</b>: <b>Top IPs destino mas atacadas</b> (los blancos que reciben mas
alertas) y que CPEs las golpean &mdash; util para detectar un destino comun (un mismo C2/servidor
tocado por varios CPEs). Y al final, <b>Ataques entrantes desde internet</b> (ver abajo).</td></tr>
<tr><td><b>Detalle</b></td><td>La tabla completa de ataques: quien ataca, a que IP y puerto,
protocolo, tipo de ataque, cuantas veces y desde/hasta cuando. Paginada de 20 en 20; al
imprimir a PDF salen todas las filas.</td></tr>
<tr><td><b>Cuarentena</b></td><td>Los CPEs con <b>infeccion confirmada</b> y los que consultan
<b>DNS sospechoso</b>, con su <b>nivel de confianza</b>, la <b>evidencia</b> que lo respalda (boton
"Ver evidencia") y la <b>salud del sensor</b> arriba. Desde aqui se envian/quitan del MikroTik.
Se explica mas abajo.</td></tr>
<tr><td><b>Historico</b></td><td>Los reportes guardados de los <b>ultimos 3 dias</b> (una instantanea
por hora, mas el mas reciente), cada uno abrible. Los mas viejos se borran solos. Paginado.</td></tr>
<tr><td><b>Exclusiones</b></td><td>Gestiona las IPs/firmas que NO quieres que cuenten (tus DNS,
tu monitoreo SNMP, un falso positivo puntual). Permite exclusiones <b>temporales</b> y por
<b>firma (SID)</b>. Se explica mas abajo. Solo <b>administrador</b>.</td></tr>
<tr><td><b>Ajustes</b></td><td>Tu cuenta (clave y foto). Si eres <b>administrador</b>, ademas: <b>usuarios</b>
(crear/editar/borrar/rol), <b>datos de la empresa</b> (nombre y logo de la barra), <b>MikroTik</b>
(conexion y politicas de cuarentena), <b>Reputacion/feeds</b> (Auth-Key de abuse.ch), <b>Bitacora</b>,
<b>Documentacion</b> y <b>Actualizaciones</b> del panel.</td></tr>
<tr><td><b>Documentacion</b></td><td>Esta pagina.</td></tr>
<tr><td><b>Salir</b></td><td>Cierra la sesion.</td></tr>
</table>

<h2>Cada cuanto se actualiza</h2>
<ul>
<li><b>Feed de ultimos ataques</b> (En vivo, abajo): cada <b>20 segundos</b>.</li>
<li><b>Resumen (tiles, graficos y linea de tiempo), Detalle, Top e Historico</b>: se regeneran
en segundo plano cada <b>5 minutos</b>. Por eso los graficos casi no cambian entre
recargas y el feed de abajo si (ese es en vivo).</li>
<li><b>Salud del sensor</b> (tarjeta en Cuarentena): se mide cada <b>~60 segundos</b>.</li>
<li><b>El distintivo "En cuarentena" del Top</b> no espera esos 5 minutos: cada vez que
<b>entra o sale</b> un CPE de cualquiera de las dos listas (infectados o DNS), el resumen se
regenera en unos segundos. Asi el Top no marca como en cuarentena a un CPE que acabas de
quitar, ni deja sin marcar al que acaba de entrar (tambien cuando lo libera el sistema solo).</li>
<li><b>Cuarentena automatica</b> (si esta activada): las politicas por banda se aplican junto
con el resumen (cada 5 min), pero hay un <b>barrido rapido cada ~60 s</b> que envia YA a los CPEs
con <b>infeccion confirmada</b> (no esperan los 5 min). Ver "Cuarentena automatica" mas abajo.</li>
<li><b>Ventana del resumen</b>: por defecto <b>24 h</b>. Se puede acortar para ver solo la
<b>actividad reciente</b> (asi una IP ya atendida se cae sola del top al no tener alertas
nuevas). Se ajusta con <code>VENTANA_MIN</code> en <code>/etc/suricata-dashboard.conf</code>
(en minutos; p.ej. <code>VENTANA_MIN=30</code> = ultimos 30 min) y <code>systemctl restart suricata-dashboard</code>.</li>
<li><b>Reglas ET</b>: se actualizan solas cada dia a las 04:30. <b>Informe por Telegram</b>: 07:30.</li>
<li>Todas las horas del panel estan en <b>hora de Ecuador</b> (UTC-5).</li>
</ul>

<!--CAT:Deteccion--><h2>De donde saca Suricata para confirmar (reglas) y como se actualiza</h2>
<p>Suricata no "adivina": compara cada paquete/flujo contra un conjunto de <b>reglas</b>
(firmas). Una alerta existe solo si algo coincide con una regla. Aqui las reglas vienen de
dos fuentes:</p>
<table><tr><th>Fuente</th><th>Que trae</th><th>Archivo en disco</th></tr>
<tr><td><b>ET Open</b> (Emerging Threats, de Proofpoint)</td>
<td>El grueso: ~40&nbsp;000 firmas gratuitas de malware, CnC/botnets, troyanos, exploits,
escaneos, dominios de mala fama, etc. Es el catalogo publico estandar de la industria.</td>
<td><code>/var/lib/suricata/rules/suricata.rules</code></td></tr>
<tr><td><b>Reglas propias</b> (las crea este instalador)</td>
<td>Deteccion de <b>escaneo/ataque saliente</b> de tus CPEs (port-scan, fuerza bruta SSH),
que ET Open no cubre. SIDs en rango local 90000xx.</td>
<td><code>/var/lib/suricata/rules/local.rules</code></td></tr>
</table>
<p>Quien las descarga es la herramienta <code>suricata-update</code>: baja el paquete de
ET Open desde los servidores de Emerging Threats por HTTPS, lo combina con tus reglas
propias y con la lista de reglas desactivadas (<code>/etc/suricata/disable.conf</code>,
que quita el ruido de stream/app-layer cuando el trafico llega por espejo TZSP), y escribe
el <code>suricata.rules</code> final.</p>
<p><b>Como se actualiza (automatico):</b></p>
<ul>
<li>Un <b>timer</b> de systemd (<code>suricata-rules-update.timer</code>) corre
<b>todos los dias a las 04:30</b> (con un retardo aleatorio de hasta 30&nbsp;min para no
golpear al servidor a la misma hora que todos).</li>
<li>Ejecuta <code>suricata-update</code> &rarr; descarga la ultima version de ET Open y
recarga las reglas <b>en caliente</b> (<code>reload-rules</code>), sin reiniciar Suricata
ni perder trafico.</li>
<li>El registro de cada descarga queda en <code>/tmp/suricata-update.log</code>.</li>
</ul>
{ubox}
<p><b>Forzar una actualizacion ahora</b> (sin esperar a las 04:30), tambien desde el servidor:</p>
<pre style="background:#f4f4f2;border:1px solid #e7e6e2;border-radius:8px;padding:10px 12px;overflow:auto"><code>suricata-rules-update        # descarga ET Open + recarga en caliente
systemctl start suricata-rules-update.service   # equivalente por systemd
suricata-update list-sources # ver catalogos disponibles</code></pre>

<h2>Colores de gravedad</h2>
<p>Cada alerta se clasifica por el texto de su firma. Se evalua de arriba hacia abajo y
gana la primera que coincide, asi que lo mas grave manda. Estas son <b>todas</b> las etiquetas:</p>
<table><tr><th>Etiqueta</th><th>Que significa</th><th>Palabras clave en la firma</th><th>Que hacer</th></tr>
<tr><td><span class="b" style="background:#e34948">INFECTADO</span></td>
<td>El equipo habla con un centro de mando (CnC/botnet/troyano). Es la mas grave:
comunicacion real con el atacante, infeccion confirmada.</td>
<td>cnc, c2, command and control, checkin, botnet, mirai, katana, trojan, ransom,
coinminer, cryptominer, compromised.</td>
<td>Aislar el equipo y avisar al cliente.</td></tr>
<tr><td><span class="b" style="background:#eb6834">ATAQUE</span></td>
<td>Escaneo o ataque saliente: el equipo esta agrediendo a otros (SSH, barrido de puertos,
intento de exploit).</td>
<td>scan, brute, exploit, attack, recon, sweep, portscan.</td>
<td>Revisar el equipo.</td></tr>
<tr><td><span class="b" style="background:#eda100">SOSPECHOSO</span></td>
<td>Consulta a dominios de mala fama (.su, .cc, .top, DNS dinamico como dyndns/duckdns/no-ip)
o firma generica de malware/adware. El destino suele ser tu propio DNS; el sospechoso
es el equipo de ORIGEN.</td>
<td>malware, dns query, tld, dyndns, duckdns, no-ip, adware, pup, suspicious, hostile,
observed dns.</td>
<td>Vigilar; si se repite, revisar el equipo.</td></tr>
<tr><td><span class="b" style="background:#8a8a86">OTRO</span></td>
<td>Alerta que no encaja en ninguna categoria anterior (firma poco comun o de otro tipo).
No es benigna &mdash; el ruido puramente informativo (ET INFO) ya se descarta antes.</td>
<td>Cualquier otra firma (ninguna de las palabras de arriba).</td>
<td>Revisar el detalle para entender que es.</td></tr>
</table>
<p class="muted" style="color:#52514e;font-size:12px">Nota: las alertas <b>ET INFO</b> (trafico
informativo, no sospechoso) no se muestran en el panel ni cuentan en los reportes.</p>

<h2>Modulo de Exclusiones</h2>
<p>El apartado <b>Exclusiones</b> (en el menu de arriba) sirve para que ciertas IPs propias
no aparezcan en el panel ni en los reportes. Tipico: tu servidor DNS y tu servidor de
monitoreo, que generan mucho trafico normal (consultas DNS, sondeos SNMP) y ensucian las
estadisticas sin ser un ataque.</p>
<p><b>Como funciona:</b> por cada alerta, si coincide con una regla de exclusion, se descarta
antes de contarla. Se aplica en los tres lados a la vez (resumen de 24h, feed en vivo e
informe de texto) y surte efecto al instante, sin reiniciar nada.</p>
<p><b>Campos al agregar una exclusion:</b></p>
<table><tr><th>Campo</th><th>Que es</th></tr>
<tr><td>Tipo</td><td><b>Destino</b>: ignora el trafico que va HACIA esa IP (p. ej. tu DNS).
<b>Origen</b>: ignora el que SALE de esa IP (p. ej. tu monitor).</td></tr>
<tr><td>IP</td><td>La direccion a excluir. Se valida que sea una IP correcta.</td></tr>
<tr><td>Puertos</td><td>Los puertos a ignorar, separados por coma (p. ej. <code>53</code> o
<code>161</code>). <b>Vacio = todos los puertos</b> de esa IP.</td></tr>
<tr><td>Firma (SID)</td><td>El numero de firma a excluir SOLO para esa IP (p. ej. un falso
positivo puntual de un CPE). <b>Vacio = cualquier firma</b>. El SID sale en la ficha de evidencia.</td></tr>
<tr><td>Vigencia</td><td>Exclusion <b>temporal</b>: se ignora hasta que venza (24 h / 7 d / 30 d)
y luego el trafico vuelve a analizarse solo. <b>Permanente</b> no vence. Queda registrado quien la creo.</td></tr>
<tr><td>Motivo</td><td>Una nota para acordarte por que (p. ej. "DNS interno").</td></tr>
</table>
<p><b>Ejemplos utiles:</b></p>
<ul>
<li><b>Tu DNS</b>: Tipo <b>Destino</b>, puerto <b>53</b>. Asi las consultas de clientes a
dominios de mala fama (que van a tu DNS) dejan de marcarse.</li>
<li><b>Tu monitoreo SNMP</b>: Tipo <b>Origen</b>, puerto <b>161</b>. Quita el ruido del
servidor que sondea tus equipos.</li>
<li><b>Ignorar una IP entera</b>: deja Puertos vacio.</li>
</ul>
<p><b>Por que filtrar por puerto y no la IP entera:</b> si excluyes tu DNS solo en el puerto
53, sigues viendo si ese mismo equipo hace algo raro en otro puerto (un escaneo, una conexion
a un CnC). Silenciar la IP completa te dejaria ciego a eso.</p>
<p><b>Para eliminar</b> una exclusion, usa el boton Eliminar en la lista del apartado.</p>
<p>Se guardan en <code>/etc/suricata-exclusiones.json</code>. Tambien se respetan lineas
antiguas <code>IGNORAR_DESTINOS=</code>/<code>IGNORAR_ORIGENES=</code> del
<code>/etc/suricata-report.conf</code>, pero lo recomendado es usar el apartado.</p>
<p><b>Ojo con el criterio:</b> al excluir tu DNS dejas de ver en el panel que un cliente
consulto un dominio malicioso. Esa senal sigue disponible en EveBox filtrando por IP de
origen, si quieres cazar clientes infectados por sus consultas.</p>

<!--CAT:Operacion diaria--><h2>Usuarios, roles y clave</h2>
<p>El panel soporta <b>varios usuarios</b> con tres roles:</p>
<ul>
<li><b>Administrador</b>: acceso total (exclusiones, MikroTik y politicas, feeds, actualizar
reglas y panel, gestionar usuarios, bitacora).</li>
<li><b>Operador</b>: opera el dia a dia &mdash; ve todo y <b>gestiona la cuarentena</b> (enviar/quitar
CPEs, excluir un destino de falso positivo). <b>No</b> toca usuarios, conexion MikroTik,
exclusiones de deteccion ni actualizaciones. Cada accion suya queda en la <b>bitacora</b>.</li>
<li><b>Solo lectura</b>: ve los paneles y reportes y cambia su propia clave; no opera cuarentena
ni edita nada.</li>
</ul>
<p>Todo se maneja en el apartado <b>Perfil</b>: cualquiera cambia su clave; un administrador
ademas crea/borra usuarios y cambia roles. Las claves se guardan <b>hasheadas</b> (PBKDF2 con sal)
en <code>/etc/suricata-dashboard-users.json</code>; nunca en texto plano. El primer admin sale del
<code>USER</code>/<code>PASS</code> de <code>/etc/suricata-dashboard.conf</code> la primera vez.</p>

<h2>Abuso saliente: el numero que hay que poder enseñar</h2>
<p>La pestana <b>Historico</b> ya no es una lista de archivos: es la <b>tendencia del abuso que sale
de tu red</b>. Es el dato que hace que las IPs publicas acaben en listas negras, y el unico que sirve
para demostrarle a alguien &mdash;a quien te deslista, o a tu cliente&mdash; que la limpieza
funciona.</p>
<p>Arriba salen los numeros de cabecera: ataques salientes <b>hoy</b> y ayer, la <b>media diaria de 7
dias</b>, la <b>tendencia</b> (los ultimos 7 dias frente a los 7 anteriores, en verde si baja), el
maximo de <b>CPEs distintos atacando</b> y cuantos se pusieron en cuarentena y cuantos se liberaron.
Debajo, una barra por dia (7, 30, 90 o 365) y dos tablas: <b>por que atacan</b> y <b>por que puerto
salen</b>, que es justo lo que hay que mirar para decidir la regla de salida que mas abuso corta.</p>
<h3>De donde salen esos numeros</h3>
<ul>
<li>Los reportes HTML se podan a los <b>3 dias</b>, asi que la tendencia <b>no</b> sale de ellos: se
acumula aparte en <code>/var/log/suricata-metricas.json</code> y se guarda <b>400 dias</b>.</li>
<li>Se cuenta de forma <b>incremental</b> (solo lo posterior a la corrida anterior), no recontando la
ventana. Importa: si bajas la ventana a 30 minutos, recontar daria un "hoy" ridiculamente bajo y sin
avisar de nada. Asi el total del dia es correcto sea cual sea la ventana.</li>
<li>Si el generador estuvo parado mas que la ventana, ese dia queda <b>marcado como incompleto</b> y
su barra sale gris: un dia sin datos no es un dia tranquilo.</li>
<li>Las cuarentenas se cuentan aparte, en el archivo del panel, porque el log de cuarentena solo
guarda 15 dias.</li>
<li>La tendencia necesita <b>14 dias</b> de datos para poder comparar; antes de eso lo dice.</li>
</ul>

<h2>IDS e IPS: que puede y que no puede hacer este montaje</h2>
<p>Conviene tenerlo claro desde el principio. Suricata aqui recibe un <b>espejo</b>: una copia del
trafico. Cuando ve un ataque, el paquete <b>ya paso</b>. Por diseño, <b>nunca</b> va a poder
bloquearlo. Un IPS de verdad exige que el trafico <b>atraviese</b> el sensor (modo inline), y eso
significa poner una maquina Linux en el camino de todos tus abonados: pasa a ser punto unico de
fallo y tiene que aguantar el caudal entero.</p>
<p>La alternativa practica es que <b>el que corta sea el MikroTik</b>, en dos capas:</p>
<ul>
<li><b>Instantanea, en el router.</b> Reglas nativas de RouterOS que no necesitan al sensor para
nada: deteccion de escaneo (<code>psd</code>), limite de conexiones nuevas, tope de conexiones por
abonado, higiene de salida. Cortan a velocidad de linea y funcionan aunque el sensor este apagado.
Lo que no hacen es distinguir por firma.</li>
<li><b>Con criterio, desde el panel.</b> Suricata identifica al CPE por firma y el panel lo mete en
una address-list del router. Entre que el ataque empieza y el CPE queda cortado pasan segundos o
algunos minutos, no es instantaneo, pero acierta mucho mas.</li>
</ul>
<p>Las dos juntas se acercan bastante a un IPS. Y el orden importa: primero las nativas, que son
gratis y no dependen de nada; despues las del panel.</p>

<h3>Proteccion en el MikroTik: que le falta</h3>
<p>Al principio de <b>Abuso saliente</b>, el panel <b>le pregunta al router</b> y dice que tiene y
que le falta para poder cortar, con el comando exacto de cada cosa:</p>
<ul>
<li><b>El espejo activo.</b> Si el sniffer se paro, el sensor esta ciego y todo lo demas da igual.</li>
<li><b>Que las address-lists CORTEN.</b> Es el fallo mas caro: el panel mete CPEs en la lista, dice
"enviado", y si ninguna regla usa esa lista el abonado sigue atacando igual. Una regla
<b>desactivada</b> tampoco cuenta.</li>
<li><b>Origen falsificado</b> (<code>rp-filter</code>). Es la base de los ataques de amplificacion y
de las quejas que no se pueden rastrear, y <b>ningun IDS lo detecta</b>, porque el trafico parece
venir de otro sitio. Aviso: con rutas asimetricas o varios proveedores, <code>strict</code> tira
trafico legitimo; se prueba antes con <code>loose</code>.</li>
<li><b>Deteccion de escaneo en el propio router</b> y <b>tope de conexiones por abonado</b>.</li>
<li><b>Cortar en <code>raw</code></b>: con muchas IPs en cuarentena conviene descartar antes de
crear la conexion, para no llenar la tabla de conntrack.</li>
</ul>

<h2>P2P: verlo y controlarlo</h2>
<p>El BitTorrent <b>no</b> hace que te baneen una IP publica, asi que no cuenta como abuso
saliente &mdash;si contara, el numero que hay que poder enseñar no valdria nada&mdash;. Pero suele
ser <b>el grueso de las alertas</b> y de la banda, asi que se ve <b>aparte</b>: en <b>Abuso
saliente</b> sale su propia tarjeta con cuantas alertas son, cuantos CPEs lo hacen y <b>quienes
son</b>, y el total no abusivo aparece tambien en la cabecera.</p>
<h3>Que funciona y que no</h3>
<ul>
<li><b>Puertos clasicos</b> (6881-6889, 6969, 51413), en TCP <b>y</b> UDP porque el DHT va por UDP.
Caza al cliente que quedo como venia de fabrica.</li>
<li><b>Un cliente configurado a mano con puerto aleatorio y cifrado NO cae ahi.</b> Bloquear P2P del
todo es una pelea perdida y conviene saberlo antes de prometerselo a nadie.</li>
<li><b>El tope de conexiones simultaneas es lo que de verdad le duele</b>: un cliente de torrent
abre cientos, y un limite alto no molesta a quien solo navega.</li>
<li>Si lo que te molesta es <b>la banda</b> y no el trafico en si, sale mucho mejor
<b>encolarlo</b> con <code>/queue</code> que intentar cortarlo.</li>
</ul>

<h2>Sensor POST-NAT: analizar lo que hacen tus IPs publicas</h2>
<p>Lo normal es espejar el <b>bridge</b> del MikroTik: ahi se ve quien es cada abonado (<code>10.x</code>)
pero <b>nunca</b> la IP publica por la que salio. Hay un montaje distinto para lo contrario: espejar
la <b>WAN</b>. Entonces el sensor ve el trafico <b>ya traducido</b> y el origen es tu IP publica, que
es exactamente lo que ve -y denuncia- el resto de internet.</p>
<p>Los dos se complementan: el de la LAN dice <b>quien</b>, el de la WAN dice <b>que sale por cada
publica</b>. En el de la WAN, <b>HOME_NET son tus rangos PUBLICOS</b>, no los privados.</p>
<pre><code>curl -fsSL .../install-suricata.sh | sudo bash -s --   -t -m IP_DEL_ROUTER_EN_EL_TUNEL   -n TUS_RANGOS_PUBLICOS</code></pre>
<p>Y en el MikroTik, <code>filter-interface</code> apuntando a la <b>WAN</b>, no al bridge.</p>
<h3>Tres avisos que hay que leer antes</h3>
<ul>
<li><b>Tu propia publica NO puede ir a la cuarentena.</b> Como HOME_NET son las publicas, el panel
las trata como si fueran CPEs; mandar tu IP de NAT a la address-list dejaria <b>sin internet a todos
los abonados que salen por ella</b>. El panel lo <b>impide</b> si esas IPs estan declaradas en
<b>Consultar IP &rarr; Tus IPs publicas</b>. Declararlas ahi no es opcional en este modo.</li>
<li><b>Por VPN, el origen es la IP del TUNEL</b>, no la LAN del router. Si en <code>-m</code> pones la
LAN, el receptor descarta todos los paquetes y solo se ve en su contador
<code>rechazados_origen</code>: un fallo perfectamente silencioso.</li>
<li><b>El espejo duplica el trafico dentro del tunel</b> y va por UDP sin retransmision: con perdida
el IDS ve trafico incompleto <b>y no avisa</b>. Para un sensor remoto conviene <b>filtrar en el
propio MikroTik</b> (<code>filter-port</code>, <code>filter-protocol</code>): con 25, 22, 23, 445,
3389 y 7547 se caza casi todo el abuso que ensucia las publicas, a una fraccion del ancho de
banda.</li>
</ul>

<h2>Una lista por categoria de abuso</h2>
<p>Meter en el mismo cajon al que tiene una <b>botnet</b> y al que usa <b>BitTorrent</b> obliga a
darles el mismo trato en el firewall, y no es el mismo problema. Por eso cada CPE va a la
address-list de <b>su categoria</b>, y cada lista se trata como corresponde:</p>
<table>
<tr><th>Categoria</th><th>Lista</th><th>Que se hace</th></tr>
<tr><td>Botnet / CnC</td><td><code>clientes-botnet</code></td><td><b>Cortar.</b> El equipo esta
comprometido y ataca a terceros.</td></tr>
<tr><td>Escaneo</td><td><code>clientes-escaneo</code></td><td><b>Cortar.</b></td></tr>
<tr><td>Fuerza bruta</td><td><code>clientes-fuerza-bruta</code></td><td><b>Cortar.</b></td></tr>
<tr><td>Spam</td><td><code>clientes-spam</code></td><td>Cerrarle <b>solo el correo saliente</b>. No
hace falta dejarlo sin internet.</td></tr>
<tr><td>DNS de malware</td><td><code>clientes-dns-malware</code></td><td><b>Redirigir</b> su DNS a tu
resolutor, que ya filtra. Ni se entera.</td></tr>
<tr><td>Criptominado</td><td><code>clientes-minado</code></td><td><b>Encolar</b>, no cortar: es
consumo. Con <b>su propia marca y su propia cola</b> (<code>minado-con</code> /
<code>minado</code>), separadas de las del P2P.</td></tr>
<tr><td>P2P</td><td><code>clientes-p2p</code></td><td><b>Encolar</b>, no cortar: es consumo. Marca
<code>p2p-con</code> / <code>p2p</code> y su cola.</td></tr>
<tr><td>Otros</td><td><code>clientes-otros</code></td><td>Lo que no encaja en nada de lo anterior.</td></tr>
</table>
<p>La clasificacion va de <b>lo mas grave a lo mas leve</b> y manda la primera que casa: quien tiene
una botnet <b>y ademas</b> usa BitTorrent es, a efectos de que hacer con el, un CPE con botnet
&mdash; aunque el P2P tenga diez veces mas alertas.</p>
<p><b>Encolar no es poner una cola.</b> Lo que de verdad limita son <b>tres</b> piezas
encadenadas: <code>mark-connection</code> &rarr; <code>mark-packet</code> &rarr; una
<code>/queue tree</code> que consuma esa marca. Faltando cualquiera de las tres <b>no se limita
nada y no da error</b>: una <code>/queue simple</code> con <code>target=""</code> no engancha
trafico, y una marca de paquete que ninguna cola consume no la usa nadie. P2P y criptominado
llevan <b>marcas y colas distintas</b>, para poder darles limites distintos y saber cual consume.
Las reglas listas para copiar estan en <b>MikroTik &rarr; Reglas</b>.</p>
<p>Tres cosas que hacen que las reglas <b>parezcan</b> no funcionar:</p>
<ul>
<li><b>El orden frente a <code>fasttrack-connection</code>.</b> Los <code>drop</code> tienen que ir
<b>antes</b> de la regla de fasttrack y de los <code>accept</code>: con fasttrack activo una
conexion ya establecida deja de pasar por <code>filter</code> y el bloqueo no se aplica.</li>
<li><b>Meter el CPE en la lista no corta lo que ya esta abierto.</b> La regla solo mira los paquetes
que pasan por ella; las conexiones vivas hay que soltarlas a mano con
<code>/ip firewall connection remove [find src-address~"^192.0.2.25:"]</code>.</li>
<li><b><code>action=redirect to-ports=53</code> apunta al resolutor del propio router.</b> Si el
router no resuelve, el cliente se queda <b>sin DNS</b> y parece que le cortaste internet. O
habilitas <code>/ip dns set allow-remote-requests=yes</code>, o usas
<code>action=dst-nat to-addresses=&lt;tu resolutor&gt; to-ports=53</code>.</li>
</ul>
<p>Los nombres se pueden cambiar en <code>/etc/suricata-mikrotik.conf</code> con
<code>LISTA_BOTNET=</code>, <code>LISTA_P2P=</code> y demas, por si ya tienes tu propia
nomenclatura. Y al enviar se <b>guarda en que lista quedo</b>: si manana cambia su categoria o
renombras la lista, el panel lo saca de donde esta de verdad y no de donde tocaria hoy.</p>

<h2>Las address-lists: cual es cual</h2>
<p>Ya son cinco y conviene tenerlas claras, porque <b>no todas se usan igual</b>: tres miran el
<b>origen</b> (a quien se corta) y dos el <b>destino</b> o la entrada. Confundir
<code>src-address-list</code> con <code>dst-address-list</code> en la regla es el error que hace que
"funcione" sin bloquear nada, o que bloquee lo que no era.</p>
<table>
<tr><th>Lista</th><th>Que lleva dentro</th><th>En la regla</th><th>TTL</th></tr>
<tr><td><code>suricata-cuarentena</code></td><td><b>CPEs infectados</b> (malware/CnC confirmado)</td>
<td><code>src-address-list</code></td><td>1 h</td></tr>
<tr><td><code>suricata-dns-sospechoso</code></td><td><b>CPEs</b> que consultan dominios de botnet</td>
<td><code>src-address-list</code></td><td>1 d</td></tr>
<tr><td><code>suricata-graduada</code></td><td><b>CPEs</b> con corte <b>parcial</b>: solo los puertos
de abuso, el resto le sigue funcionando</td><td><code>src-address-list</code></td><td>1 d</td></tr>
<tr><td><code>suricata-destinos-malos</code></td><td><b>IPs publicas ajenas</b> de mala reputacion a
las que tus CPEs salen (C2, malware, redes secuestradas)</td><td><b><code>dst-address-list</code></b>
</td><td>7 d</td></tr>
<tr><td><code>suricata-atacantes</code></td><td><b>IPs publicas ajenas</b> que atacan tu red desde
internet</td><td><code>src-address-list</code> + <code>connection-state=new</code></td><td>1 d</td></tr>
</table>
<p>Las tres primeras contienen <b>IPs de tus abonados</b>; las dos ultimas, <b>IPs publicas de
terceros</b> &mdash; y ninguna de esas dos acepta una IP tuya, ni privada ni publica. Cada lista
tiene su nombre y su TTL configurables <b>por nodo</b> en <b>Ajustes &rarr; MikroTik</b>, y cada una
lleva su propio registro en el panel, asi que quitar algo de una no toca las demas.</p>
<p>El TTL de los destinos es mas largo (7 d) a proposito: un servidor de control no deja de serlo en
una hora, y ahi no hay ningun abonado esperando a que se le devuelva el servicio.</p>

<h2>Destinos de mala reputacion (en Cuarentena)</h2>
<p>La cuarentena corta al <b>abonado</b>. Esto corta el <b>destino</b>, que es lo que mantiene vivo
al equipo infectado: sin canal de control, la botnet no manda nada. Y vale para <b>todos</b> los
abonados a la vez, sin tener que identificar a ninguno.</p>
<p>Al final de la pestana <b>Cuarentena</b> aparecen los destinos fichados a los que tus CPEs
<b>estan saliendo de verdad</b> (no el feed entero), con de que lista vienen, cuantos CPEs los
contactan y un boton para bloquearlos en <b>todos</b> los nodos a la vez. La regla es de
<code>dst-address-list</code>, no de origen: no se bloquea a nadie, se bloquea <b>a donde va</b>.</p>
<h3>Preventivo: cortar ANTES de que nadie llegue</h3>
<p>Lo anterior es <b>reactivo</b>: bloquea destinos que un CPE <b>ya</b> contacto. Mejor es lo
contrario, y tambien esta: el router se baja cada hora la lista de <b>infraestructura fichada</b> y
corta la salida hacia ella <b>antes</b> de que ningun abonado llegue. Asi el equipo infectado ni
siquiera consigue instrucciones, y no hace falta detectarlo primero.</p>
<p>Al <b>preventivo</b> solo entran los feeds en los que se puede confiar para cortar <b>por
destino</b>: <b>C2 activo</b> (Feodo) e <b>infraestructura delictiva</b> (Spamhaus DROP), que son
unos pocos miles de entradas y caben de sobra en cualquier router. <b>No</b> entran las listas de
"esta IP escaneo a alguien" (CINS, AbuseIPDB): describen a un atacante, pero <b>esa misma IP puede
alojar una web que un abonado visita</b>, y cortarla por destino lo deja sin servicio.</p>
<p>La importacion <b>solo borra lo que puso el feed</b> (por el comentario), asi que lo que hayas
bloqueado a mano desde el panel no se toca. Y nunca entra nada tuyo: ni tus redes privadas ni tus
publicas declaradas, aunque un feed las fiche.</p>

<h3>Los dos frenos, que son lo importante</h3>
<ul>
<li><b>Solo IPs publicas.</b> Una privada aqui seria de tu propia red, y bloquearla como destino
dejaria a tus abonados sin verse entre si. Tambien se frena una IP <b>publica que sea tuya</b> (tu
rango de NAT), que pasa el filtro de "es publica" y aun asi no hay que bloquearla.</li>
<li><b>Solo feeds que se sostienen</b>: C2 activo, IOC de C2, distribucion de malware e infra
delictiva. <b>No</b> se propone lo que viene de listas de "esta IP escaneo a alguien": esas pueden
alojar ademas algo legitimo, y bloquearlas deja sin servicio a un abonado que no hizo nada. Si aun
asi las quieres ver, se pueden pedir.</li>
</ul>
<p>Lo que marques como <b>destino confiable</b> (falso positivo) desaparece de la lista y no se
vuelve a proponer. Y sin una regla en el MikroTik que use esa address-list, el panel diria
"bloqueado" sin bloquear nada: la regla esta ahi mismo para copiarla.</p>

<h2>Cortar a los que te atacan desde internet</h2>
<p>Es la otra mitad del problema, y la cadena importa: <b>el atacante de fuera es el que infecta al
CPE, y el CPE infectado es el que ensucia tus publicas</b>. Cortar la entrada no limpia lo que ya
esta infectado &mdash;para eso esta la cuarentena&mdash; pero corta las <b>infecciones nuevas</b>,
que es lo unico que hace que el numero baje y se quede abajo.</p>
<p>En <b>Abuso saliente</b> el panel arma la lista con los origenes de internet que <b>de verdad</b>
estan golpeando tu red: los que pegan fuerte y a varios destinos, mas los que ademas aparecen
fichados en los feeds de reputacion (a esos les basta con poco). <b>No</b> se vuelcan los feeds
enteros: son cientos de miles de IPs, llenan la RAM del router y meten falsos positivos de sitios
que tus abonados visitan.</p>
<h3>Dos detalles que deciden si esto sirve o rompe clientes</h3>
<ul>
<li><b><code>connection-state=new</code>.</b> Se cortan solo las conexiones que <b>entran</b> desde
esas IPs. Sin ese matcher &mdash;o cortando en <code>raw</code>&mdash; se tiran tambien las
<b>respuestas</b> a lo que pidio tu abonado, y el cliente se queda sin poder entrar a un sitio
legitimo sin que nadie entienda por que.</li>
<li><b>El router se baja la lista solo</b> con <code>/tool fetch</code> cada hora, y la importa.
Meterle miles de entradas una a una por la API tardaria horas. La URL <code>/blocklist.rsc</code>
responde <b>unicamente</b> a las IPs de los routers dados de alta, asi que no hace falta poner
ninguna contraseña en la configuracion del router.</li>
</ul>
<p>Nunca entran en la lista tus propias redes ni las de <b>Nunca bloquear</b>, y cada importacion
<b>reemplaza</b> la lista entera, asi que lo que deja de atacar desaparece solo.</p>

<h2>Reglas de salida: lo que baja los baneos</h2>
<p>Al final de <b>Abuso saliente</b> el panel propone <b>reglas de firewall para el MikroTik</b>
sacadas de lo que el sensor vio <b>de verdad</b>, no de una lista generica. Cada una dice
<b>cuantas alertas corta</b>, <b>cuantos CPEs la provocan</b> y <b>que porcentaje</b> de tu abuso
representa, ordenadas de mayor a menor.</p>
<p>Esto es distinto de la cuarentena: no senala a un abonado, cambia la <b>politica del nodo</b> y
actua sobre <b>todos</b> a la vez, sin esperar a detectar a nadie. Por eso es lo que mas rapido baja
los baneos.</p>
<ul>
<li><b>Correo saliente.</b> Es la causa numero uno de acabar en Spamhaus. Ojo con un detalle que se
equivoca a menudo: se corta el <b>25</b> y se <b>deja</b> el 587 y el 465, que son el envio
<b>autenticado</b> que usan los clientes de correo legitimos. Cortar el 587 rompe a gente que no hizo
nada. Tu servidor de correo va en la lista de excepciones.</li>
<li><b>Administracion remota</b> (SSH, Telnet, RDP, VNC): un abonado domestico no necesita salir por
ahi, y es lo que mas denuncias genera despues del spam.</li>
<li><b>SMB</b> (445, 139), <b>TR-069 e IoT</b> y <b>bases de datos ajenas</b>: sin uso legitimo
saliendo a internet.</li>
</ul>
<p>Solo aparecen los grupos con abuso <b>real</b> en tus datos, y dentro de cada uno solo los puertos
que efectivamente se usaron. Las reglas salen con <b>tus</b> redes de abonado como origen y una
address-list <code>suricata-salida-permitida</code> para las excepciones. <b>Revisa las excepciones
antes de pegarlas</b>: afectan a todos.</p>

<h2>Cuarentena graduada: cortar sin dejar sin internet</h2>
<p>El corte total tiene un problema practico: el abonado llama a soporte, soporte lo desbloquea y el
ataque vuelve. Ese ciclo es la razon habitual de que estos programas no bajen ningun numero.</p>
<p>La <b>cuarentena graduada</b> mete al CPE en otra address-list
(<code>suricata-graduada</code>) cuyas reglas cortan <b>solo los puertos de abuso</b>: correo,
SSH/Telnet, SMB, RDP/VNC y TR-069. El abonado sigue navegando, viendo streaming y jugando, asi que
<b>no llama</b>, y el corte aguanta en el tiempo. Aqui si se corta tambien el 587/465: ese equipo ya
esta comprometido.</p>
<p>Las reglas se pegan una vez y estan en <b>Ajustes &rarr; MikroTik</b>. Al enviar el primer CPE el
panel <b>comprueba que exista alguna regla usando esa lista</b> y avisa si no: una address-list sin
regla que la use no bloquea nada, y sin ese aviso el panel diria "enviado" mientras el CPE sigue
atacando.</p>

<h2>Reportes e informe diario</h2>
<ul>
<li>Reporte grafico a mano: <code>suricata-html-report</code> (queda en <code>/var/log/suricata/</code>).</li>
<li>Informe de texto por Telegram: rellena <code>TELEGRAM_TOKEN</code> y <code>TELEGRAM_CHAT_ID</code>
en <code>/etc/suricata-report.conf</code>. Se envia cada dia a las 07:30.</li>
<li>Las reglas ET se actualizan solas cada dia a las 04:30.</li>
</ul>

<h2>Archivos y comandos utiles</h2>
<table><tr><th>Que</th><th>Donde / como</th></tr>
<tr><td>Config del panel</td><td><code>/etc/suricata-dashboard.conf</code> (puerto {port}, usuario, clave)</td></tr>
<tr><td>Config de reportes / exclusiones</td><td><code>/etc/suricata-report.conf</code></td></tr>
<tr><td>Reglas propias de escaneo</td><td><code>/var/lib/suricata/rules/local.rules</code></td></tr>
<tr><td>Alertas / logs</td><td><code>/var/log/suricata/fast.log</code>, <code>eve.json</code></td></tr>
<tr><td>Estado de servicios</td><td><code>systemctl status suricata evebox tzsp-decap suricata-dashboard</code></td></tr>
<tr><td>Ver logs en vivo</td><td><code>journalctl -u suricata-dashboard -f</code></td></tr>
<tr><td>Base GeoIP del mapa</td><td><code>/var/lib/suricata-geoip/ipv4.bin</code> (IP&rarr;pais, offline)</td></tr>
<tr><td>Assets del mapa</td><td><code>/var/lib/suricata-mapa/</code> (TopoJSON + topojson-client)</td></tr>
</table>

<!--CAT:Cuarentena y MikroTik--><h2>Espejo MikroTik y HOME_NET (por que a veces no se ven datos)</h2>
<p>Con espejo TZSP desde el MikroTik, el flujo llega al receptor (<code>tzsp-decap</code>)
y Suricata lo inspecciona. Pero el panel muestra <b>alertas</b>, no trafico normal, y las
reglas de <b>ataque saliente</b> (escaneo de puertos, Telnet/Mirai, fuerza bruta SSH de un
CPE) solo disparan si la IP de origen esta dentro de <code>HOME_NET</code>.</p>
<p><b>Sintoma tipico:</b> el espejo llega (<code>journalctl -u tzsp-decap</code> muestra
<code>rx/tx</code> subiendo) pero el panel se ve casi vacio. Casi siempre es que
<code>HOME_NET</code> no incluye las redes de tus clientes.</p>
<p>En un ISP los CPE suelen estar repartidos en varias redes privadas (10.6.x, 10.69.x,
172.16.x...), asi que lo mas seguro es cubrir <b>todas las redes privadas (RFC1918)</b>:</p>
<pre><code># en la instalacion (flag -n):
... -t -m &lt;IP_MikroTik&gt; -n 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# o cambiarlo despues sin reinstalar:
sed -i 's#^\\s*HOME_NET:.*#    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"#' /etc/suricata/suricata.yaml
suricata -T -c /etc/suricata/suricata.yaml   # validar
systemctl restart suricata</code></pre>
<p><code>EXTERNAL_NET</code> se ajusta solo (<code>!$HOME_NET</code>).</p>

<h2>Cuarentena: enviar CPEs infectados al MikroTik (API v6 y v7)</h2>
<p>La pestana <b>Cuarentena</b> lista los CPE con <b>infeccion confirmada</b> (por repeticion y
contexto, no por una sola firma). Desde ahi, con un boton, el panel empuja la IP a una
<b>address-list</b> del MikroTik por su <b>API</b>. El panel <b>solo mete y saca IPs de la lista</b>;
<b>que se hace con esa lista lo decides tu</b> con una regla de firewall. Es compatible con
<b>RouterOS v6</b> (incluye login antiguo &lt;6.43 por reto MD5) y <b>v7</b>, en API plano (8728) o
API-SSL (8729).</p>

<h3>1) Habilitar el servicio API (igual en v6 y v7)</h3>
<pre><code># API plano (puerto 8728)
/ip service enable api
# o API-SSL (puerto 8729) si vas a usar TLS
/ip service enable api-ssl
# recomendado: limitar desde donde se conecta (IP del servidor Suricata)
/ip service set api address=IP_DEL_SERVIDOR_SURICATA</code></pre>

<h3>2) Usuario API dedicado con permisos minimos (igual en v6 y v7)</h3>
<pre><code>/user group add name=suricata policy=api,read,write,test
/user add name=suricata-api group=suricata password=UNA_CLAVE_FUERTE</code></pre>
<p>Ese <b>usuario</b> y <b>clave</b> son los que pones en <b>Ajustes &rarr; MikroTik</b>. La clave se
guarda solo en este servidor, en <code>/etc/suricata-mikrotik.conf</code> con permisos 600.</p>

<h3>3) La regla que DECIDE que hacer con la lista (tu la defines)</h3>
<p>Ejemplo: cortar el trafico saliente de los CPE en cuarentena (misma sintaxis en v6 y v7):</p>
<pre><code>/ip firewall filter add chain=forward src-address-list=suricata-cuarentena action=drop comment="Suricata: CPE en cuarentena"</code></pre>
<p>Alternativas segun tu politica: en vez de <code>action=drop</code> puedes redirigir a un portal,
marcar en <code>mangle</code> para limitar velocidad, o registrar. La <b>address-list</b> por defecto
es <code>suricata-cuarentena</code> (cambiala en Ajustes si usas otro nombre). Las entradas entran con
un <b>TTL</b> (timeout, ej. <code>1h</code>) y se <b>auto-liberan</b>; tambien puedes quitarlas a mano
con el boton <b>Quitar</b> de la pestana.</p>

<h3>4) Configurar y probar en el panel</h3>
<ol>
<li><b>Ajustes &rarr; MikroTik</b>: host, puerto (8728 / 8729 si TLS), usuario, clave, nombre de la
address-list y TTL. Marca <b>Habilitar</b>.</li>
<li>Pulsa <b>Probar conexion</b>: si conecta, muestra el nombre (identity) del router.</li>
<li>En <b>Cuarentena</b>, cada CPE infectado confirmado muestra <b>Enviar a cuarentena</b>
(lo agrega a la lista) y luego <b>Quitar</b> (lo saca). Todo queda en
<code>/var/log/suricata-cuarentena.log</code>.</li>
</ol>
<p>En la tabla <b>Enviados manualmente</b> puedes <b>ordenar por cualquier columna</b>: haz
clic en la cabecera (CPE, Lista, Por, Enviado, Ultima revision&hellip;) para ordenar de forma
<b>ascendente</b>, y otra vez para <b>descendente</b>. Las columnas de fecha ordenan por
tiempo real, no por texto. El orden que elijas <b>se conserva</b> al pulsar <b>Quitar</b> o
al recargarse la pagina, y esta <b>vuelve a la altura donde estabas</b> en vez de saltar
arriba del todo (tambien en el refresco automatico de cada 5 min).</p>
<p><b>Quitar varias a la vez:</b> cada fila tiene una <b>casilla</b> (y la cabecera una para
<b>seleccionar todas</b>). Al marcar alguna se activa <b>Quitar seleccionados (N)</b>, que abre
una <b>ventana de confirmacion</b> con la lista de IPs antes de tocar nada; las de la lista de
DNS salen marcadas como tal. Puedes mezclar IPs de <b>ambas listas</b>: cada una se saca de la
suya. Es reversible (puedes volver a enviarlas) y queda todo en
<code>/var/log/suricata-cuarentena.log</code>. Si el router falla con alguna, se te dice
<b>cual y por que</b>, y esa IP <b>se queda</b> en el registro para reintentarla.</p>
<p>Las IPs se sacan <b>una por una y se ve el avance</b> (barra + cada IP marcada &#10003; o
&#10007; segun sale), porque cada una es una llamada al MikroTik y en bloque la pantalla se
quedaba parada sin decir nada. Si una falla <b>no se detiene el resto</b>. Mientras corre, la
ventana no se cierra, para no perder de vista el avance.</p>
<p><b>Seguridad:</b> usa un usuario API solo con <code>api,read,write,test</code> (no full), limita el
servicio API a la IP del servidor Suricata, y si el enlace no es de confianza usa <b>API-SSL</b>. Si
dejas el envio <b>deshabilitado</b>, la pestana Cuarentena solo <b>sugiere</b> (no toca el router).</p>

<h3>5) Estados de la pestana Cuarentena</h3>
<p>El aviso de arriba de la pestana cambia de color segun el estado:</p>
<ul>
<li><b style="color:#1a7f37">Verde &mdash; MikroTik habilitado</b>: marcaste <b>Permitir enviar</b> y la conexion
(host, usuario, clave) esta completa. Aparecen los botones <b>Enviar a cuarentena</b> por CPE y
<b>Enviar todos</b>.</li>
<li><b style="color:#b52a2a">Rojo &mdash; Falta configurar la conexion</b>: marcaste <b>Permitir enviar</b>
pero todavia falta host, usuario o clave (o no conecta). Completa <b>Ajustes &rarr; MikroTik</b> y pulsa
<b>Probar conexion</b>. Mientras tanto no se envia nada.</li>
<li><b>Gris &mdash; Modo sugerencia (dry-run)</b>: el permiso esta apagado. Solo se listan candidatos;
el panel no toca el router.</li>
</ul>
<p><b>Enviar todos:</b> con el estado en verde, el boton <b>Enviar todos (N)</b> manda de una a la
address-list todos los CPE de la lista que aun no esten en cuarentena (tope de 50 por accion; si el
router deja de responder, se detiene y avisa). Cada IP queda con su <b>TTL</b> y se puede sacar con
<b>Quitar</b>. Toda accion se registra en <code>/var/log/suricata-cuarentena.log</code>.</p>

<h2>Salud del sensor</h2>
<p>Arriba de la pestana <b>Cuarentena</b> hay una tarjeta que responde de un vistazo si el
sensor esta <b>viendo trafico</b>. Se mide en segundo plano cada ~60&nbsp;s (cache en
<code>/var/log/suricata-sensor.json</code>) y distingue:</p>
<ul>
<li><b>Viendo trafico</b> (verde): captura activa, con o sin amenazas.</li>
<li><b>Sin trafico</b> / <b>Receptor TZSP caido</b> / <b>Suricata detenido</b> (rojo): no llega nada
que inspeccionar &mdash; revisa el espejo del MikroTik o los servicios.</li>
<li><b>Captura con perdidas</b> (ambar): Suricata descarta paquetes (drop ratio alto).</li>
<li><b>Reporte desactualizado</b> (ambar): el resumen no se regenera; revisa el panel.</li>
</ul>
<p>Muestra chips de servicios, interfaces de captura, paquetes/s y % de perdidas. Usa
<code>suricatasc iface-stat</code> y <code>systemctl is-active</code>.</p>

<h2>Por que un CPE es candidato: confianza y evidencia</h2>
<p>Una coincidencia en una lista o varias alertas repetidas <b>no bastan</b> para confirmar una
infeccion. Cada candidato lleva un <b>nivel de confianza</b>:</p>
<ul>
<li><b>Alta confianza</b>: hay <b>≥2 evidencias independientes</b> (firmas CnC distintas, reputacion
del destino, persistencia, campana, DNS). Es lo que se envia con "Enviar alta confianza".</li>
<li><b>Sospechoso</b>: solo repeticion, sin corroboracion &rarr; vigilar, no aislar todavia.</li>
</ul>
<p>El boton <b>Ver evidencia</b> abre la <b>ficha del CPE</b>, que muestra: el <b>cliente/abonado</b>
(nombre PPPoE/DHCP tomado del MikroTik), la <b>actividad</b> (a que destinos hablo), las <b>alertas</b>
con su SID/firma/fecha/flow_id, las <b>coincidencias de reputacion</b> con su fuente/CIDR y su
<b>vigencia</b> (si el feed sigue vigente o caduco), la <b>corroboracion</b> independiente y la
<b>decision</b>. Si el destino no tiene DNS inverso, se muestra el <b>operador de red</b> del bloque
(via RDAP) en vez de "sin PTR".</p>
<p><b>Quien tenia la IP en el momento del evento:</b> el panel guarda un historico de asignaciones
(PPPoE/DHCP). Si la IP cambio de dueño entre el ataque y ahora, la ficha lo avisa &mdash; asi no se
culpa al cliente que hoy tiene esa IP por lo que hizo otro antes.</p>

<h2>Varios MikroTik en un mismo sensor (multi-nodo)</h2>
<p>Un sensor puede vigilar <b>varios routers</b>. Cada uno manda su espejo y el sensor lo
recibe por <b>una interfaz distinta</b> (<code>ids-mon</code>, <code>ids-mon2</code>,
<code>ids-mon3</code>&hellip;). De ahi sale <b>de que nodo es cada CPE</b>, y eso resuelve los
dos problemas que hacen inviable compartir sensor sin mas:</p>
<ul>
<li><b>Rangos repetidos.</b> Es normal que cada nodo use <code>10.0.0.x</code>. Sin saber el
router, <code>10.0.0.5</code> serian tres clientes mezclados en uno: alertas sumadas, riesgo
inflado y el <b>abonado equivocado</b> en la ficha. Con el nodo, la identidad es el par
<b>(router, IP)</b> y cada uno va por su lado.</li>
<li><b>A que router bloquear.</b> Cada CPE se envia a la address-list de <b>su</b> MikroTik, con
el nombre de lista que ese router tenga configurado (pueden llamarse distinto en cada uno).</li>
</ul>

<h3>Como se ve en el panel</h3>
<p>Con <b>un solo</b> MikroTik no cambia nada: los CPEs se siguen viendo por su IP. En cuanto hay
<b>mas de uno</b>, junto a cada IP aparece una <b>etiqueta azul con el nombre del nodo</b>, tanto
en el Top como en la pestana Cuarentena. Esa etiqueta no es decorativa: dos abonados distintos
pueden tener la misma IP en routers distintos, y el panel los trata como lo que son, dos CPEs
separados.</p>
<ul>
<li>El boton <b>&#9888; Cuarentena</b> del Top envia al MikroTik <b>de ese nodo</b>, a la
address-list que ese router tenga configurada.</li>
<li>La marca <b>&#10003; En cuarentena</b> aparece cuando ese CPE concreto (nodo + IP) esta en una
de las dos listas, la de infectados o la de DNS sospechoso.</li>
<li><b>Quitar</b> libera solo a ese, no al homonimo del otro nodo.</li>
<li>Cada linea de la bitacora termina en <code>nodo=&lt;nombre&gt;</code>, para saber despues en
que router se actuo.</li>
<li>Un nodo que este <b>sin habilitar</b> no recibe envios: se avisa en pantalla y no se toca.</li>
</ul>

<h3>Como se monta</h3>
<ol>
<li><b>Instalar/re-ejecutar el instalador</b> con todas las IPs de los routers en <code>-m</code>:
<pre><code>curl -fsSL .../install-suricata.sh | sudo bash -s -- \
  -t -m 10.0.0.1,10.9.9.1,192.0.2.1 \
  -n 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</code></pre>
Eso crea una interfaz por router y hace que Suricata capture todas. <b>Este paso es el que
habilita la captura</b>; sin el, un nodo dado de alta en el panel no se vigila.</li>
<li><b>En cada MikroTik</b>, apuntar el espejo al sensor (igual que con uno solo):
<pre><code>/tool sniffer set filter-interface=bridge1 streaming-enabled=yes \
    streaming-server=IP_DEL_SENSOR:37008
/tool sniffer start</code></pre></li>
<li><b>En Ajustes &rarr; MikroTik</b>, dar de alta cada nodo con su IP, usuario y clave de API,
y marcar <b>Permitir enviar</b> en los que deban bloquear.</li>
</ol>

<h3>Como comprobar que llegan todos</h3>
<p>El receptor escribe un resumen cada minuto con el <b>desglose por origen</b>. Si un router
deja de espejar, ese nodo se queda ciego y <b>no hay ningun otro aviso</b>, asi que conviene
mirarlo:</p>
<pre><code>journalctl -u tzsp-decap -n 5
# ... rx=... tx=... por_origen=10.0.0.1:812,10.9.9.1:655,192.0.2.1:430</code></pre>
<p>Si falta un origen, revisa el sniffer de ese MikroTik y que su IP este en el
<code>-m</code> del instalador.</p>

<h3>Limites que conviene tener claros</h3>
<ul>
<li><b>Todos los routers deben estar en la misma red que el sensor.</b> El espejo va por UDP
sin retransmision: si cruza un enlace con perdida o saturado, el IDS ve trafico incompleto y
<b>no te avisa</b>. Para un nodo remoto es preferible un sensor propio.</li>
<li><b>Un sensor, un punto de fallo.</b> Si la caja cae, quedas ciego en todos los nodos a la
vez; con un sensor por router solo pierdes ese.</li>
<li><b>La capacidad se suma.</b> El trafico espejado de los tres nodos entra en la misma
maquina: revisa la tabla de RAM y vigila <code>memcap_drop</code>.</li>
<li><b>Quitar un nodo del panel no libera sus CPEs</b>: siguen bloqueados en ese MikroTik y hay
que soltarlos desde el propio router.</li>
</ul>

<h2>Ataques entrantes desde internet (y por que van aparte)</h2>
<p>Suricata ve las <b>dos direcciones</b>: tus CPEs atacando hacia afuera y hosts de internet
atacando hacia adentro. Este panel existe para lo primero, asi que <b>solo los origenes de tus
redes</b> pueden ser candidatos a cuarentena, entrar al ranking de riesgo o ser enviados al
MikroTik. Lo de fuera aparece en <b>Top &rarr; Ataques entrantes desde internet</b>.</p>
<p><b>Por que importa:</b> ET Open trae firmas que disparan sobre trafico <b>entrante</b> (por
ejemplo <code>ET COMPROMISED Known Compromised or Hostile Host Traffic</code>), y la palabra
"compromised" cuenta aqui como infeccion. Sin este filtro, un escaner de internet insistente
podia aparecer como "CPE infectado" y, con <b>politicas automaticas</b> activadas, acabar en la
address-list de cuarentena: no bloquea nada util y ensucia la lista.</p>
<p><b>Que hacer con un ataque entrante:</b> no va a la cuarentena de CPEs (esa lista es de
abonados). Se corta en el <b>firewall de borde</b>, o mejor: se <b>cierra la exposicion</b> del
equipo golpeado. Si algo tuyo recibe escaneo constante desde internet, casi siempre es que tiene
un puerto publicado que no hacia falta.</p>
<p><b>Si das IP publica a tus clientes</b>, dilo con <code>MIS_REDES=203.0.113.0/24,10.0.0.0/8</code>
en <code>/etc/suricata-dashboard.conf</code>; por defecto son las privadas
(<code>10/8</code>, <code>172.16/12</code>, <code>192.168/16</code>) mas CGNAT
(<code>100.64/10</code>). Ojo: lo que pongas <b>reemplaza</b> el valor por defecto.</p>

<h2>Cuarentena automatica (politicas por banda)</h2>
<p>Ademas de enviar a mano, el panel puede actuar solo. En <b>Ajustes &rarr; MikroTik</b>, con
<b>Aplicar politicas automaticamente</b> activado, defines que hacer por <b>banda de riesgo</b>:</p>
<table><tr><th>Banda</th><th>Accion posible</th></tr>
<tr><td><b>ALTO</b> / <b>MEDIO</b> / <b>BAJO</b></td>
<td><b>nada</b> (no hacer), <b>notificar</b> (solo avisar, dedupe 6&nbsp;h), <b>dns</b> (a la lista de
DNS sospechoso) o <b>cuarentena</b> (a la address-list de bloqueo).</td></tr></table>
<p>Las politicas se aplican junto con el resumen (cada 5&nbsp;min) y <b>liberan solas</b> a los CPEs
que dejan de calificar. Ademas:</p>
<p><b>Por que se bloqueo cada uno:</b> las politicas eligen por <b>banda de riesgo</b>, no por
infeccion confirmada, asi que el motivo guardado es el <b>desglose del puntaje</b> (severidad,
destinos unicos, puertos unicos, persistencia, correlacion de flota y reputacion) junto con la
banda y los conteos. La columna <b>Motivo</b> lo muestra tal cual, y la columna <b>Por</b> dice
<code>politica</code> o <code>politica-rapida</code> segun quien lo envio.</p>
<ul>
<li><b>Barrido rapido de ALTO (~60&nbsp;s):</b> si <b>ALTO &rarr; cuarentena</b>, un chequeo ligero cada
minuto envia <b>ya</b> a los CPEs con <b>infeccion confirmada</b> (firmas CnC repetidas), sin esperar
los 5&nbsp;min. Es conservador (solo infeccion confirmada), respeta allowlist, destinos de confianza y
exclusiones, con <b>anti-rebote de 60&nbsp;s</b> por CPE. MEDIO/BAJO siguen en el ciclo de 5&nbsp;min.</li>
<li><b>Auto-mantener:</b> las IPs entran sin caducidad y se liberan cuando el CPE deja de atacar (en
vez de caducar por TTL).</li>
</ul>

<h2>Falsos positivos: excluir un destino y liberar en cadena</h2>
<p>Si una IP <b>destino</b> (p.ej. un DNS publico) dispara falsos positivos en muchos CPEs, en la
pestana Cuarentena esta <b>Excluir destino (falso positivo)</b>: marca esa IP como <b>confiable</b>,
sus alertas dejan de contar y se <b>liberan automaticamente</b> todos los CPEs que fueron a la lista
por su culpa. Los destinos confiables se guardan en <code>/etc/suricata-destinos-confianza.lst</code>.</p>

<h2>Allowlist "nunca bloquear"</h2>
<p>En <b>Ajustes</b> puedes definir IPs/CIDR que <b>jamas</b> van a cuarentena (tu infraestructura,
clientes criticos), aunque disparen alertas. Se guardan en
<code>/etc/suricata-nunca-bloquear.lst</code> y las respetan tanto las politicas como el barrido rapido.</p>

<h2>Reputacion / feeds (abuse.ch y AbuseIPDB)</h2>
<p>El panel enriquece los destinos con <b>feeds de reputacion</b> (IPs/CIDR y dominios maliciosos)
con su <b>procedencia</b> y <b>caducidad</b>. En <b>Ajustes &rarr; Reputacion/feeds</b> (admin) se pegan
las claves: la <b>Auth-Key</b> de abuse.ch (URLhaus/ThreatFox) y la <b>clave de AbuseIPDB</b>. Se
guardan <b>solo-escritura</b> en <code>/etc/suricata-feeds.conf</code> (permisos 600, no se vuelven a
mostrar) y hay un <b>validador</b> que comprueba cada clave antes de guardarla. Feodo, CINS y Spamhaus
no necesitan clave. La tabla muestra el estado por fuente (vigente/vacia/caducada) y un boton para
actualizar los feeds al momento.</p>
<p>La fuente <code>abuseipdb</code> es la <b>lista masiva</b> de atacantes denunciados por la comunidad:
se baja como mucho <b>cada 6 horas</b> (el plan gratuito permite 5 descargas al dia) y trae hasta
10.000 IPs de <b>confianza 100&nbsp;%</b> &mdash; acotar ese umbral es de pago. Si un dia se agota la
cuota, se conserva la lista anterior en vez de dar la fuente por rota.</p>

<h2>Consultar IP o red: que ataques se le denuncian</h2>
<p>La pestana <b>Consultar IP</b> responde algo que los feeds no responden: no solo <i>si</i> una IP
publica es mala, sino <b>a que se dedica</b>. Se pegan una o varias IPs (hasta 25) y para cada una sale
el <b>porcentaje de confianza de abuso</b>, el operador, el pais, el tipo de uso, cuantas denuncias
tiene y de cuantos denunciantes distintos, y sobre todo <b>las categorias</b> de esas denuncias
(escaneo de puertos, fuerza bruta SSH, ataque a aplicacion web, host comprometido&hellip;) con un
resumen de <b>que suele haber detras</b> de cada una.</p>

<h3>Redes enteras (lo que conviene para tu rango de NAT)</h3>
<p>Tambien acepta <b>redes en CIDR</b>: <code>200.0.0.0/24</code>. Eso no son 256 consultas sino
<b>una sola</b>, porque usa un endpoint distinto pensado para bloques. Devuelve <b>que direcciones de
esa red estan denunciadas</b>, con su porcentaje, cuantas denuncias tienen y cuando fue la ultima; y
desde cada fila se puede pedir el detalle de esa IP concreta.</p>
<ul>
<li>Es la forma practica de revisar <b>todo tu rango publico de salida</b> de una vez y ver cuales de
tus direcciones estan ensuciadas.</li>
<li>Las redes tienen su <b>propia cuota</b>: <b>100 al dia</b> en el plan gratuito, independiente de
las 1.000 consultas por IP. Ambas se muestran en la pestana.</li>
<li>El plan gratuito llega hasta <b>/24</b>. Si pides algo mayor, AbuseIPDB responde 402 y el panel te
lo dice tal cual en vez de soltar un error generico (de pago se llega a /20 y /16).</li>
<li>Las redes <b>privadas</b> se rechazan igual que las IPs privadas, y tambien las descomunales
(por debajo de /16 ni se intenta).</li>
<li>Si la red no tiene <b>ninguna</b> direccion denunciada se dice claramente, con un apunte util: si
aun asi te rebota el correo, el problema no esta en AbuseIPDB sino en las listas de spam.</li>
</ul>
<p>Tiene <b>dos</b> usos, y el segundo es el que arregla cosas:</p>
<ul>
<li>Una IP que <b>te ataca</b> (las de la pestana Entrantes): saber a que se dedica antes de decidir
si se corta en el borde.</li>
<li><b>Tus propias IPs publicas de NAT.</b> Si a tu IP de salida le llueven denuncias por fuerza bruta
SSH, hay un <b>abonado infectado</b> detras atacando al resto de internet desde tu red. Eso es lo que
hay que corregir, y es la unica forma de enterarte antes de que te metan en una lista negra.</li>
</ul>
<h3>Tus IPs publicas: de "me banean" a "este abonado lo causa"</h3>
<p>El espejo del MikroTik es <b>pre-NAT</b>: Suricata ve <code>10.x</code> y <b>nunca</b> la IP
publica por la que salio el ataque. Por eso las publicas se <b>declaran</b> en la propia pestana
<b>Consultar IP</b> (arriba del todo, una caja por nodo, admite IPs sueltas y redes CIDR). A partir
de ahi el panel hace el cruce que ninguna de las dos mitades puede hacer sola:</p>
<ol class=doc>
<li>La <b>reputacion de tu publica</b> dice <b>que tipo</b> de abuso sale por ella: fuerza bruta SSH,
escaneo de puertos, spam de correo&hellip;</li>
<li><b>Suricata</b> dice <b>quien</b>, dentro de ese nodo, hace ese tipo de trafico: que CPEs hablan
por el 22, por el 25, cuales escanean.</li>
<li>El panel <b>traduce</b> cada categoria denunciada a esos puertos y firmas, y te lista los CPEs
del nodo ordenados por cuanto encajan, <b>diciendo por que</b> ("1.500 alertas por 25/tcp"). Cada
uno lleva su boton de <b>Cuarentena</b> al lado.</li>
</ol>
<p>Se revisan solas <b>cada 6 horas</b>. Cuando una publica <b>cruza</b> el 25&nbsp;% de abuso llega un
aviso por Telegram (una vez, no en cada vuelta) y queda en la bitacora. De cada publica se guarda la
<b>serie por dia</b> durante 180 dias: es lo que permite enseñar que despues de limpiar, el puntaje
baja.</p>
<p>Avisos importantes de honestidad: la traduccion sirve para <b>ordenar sospechosos</b>, no para
condenar; el listado de una <b>red</b> no trae categorias, asi que para saber el porque hay que
consultar la direccion concreta; y si ningun CPE encaja, se dice, en vez de señalar a cualquiera.
Los CPEs de <b>otros nodos</b> nunca se mezclan, aunque hagan lo mismo.</p>

<h3>Listas negras (DNSBL): lo que de verdad te banea</h3>
<p>Conviene no confundir dos cosas. <b>AbuseIPDB</b> es una base de <b>denuncias</b>: sirve para saber
<b>que hace</b> una IP, pero casi nadie corta correo o trafico mirandola. Lo que rebota los correos y
bloquea servicios son las <b>DNSBL</b>. Por eso el panel revisa cada publica declarada, cada 6 horas,
en <b>Spamhaus ZEN, SpamCop, SORBS, Barracuda, PSBL y UCEPROTECT</b>. Son consultas DNS: <b>no gastan
cuota de AbuseIPDB</b> y funcionan aunque no haya clave.</p>
<p>Tres detalles que evitan sustos y falsas tranquilidades:</p>
<ul>
<li><b>La PBL de Spamhaus no es un problema.</b> Que un rango residencial este en la PBL es lo
<b>correcto</b>: significa "por aqui no deberia salir correo directo". Se cuenta <b>aparte</b> y no se
pinta en rojo. Solo importa si tu servidor de correo sale por esa IP.</li>
<li><b>Una consulta rechazada no es "limpia".</b> Spamhaus responde <code>127.255.255.x</code> cuando
no acepta la consulta, cosa que pasa si el servidor resuelve por un DNS publico (8.8.8.8 y
similares). El panel lo dice en vez de darlo por bueno: para que el dato sea fiable, el sensor tiene
que usar un <b>resolutor propio</b>.</li>
<li>De una red se revisan hasta <b>256 direcciones</b>; si tiene mas, se avisa de cuantas se
miraron.</li>
</ul>
<p>Cada publica guarda tambien la <b>serie por dia</b> de cuantas direcciones suyas estan listadas:
es la prueba de que la limpieza funciona, y lo que se le enseña a quien pide el deslistado.</p>

<h3>Cuota y privacidad</h3>
<ul>
<li>El plan gratuito da <b>1.000 consultas al dia</b> (se reinicia a medianoche <b>UTC</b>). El panel
lleva la cuenta y la muestra en la pestana.</li>
<li>Lo ya consultado sale de una <b>cache</b> y no gasta cuota: 7 dias si la IP esta limpia, 12 horas
si tiene denuncias. Se puede marcar <b>Forzar consulta nueva</b> para saltarsela.</li>
<li>El enriquecimiento automatico tiene su propio tope y <b>no puede tocar una reserva</b> de 300
consultas, para que un barrido no te deje sin poder consultar a mano.</li>
<li><b>Nunca</b> se envian IPs privadas: las de tus abonados (10.x, 172.16-31.x, 192.168.x, 100.64.x)
se rechazan antes de salir del servidor. Solo viajan IPs publicas.</li>
<li>Si AbuseIPDB responde <b>429</b> (cuota agotada), el panel deja de llamar hasta que pasa el tiempo
que indica, en vez de insistir; mientras tanto sigue sirviendo lo que tenga en cache.</li>
<li>Sin clave configurada, la pestana lo avisa y <b>no se llama a nadie</b>: el resto del panel
funciona igual que siempre.</li>
</ul>

<h3>Tambien sale en el Top y en Entrantes</h3>
<p>Lo que ya se consulto queda en cache, y el panel va consultando <b>unos pocos destinos por
ciclo</b> de los CPE candidatos. Por eso, sin pulsar nada, en la columna <b>Dueño / organizacion</b>
del Top y en cada atacante de <b>Ataques entrantes</b> puede aparecer una etiqueta
<b>abuso&nbsp;NN&nbsp;%</b> con las dos categorias principales. El generador del reporte
<b>solo lee la cache</b>: nunca llama a la API, para que la cuota la controle un unico proceso.</p>

<h3>Denunciar atacantes (apagado por defecto)</h3>
<p>El panel puede <b>devolver la denuncia</b>: mandar a AbuseIPDB las IPs de internet que golpean tu
red, que es lo que hace que la base sirva para todos. Es la unica funcion que <b>publica algo hacia
fuera y a tu nombre</b>, asi que viene <b>apagada</b> y se activa en <b>Ajustes &rarr; Reputacion</b>.
Con ella activa, cada atacante de <b>Ataques entrantes</b> muestra un boton <b>Denunciar</b>.</p>
<ul>
<li><b>Nunca se denuncia solo.</b> Siempre lo pulsa una persona, y con confirmacion.</li>
<li><b>Nunca se denuncian IPs tuyas.</b> Ni las privadas de tus abonados ni tus rangos publicos de
NAT: denunciar tu propio rango te mete a <b>vos</b> en las listas negras. Tampoco las de la lista
<b>Nunca bloquear</b>.</li>
<li><b>El comentario no lleva ninguna IP</b>, ni la del atacante (ya va en su campo) ni la de la
maquina golpeada. Solo el nombre de la firma, el puerto y cuantas alertas hubo.</li>
<li>Las <b>categorias</b> salen de la firma de Suricata y se <b>suman</b>: un "SSH Scan" se denuncia
como <i>SSH</i> y <i>Escaneo de puertos</i>, no como fuerza bruta.</li>
<li>La misma IP <b>no se repite antes de 24 h</b>.</li>
<li>Todo queda en la <b>bitacora</b> (<code>DENUNCIA-ABUSEIPDB</code>): quien, cuando y con que
categorias.</li>
</ul>

<h2>Bitacora (auditoria)</h2>
<p>Toda accion sensible queda registrada: accesos, envios/quitados de cuarentena, cambios de
configuracion, usuarios y actualizaciones, con <b>quien, que, cuando y desde que IP</b>. Se ve en
<b>Ajustes &rarr; Bitacora</b> (admin), con buscador y paginacion.</p>

<h2>Avisos por Telegram</h2>
<p>Cuando un CPE va a cuarentena (a mano, por politica o por el barrido rapido) se manda un aviso por
Telegram con el <b>cliente/abonado</b>, la <b>accion</b> (a que lista), el <b>nivel de confianza</b>, la
<b>evidencia</b> (top 3) y un enlace a la <b>ficha</b>. Hay dedupe por IP (no re-avisa dentro de 6&nbsp;h)
y los envios masivos mandan un solo resumen. Usa el mismo <code>TELEGRAM_TOKEN</code>/<code>CHAT_ID</code>
del informe diario. Para que el enlace de la ficha sea clicable, pon <code>PANEL_URL</code> en
<code>/etc/suricata-dashboard.conf</code>.</p>

<!--CAT:Mantenimiento--><h2>Actualizar el panel (boton) y recuperacion</h2>
<p>En <b>Ajustes &rarr; Actualizaciones</b> el admin ve la version desplegada y, si hay una nueva en
GitHub, un boton con la lista de mejoras. El actualizador (<code>suricata-panel-update</code>) baja el
ultimo commit por SHA, valida el codigo (<code>ast</code>/<code>sh -n</code>), <b>respalda la version
actual</b> en <code>/root/backups/panel/</code> (conserva 5) y reinicia el panel. Luego hace un
<b>health-check</b>: si el panel no responde, <b>revierte solo</b> al respaldo previo. No toca tu
configuracion (usuarios, exclusiones, empresa, IPs de confianza, <code>.conf</code>, suricata.yaml ni
las units). El registro queda en <code>/tmp/suricata-panel-update.log</code> y el resultado en
<code>/var/log/suricata-update-result.json</code>.</p>

<h2>Mapa: a donde atacan tus CPEs</h2>
<p>En la pestana <b>En vivo</b>, <b>debajo de la linea de tiempo</b> ("Ataques por hora y minuto"),
hay un <b>mapa mundial</b> que pinta los <b>paises destino</b> de las alertas (a donde va el
trafico sospechoso de tus CPEs). El color sube con el nº de alertas y al lado sale el
<b>Top paises destino</b>.</p>
<ul>
<li><b>Geolocalizacion offline:</b> la IP destino se traduce a pais con una base
<b>IP&rarr;pais DB-IP lite</b> (via ip-location-db, CC-BY-4.0, &copy; db-ip.com) que se guarda en el servidor
(<code>/var/lib/suricata-geoip/ipv4.bin</code>). No usa servicios externos en caliente.</li>
<li><b>Flujo "de donde -> a donde":</b> ademas del color, salen <b>arcos animados</b> desde tu red
hacia cada pais destino (un punto viaja por el arco = sensacion de trafico en vivo), y <b>cada punta
late</b> igual que el origen, para ver de un vistazo donde cae cada flujo. El punto de
origen se puede fijar con <code>MAPA_ORIGEN=lon,lat</code> en <code>/etc/suricata-dashboard.conf</code>
(por defecto Ecuador); es solo el inicio visual del arco, no un dato real.</li>
<li><b>Detalle por pais:</b> al <b>pasar el mouse</b> por un pais sale un recuadro con <b>a que IPs
destino</b> va el trafico, <b>por que puertos</b> (p.ej. <code>443/tcp</code>) y <b>desde que CPEs</b> de
tu red sale, ademas de la <b>direccion</b> (siempre saliente: tus CPEs &rarr; el pais). Se muestran los
mas repetidos y se indica cuantos mas hay.</li>
<li><b>Zoom por pais:</b> <b>clic en un pais</b> (o en una fila del Top) lo <b>acerca</b> y abre debajo
un panel fijo con ese mismo detalle, comodo de leer en el telefono. Puedes <b>arrastrar</b> para
mover el mapa, usar <b>+</b> / <b>&minus;</b> o <b>Ctrl + rueda</b> para acercar, y <b>Vista completa</b>
para volver al mundo entero.</li>
<li><b>No pierde el zoom:</b> la pagina se recarga sola cada 5 min; el mapa <b>repone la vista</b>
(el zoom, el desplazamiento y el pais que tenias abierto) en vez de volver al mundo entero. Se
guarda por pestana del navegador, asi que otra pestana o una sesion nueva empiezan limpias.</li>
<li><b>Cobertura:</b> el mapa reconoce los <b>174 paises</b> del atlas (todos los que trae el
TopoJSON, mas Kosovo). Si un pais no tiene nombre traducido, se usa el del propio mapa.</li>
<li><b>Solo destinos publicos:</b> las IPs privadas (tu red) o sin pais no cuentan en el mapa.</li>
<li><b>El mapa</b> se dibuja en el navegador con un <b>TopoJSON</b> del mundo servido por el
propio panel (<code>/var/lib/suricata-mapa/</code>); no llama a ningun CDN externo.</li>
<li>Si el mapa sale vacio, casi siempre es que la base GeoIP no se instalo (no habia internet
en la instalacion). El panel <b>se auto-provisiona</b> al arrancar (baja el mapa y construye la
base GeoIP en 2do plano si faltan); tambien se reconstruye con el boton <b>Actualizar</b> o
re-ejecutando el instalador. Necesita salida a internet la primera vez.</li>
</ul>
<p class="muted" style="color:#52514e;font-size:12px">Mapa inspirado en
<b>MikroDash</b> (MIT). Geometria del mundo: World Atlas / Natural Earth (dominio publico).</p>

<h2>Reinstalar o actualizar</h2>
<p>Todo esta en un instalador idempotente. Para actualizar a la ultima version
(ejemplo ISP con espejo y todas las redes privadas):</p>
<pre><code>curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -t -m &lt;IP_MikroTik&gt; -n 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</code></pre>"""
    # --- La documentacion se parte en PAGINAS (una por tema), agrupadas en categorias.
    # Antes era un unico muro con indice lateral: con 23 temas costaba encontrar nada.
    # Las categorias se marcan en el texto con <!--CAT:Nombre--> delante del <h2> que
    # abre el grupo. Cada tema conserva su ancla de siempre, asi que los enlaces
    # antiguos (#cuarentena, #reglas...) siguen llevando a su sitio.
    usados = {}
    def _slug(t):
        s = re.sub(r"<[^>]+>", "", t)
        s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "sec"
        n = usados.get(s, 0) + 1; usados[s] = n
        return s if n == 1 else f"{s}-{n}"

    paginas = []        # [{slug, titulo, cat, html}]
    cat_actual = "General"
    for trozo in re.split(r"(?=<h2>)", art):
        mcat = re.findall(r"<!--CAT:([^>]*?)-->", trozo)
        if mcat:
            cat_actual = mcat[-1].strip() or cat_actual
            trozo = re.sub(r"<!--CAT:[^>]*?-->", "", trozo)
        mt = re.match(r"\s*<h2>(.*?)</h2>", trozo, re.S)
        if not mt:
            continue                      # texto antes del primer tema (no deberia haber)
        titulo = re.sub(r"<[^>]+>", "", mt.group(1))
        sl = _slug(mt.group(1))
        cuerpo = trozo[mt.end():]
        paginas.append({"slug": sl, "titulo": titulo, "cat": cat_actual, "html": cuerpo})

    pedida = (pagina or "").strip().lower()
    todo = (pedida == "todo")
    idx = 0
    if pedida and not todo:
        for i, pg in enumerate(paginas):
            if pg["slug"] == pedida:
                idx = i
                break
    actual = paginas[idx] if paginas else {"slug": "", "titulo": "", "cat": "", "html": ""}

    def _ir(slug):
        """Enlace a otro tema. Dentro del modal de Ajustes hay que arrastrar embed=1: sin
        el, al pulsar un tema se cargaba el panel ENTERO (barra incluida) dentro de la
        ventanita."""
        return f"?p={slug}&embed=1" if embed else f"?p={slug}"

    # --- barra lateral: categorias -> temas, con buscador ---
    # ojo con el nombre: nav() es la funcion que dibuja la barra del panel, no tocar
    lateral = []
    cat_prev = None
    for pg in paginas:
        if pg["cat"] != cat_prev:
            if cat_prev is not None:
                lateral.append("</ul>")
            lateral.append(f"<div class=navcat>{html.escape(pg['cat'])}</div><ul class=navlist>")
            cat_prev = pg["cat"]
        act = " class=on" if (not todo and pg["slug"] == actual["slug"]) else ""
        lateral.append(f'<li><a href="{_ir(pg["slug"])}"{act} data-t="{html.escape(pg["titulo"].lower())}">'
                       f'{html.escape(pg["titulo"])}</a></li>')
    if cat_prev is not None:
        lateral.append("</ul>")
    toc = ("<input id=docq class=docq type=search placeholder='Buscar en la documentacion'"
           " autocomplete=off aria-label='Buscar'>"
           + "".join(lateral)
           + f'<div class=navcat>Todo</div><ul class=navlist><li>'
             f'<a href="{_ir("todo")}"{" class=on" if todo else ""}>Ver la guia completa</a></li></ul>')

    if todo:
        art = "".join(
            f'<h2 id="{pg["slug"]}">{html.escape(pg["titulo"])}'
            f'<a class=anchor href="#{pg["slug"]}" aria-label=enlace>&para;</a></h2>{pg["html"]}'
            for pg in paginas)
        pag_tit = "Guia completa"
        pies = ""
    else:
        art = (f'<div class=docbreadcrumb id="{actual["slug"]}">{html.escape(actual["cat"])}</div>'
               + actual["html"])
        pag_tit = actual["titulo"]
        ant = paginas[idx - 1] if idx > 0 else None
        sig = paginas[idx + 1] if idx + 1 < len(paginas) else None
        pies = ("<nav class=docpn>"
                + (f'<a class=pnprev href="{_ir(ant["slug"])}"><span>Anterior</span>'
                   f'<b>{html.escape(ant["titulo"])}</b></a>' if ant else "<span></span>")
                + (f'<a class=pnnext href="{_ir(sig["slug"])}"><span>Siguiente</span>'
                   f'<b>{html.escape(sig["titulo"])}</b></a>' if sig else "<span></span>")
                + "</nav>")
        art += pies
    wcss = (
        "*{box-sizing:border-box}"
        "body{margin:0;background:#fff;color:#202122;font:16px/1.65 Georgia,'Times New Roman',serif}"
        ".wiki{display:flex;gap:34px;max-width:1120px;margin:0 auto;padding:24px 24px 70px;align-items:flex-start}"
        ".toc{position:sticky;top:58px;flex:0 0 240px;font:13px/1.5 -apple-system,system-ui,Segoe UI,sans-serif}"
        ".toc .toch{font-weight:700;color:#54595d;text-transform:uppercase;font-size:11px;letter-spacing:.5px;"
        "margin:0 0 8px;padding-bottom:7px;border-bottom:1px solid #eaecf0}"
        # --- barra lateral tipo documentacion: buscador + categorias + temas ---
        ".docq{width:100%;padding:7px 10px;border:1px solid #c8ccd1;border-radius:6px;"
        "font:13px system-ui;margin:0 0 12px;background:#fff}"
        ".docq:focus{outline:none;border-color:#3366cc;box-shadow:0 0 0 3px rgba(51,102,204,.12)}"
        ".navcat{font-weight:700;color:#54595d;text-transform:uppercase;font-size:10.5px;"
        "letter-spacing:.6px;margin:14px 0 5px}"
        ".navlist{list-style:none;margin:0 0 4px;padding:0}"
        ".navlist li{margin:0}"
        ".navlist a{color:#3366cc;text-decoration:none;display:block;padding:5px 9px;"
        "border-left:2px solid transparent;border-radius:0 4px 4px 0}"
        ".navlist a:hover{background:#f4f8ff;border-left-color:#a7c0ea}"
        ".navlist a.on{background:#eaf1fd;border-left-color:#3366cc;color:#1c4587;font-weight:700}"
        ".navlist li.oculto,.navcat.oculto{display:none}"
        ".docvacio{color:#72777d;font-size:12.5px;padding:6px 9px}"
        # miga de pan y navegacion entre temas
        ".docbreadcrumb{font:600 11px/1 system-ui;text-transform:uppercase;letter-spacing:.6px;"
        "color:#72777d;margin:0 0 4px}"
        ".docpn{display:flex;gap:12px;justify-content:space-between;margin:34px 0 0;"
        "padding-top:16px;border-top:1px solid #eaecf0;font-family:system-ui}"
        ".docpn a{flex:1;max-width:48%;border:1px solid #eaecf0;border-radius:6px;padding:9px 12px;"
        "text-decoration:none;color:#3366cc}"
        ".docpn a:hover{border-color:#3366cc;background:#f8fbff}"
        ".docpn a span{display:block;font-size:11px;color:#72777d;text-transform:uppercase;letter-spacing:.5px}"
        ".docpn a b{font-size:14px}"
        ".docpn .pnnext{text-align:right}"
        "article{flex:1;min-width:0;max-width:770px}"
        "article h1{font:400 28px/1.3 Georgia,serif;margin:0 0 3px;border-bottom:1px solid #a2a9b1;padding-bottom:7px}"
        ".lead{color:#54595d;font-size:15px;margin:0 0 8px}"
        "article h2{font:400 22px/1.3 Georgia,serif;border-bottom:1px solid #a2a9b1;padding-bottom:5px;"
        "margin:30px 0 10px;scroll-margin-top:62px;display:flex;align-items:baseline}"
        "article h3{font-size:16px;font-weight:700;margin:18px 0 6px;color:#202122}"
        "p,li{color:#202122}a{color:#3366cc;text-decoration:none}a:hover{text-decoration:underline}"
        "code{font-family:ui-monospace,Consolas,monospace;font-size:13px;background:#f8f9fa;border:1px solid #eaecf0;border-radius:3px;padding:1px 5px}"
        "pre{background:#f8f9fa;border:1px solid #eaecf0;color:#202122;padding:12px 14px;border-radius:4px;overflow-x:auto;font-size:13px}"
        "pre code{border:0;background:none;padding:0}"
        "table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}"
        "th,td{border:1px solid #a2a9b1;padding:7px 10px;text-align:left;vertical-align:top}th{background:#eaecf0}"
        "ul,ol.doc{margin:8px 0;padding-left:22px}"
        ".b{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}"
        ".anchor{color:#c8ccd1;text-decoration:none;font-size:14px;margin-left:8px;opacity:0;transition:opacity .1s}"
        "article h2:hover .anchor{opacity:1}"
        "@media(max-width:900px){.wiki{flex-direction:column;gap:14px}.toc{position:static;flex:none;width:100%;"
        "border:1px solid #eaecf0;border-radius:8px;padding:12px 14px;background:#f8f9fa}}")
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>" + refresh_meta +
            "<title>Suricata</title><style>" + wcss + "</style></head><body>"
            + ("" if embed else nav("/documentacion")) +
            "<div class=wiki>"
            "<aside class=toc><div class=toch>Documentacion</div><nav>" + toc + "</nav></aside>"
            f"<article><h1>{html.escape(pag_tit)}</h1>"
            + art +
            "</article></div>"
            "<script>(function(){var q=document.getElementById('docq');if(!q)return;"
            # se filtra en el navegador: la doc va entera en la pagina, no hay que ir al servidor
            "var items=[].slice.call(document.querySelectorAll('.navlist li'));"
            "var cats=[].slice.call(document.querySelectorAll('.navcat'));"
            "function filtrar(){var t=q.value.trim().toLowerCase();"
            "items.forEach(function(li){var a=li.querySelector('a');"
            "var txt=(a.getAttribute('data-t')||a.textContent||'').toLowerCase();"
            "li.classList.toggle('oculto',!!t&&txt.indexOf(t)<0);});"
            # una categoria sin temas visibles se esconde tambien
            "cats.forEach(function(c){var ul=c.nextElementSibling,vis=0;"
            "if(ul)[].slice.call(ul.children).forEach(function(li){if(!li.classList.contains('oculto'))vis++;});"
            "c.classList.toggle('oculto',!!t&&vis===0);if(ul)ul.classList.toggle('oculto',!!t&&vis===0);});}"
            "q.addEventListener('input',filtrar);"
            "q.addEventListener('keydown',function(e){if(e.key==='Escape'){q.value='';filtrar();}});"
            "})();</script></body></html>")
    return body

def log_page(embed=False):
    """Pestana Log: actividad del panel (accesos + acciones de cuarentena). Solo admin."""
    esc = html.escape
    _col = {"OK": "#12b886", "FAIL": "#e34948", "BLOQUEADO": "#eb6834",
            "ENVIADO": "#b52a2a", "QUITADO": "#6b6a66"}
    def estb(e):
        if e in _col:
            c = _col[e]
        elif e.startswith("DESBLOQUEO"):
            c = "#2a78d6"
        elif e.startswith("ERROR"):
            c = "#e58a00"
        else:
            c = "#8a8a86"
        return (f'<span style="background:{c};color:#fff;font-size:10px;font-weight:700;'
                f'padding:2px 8px;border-radius:20px">{esc(e)}</span>')
    def tipob(t):
        c = "#7048e8" if t == "Cuarentena" else "#2a78d6"
        return (f'<span style="background:{c}1a;color:{c};font-size:10px;font-weight:700;'
                f'padding:2px 8px;border-radius:20px">{esc(t)}</span>')
    rec = actividad_reciente(800)
    if rec:
        rows = "".join(
            f"<tr data-f=\"{esc((ts + ' ' + tipo + ' ' + ip + ' ' + us + ' ' + acc + ' ' + det).lower())}\">"
            f"<td class=mono>{esc(ts)}</td><td>{tipob(tipo)}</td><td class=mono>{esc(ip)}</td>"
            f"<td>{esc(us) or '<span style=color:#c3c2be>&mdash;</span>'}</td><td>{estb(acc)}</td>"
            f"<td class=det>{esc(det)}</td></tr>"
            for ts, tipo, ip, us, acc, det in rec)
        cuerpo = ("<div class=twrap><table class=ut><thead><tr><th>Fecha (Ecuador)</th><th>Tipo</th><th>IP</th>"
                  f"<th>Usuario</th><th>Accion</th><th>Detalle</th></tr></thead><tbody id=logbody>{rows}</tbody></table></div>"
                  "<div class=pager><button id=lprev type=button onclick=lprev()>&larr; Anterior</button>"
                  "<span id=lpi></span>"
                  "<button id=lnext type=button onclick=lnext()>Siguiente &rarr;</button></div>")
    else:
        cuerpo = "<p class=sub2>Sin actividad registrada todavia.</p>"
    css = (
        BASE_CSS +
        "body{background:#f6f6f4}main{max-width:1000px;padding:22px 22px 40px}"
        "h1{margin:0 0 2px}.sub2{color:#6b6a66;margin:0 0 14px}"
        ".card{border:1px solid #e7e6e2;border-radius:14px;padding:20px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.03)}"
        ".uhead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}"
        ".search{width:240px;padding:8px 12px;border:1px solid #d7d6d2;border-radius:8px;font:14px system-ui}"
        ".twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}"
        ".ut{width:100%;border-collapse:collapse;font-size:13px;white-space:nowrap}"
        ".ut th{text-align:left;color:#8a8a86;font-weight:600;padding:10px 12px;background:#fafafa;border-bottom:1px solid #eee}"
        ".ut td{padding:8px 12px;border-bottom:1px solid #f2f1ee}"
        ".ut tbody tr:last-child td{border-bottom:0}.ut tbody tr:hover{background:#fafbfd}"
        ".det{white-space:normal;color:#6b6a66;font-size:12px;max-width:320px}"
        ".pager{display:flex;align-items:center;gap:12px;margin-top:12px;flex-wrap:wrap}"
        ".pager button{font:13px system-ui;padding:6px 12px;border:1px solid #d7d6d2;background:#fff;border-radius:8px;cursor:pointer;color:#0b0b0b}"
        ".pager button:hover:not(:disabled){background:#eef4fd;border-color:#2a78d6}"
        ".pager button:disabled{opacity:.4;cursor:default}.pager #lpi{font-weight:600;font-size:13px;color:#52514e}")
    script = ("<script>(function(){var SIZE=50,page=0,"
              "rows=[].slice.call(document.querySelectorAll('#logbody tr')),q='';"
              "function filtered(){return rows.filter(function(r){return (r.getAttribute('data-f')||'').indexOf(q)>=0;});}"
              "function render(){var f=filtered(),pages=Math.max(1,Math.ceil(f.length/SIZE));"
              "if(page>=pages)page=pages-1;if(page<0)page=0;"
              "rows.forEach(function(r){r.style.display='none';});"
              "f.slice(page*SIZE,page*SIZE+SIZE).forEach(function(r){r.style.display='';});"
              "var pi=document.getElementById('lpi');if(pi)pi.textContent='Pagina '+(page+1)+' de '+pages+' ('+f.length+' registros)';"
              "var pv=document.getElementById('lprev'),nx=document.getElementById('lnext');"
              "if(pv)pv.disabled=page<=0;if(nx)nx.disabled=page>=pages-1;}"
              "window.lfiltrar=function(){q=(document.getElementById('lsearch').value||'').toLowerCase();page=0;render();};"
              "window.lprev=function(){page--;render();};window.lnext=function(){page++;render();};"
              "if(rows.length)render();})();</script>")
    return ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>Suricata</title>"
            f"<style>{css}</style></head><body>" + ("" if embed else nav("/log")) +
            "<main><h1>Log de actividad</h1>"
            "<p class=sub2>Accesos al panel y acciones de cuarentena (quien envio o quito una IP). "
            f"Los registros de mas de {LOG_RETENCION_DIAS} dias se borran solos.</p>"
            "<section class=card><div class=uhead><h2 style='font-size:15px;margin:0'>Ultima actividad</h2>"
            "<input class=search id=lsearch placeholder='Buscar IP, usuario, accion...' oninput='lfiltrar()'></div>"
            + cuerpo + "</section></main>" + script + "</body></html>")

def reputacion_page(res=None, texto="", msg="", ok=False, es_admin=False, volver=""):
    """Consultar en AbuseIPDB que ataques se le denuncian a una IP publica.

    Dos usos, y el segundo es el que de verdad arregla cosas:
      1. una IP que ATACA a tu red (pestana Entrantes) -> saber a que se dedica;
      2. TUS PROPIAS IPs publicas de NAT -> ver por que te denuncian a vos, que es la
         pista de que hay un abonado infectado detras y de que hay que corregir."""
    esc = html.escape
    quedan = aidb_restantes()
    quedan_red = aidb_restantes_bloque()
    hay_clave = aidb_configurada()
    banner = ""
    if msg:
        col = "#1baf7a" if ok else "#e34948"
        banner = (f"<div class=banner style='background:{col};color:#fff;padding:10px 14px;"
                  f"border-radius:8px;margin-bottom:16px;font-size:13px'>{esc(msg)}</div>")
    if not hay_clave:
        banner += ("<div class=banner style='background:#fdf0e6;color:#a15c12;border:1px solid #f2d3ad;"
                   "padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px'>"
                   "Falta la <b>clave de AbuseIPDB</b>. Se saca gratis en "
                   "<a href='https://www.abuseipdb.com/account/api' target=_blank rel=noopener>"
                   "abuseipdb.com</a> y se pega en <b>Ajustes &rarr; Reputacion</b>.</div>")

    def _scb(n, corto=False, verde=True):
        # verde=False cuando hay direcciones con denuncias aunque el peor puntaje sea 0:
        # pintarlo de verde diria "todo bien" y no es lo que pasa
        c = ("#3a9d5d" if verde else "#8a8a86") if n == 0 else (
            "#e58a00" if n < 25 else ("#e07b39" if n < 75 else "#e34948"))
        txt = f"{n} %" if corto else f"Confianza de abuso {n}%"
        return (f"<span style='background:{c};color:#fff;font-weight:700;font-size:12px;"
                f"padding:3px 10px;border-radius:20px'>{txt}</span>")

    # Barra de vuelta. Estaba como un enlace suelto ENCIMA del bloque de las publicas, o
    # sea fuera de la vista: se aterrizaba en una pagina larga con el resultado abajo y
    # sin retorno aparente. Ahora va pegada al resultado y con aspecto de boton.
    atras = ""
    if res:
        destino = f"?ips={esc(volver)}" if volver else "/reputacion"
        que = ("Volver a " + esc(volver)) if volver else "Volver a Consultar IP"
        atras = ("<div class=volver><a href='" + destino + "'>&larr; " + que + "</a>"
                 "<span class=hint>" + esc(texto[:60]) + "</span></div>")

    tarjetas = []
    for ip, d, origen, err in (res or []):
        if d and d.get("tipo") == "red":
            # --- una RED entera: una sola peticion cubrio todas sus direcciones ---
            den = d.get("denunciadas") or []
            hosts = int(d.get("hosts") or 0)
            cuando = time.strftime("%d/%m %H:%M", time.localtime(d.get("ts", 0)))
            proc = f"ultima verificacion: {cuando}"
            if not den:
                cuerpo = ("<div style='background:#e6f4ea;color:#1a7f37;border:1px solid #b7e0c2;"
                          "border-radius:8px;padding:12px 14px;font-size:13px'>"
                          "<b>Ninguna direccion de esta red esta denunciada.</b> Si aun asi te "
                          "rebota el correo o te bloquean, el problema no es AbuseIPDB: mira las "
                          "listas de spam (Spamhaus, SORBS, Barracuda).</div>")
            else:
                filas = "".join(
                    "<tr><td class=mono>" + esc(str(a[0])) + "</td>"
                    f"<td class=num>{_scb(int(a[1]), corto=True)}</td>"
                    f"<td class=num>{int(a[2]):,}</td>"
                    f"<td class=mono>{esc(str(a[3]))}</td>"
                    f"<td>{esc(str(a[4]))}</td>"
                    f"<td><a href='?ips={esc(str(a[0]))}&amp;volver={esc(d.get('red') or ip)}'>"
                    "ver que hace</a></td></tr>"
                    for a in den[:120])
                peor = sum(1 for a in den if int(a[1]) >= 75)
                cuerpo = (
                    f"<p style='font-size:13px;margin:0 0 10px'><b>{len(den):,}</b> de "
                    f"<b>{hosts:,}</b> direcciones estan denunciadas"
                    + (f", <b style='color:#b52a2a'>{peor:,}</b> de ellas con 75 % o mas" if peor else "")
                    + ". Cada fila es una IP publica tuya por la que se esta atacando: "
                      "pulsa <b>ver que hace</b> para el detalle con categorias.</p>"
                    "<div class=tablewrap><table><thead><tr><th>Direccion</th>"
                    "<th class=num>Abuso</th><th class=num>Denuncias</th><th>Ultima</th>"
                    "<th>Pais</th><th></th></tr></thead><tbody>" + filas + "</tbody></table></div>"
                    + (f"<p class=hint>Se muestran las 120 peores de {len(den):,}.</p>"
                       if len(den) > 120 else ""))
            tarjetas.append(
                "<div class=card style='margin:0 0 12px'>"
                "<div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap'>"
                f"<b class=mono style='font-size:15px'>{esc(d.get('red') or ip)}</b>"
                f"<span class=hint>{esc(d.get('desc') or 'red publica')}</span>"
                f"<span class=hint style='margin-left:auto'>{esc(proc)}</span></div>"
                f"<div style='margin-top:10px'>{cuerpo}</div></div>")
            continue
        if not d:
            tarjetas.append(
                f"<div class=card style='margin:0 0 12px'><b class=mono>{esc(ip)}</b> "
                f"<span style='color:#b52a2a'>&mdash; {esc(err or 'sin datos')}</span></div>")
            continue
        cats = d.get("cats") or []
        chips = "".join(
            "<span style='display:inline-block;background:#f1f1ef;border:1px solid #e0dfda;"
            "border-radius:20px;padding:3px 10px;margin:0 6px 6px 0;font-size:12.5px'>"
            + esc(AIDB_CATS.get(int(c), "categoria %d" % int(c)))
            + f" <b>{int(n)}</b></span>" for c, n in cats) or "<span class=hint>sin denuncias en 90 dias</span>"
        # que hacer: solo de las categorias que de verdad aparecen
        arreglos = []
        for c, _n in cats:
            t = AIDB_REMEDIO.get(int(c))
            if t and t not in arreglos:
                arreglos.append(t)
        arr_html = ""
        if arreglos:
            arr_html = ("<div style='margin-top:10px'><b style='font-size:13px'>Que suele haber detras</b>"
                        "<ul style='margin:6px 0 0;padding-left:20px;font-size:13px'>"
                        + "".join(f"<li>{esc(t)}</li>" for t in arreglos[:5]) + "</ul></div>")
        ejem = ""
        if d.get("ejemplos"):
            ejem = ("<details style='margin-top:10px'><summary style='cursor:pointer;font-size:13px'>"
                    "Texto de las denuncias</summary>"
                    "<ul class=mono style='font-size:12px;color:#52514e;margin:6px 0 0;padding-left:20px'>"
                    + "".join(f"<li>{esc(t)}</li>" for t in d["ejemplos"]) + "</ul></details>")
        extra = []
        if d.get("tor"):
            extra.append("nodo Tor")
        if d.get("blanca"):
            extra.append("en lista blanca de AbuseIPDB")
        cuando = time.strftime("%d/%m %H:%M", time.localtime(d.get("ts", 0)))
        proc = f"ultima verificacion: {cuando}"
        tarjetas.append(
            "<div class=card style='margin:0 0 12px'>"
            f"<div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap'>"
            f"<b class=mono style='font-size:15px'>{esc(d.get('ip') or ip)}</b>{_scb(d.get('score', 0))}"
            + (f"<span class=hint>{esc(' · '.join(extra))}</span>" if extra else "")
            + f"<span class=hint style='margin-left:auto'>{esc(proc)}</span></div>"
            "<div style='font-size:13px;color:#52514e;margin:8px 0 10px'>"
            + esc(d.get("isp") or "operador desconocido")
            + (f" &middot; {esc(d.get('pais'))}" if d.get("pais") else "")
            + (f" &middot; {esc(d.get('uso'))}" if d.get("uso") else "")
            + (f" &middot; {esc(d.get('dominio'))}" if d.get("dominio") else "")
            + "</div>"
            f"<div style='font-size:13px;margin-bottom:8px'><b>{d.get('reportes', 0):,}</b> denuncias de "
            f"<b>{d.get('denunciantes', 0):,}</b> denunciantes distintos"
            + (f" &middot; ultima {esc(d.get('ultimo'))}" if d.get("ultimo") else "") + "</div>"
            + chips + arr_html + ejem + "</div>")

    # --- Tus IPs publicas: el puente entre "me banean" y "quien lo causa" -----------
    decl = cargar_publicas()
    hist = _pub_hist()
    dnsbl = _dnsbl_hist()
    rs = cargar_routers()
    multi = len(rs) > 1
    bloques = []
    for r in rs:
        rid = r.get("id", "")
        entradas = decl.get(rid) or []
        nom = r.get("nombre") or r.get("HOST") or rid
        filas = []
        for ent in entradas:
            h = hist.get(ent) or {}
            sc = int(h.get("ultimo_score", 0))
            visto = (time.strftime("%d/%m %H:%M", time.localtime(h["ultimo_ts"]))
                     if h.get("ultimo_ts") else "nunca")
            dat = (_aidb_cache() or {}).get(ent) or {}
            cats = _cats_de(dat)
            # que se le denuncia y, sobre todo, QUIEN de este nodo lo esta haciendo
            det = ""
            if sc:
                if cats:
                    det = "<div class=hint style='margin-top:4px'>" + esc(aidb_cats_txt(
                        [[c, 1] for c in cats], sep=" &middot; ")).replace(" (1)", "") + "</div>"
                culp = culpables_de(rid, cats) if cats else []
                if culp:
                    lis = "".join(
                        "<li style='margin:6px 0'>"
                        f"<b class=mono>{esc(ip_de(k))}</b> "
                        f"<span class=hint>{esc(', '.join(mot))}</span> "
                        + ("<span class=hint style='color:#3a9d5d'>&#10003; ya en cuarentena</span>"
                           if yaesta else
                           "<form method=post action='/cuarentena/enviar' style='display:inline'>"
                           f"<input type=hidden name=ip value='{esc(k)}'>"
                           f"<input type=hidden name=score value='{c.get('riesgo', 0)}'>"
                           "<button class='qbtn send' style='padding:3px 10px;font-size:12px'>"
                           "Cuarentena</button></form>")
                        + "</li>"
                        for k, c, _pts, mot, yaesta in culp)
                    det += ("<details open style='margin-top:8px'><summary style='cursor:pointer;"
                            "font-size:13px;font-weight:600'>Quien lo esta causando ("
                            + str(len(culp)) + ")</summary>"
                            "<ul style='margin:6px 0 0;padding-left:18px;font-size:13px'>"
                            + lis + "</ul></details>")
                elif cats:
                    det += ("<div class=hint style='margin-top:6px'>Ningun CPE de este nodo "
                            "coincide ahora mismo con ese tipo de trafico: puede haberse "
                            "limpiado solo, o el abuso salir por otro nodo.</div>")
                elif dat.get("tipo") == "red":
                    det += ("<div class=hint style='margin-top:6px'>Consulta cada direccion "
                            "denunciada (abajo) para saber por que: el listado de una red no "
                            "trae las categorias.</div>")
            # --- listas negras: esto es lo que de verdad hace que te bloqueen ---
            bl = dnsbl.get(ent) or {}
            bl_html = ""
            if bl.get("ts"):
                n_bl = int(bl.get("n_listadas", 0))
                n_pbl = int(bl.get("n_pbl", 0))
                if n_bl:
                    peores = [(k, v) for k, v in (bl.get("ips") or {}).items()
                              if not v.get("solo_pbl")][:8]
                    det = "".join(
                        f"<li><b class=mono>{esc(k)}</b> &mdash; {esc(', '.join(v.get('listas') or []))}</li>"
                        for k, v in peores)
                    bl_html = ("<div style='margin-top:8px;background:#fdecec;border:1px solid #f3c4c4;"
                               "border-radius:8px;padding:10px 12px'>"
                               f"<b style='color:#b52a2a'>En listas de bloqueo: {n_bl} direccion(es)</b>"
                               " <span class=hint>esto si corta correo y servicios</span>"
                               "<ul style='margin:6px 0 0;padding-left:18px;font-size:12.5px'>"
                               + det + "</ul></div>")
                else:
                    bl_html = ("<div class=hint style='margin-top:8px;color:#1a7f37'>"
                               "&#10003; Ninguna direccion en listas de bloqueo</div>")
                if n_pbl:
                    bl_html += ("<div class=hint style='margin-top:4px'>"
                                f"{n_pbl} en la PBL de Spamhaus, que es <b>lo normal</b> en un rango "
                                "residencial: dice que por ahi no deberia salir correo directo. "
                                "Solo importa si tu servidor de correo sale por esa IP.</div>")
                if bl.get("rechazadas"):
                    bl_html += ("<div class=hint style='margin-top:4px;color:#a15c12'>"
                                + esc(", ".join(bl["rechazadas"]))
                                + " no acepta consultas desde el resolutor de este servidor "
                                  "(pasa con los publicos tipo 8.8.8.8). Usa un resolutor propio "
                                  "para que el dato sea fiable.</div>")
                if bl.get("truncado"):
                    bl_html += (f"<div class=hint style='margin-top:4px'>Se revisaron las primeras "
                                f"{int(bl.get('n_ips', 0)):,} direcciones de la red.</div>")
            else:
                bl_html = ("<div class=hint style='margin-top:8px'>Listas de bloqueo: sin revisar "
                           "todavia (se revisan solas cada 6 h).</div>")

            den_n = ""; n_den = 0
            if isinstance(dat, dict) and dat.get("tipo") == "red":
                n_den = int(dat.get("n_den", 0))
                den_n = (f"<span class=hint>{n_den:,} de "
                         f"{int(dat.get('hosts', 0)):,} con denuncias</span>")
            filas.append(
                "<div style='padding:10px 0;border-top:1px solid #f0efec'>"
                "<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap'>"
                f"<b class=mono>{esc(ent)}</b>{_scb(sc, verde=(sc == 0 and not n_den))}{den_n}"
                f"<a class=hint href='?ips={esc(ent)}'>ver detalle</a>"
                f"<span class=hint style='margin-left:auto'>ultima verificacion: {esc(visto)}</span></div>"
                + bl_html + det + "</div>")
        if not entradas and not es_admin:
            continue
        # Las entradas, como fichas pequeñas con su x. Antes era un textarea enorme por
        # nodo y encima otro para consultar: dos cajones iguales haciendo cosas distintas.
        chips = ""
        if es_admin and entradas:
            chips = "".join(
                "<span class=pchip><span class=mono>" + esc(e) + "</span>"
                "<form method=post action='/publicas/quitar'>"
                f"<input type=hidden name=rid value='{esc(rid)}'>"
                f"<input type=hidden name=entrada value='{esc(e)}'>"
                "<button title='Quitar de la lista'>&times;</button></form></span>"
                for e in entradas)
        acciones = []
        if es_admin:
            acciones.append(
                "<form method=post action='/publicas/agregar' class=padd>"
                f"<input type=hidden name=rid value='{esc(rid)}'>"
                "<input name=entrada size=20 placeholder='IP o red (CIDR)' autocomplete=off>"
                "<button class=primary type=submit>Agregar</button></form>")
        if es_admin:
            acciones.append("<form method=post action='/publicas/detectar'>"
                            f"<input type=hidden name=rid value='{esc(rid)}'>"
                            "<button class=cancelbtn type=submit title='Pregunta al MikroTik "
                            "por las direcciones de sus interfaces y el to-addresses de sus "
                            "reglas de src-nat'>Detectar del MikroTik</button></form>")
        if entradas:
            acciones.append("<form method=post action='/publicas/revisar'>"
                            f"<input type=hidden name=rid value='{esc(rid)}'>"
                            "<button class=cancelbtn type=submit>Revisar ahora</button></form>")
        editor = ("<div class=pedit>" + chips + "".join(acciones) + "</div>") if (chips or acciones) else ""
        bloques.append(
            "<section class=card style='margin:0 0 12px'>"
            + (f"<h3 style='font-size:14px;margin:0 0 4px;color:#52514e'>Nodo {esc(nom)}</h3>"
               if multi else "")
            + ("".join(filas) if filas else
               "<p class=hint style='margin:8px 0 0'>Todavia no declaraste ninguna. "
               "Ponlas aqui: el sensor no las ve (el espejo es pre-NAT) y sin ellas no se "
               "puede ligar un baneo con el abonado que lo provoca.</p>")
            + editor + "</section>")
    pub_html = ("<h2 style='font-size:17px;margin:18px 0 10px'>Tus IPs publicas</h2>"
                "<p class=sub2 style='margin:-4px 0 10px'>El sensor no las ve (el espejo es "
                "pre-NAT): declaralas aqui y el panel vigila su reputacion y sus listas negras.</p>"
                + "".join(bloques)) if bloques else ""

    css = BASE_CSS + (
        "textarea{width:100%;min-height:84px;padding:10px 12px;border:1px solid #d9d7d2;"
        "border-radius:9px;font:13px ui-monospace,Consolas,monospace;resize:vertical}"
        ".qbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:10px}"
        ".volver{display:flex;align-items:center;gap:12px;margin:0 0 14px;flex-wrap:wrap}"
        ".volver a{display:inline-flex;align-items:center;background:#eef4fd;color:#1c5cab;"
        "border:1px solid #cfe0f6;border-radius:9px;padding:7px 14px;text-decoration:none;"
        "font:600 13px system-ui}"
        ".volver a:hover{background:#dceafb;border-color:#a7c0ea}"
        ".cab{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin:0 0 6px}"
        ".busca{display:flex;align-items:center;gap:8px;margin-left:auto}"
        ".busca input[name=ips]{padding:7px 11px;border:1px solid #d9d7d2;border-radius:9px;"
        "font:13px ui-monospace,Consolas,monospace;min-width:190px}"
        ".busca .chk{font-size:12.5px;color:#8a8a86;white-space:nowrap}"
        ".pedit{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px}"
        ".pchip{display:inline-flex;align-items:center;gap:6px;background:#f1f1ef;"
        "border:1px solid #e0dfda;border-radius:20px;padding:3px 6px 3px 11px;font-size:12.5px}"
        ".pchip form{display:inline;margin:0}"
        ".pchip button{border:0;background:#e0dfda;color:#52514e;border-radius:50%;width:18px;"
        "height:18px;line-height:1;cursor:pointer;font-size:13px;padding:0}"
        ".pchip button:hover{background:#e34948;color:#fff}"
        ".pedit form{display:inline;margin:0}"
        ".pedit .padd input{padding:6px 10px;border:1px solid #d9d7d2;border-radius:8px;"
        "font:12.5px ui-monospace,Consolas,monospace}"
        ".pedit .padd{display:inline-flex;gap:6px;align-items:center}")
    return ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>Suricata</title>"
            f"<style>{css}</style></head><body>" + nav("/reputacion") +
            "<main><div class=cab><h1 style='margin:0'>Reputacion de IPs</h1>"
            # El buscador vive en la cabecera. Antes era una seccion entera con su titulo,
            # su tarjeta y tres lineas de ayuda, justo debajo del bloque que hace lo mismo
            # con TUS publicas: dos sitios para lo mismo y el doble de pagina para nada.
            "<form method=get action='/reputacion' class=busca>"
            f"<input name=ips size=22 value='{esc(texto)}' autocomplete=off "
            "placeholder='Buscar IP o red (CIDR)' "
            "title='Una red en CIDR se revisa con una sola peticion; hasta "
            + str(AIDB_MAX_LOTE) + " separadas por comas. Las privadas nunca se envian'>"
            "<label class=chk title='Ignora la cache y vuelve a preguntar'>"
            "<input type=checkbox name=refrescar> sin cache</label>"
            "<button class=primary type=submit>Buscar</button></form></div>"
            "<p class=sub2>Que ataques se le denuncian a una IP publica, en que listas de bloqueo "
            "esta, y &mdash;si es tuya&mdash; que abonado la esta ensuciando. "
            f"Hoy quedan <b>{quedan:,}</b> consultas por IP y <b>{quedan_red:,}</b> por red.</p>"
            + banner + atras
            + ("".join(tarjetas) if tarjetas else "")
            + ("" if res else pub_html)
            + "</main></body></html>")

def bitacora_page(embed=False):
    """Bitacora auditable: quien hizo que y cuando (logins, cuarentenas, config, usuarios, updates)."""
    esc = html.escape
    lineas = []
    try:
        with open(BITACORA_LOG, encoding="utf-8", errors="replace") as f:
            lineas = f.readlines()[-1500:]
    except OSError:
        pass
    lineas.reverse()
    def accb(a):
        au = a.upper(); c = "#8a8a86"
        if au.startswith("LOGIN"): c = "#12b886"
        elif "ELIMINA" in au or au.startswith("ERROR"): c = "#e34948"
        elif au.startswith("USUARIO"): c = "#7048e8"
        elif au.startswith("CONFIG") or au.startswith("ACTUALIZAR"): c = "#2a78d6"
        elif au.startswith("ENVIADO") or "CUARENTENA" in au or au.startswith("QUITADO") or au.startswith("AUTO"): c = "#b52a2a"
        return (f'<span style="background:{c};color:#fff;font-size:10px;font-weight:700;'
                f'padding:2px 8px;border-radius:20px">{esc(a)}</span>')
    rows = ""
    for ln in lineas:
        p = ln.rstrip("\n").split("\t")
        if len(p) < 4:
            continue
        ts, us, ip, acc = p[0], p[1], p[2], p[3]
        det = p[4] if len(p) > 4 else ""
        rows += (f"<tr data-f=\"{esc((ts + ' ' + us + ' ' + ip + ' ' + acc + ' ' + det).lower())}\">"
                 f"<td class=mono>{esc(ts)}</td><td>{esc(us) or '&mdash;'}</td><td class=mono>{esc(ip)}</td>"
                 f"<td>{accb(acc)}</td><td class=det>{esc(det)}</td></tr>")
    if rows:
        cuerpo = ("<div class=twrap><table class=ut><thead><tr><th>Fecha (Ecuador)</th><th>Usuario</th><th>IP</th>"
                  f"<th>Accion</th><th>Detalle</th></tr></thead><tbody id=logbody>{rows}</tbody></table></div>"
                  "<div class=pager><button id=lprev type=button onclick=lprev()>&larr; Anterior</button>"
                  "<span id=lpi></span>"
                  "<button id=lnext type=button onclick=lnext()>Siguiente &rarr;</button></div>")
    else:
        cuerpo = "<p class=sub2>Sin acciones registradas todavia.</p>"
    css = (
        BASE_CSS +
        "body{background:#f6f6f4}main{max-width:1000px;padding:22px 22px 40px}"
        "h1{margin:0 0 2px}.sub2{color:#6b6a66;margin:0 0 14px}"
        ".card{border:1px solid #e7e6e2;border-radius:14px;padding:20px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.03)}"
        ".uhead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}"
        ".search{width:240px;padding:8px 12px;border:1px solid #d7d6d2;border-radius:8px;font:14px system-ui}"
        ".twrap{overflow-x:auto;border:1px solid #eee;border-radius:10px}"
        ".ut{width:100%;border-collapse:collapse;font-size:13px;white-space:nowrap}"
        ".ut th{text-align:left;color:#8a8a86;font-weight:600;padding:10px 12px;background:#fafafa;border-bottom:1px solid #eee}"
        ".ut td{padding:8px 12px;border-bottom:1px solid #f2f1ee}"
        ".ut tbody tr:last-child td{border-bottom:0}.ut tbody tr:hover{background:#fafbfd}"
        ".det{white-space:normal;color:#6b6a66;font-size:12px;max-width:360px}"
        ".pager{display:flex;align-items:center;gap:12px;margin-top:12px;flex-wrap:wrap}"
        ".pager button{font:13px system-ui;padding:6px 12px;border:1px solid #d7d6d2;background:#fff;border-radius:8px;cursor:pointer;color:#0b0b0b}"
        ".pager button:hover:not(:disabled){background:#eef4fd;border-color:#2a78d6}"
        ".pager button:disabled{opacity:.4;cursor:default}.pager #lpi{font-weight:600;font-size:13px;color:#52514e}")
    script = ("<script>(function(){var SIZE=50,page=0,"
              "rows=[].slice.call(document.querySelectorAll('#logbody tr')),q='';"
              "function filtered(){return rows.filter(function(r){return (r.getAttribute('data-f')||'').indexOf(q)>=0;});}"
              "function render(){var f=filtered(),pages=Math.max(1,Math.ceil(f.length/SIZE));"
              "if(page>=pages)page=pages-1;if(page<0)page=0;"
              "rows.forEach(function(r){r.style.display='none';});"
              "f.slice(page*SIZE,page*SIZE+SIZE).forEach(function(r){r.style.display='';});"
              "var pi=document.getElementById('lpi');if(pi)pi.textContent='Pagina '+(page+1)+' de '+pages+' ('+f.length+' registros)';"
              "var pv=document.getElementById('lprev'),nx=document.getElementById('lnext');"
              "if(pv)pv.disabled=page<=0;if(nx)nx.disabled=page>=pages-1;}"
              "window.lfiltrar=function(){q=(document.getElementById('lsearch').value||'').toLowerCase();page=0;render();};"
              "window.lprev=function(){page--;render();};window.lnext=function(){page++;render();};"
              "if(rows.length)render();})();</script>")
    return ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>Suricata</title>"
            f"<style>{css}</style></head><body>" + ("" if embed else nav("/ajustes")) +
            "<main><h1>Bitacora de acciones</h1>"
            "<p class=sub2>Auditoria: quien hizo que y cuando (accesos, cuarentenas, cambios de "
            "configuracion, usuarios y actualizaciones).</p>"
            "<section class=card><div class=uhead><h2 style='font-size:15px;margin:0'>Ultimas acciones</h2>"
            "<input class=search id=lsearch placeholder='Buscar usuario, IP, accion...' oninput='lfiltrar()'></div>"
            + cuerpo + "</section></main>" + script + "</body></html>")

METRICAS_FILE = "/var/log/suricata-metricas.json"

def cargar_metricas():
    """Contadores por dia que escribe el generador (sobreviven a la poda de reportes)."""
    try:
        d = json.load(open(METRICAS_FILE, encoding="utf-8"))
        return d.get("dias") or {}
    except (OSError, ValueError, AttributeError):
        return {}

def _serie(dias, n):
    """Los ultimos n dias como lista [(fecha, datos)], rellenando los que faltan con 0.
    Rellenar importa: un dia sin datos es un dia sin datos, no un dia tranquilo, pero el
    grafico tiene que mostrar el hueco en su sitio."""
    hoy = time.time()
    out = []
    for i in range(n - 1, -1, -1):
        f = time.strftime("%Y-%m-%d", time.localtime(hoy - i * 86400))
        out.append((f, dias.get(f) or {}))
    return out

def _media(serie, clave="sal"):
    vals = [int((d or {}).get(clave, 0)) for _f, d in serie]
    return (sum(vals) / len(vals)) if vals else 0.0

def _grafico(serie, esc):
    """Barras en SVG puro (sin librerias): una por dia, con el dato en el tooltip."""
    vals = [int((d or {}).get("sal", 0)) for _f, d in serie]
    ent = [int((d or {}).get("ent", 0)) for _f, d in serie]
    mx = max(vals + ent + [1])
    n = len(serie)
    W, H, PAD = 900.0, 200.0, 24.0
    bw = (W - PAD) / max(1, n)
    barras = []
    for i, (f, d) in enumerate(serie):
        v = vals[i]
        h = (H - PAD * 2) * (v / mx) if mx else 0
        x = PAD + i * bw
        y = H - PAD - h
        col = "#2a78d6"
        if (d or {}).get("hueco"):
            col = "#c8ccd1"            # hubo un corte de datos ese dia: no se pinta como bueno
        cpes = int((d or {}).get("cpes_n", 0))
        t = f"{f}: {v:,} ataques salientes, {cpes:,} CPE distintos"
        if (d or {}).get("hueco"):
            t += " (faltan datos: el sensor estuvo parado)"
        barras.append(
            f"<g><title>{esc(t)}</title>"
            f"<rect x='{x:.1f}' y='{y:.1f}' width='{max(1.0, bw - 1.5):.1f}' height='{max(0.0, h):.1f}' "
            f"fill='{col}' rx='1.5'/></g>")
    # etiquetas: primera, mitad y ultima, para no amontonar
    etiq = []
    for i in (0, n // 2, n - 1):
        if 0 <= i < n:
            x = PAD + i * bw + bw / 2
            anc = "start" if i == 0 else ("end" if i == n - 1 else "middle")
            etiq.append(f"<text x='{x:.1f}' y='{H - 6:.1f}' text-anchor='{anc}' "
                        f"font-size='11' fill='#8a8a86'>{esc(serie[i][0][5:])}</text>")
    return (f"<svg viewBox='0 0 {W:.0f} {H:.0f}' preserveAspectRatio='none' "
            f"style='width:100%;height:200px;display:block'>"
            f"<line x1='{PAD}' y1='{H - PAD}' x2='{W}' y2='{H - PAD}' stroke='#e7e6e2'/>"
            f"<text x='2' y='{PAD}' font-size='11' fill='#8a8a86'>{mx:,}</text>"
            + "".join(barras) + "".join(etiq) + "</svg>")

def historico_page(dias_n=30):
    esc = html.escape
    dias = cargar_metricas()
    acc = cargar_acciones()
    serie = _serie(dias, dias_n)
    hay = any(d for _f, d in serie)

    # --- el numero que hay que poder enseñar ---
    hoy = int((serie[-1][1] or {}).get("sal", 0)) if serie else 0
    ayer = int((serie[-2][1] or {}).get("sal", 0)) if len(serie) > 1 else 0
    ult7 = _media(serie[-7:]) if len(serie) >= 7 else _media(serie)
    prev7 = _media(serie[-14:-7]) if len(serie) >= 14 else 0.0
    if prev7 > 0:
        var = (ult7 - prev7) / prev7 * 100.0
        col = "#3a9d5d" if var < 0 else ("#e34948" if var > 0 else "#8a8a86")
        flecha = "&darr;" if var < 0 else ("&uarr;" if var > 0 else "&rarr;")
        var_html = (f"<span style='color:{col};font-weight:700'>{flecha} {abs(var):.0f} %</span>"
                    f"<div class=kh>media de 7 dias frente a los 7 anteriores</div>")
    else:
        var_html = "<span style='color:#8a8a86'>&mdash;</span><div class=kh>hacen falta 14 dias de datos</div>"

    total = sum(int((d or {}).get("sal", 0)) for _f, d in serie)
    ruido = sum(int((d or {}).get("ruido", 0)) for _f, d in serie)
    cpes_pico = max([int((d or {}).get("cpes_n", 0)) for _f, d in serie] or [0])
    enviados = sum(int((acc.get(f) or {}).get(a, 0)) for f, _d in serie
                   for a in ("ENVIADO", "POLITICA-ENVIADO", "POLITICA-RAPIDA"))
    liberados = sum(int((acc.get(f) or {}).get(a, 0)) for f, _d in serie
                    for a in ("QUITADO", "AUTO-LIBERADO", "POLITICA-LIBERADO", "LIBERADO-FALSO-POSITIVO"))

    def _kpi(v, t, h=""):
        return (f"<div class=kpi><div class=kv>{v}</div><div class=kt>{esc(t)}</div>"
                + (f"<div class=kh>{h}</div>" if h else "") + "</div>")

    kpis = ("<div class=kpis>"
            + _kpi(f"{hoy:,}", "ataques salientes hoy", f"ayer: {ayer:,}")
            + _kpi(f"{ult7:,.0f}", "media diaria (7 dias)")
            + f"<div class=kpi><div class=kv>{var_html}</div><div class=kt>tendencia</div></div>"
            + _kpi(f"{cpes_pico:,}", "CPEs distintos atacando", "maximo en el periodo")
            + _kpi(f"{ruido:,}", "no abusivo", "P2P, chequeos de conectividad: no banean")
            + _kpi(f"{enviados:,}", "puestos en cuarentena", f"liberados: {liberados:,}")
            + "</div>")

    # --- por que atacan y por donde ---
    def _tabla(campo, titulo, tope=8):
        ac = {}
        for _f, d in serie:
            for k, v in ((d or {}).get(campo) or {}).items():
                ac[k] = ac.get(k, 0) + int(v)
        if not ac:
            return ""
        tot = sum(ac.values()) or 1
        filas = "".join(
            f"<tr><td>{esc(k)}</td><td class=num>{v:,}</td>"
            f"<td class=num>{v * 100.0 / tot:.0f}&#160;%</td></tr>"
            for k, v in sorted(ac.items(), key=lambda kv: kv[1], reverse=True)[:tope])
        return (f"<section class=card style='flex:1;min-width:280px'><h2 style='font-size:15px;margin:0 0 8px'>{esc(titulo)}</h2>"
                f"<table><thead><tr><th>{'Categoria' if campo == 'cats' else 'Puerto'}</th>"
                f"<th class=num>Alertas</th><th class=num>%</th></tr></thead><tbody>{filas}</tbody></table></section>")

    # --- Que le falta al router para poder CORTAR ------------------------------------
    # Con un espejo, Suricata no bloquea nunca: ve una copia y el paquete ya paso. El que
    # corta es el router, asi que lo primero es saber si esta en condiciones de hacerlo.
    def _diag_html(r, nom, multi):
        # de la cache que llena el hilo de fondo: consultar el router aqui dejaba la
        # pagina esperando 4 llamadas a su API
        _d = diagnostico_de(r.get("id", ""))
        cab = ("<section class=card><h2 style='font-size:15px;margin:0 0 6px'>"
               + ("Proteccion en " + esc(nom) if multi else "Proteccion en el MikroTik")
               + "</h2>")
        if not _d:
            return cab + ("<p class=hint>Todavia sin medir. El panel consulta el router "
                          "cada 10 minutos en segundo plano.</p></section>")
        if _d.get("error"):
            return cab + ("<p class=hint>No se pudo consultar el router: "
                          + esc(_d["error"]) + "</p></section>")
        checks = _d.get("checks") or []
        col = {"ok": "#3a9d5d", "falta": "#e34948", "aviso": "#e58a00"}
        ico = {"ok": "&#10003;", "falta": "&#9888;", "aviso": "&#9679;"}
        faltan = sum(1 for e, _t, _d, _f in checks if e == "falta")
        filas = "".join(
            "<div class=diagl>"
            f"<span style='color:{col.get(e, '#8a8a86')};font-weight:700'>{ico.get(e, '')}</span>"
            f"<div><b>{esc(t)}</b>"
            + (f"<div class=rn>{esc(det)}</div>" if det else "")
            + (f"<pre class=diagfix>{esc(fix)}</pre>" if fix else "")
            + "</div></div>"
            for e, t, det, fix in checks)
        return ("<section class=card>"
                + "<h2 style='font-size:15px;margin:0 0 4px'>"
                + ("Proteccion en " + esc(nom) if multi else "Proteccion en el MikroTik")
                + "</h2>"
                + "<p class=sub2 style='margin:0 0 8px'>Suricata <b>no bloquea</b>: con un espejo "
                  "ve una copia y el paquete ya paso. El que corta es el router. "
                + (f"<b style='color:#b52a2a'>Le faltan {faltan} cosas.</b>" if faltan
                   else "<b style='color:#1a7f37'>Esta en condiciones de cortar.</b>")
                + "</p>" + filas + "</section>")

    # --- Reglas de salida: de los eventos que ve el sensor a lo que hay que pegar ----
    rs = cargar_routers()
    multi = len(rs) > 1
    secc_reglas = []
    for r in (rs if multi else [None]):
        rid = r.get("id", "") if r else None
        nom = (r.get("nombre") or r.get("HOST") or rid) if r else ""
        tot, n_cpes, grupos = analisis_salida(rid)
        # se calculan UNA vez: antes se pedian dos veces cada uno (una para saber si
        # habia algo que mostrar y otra para mostrarlo)
        _conductas = analisis_conducta(rid)
        _ctls = analisis_control(rid)
        if not grupos and not _conductas and not _ctls:
            continue
        tarjetas_g = []
        for ctl in _ctls:
            filas_c = "".join(
                f"<tr><td class=mono>{esc(ip_de(k))}</td>"
                f"<td class=num>{n:,}</td><td class=num>{rg}</td></tr>"
                for k, n, rg in ctl["top"])
            tarjetas_g.append(
                "<div class=regla>"
                f"<div class=rh><b>{esc(ctl['titulo'])}</b>"
                "<span class=rp>no cuenta como abuso</span></div>"
                f"<div class=rn><b>{ctl['alertas']:,}</b> alertas de <b>{ctl['cpes']:,}</b> "
                f"CPE(s). {esc(ctl['porque'])}</div>"
                "<div class=tablewrap style='margin-top:6px'><table><thead><tr><th>CPE</th>"
                "<th class=num>Alertas</th><th class=num>Riesgo</th></tr></thead>"
                f"<tbody>{filas_c}</tbody></table></div>"
                "<details style='margin-top:6px'><summary style='cursor:pointer;font-size:12.5px'>"
                "Reglas para controlarlo</summary>"
                f"<pre style='background:#f8f9fa;border:1px solid #eaecf0;border-radius:6px;"
                f"padding:10px;overflow-x:auto;font-size:12px'>"
                f"{esc(reglas_p2p_texto(ctl['puertos']))}</pre></details></div>")
        conductas = _conductas
        for g in conductas:
            det = ", ".join("%s (%d)" % (c, n) for c, n in g["cats"][:3])
            tarjetas_g.append(
                "<div class=regla>"
                f"<div class=rh><b>{esc(g['titulo'])}</b>"
                "<span class=rp>por conducta</span>"
                f"<span class=rpct>{g['pct']:.0f} %</span></div>"
                f"<div class=rn><b>{g['alertas']:,}</b> alertas de <b>{g['cpes']:,}</b> CPE(s)"
                + (f" &mdash; {esc(det)}" if det else "") + ". " + esc(g["porque"]) + "</div>"
                "<details style='margin-top:6px'><summary style='cursor:pointer;font-size:12.5px'>"
                "Reglas para pegar</summary>"
                "<p class=hint style='margin:6px 0'>El <b>drop va desactivado</b>: mira unos dias "
                "quien cae en la address-list y actívalo cuando estes seguro. El P2P y algunos "
                "juegos abren muchas conexiones y darian falso positivo.</p>"
                f"<pre style='background:#f8f9fa;border:1px solid #eaecf0;border-radius:6px;"
                f"padding:10px;overflow-x:auto;font-size:12px'>"
                f"{esc(reglas_conducta_texto(g['clave']))}</pre></details></div>")
        for g in grupos:
            pts = ", ".join(g["puertos"])
            tarjetas_g.append(
                "<div class=regla>"
                f"<div class=rh><b>{esc(g['titulo'])}</b>"
                f"<span class=rp>{esc(pts)}/{esc(g['proto'])}</span>"
                f"<span class=rpct>{g['pct']:.0f} %</span></div>"
                f"<div class=rn><b>{g['alertas']:,}</b> alertas de <b>{g['cpes']:,}</b> CPE(s). "
                + esc(g["porque"]) + "</div>"
                + (f"<div class=rcuidado>&#9888; {esc(g['cuidado'])}</div>" if g["cuidado"] else "")
                + "</div>")
        secc_reglas.append(
            "<section class=card>"
            + (f"<h2 style='font-size:15px;margin:0 0 4px'>Reglas de salida &mdash; {esc(nom)}</h2>"
               if multi else "<h2 style='font-size:15px;margin:0 0 4px'>Reglas de salida recomendadas</h2>")
            + f"<p class=sub2 style='margin:0 0 10px'>Salidas de <b>{n_cpes:,}</b> CPEs con actividad. "
              "Cada regla dice <b>cuanto de tu abuso corta</b>, medido con lo que el sensor vio de "
              "verdad, no con una lista generica. Es lo que baja los baneos, porque actua sobre "
              "<b>todos</b> los abonados a la vez y no espera a detectar a nadie.</p>"
            + "".join(tarjetas_g)
            + "<details style='margin-top:10px'><summary style='cursor:pointer;font-weight:600;"
              "font-size:13px'>Reglas para pegar en el MikroTik</summary>"
              "<p class=hint style='margin:6px 0'>Revisa las excepciones ANTES de pegarlas: "
              "esto afecta a todos tus abonados, no a uno.</p>"
              f"<pre style='background:#f8f9fa;border:1px solid #eaecf0;border-radius:6px;"
              f"padding:10px;overflow-x:auto;font-size:12px'>{esc(reglas_salida_texto(grupos))}</pre>"
              "</details></section>")
    # --- cortar a los que nos atacan desde internet ---------------------------------
    bl = blocklist_borde()
    bl_html = ""
    if bl:
        con_feed = sum(1 for x in bl if x["fuente"])
        top = "".join(
            f"<tr><td class=mono>{esc(x['ip'])}</td><td>{esc(x['pais'])}</td>"
            f"<td class=num>{x['alertas']:,}</td><td class=num>{x['destinos']:,}</td>"
            f"<td>{esc(x['fuente'] or '')}</td></tr>" for x in bl[:10])
        bl_html = (
            "<section class=card><h2 style='font-size:15px;margin:0 0 4px'>"
            "Cortar a los que te atacan desde internet</h2>"
            f"<p class=sub2 style='margin:0 0 8px'><b>{len(bl):,}</b> IPs de internet estan "
            f"golpeando tu red"
            + (f", <b>{con_feed:,}</b> de ellas ademas fichadas en feeds de reputacion" if con_feed else "")
            + ". Cortarlas no limpia lo que ya esta infectado, pero <b>corta las infecciones "
              "nuevas</b>: el atacante de fuera es el que infecta al CPE, y el CPE infectado es "
              "el que ensucia tus publicas.</p>"
            "<div class=tablewrap><table><thead><tr><th>IP</th><th>Pais</th>"
            "<th class=num>Alertas</th><th class=num>Destinos</th><th>Feed</th></tr></thead>"
            f"<tbody>{top}</tbody></table></div>"
            + (f"<p class=hint>Las 10 peores de {len(bl):,}.</p>" if len(bl) > 10 else "")
            + "<details style='margin-top:10px'><summary style='cursor:pointer;font-weight:600;"
              "font-size:13px'>Como montarlo en el MikroTik</summary>"
              "<p class=hint style='margin:6px 0'>El router se baja la lista solo cada hora: "
              "meterle miles de entradas por la API tardaria horas. La URL solo responde a las "
              "IPs de los routers dados de alta.</p>"
              f"<pre style='background:#f8f9fa;border:1px solid #eaecf0;border-radius:6px;"
              f"padding:10px;overflow-x:auto;font-size:12px'>{esc(blocklist_reglas())}</pre>"
              "</details></section>")

    diag_html = ""
    for r in rs:
        if (r.get("HOST") or "") and r.get("ENABLED") == "1":
            diag_html += _diag_html(r, r.get("nombre") or r.get("HOST") or r.get("id", ""),
                                    len(rs) > 1)
    reglas_html = diag_html + bl_html + "".join(secc_reglas)

    sel = "".join(
        f"<a href='?d={n}' class='{'on' if n == dias_n else ''}'>{n} dias</a>"
        for n in (7, 30, 90, 365))

    vacio = ("<div class=banner style='background:#fdf0e6;color:#a15c12;border:1px solid #f2d3ad;"
             "padding:12px 14px;border-radius:8px;margin:0 0 16px;font-size:13px'>"
             "Todavia no hay historico. Los contadores empiezan a acumularse con la primera "
             "corrida del generador y la tendencia se vuelve util a partir de los 14 dias.</div>"
             if not hay else "")

    # --- reportes guardados (lo que habia antes, ahora al final) ---
    fs = sorted(glob.glob(f"{LOGDIR}/report-*.html"), key=os.path.getmtime, reverse=True)
    rows = []
    for f in fs:
        b = os.path.basename(f)
        t = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(f)))
        kb = os.path.getsize(f) // 1024
        rows.append(f'<tr><td><a href="/r/{b}">{b}</a></td><td>{t}</td><td>{kb} KB</td></tr>')
    pager = ("<div class=pager><button id=hprev type=button onclick=hprev()>&larr; Anterior</button>"
             "<span id=hpi></span>"
             "<button id=hnext type=button onclick=hnext()>Siguiente &rarr;</button></div>") if rows else ""
    script = ("<script>(function(){var SIZE=20,page=0,"
              "rows=[].slice.call(document.querySelectorAll('#hbody tr'));"
              "function render(){var pages=Math.max(1,Math.ceil(rows.length/SIZE));"
              "if(page>=pages)page=pages-1;if(page<0)page=0;"
              "rows.forEach(function(r,i){r.style.display=(i>=page*SIZE&&i<page*SIZE+SIZE)?'':'none';});"
              "var pi=document.getElementById('hpi');if(pi)pi.textContent='Pagina '+(page+1)+' de '+pages+' ('+rows.length+' reportes)';"
              "var pv=document.getElementById('hprev'),nx=document.getElementById('hnext');"
              "if(pv)pv.disabled=page<=0;if(nx)nx.disabled=page>=pages-1;}"
              "window.hprev=function(){page--;render();};window.hnext=function(){page++;render();};"
              "if(rows.length)render();})();</script>") if rows else ""
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Suricata</title><style>" + BASE_CSS +
            "main{max-width:1100px;padding:20px}a{color:#2a78d6}"
            ".kpis{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 18px}"
            ".kpi{flex:1;min-width:150px;background:#fff;border:1px solid #e7e6e2;border-radius:12px;padding:14px 16px}"
            ".kpi .kv{font-size:26px;font-weight:800;line-height:1.1;color:#33322f}"
            ".kpi .kt{font-size:12.5px;color:#52514e;margin-top:4px}"
            ".kpi .kh{font-size:11.5px;color:#8a8a86;margin-top:2px}"
            ".rango{display:flex;gap:8px;margin:0 0 12px;flex-wrap:wrap}"
            ".rango a{font:13px system-ui;padding:5px 12px;border:1px solid #d7d6d2;border-radius:20px;"
            "text-decoration:none;color:#52514e;background:#fff}"
            ".rango a.on{background:#2a78d6;border-color:#2a78d6;color:#fff;font-weight:600}"
            ".doscol{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0;align-items:flex-start}"
            ".doscol table{table-layout:fixed;width:100%}"
            ".doscol td:first-child,.doscol th:first-child{word-break:break-word;line-height:1.35}"
            ".doscol .num{text-align:right;white-space:nowrap;width:74px}"
            ".doscol td,.doscol th{vertical-align:top;padding:6px 8px}"
            ".regla{border-top:1px solid #f0efec;padding:10px 0}"
            ".regla .rh{display:flex;align-items:center;gap:10px;flex-wrap:wrap}"
            ".regla .rp{font:12px ui-monospace,Consolas,monospace;background:#f1f1ef;"
            "border:1px solid #e0dfda;border-radius:5px;padding:1px 7px}"
            ".regla .rpct{margin-left:auto;font-weight:800;color:#2a78d6;font-size:15px}"
            ".regla .rn{font-size:13px;color:#52514e;margin-top:4px}"
            ".regla .rcuidado{font-size:12.5px;color:#a15c12;margin-top:4px}"
            ".diagl{display:flex;gap:10px;align-items:flex-start;border-top:1px solid #f0efec;"
            "padding:9px 0;font-size:13px}"
            ".diagfix{background:#f8f9fa;border:1px solid #eaecf0;border-radius:6px;"
            "padding:8px 10px;margin:6px 0 0;overflow-x:auto;font-size:12px;white-space:pre-wrap}"
            ".pager{display:flex;align-items:center;gap:12px;margin-top:14px;flex-wrap:wrap}"
            ".pager button{font:13px system-ui;padding:6px 12px;border:1px solid #d7d6d2;background:#fff;border-radius:8px;cursor:pointer}"
            ".pager button:hover:not(:disabled){background:#eef4fd;border-color:#2a78d6}"
            ".pager button:disabled{opacity:.4;cursor:default}.pager #hpi{font-weight:600;font-size:13px;color:#52514e}"
            "</style></head><body>"
            "<main><h1>Abuso saliente</h1>"
            "<p class=sub2 style='margin:0 0 14px'>Cuantos ataques salen de tu red hacia internet, dia a dia. "
            "Es el numero que hace que las <b>IPs publicas acaben en listas negras</b>, y el unico que sirve "
            "para demostrar que la limpieza funciona: los reportes HTML se borran a los 3 dias, esto no.</p>"
            + vacio
            + f"<div class=rango>{sel}</div>"
            + kpis
            + "<section class=card><h2 style='font-size:15px;margin:0 0 4px'>Ataques salientes por dia</h2>"
            + f"<p class=sub2 style='margin:0 0 8px'>{total:,} en los ultimos {dias_n} dias. "
              "Las barras grises son dias con datos incompletos (el sensor estuvo parado).</p>"
            + _grafico(serie, esc) + "</section>"
            + f"<div class=doscol>{_tabla('cats', 'Por que atacan')}{_tabla('puertos', 'Por que puerto salen')}</div>"
            + reglas_html
            + "<h2 style='font-size:16px;margin:22px 0 4px'>Reportes guardados</h2>"
            "<p style='color:#8a8a86;font-size:13px;margin:0 0 8px'>Instantaneas de los ultimos 3 dias "
            "(una por hora, mas la mas reciente). La tendencia de arriba NO depende de ellas.</p>"
            "<table><tbody id=hbody>"
            + ("".join(rows) or "<tr><td>Sin reportes todavia.</td></tr>")
            + "</tbody></table>" + pager + script + "</main></body></html>")
    return wrap(body, refresh=False, active="/historico")

def _salud_html():
    """Tarjeta de salud del sensor: responde de un vistazo si esta VIENDO trafico, con
    perdidas, si el reporte esta fresco y si los servicios estan vivos. Autocontenida."""
    esc = html.escape
    s = estado_sensor()
    css = ("<style>.saludc{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 14px;overflow:hidden}"
           ".saludh{display:flex;align-items:center;gap:10px;padding:12px 15px;font-size:15px}"
           ".saludh .sdot{width:12px;height:12px;border-radius:50%;flex:none}"
           ".saludh .verde{background:#2ea44f;box-shadow:0 0 0 4px rgba(46,164,79,.18)}"
           ".saludh .ambar{background:#e58a00;box-shadow:0 0 0 4px rgba(229,138,0,.18)}"
           ".saludh .rojo{background:#e34948;box-shadow:0 0 0 4px rgba(227,73,72,.18)}"
           ".saludh .gris{background:#9a9a95}"
           ".saludh b{font-size:15px}.saludh .stit{color:#52514e;font-weight:600}"
           ".saludb{display:flex;flex-wrap:wrap;gap:8px;padding:0 15px 13px}"
           ".schip{font-size:12.5px;background:#f4f4f2;border:1px solid #e7e6e2;border-radius:20px;padding:4px 11px;color:#33322f}"
           ".schip.bad{background:#fdecec;border-color:#f3c4c4;color:#b52a2a;font-weight:700}"
           ".schip.warn{background:#fff7ed;border-color:#f2d3ad;color:#7a4a12;font-weight:700}"
           "</style>")
    if not s:
        return css + ("<div class='saludc'><div class='saludh'><span class='sdot gris'></span>"
                      "<b>Salud del sensor</b><span class='stit'>&mdash; aun sin medicion (vuelve en ~1 min)</span>"
                      "</div></div>")
    niv = s.get("nivel", "warn")
    dot = {"ok": "verde", "warn": "ambar", "down": "rojo"}.get(niv, "ambar")
    chips = []
    chips.append(("Suricata activo" if s.get("suricata") else "Suricata DETENIDO",
                  "" if s.get("suricata") else "bad"))
    if s.get("tzsp_mode"):
        chips.append(("Receptor TZSP activo" if s.get("tzsp") else "Receptor TZSP CAIDO",
                      "" if s.get("tzsp") else "bad"))
    if s.get("ifaces"):
        chips.append(("Captura: " + ", ".join(s["ifaces"]), ""))
    pps = s.get("pps")
    if pps is not None:
        chips.append((f"Trafico: {pps:,.0f} pkts/s", "" if pps >= 1 else "warn"))
    dr = s.get("drop_ratio") or 0
    chips.append((f"Perdidas: {dr*100:.2f}%", "warn" if dr > 0.02 else ""))
    ed = s.get("reporte_edad")
    if ed is not None:
        chips.append((f"Reporte: hace {ed//60} min", "warn" if ed > 2 * REFRESH_SECS else ""))
    hace = int(time.time() - s.get("ts", 0))
    chip_html = "".join(f"<span class='schip {c}'>{esc(t)}</span>" for t, c in chips)
    return css + (f"<div class='saludc'><div class='saludh'><span class='sdot {dot}'></span>"
                  f"<b>{esc(s.get('titulo',''))}</b>"
                  f"<span class='stit'>&mdash; medido hace {hace}s</span></div>"
                  f"<div class='saludb'>{chip_html}</div></div>")

def ficha_page(ip, embed=False):
    """Ficha de EVIDENCIA por CPE: por que tiene ese riesgo (alertas, coincidencias de
    reputacion con su fuente/CIDR/vigencia, corroboracion independiente y decision)."""
    esc = html.escape
    ip = (ip or "").strip()
    try:
        data = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
    except Exception:
        data = {}
    c = None; categoria = ""
    for key, lbl in (("candidatos", "Infeccion CnC"), ("dns_candidatos", "DNS sospechoso")):
        for x in data.get(key, []):
            if x.get("ip") == ip:
                c = x; categoria = lbl; break
        if c:
            break
    env = cargar_enviados(MK_SENT); envd = cargar_enviados(MK_SENT_DNS)
    ent = env.get(ip) or envd.get(ip)
    en_lista = bool(ent)
    def _fecha(t):
        return time.strftime("%d/%m/%Y %H:%M", time.localtime(t)) if t else "&mdash;"
    if not c and not en_lista:
        cuerpo = "<p class=sub2>No hay evidencia para <b>" + esc(ip) + "</b> en la ventana actual.</p>"
    else:
        c = c or (ent or {}).get("motivo", {}) or {}
        conf = c.get("confianza", "")
        conf_b = ("<span class='cfb alta'>Alta confianza</span>" if conf == "alta"
                  else "<span class='cfb sosp'>Sospechoso</span>" if conf == "sospechoso" else "")
        # Actividad (de las pruebas)
        act = []
        for p in (c.get("pruebas") or [])[:8]:
            if p.get("tipo") == "dns":
                act.append("Consulta DNS a <span class=mono>" + esc(p.get("rrname") or p.get("dst", "")) + "</span>")
            else:
                dst = esc(p.get("dst", "")) + ((":" + esc(str(p.get("dport")))) if p.get("dport") else "")
                act.append("Comunicacion a <span class=mono>" + dst + "</span>")
        act_html = "<br>".join(dict.fromkeys(act)) or "&mdash;"
        # Alertas
        al = ""
        for p in (c.get("pruebas") or [])[:8]:
            al += (f"<tr><td class=mono>{esc(str(p.get('sid') or '-'))}</td>"
                   f"<td class=mono>{esc(str(p.get('rev') or '-'))}</td>"
                   f"<td>{esc(p.get('sig', ''))}</td>"
                   f"<td class=mono>{_fecha(p.get('ts', 0))}</td>"
                   f"<td class=mono>{esc(str(p.get('flow_id') or '-'))}</td></tr>")
        al = (f"<table class=fichat><thead><tr><th>SID</th><th>rev</th><th>Firma</th>"
              f"<th>Fecha</th><th>flow_id</th></tr></thead><tbody>{al}</tbody></table>") if al else "&mdash; (sin alertas guardadas)"
        # Coincidencia + Vigencia (reputacion)
        rep = c.get("reputacion") or []
        if rep:
            co = ""; vg = ""
            for r in rep:
                co += (f"<tr><td class=mono>{esc(r.get('cidr') or r.get('ip', ''))}</td>"
                       f"<td>{esc(r.get('fuente', ''))}</td><td>{esc(r.get('categoria', ''))}</td></tr>")
                vg += (f"<tr><td>{esc(r.get('fuente', ''))}</td><td class=mono>{_fecha(r.get('fetched_valid', 0))}</td>"
                       f"<td class=mono>{_fecha(r.get('expira', 0))}</td>"
                       f"<td>{'vigente' if r.get('vigente') else 'CADUCADA'}</td></tr>")
            coincidencia = f"<table class=fichat><thead><tr><th>IP/CIDR</th><th>Fuente</th><th>Categoria</th></tr></thead><tbody>{co}</tbody></table>"
            vigencia = f"<table class=fichat><thead><tr><th>Fuente</th><th>Ultima valida</th><th>Caduca</th><th>Estado</th></tr></thead><tbody>{vg}</tbody></table>"
        else:
            coincidencia = "&mdash; (ningun destino en listas de reputacion)"
            vigencia = "&mdash;"
        # Corroboracion
        evs = c.get("evidencias") or []
        corr = ("<ul class=evlist>" + "".join(f"<li>{esc(e)}</li>" for e in evs) + "</ul>"
                + f"<div class=rowmeta>Confianza: <b>{esc(conf or '-')}</b> ({len(evs)} evidencia(s) independiente(s))</div>") \
            if evs else "<div class=rowmeta>Sin evidencia independiente (solo repeticion) &rarr; vigilar</div>"
        # Decision
        if en_lista:
            decision = f"<b>En cuarentena</b> desde {_fecha((ent or {}).get('cuando', 0))} (lista del MikroTik)"
        elif conf == "alta":
            decision = "<b>Investigar / poner en cuarentena</b> (alta confianza)"
        else:
            decision = "<b>Vigilar</b> (sospechoso; falta corroboracion independiente)"
        def _row(k, v):
            return f"<tr><th>{k}</th><td>{v}</td></tr>"
        ab = abonado_de(ip)
        _abinfo = cargar_abonados()
        _snap = time.strftime("%d/%m %H:%M", time.localtime(_abinfo.get("ts", 0))) if _abinfo.get("ts") else "—"
        # Punto-en-el-tiempo: quien tenia esta IP cuando ocurrio el evento
        ev_ts = 0
        for p in (c.get("pruebas") or []):
            try: ev_ts = max(ev_ts, int(p.get("ts") or 0))
            except (TypeError, ValueError): pass
        if not ev_ts and en_lista:
            try: ev_ts = int((ent or {}).get("cuando", 0) or 0)
            except (TypeError, ValueError): ev_ts = 0
        _hist = historial_abonado(ip, ev_ts) if ev_ts else {}
        pit = ""
        if _hist:
            _et = time.strftime("%d/%m %H:%M", time.localtime(ev_ts))
            _dif = (_hist.get("nombre", "") != (ab.get("nombre", "") if ab else "")) or \
                   (_hist.get("mac", "") != (ab.get("mac", "") if ab else ""))
            if _dif:
                pit = ("<div class=rowmeta style='color:#7a4a12'>&#9888; En el momento del evento (" + _et +
                       ") esta IP la tenia <b>" + esc(_hist.get("nombre") or "(sin nombre)") + "</b> (" +
                       esc(_hist.get("tipo", "")) + ", MAC " + esc(_hist.get("mac", "") or "—") +
                       ") &mdash; distinta de la asignacion actual</div>")
            else:
                pit = "<div class=rowmeta>Misma asignacion en el momento del evento (" + _et + ")</div>"
        if ab:
            cliente = (f"<b>{esc(ab.get('nombre') or '(sin nombre)')}</b> "
                       f"<span class=cfb style='background:#e7f0fb;color:#1c5cab'>{esc(ab.get('tipo', ''))}</span>"
                       f"<div class=rowmeta>IP {esc(ip)} · MAC {esc(ab.get('mac', '') or '—')}"
                       f"{(' · ' + esc(ab.get('extra', ''))) if ab.get('extra') else ''}"
                       f" · asignacion actual (snapshot {_snap})</div>")
        elif _abinfo.get("mapa") is not None:
            cliente = f"{esc(ip)} <span class=rowmeta>sin asignacion PPPoE/DHCP conocida (snapshot {_snap})</span>"
        else:
            cliente = f"{esc(ip)} <span class=rowmeta>configura el MikroTik en Ajustes para ver el abonado</span>"
        cliente += pit
        cuerpo = (
            f"<div class=fichah><h2 style='margin:0'>{esc(ip)}</h2>{conf_b}"
            f"<span class=sub2 style='margin-left:auto'>{esc(categoria)} · riesgo {c.get('riesgo', '')}</span></div>"
            "<table class=ficha>"
            + _row("Cliente", cliente)
            + _row("Actividad", act_html)
            + _row("Alerta", al)
            + _row("Coincidencia", coincidencia)
            + _row("Vigencia", vigencia)
            + _row("Corroboracion", corr)
            + _row("Decision", decision)
            + "</table>")
    css = (BASE_CSS +
           "main{max-width:820px;padding:18px 20px 40px}h1{font-size:19px;margin:0 0 10px}.sub2{color:#6b6a66}"
           ".fichah{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 12px}"
           ".ficha{width:100%;border-collapse:collapse}"
           ".ficha th{text-align:left;vertical-align:top;width:130px;color:#52514e;font-weight:700;padding:10px 12px;border-top:1px solid #eee;background:#faf9f6}"
           ".ficha td{padding:10px 12px;border-top:1px solid #eee}"
           ".fichat{width:100%;border-collapse:collapse;font-size:12.5px;margin:2px 0}"
           ".fichat th{background:#f4f4f2;text-align:left;padding:6px 8px;color:#52514e;border-bottom:1px solid #e7e6e2}"
           ".fichat td{padding:6px 8px;border-bottom:1px solid #f2f1ee;vertical-align:top}"
           ".cfb{font-size:11px;font-weight:800;padding:2px 9px;border-radius:20px}"
           ".cfb.alta{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4}"
           ".cfb.sosp{background:#fff7ed;color:#7a4a12;border:1px solid #f2d3ad}"
           ".evlist{margin:2px 0;padding-left:16px;color:#245c3c}.rowmeta{font-size:12px;color:#6b6a66;margin-top:4px}"
           "@media(max-width:640px){"
           "main{padding:14px 14px 32px}"
           # la ficha (label | valor) se apila: la etiqueta pasa a encabezado de fila
           ".ficha tr{display:block;border-top:1px solid #eee}"
           ".ficha th{display:block;width:auto;background:transparent;border-top:0;padding:8px 0 0}"
           ".ficha td{display:block;padding:2px 0 10px;border-top:0}"
           # tablas internas (Alertas, Coincidencia, Vigencia) scrollean en vez de desbordar
           ".ficha td>.fichat{min-width:520px}"
           ".ficha td{overflow-x:auto}"
           "}")
    return ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>Suricata</title>"
            f"<style>{css}</style></head><body>" + ("" if embed else nav("/cuarentena")) +
            "<main><h1>Ficha de evidencia</h1>" + cuerpo + "</main></body></html>")

def cuarentena_page(msg="", es_admin=False):
    """Cuarentena: CPEs INFECTADOS CONFIRMADOS. Si el MikroTik esta configurado y HABILITADO
    y quien mira es admin, aparece el boton Enviar (a la address-list) / Quitar. Si no, dry-run.
    La lista de candidatos la calcula el reporte (cuarentena.json)."""
    esc = html.escape
    data, gen, vmin, cand = {}, 0, 0, []
    try:
        data = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8"))
        gen = data.get("generado", 0); vmin = data.get("ventana_min", 0)
        cand = data.get("candidatos", [])
    except Exception:
        pass
    dns_cand = data.get("dns_candidatos", []); umbral_dns = data.get("umbral_dns", 3)
    edad = f"{int((time.time()-gen)//60)} min" if gen else "-"
    m = cargar_mk(); en = m.get("ENABLED") == "1"; conf_ok = mk_configurado()
    activo = en and conf_ok
    enviados = cargar_enviados(MK_SENT)
    enviados_dns = cargar_enviados(MK_SENT_DNS)
    def _col(b):
        return {"ALTO": "#e34948", "MEDIO": "#e58a00"}.get(b, "#3a9d5d")

    def _cli(ip, rid=""):
        # con varios nodos hace falta decir en CUAL: la misma IP puede ser de dos clientes
        a = abonado_de(ip, rid)
        if a and a.get("nombre"):
            return f"<div class='rowmeta'>{esc(a['nombre'])} · {esc(a.get('tipo', ''))}</div>"
        return ""

    def _rev(mm):
        """Meta legible: cuando se reviso por ultima vez, si sigue activo y si esta en el router."""
        p = []
        le = mm.get("last_eval")
        if le:
            p.append("revisado " + time.strftime("%d/%m %H:%M", time.localtime(le)))
        if "sigue" in mm:
            p.append("sigue activo" if mm.get("sigue") else "sin actividad reciente")
        if mm.get("en_router"):
            p.append("en router ✓")
        return " · ".join(p)

    def _mot_txt(mm):
        """Por que se bloqueo, a partir del motivo guardado al enviar (sobrevive aunque el CPE calle)."""
        mt = mm.get("motivo") or {}
        if not mt:
            return ""
        tp = {"infeccion": "Infeccion CnC", "dns": "DNS malicioso",
              "politica": "Politica por riesgo"}.get(mt.get("tipo"), "Bloqueo")
        fw = esc((mt.get("firma") or "")[:70])
        # el desglose ya viene como HTML corto del generador (Severidad x/30 · Destinos...)
        des = mt.get("desglose") or ""
        extra = f"<br><span class='fw'>{des}</span>" if des else ""
        return (f"<b>{tp}</b> riesgo {esc(str(mt.get('score', '')))} {esc(mt.get('banda', ''))}<br>"
                f"<span class='fw'>{esc(mt.get('conteo', ''))}{(' · ' + fw) if fw else ''}</span>{extra}")

    def _conf_badge(c):
        cf = c.get("confianza")
        if cf == "alta":
            return "<span class='cfb alta'>Alta confianza</span>"
        if cf == "sospechoso":
            return "<span class='cfb sosp'>Sospechoso</span>"
        return ""

    def _ev_html(c):
        ev = c.get("evidencias") or []
        if ev:
            return "<ul class='evlist'>" + "".join(f"<li>{esc(e)}</li>" for e in ev) + "</ul>"
        return "<div class='rowmeta'>sin evidencia independiente (solo repeticion)</div>"

    def _seccion(titulo, sub, candidatos, env_map, pref, lista_name, cnt_key, cnt_lbl, fir_key, vacio):
        """Arma una seccion (titulo + tabla + boton 'enviar todos') para una categoria."""
        # La identidad de un CPE es (router, IP), que es como esta guardado el registro de
        # enviados. Buscar por la IP pelada dejaba "sin enviar" a CPEs ya bloqueados en
        # cuanto el sensor vigila mas de un MikroTik.
        _k = lambda c: clave_cpe(c.get("ip", ""), c.get("router", ""))
        pend = [c for c in candidatos if _k(c) not in env_map]
        def _acc(c):
            ip = c.get("ip", ""); k = _k(c)
            if k in env_map:
                cuando = time.strftime("%d/%m %H:%M", time.localtime(env_map[k].get("cuando", 0)))
                quitar = (f"<form method=post action='/{pref}/quitar' style='display:inline'>"
                          f"<input type=hidden name=ip value='{esc(k)}'>"
                          f"<button class='qbtn quit' onclick=\"return confirm('Quitar {esc(ip)} de la lista {esc(lista_name)}?')\">Quitar</button></form>"
                          ) if es_admin else ""
                meta = _rev(env_map[k])
                meta_html = f"<div class='rowmeta'>desde {cuando}{(' · ' + meta) if meta else ''}</div>"
                return f"<span class='enq' title='En {esc(lista_name)} desde {cuando}'>En lista</span> {quitar}{meta_html}"
            if es_admin and activo:
                return (f"<form method=post action='/{pref}/enviar' style='display:inline'>"
                        f"<input type=hidden name=ip value='{esc(k)}'><input type=hidden name=score value='{c.get('riesgo',0)}'>"
                        f"<button class='qbtn send' onclick=\"return confirm('Enviar {esc(ip)} a la lista {esc(lista_name)} del MikroTik?')\">Enviar</button></form>")
            return "<span class='dry' title='Configura y habilita el MikroTik en Ajustes para activar el envio'>solo sugerencia</span>"
        filas = "".join(
            f"<tr><td data-label='CPE' class='mono ipx'>{esc(c.get('ip',''))}"
            f"{_chip_nodo_panel(_k(c))}{_cli(c.get('ip',''))}</td>"
            f"<td data-label='Riesgo'><span class='rb' style='background:{_col(c.get('banda',''))}'>{c.get('riesgo',0)} · {esc(c.get('banda',''))}</span>"
            f"<div style='margin-top:4px'>{_conf_badge(c)}</div></td>"
            f"<td data-label='Motivo' class='mot'>{c.get(cnt_key,0)} {cnt_lbl} · {c.get(fir_key,0)} firma(s)<br>"
            f"<span class='fw'>{esc((c.get('firma','') or '')[:70])}</span>{_ev_html(c)}"
            f"<button type=button class=evbtn onclick=\"verFicha('{esc(c.get('ip',''))}')\">Ver evidencia</button></td>"
            f"<td data-label='Destinos' class='num'>{c.get('destinos',0)}</td><td data-label='Puertos' class='num'>{c.get('puertos',0)}</td>"
            f"<td data-label='Alertas' class='num'>{c.get('total_alertas',0):,}</td>"
            f"<td data-label='Accion'>{_acc(c)}</td></tr>" for c in candidatos)
        if not filas:
            filas = f"<tr><td colspan=7 class='muted' style='padding:18px;text-align:center'>{vacio}</td></tr>"
        # 'Enviar todos' solo actua sobre ALTA CONFIANZA (evidencia independiente), no sospechosos
        pend_alta = [c for c in pend if c.get("confianza") == "alta"]
        btn = ""
        if es_admin and activo and pend_alta:
            btn = (f"<form method=post action='/{pref}/enviar-todos' style='display:inline;margin-left:auto'>"
                   f"<button class='qbtn send' onclick=\"return confirm('Enviar los {len(pend_alta)} CPE de ALTA CONFIANZA al MikroTik?')\">"
                   f"&#9888; Enviar alta confianza ({len(pend_alta)})</button></form>")
        return (f"<div class='seccion'><div class='shead'><div><h2>{titulo}</h2>"
                f"<p class='sub'>{sub} · {len(candidatos)} candidato(s).</p></div>{btn}</div>"
                "<div class='card'><table><thead><tr>"
                "<th>CPE (IP origen)</th><th>Riesgo / confianza</th><th>Motivo y evidencia</th>"
                "<th class='num'>Destinos</th><th class='num'>Puertos</th><th class='num'>Alertas</th><th>Accion</th>"
                f"</tr></thead><tbody>{filas}</tbody></table></div></div>")

    sec_inf = _seccion("Infectados (malware/CnC)",
                       "<b>Alta confianza</b> = ≥2 evidencias independientes (firmas distintas, reputacion del "
                       f"destino, persistencia, campana, DNS) → investigar/cuarentena. <b>Sospechoso</b> = solo "
                       f"repeticion → vigilar. Lista <code>{esc(m.get('LIST',''))}</code>",
                       cand, enviados, "cuarentena", m.get("LIST", ""), "alertas_cnc", "alertas CnC", "firmas_cnc",
                       "Sin CPEs con alertas de CnC en la ventana.")
    sec_dns = _seccion("DNS sospechoso (consultan dominios de botnet/C2)",
                       f"Consultas DNS a dominios maliciosos (&ge;{umbral_dns} alertas DNS o &ge;2 firmas) &rarr; lista <code>{esc(m.get('LIST_DNS',''))}</code> (otro trato)",
                       dns_cand, enviados_dns, "cuarentena/dns", m.get("LIST_DNS", ""), "alertas_dns", "alertas DNS", "firmas_dns",
                       "Sin CPEs consultando dominios maliciosos en la ventana.")
    # --- Destinos de mala reputacion: cortar A DONDE van, no a quien va ---------------
    # Solo IPs PUBLICAS: una privada aqui seria de tu propia red y bloquearla como destino
    # dejaria a tus abonados sin verse entre si.
    _dst = destinos_malos()
    if _dst:
        _pend = [x for x in _dst if not x["enviado"]]
        _ya = [x for x in _dst if x["enviado"]]
        def _fila_dst(x):
            acc = ""
            if es_admin and activo:
                if x["enviado"]:
                    acc = ("<form method=post action='/cuarentena/destino/quitar' style='display:inline'>"
                           f"<input type=hidden name=ip value='{esc(x['ip'])}'>"
                           "<button class='qbtn quit'>Desbloquear</button></form>")
                else:
                    acc = ("<form method=post action='/cuarentena/destino/bloquear' style='display:inline'>"
                           f"<input type=hidden name=ip value='{esc(x['ip'])}'>"
                           f"<button class='qbtn send' onclick=\"return confirm('Bloquear la salida hacia "
                           f"{esc(x['ip'])} en TODOS los nodos?')\">Bloquear</button></form>")
            elif not activo:
                acc = "<span class=dry>solo sugerencia</span>"
            marca = ("<span class='enq'>Bloqueado</span> " if x["enviado"] else "")
            return (f"<tr><td data-label='Destino' class='mono ipx'>{esc(x['ip'])}"
                    + (f" <span class=hint>{esc(x['pais'])}</span>" if x["pais"] else "") + "</td>"
                    f"<td data-label='Por que'><b>{esc(x['categoria'] or 'fichada')}</b>"
                    f"<div class=rowmeta>{esc(x['fuente'])}"
                    + (f" &middot; {esc(x['firma'][:60])}" if x["firma"] else "") + "</div></td>"
                    f"<td data-label='CPEs' class='num'>{x['cpes']:,}</td>"
                    f"<td data-label='Alertas' class='num'>{x['alertas']:,}</td>"
                    f"<td data-label='Accion'>{marca}{acc}</td></tr>")
        _filas_dst = "".join(_fila_dst(x) for x in (_pend + _ya))
        _reglas_dst = destinos_reglas(m.get("LIST_DST", "suricata-destinos-malos"))
        _n_feed = len(destinos_feed())
        if _n_feed:
            # que el router se baje la lista solo: son miles de entradas y meterlas
            # una a una por la API tardaria horas
            _reglas_dst += (
                "\n\n# --- bloqueo PREVENTIVO: que el router se baje los feeds solo ---\n"
                "/system scheduler\n"
                'add name=suricata-destinos interval=1h on-event="/tool fetch '
                'url=\\\\"http://IP_DEL_SENSOR:PUERTO/destinos.rsc\\\\" '
                'dst-path=destinos.rsc; :delay 5s; /import destinos.rsc" '
                'comment="Suricata: destinos de mala reputacion"')
        sec_dst = (
            "<div class=seccion><div class=shead><div>"
            "<h2>Destinos de mala reputacion</h2>"
            "<p class=sub>Infraestructura fichada a la que <b>tus CPEs estan saliendo</b>: "
            "servidores de control de botnets, distribucion de malware, redes secuestradas. "
            "Cortar el destino deja al equipo infectado <b>sin ordenes</b>, y vale para todos "
            "los abonados a la vez sin tener que identificar a ninguno. Solo se listan IPs "
            f"<b>publicas</b>. {len(_pend):,} sin bloquear, {len(_ya):,} ya bloqueadas.</p>"
            "</div></div>"
            "<div class=card><table><thead><tr><th>Destino</th><th>Por que</th>"
            "<th class=num>CPEs</th><th class=num>Alertas</th><th>Accion</th>"
            f"</tr></thead><tbody>{_filas_dst}</tbody></table></div>"
            + ("<div style='background:#eef4fd;border:1px solid #cfe0f6;border-radius:8px;"
               "padding:10px 12px;margin-top:10px;font-size:13px'>"
               f"<b>Bloqueo preventivo: {_n_feed:,} destinos</b> de los feeds de alta confianza "
               "(C2 activo e infraestructura delictiva). Es <b>mejor que lo de arriba</b>: corta "
               "la salida <b>antes</b> de que ningun abonado llegue, asi el equipo infectado ni "
               "siquiera consigue instrucciones. No entran los feeds de \"esta IP escaneo a "
               "alguien\": esa misma IP puede alojar una web que un abonado visita."
               "</div>" if _n_feed else "")
            + "<details style='margin-top:8px'><summary style='cursor:pointer;font-size:13px;"
            "font-weight:600'>Regla que hace falta en el MikroTik</summary>"
            "<p class=hint style='margin:6px 0'>Sin una regla que use esa address-list, el "
            "panel dice 'bloqueado' y no se bloquea nada.</p>"
            f"<pre style='background:#f8f9fa;border:1px solid #eaecf0;border-radius:6px;"
            f"padding:10px;overflow-x:auto;font-size:12px'>{esc(_reglas_dst)}</pre>"
            "</details></div>")
    else:
        sec_dst = ""

    # --- Enviados manualmente (desde Top origenes): IPs en la lista que NO son candidatos ---
    def _fila_manual(clave, mm, pref, lista):
        # 'clave' es la identidad del CPE: con varios nodos "router|IP". Se muestra la IP
        # y se manda la clave entera, para liberar en el router que corresponde.
        ip = ip_de(clave)
        _cuando_ts = mm.get("cuando", 0)
        cuando = time.strftime("%d/%m %H:%M", time.localtime(_cuando_ts))
        _rev_ts = mm.get("last_eval", 0)
        quitar = (f"<form method=post action='/{pref}/quitar' style='display:inline'>"
                  f"<input type=hidden name=ip value='{esc(clave)}'>"
                  f"<button class='qbtn quit' onclick=\"return confirm('Quitar {esc(ip)} de {esc(lista)}?')\">Quitar</button></form>"
                  ) if es_admin else ""
        # sin motivo guardado: decir de donde vino en vez de afirmar "manual", que era
        # falso justo para los que envio la politica (la fila mostraba Por=politica y
        # Motivo=manual a la vez)
        _por = (mm.get("por") or "").lower()
        _sin = ("enviado por politica automatica (sin detalle guardado)"
                if _por.startswith("politica") else
                "manual / sin motivo registrado" if _por not in ("", "?") else
                "sin motivo registrado")
        mot = _mot_txt(mm) or f"<span class='muted'>{esc(_sin)}</span>"
        # token "lista|identidad": el quitado masivo necesita saber de CUAL address-list
        # sacarla y, con varios nodos, de que router
        _tok = ("dns|" if pref.endswith("/dns") else "cuar|") + clave
        marca = (f"<td data-label='Seleccionar' class='selc'><input type=checkbox class=selm "
                 f"value='{esc(_tok)}' aria-label='Seleccionar {esc(ip)}'></td>") if es_admin else ""
        return (f"<tr>{marca}<td data-label='CPE' class='mono ipx'>{esc(ip)}"
                f"{_chip_nodo_panel(clave)}{_cli(ip, rid_de(clave))}</td>"
                f"<td data-label='Lista' class='mono'>{esc(lista)}</td>"
                f"<td data-label='Motivo' class='mot'>{mot}</td><td data-label='Por'>{esc(mm.get('por','?'))}</td>"
                f"<td data-label='Enviado' class='mono' data-sort='{int(_cuando_ts)}'>{cuando}</td>"
                f"<td data-label='Ultima revision' class='rowmeta' style='margin:0' data-sort='{int(_rev_ts)}'>{_rev(mm) or '&mdash;'}</td>"
                f"<td data-label='Accion'>{quitar}</td></tr>")
    _ci = {c.get("ip") for c in cand}; _cd = {c.get("ip") for c in dns_cand}
    manual_rows = "".join(_fila_manual(ip, mm, "cuarentena", m.get("LIST", "")) for ip, mm in enviados.items() if ip not in _ci)
    manual_rows += "".join(_fila_manual(ip, mm, "cuarentena/dns", m.get("LIST_DNS", "")) for ip, mm in enviados_dns.items() if ip not in _cd)
    if manual_rows:
        # --- quitado masivo: casillas + boton que abre un modal de confirmacion ---
        selth = ("<th data-nosort class=selc><input type=checkbox id=selall "
                 "aria-label='Seleccionar todas'></th>") if es_admin else ""
        barra = ("<div class=masivo><button type=button id=bmasivo class='qbtn quit' disabled>"
                 "Quitar seleccionados <span id=nmasivo>(0)</span></button>"
                 "<span class=mashint>Marca las casillas para sacar varias IPs de una vez</span></div>"
                 ) if es_admin else ""
        modal = ("<div id=mmasivo class=masov onclick=\"if(event.target===this)masCerrar()\">"
                 "<div class=masbox><h3>Quitar de la lista</h3>"
                 "<p class=massub id=massub>Se sacaran del MikroTik estas IPs. Es <b>reversible</b>: puedes volver "
                 "a enviarlas cuando quieras.</p>"
                 "<div id=masprog class=masprog><div id=masbar class=masbar></div></div>"
                 "<ul id=maslista class=maslist></ul>"
                 "<form id=fmasivo method=post action='/cuarentena/quitar-varios'>"
                 "<div id=mascampos></div><div class=masacts>"
                 "<button type=button class=masno id=masno onclick=masCerrar()>Cancelar</button>"
                 "<button type=submit class=massi id=massi>Quitar</button></div></form></div></div>"
                 ) if es_admin else ""
        sec_manual = ("<div class='seccion'><div class='shead'><div><h2>Enviados manualmente</h2>"
                      "<p class='sub'>IPs que pusiste a mano (p.ej. desde Top origenes) y no son candidatos actuales. "
                      "Con auto-mantener <b>no</b> se liberan solas: quitalas tu aqui cuando quieras.</p></div></div>"
                      + barra +
                      "<div class='card'><table class='orden'><thead><tr>" + selth +
                      "<th>CPE (IP origen)</th><th>Lista</th>"
                      "<th>Motivo (por que se bloqueo)</th><th>Por</th><th>Enviado</th>"
                      "<th>Ultima revision</th><th data-nosort>Accion</th></tr></thead>"
                      f"<tbody>{manual_rows}</tbody></table></div>" + modal + "</div>")
    else:
        sec_manual = ""
    # --- Excluir destino (falso positivo): un DNS u otro destino que dispara alertas en muchos CPEs ---
    if es_admin:   # es_admin aqui = operador o admin (pueden operar la cuarentena)
        dests_ok = sorted(_dest_ok_set())
        chips = ("".join(
            f"<span class=destchip><span class=mono>{esc(dp)}</span>"
            f"<form method=post action='/cuarentena/quitar-destino' style='display:inline;margin:0'>"
            f"<input type=hidden name=destino value='{esc(dp)}'>"
            f"<button class=destx title='Quitar de confiables'>&times;</button></form></span>"
            for dp in dests_ok) if dests_ok else "<span class=muted>ninguno todavia</span>")
        sec_fp = ("<div class='seccion'><div class='card' style='padding:14px 16px'>"
                  "<h2 style='font-size:15px;margin:0 0 4px'>Excluir destino (falso positivo)</h2>"
                  "<p class='sub' style='margin:0 0 10px'>Si una IP <b>destino</b> (p.ej. un DNS) dispara falsos "
                  "positivos en muchos CPEs, marcala como confiable: sus alertas dejan de contar y se "
                  "<b>liberan automaticamente</b> los CPEs que fueron a la lista por su culpa.</p>"
                  "<form method=post action='/cuarentena/excluir-destino' style='display:flex;gap:8px;flex-wrap:wrap'>"
                  "<input type=text name=destino placeholder='200.63.105.194' "
                  "style='flex:1;min-width:180px;padding:8px 11px;border:1px solid #d7d6d2;border-radius:8px;"
                  "font:13px ui-monospace,Consolas,monospace'>"
                  "<button class='qbtn' style='background:#2a78d6'>Excluir y liberar</button></form>"
                  f"<div style='margin-top:10px;font-size:12px;color:#6b6a66'>Destinos confiables: {chips}</div>"
                  "</div></div>")
    else:
        sec_fp = ""
    if activo:
        auto = m.get("AUTO_MANTENER") == "1"
        auto_txt = (" <b>Auto-mantener ON</b>: las IPs entran sin caducidad y se liberan solas cuando el CPE deja de atacar."
                    if auto else " Las IPs caducan solas con su TTL.")
        estado = (f"<div class='banner ok'><b>MikroTik habilitado.</b> Puedes enviar cada CPE a su address-list "
                  f"(infectados &rarr; <code>{esc(m.get('LIST',''))}</code>, DNS &rarr; <code>{esc(m.get('LIST_DNS',''))}</code>) "
                  f"en <code>{esc(m.get('HOST',''))}</code>; el MikroTik decide con tus reglas. Reversible con <b>Quitar</b>.{auto_txt}</div>")
    elif en and not conf_ok:
        estado = ("<div class='banner err'><b>Falta configurar la conexion.</b> Marcaste <b>Permitir enviar</b>, pero "
                  "aun falta <b>host, usuario o clave</b> del MikroTik. Ve a <b>Ajustes &rarr; MikroTik</b>, completa los datos "
                  "y pulsa <b>Probar conexion</b>. Hasta entonces esta pestana no envia nada.</div>")
    else:
        estado = ("<div class='banner'><b>Modo sugerencia (dry-run).</b> No se envia nada al MikroTik. "
                  "Para activar el envio, configura y marca <b>Permitir enviar</b> en <b>Ajustes &rarr; MikroTik</b>.</div>")
    flash = ("<div id=notif class='notifm msg'><span class=ni>&#8505;</span><span>" + esc(msg) + "</span></div>") if msg else ""
    css = ("<style>" + BASE_CSS +
           # solo lo propio de Cuarentena (lo comun ya viene de BASE_CSS)
           "main{max-width:1100px}.sub{margin:0 0 14px}"
           ".card{overflow:hidden}"
           ".ipx{font-weight:700}"
           ".rb{color:#fff;font-weight:800;font-size:12px;padding:2px 9px;border-radius:20px;white-space:nowrap}"
           ".fw{color:#7a4a12;font-size:12px}.mot{max-width:300px}"
           ".rowmeta{font-size:11.5px;color:#6b6a66;margin-top:3px}.muted{color:#9a9a95}"
           ".cfb{font-size:10.5px;font-weight:800;padding:2px 8px;border-radius:20px;white-space:nowrap}"
           ".cfb.alta{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4}"
           ".cfb.sosp{background:#fff7ed;color:#7a4a12;border:1px solid #f2d3ad}"
           ".evlist{margin:6px 0 0;padding-left:16px;font-size:11.5px;color:#3f7d55;line-height:1.5}"
           ".evlist li{margin:1px 0}"
           ".evbtn{margin-top:7px;border:1px solid #cfe0f6;background:#eef4fd;color:#2a5fa0;border-radius:7px;padding:4px 10px;font:600 12px system-ui;cursor:pointer}"
           ".evbtn:hover{background:#dbe9fb}"
           ".fichaov{display:none;position:fixed;inset:0;background:rgba(11,11,11,.5);z-index:120;align-items:center;justify-content:center;padding:20px}"
           ".fichabox{position:relative;background:#fcfcfb;border-radius:14px;max-width:880px;width:100%;height:min(88vh,820px);box-shadow:0 14px 50px rgba(0,0,0,.4);overflow:hidden}"
           ".fichax{position:absolute;top:8px;right:8px;z-index:2;border:0;background:#eceae6;width:30px;height:30px;border-radius:50%;font-size:19px;line-height:1;cursor:pointer}.fichax:hover{background:#e34948;color:#fff}"
           ".fichafr{width:100%;height:100%;border:0}"
           ".destchip{display:inline-flex;align-items:center;gap:4px;background:#eef4fd;border:1px solid #cfe0f6;color:#2a5fa0;border-radius:20px;padding:2px 4px 2px 10px;margin:2px 4px 2px 0;font-size:12px}"
           ".destx{border:0;background:transparent;color:#2a5fa0;cursor:pointer;font-size:15px;line-height:1;padding:0 4px}.destx:hover{color:#e34948}"
           ".dry{background:#eef4fd;color:#2a5fa0;border:1px solid #cfe0f6;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;white-space:nowrap}"
           ".enq{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;white-space:nowrap}"
           ".qbtn{font:12px system-ui;font-weight:700;border:0;border-radius:7px;padding:5px 11px;cursor:pointer;color:#fff}"
           ".qbtn.send{background:#e34948}.qbtn.send:hover{background:#c93b3a}"
           ".qbtn.quit{background:#6b6a66;margin-left:6px}.qbtn.quit:hover{background:#524f4c}"
           # --- quitado masivo: barra de seleccion + modal flotante ---
           ".masivo{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 10px}"
           ".masivo .qbtn:disabled{background:#d7d6d2;color:#8a8984;cursor:default}"
           ".mashint{color:#8a8984;font-size:12px}"
           ".selc{width:34px;text-align:center}"
           ".selc input{width:16px;height:16px;cursor:pointer;accent-color:#2a78d6}"
           ".masov{display:none;position:fixed;inset:0;background:rgba(11,11,11,.55);z-index:150;"
           "align-items:center;justify-content:center;padding:24px}"
           ".masbox{background:#fff;border-radius:14px;max-width:440px;width:100%;padding:22px 24px;"
           "box-shadow:0 16px 54px rgba(0,0,0,.45)}"
           ".masbox h3{margin:0 0 8px;font-size:19px}"
           ".massub{margin:0 0 12px;color:#52514e;font-size:14px;line-height:1.5}"
           ".maslist{margin:0 0 16px;padding:10px 12px;list-style:none;background:#faf9f6;border:1px solid #e7e6e2;"
           "border-radius:9px;max-height:200px;overflow:auto;font:13px ui-monospace,Consolas,monospace}"
           ".maslist li{padding:2px 0;display:flex;align-items:center;gap:8px}"
           ".maslist li .est{width:14px;text-align:center;flex:none}"
           ".maslist li.yendo{color:#2a5fa0;font-weight:700}"
           ".maslist li.hecho .est{color:#1a7f37}"
           ".maslist li.fallo{color:#b52a2a}.maslist li.fallo .est{color:#b52a2a}"
           ".maslist li .err{font:11px system-ui;color:#b52a2a}"
           # barra de avance: solo aparece mientras se estan quitando
           ".masprog{display:none;height:6px;background:#eceae6;border-radius:4px;overflow:hidden;margin:0 0 12px}"
           ".masprog.on{display:block}"
           ".masbar{height:100%;width:0;background:#2a78d6;transition:width .25s}"
           ".masacts{display:flex;gap:10px;justify-content:flex-end}"
           ".masno{background:#eef0f2;color:#33322f;border:1px solid #d7d6d2;padding:10px 16px;border-radius:9px;"
           "font:600 14px system-ui;cursor:pointer}.masno:hover{background:#e2e5e8}"
           ".massi{background:#e34948;color:#fff;border:0;padding:10px 18px;border-radius:9px;"
           "font:600 14px system-ui;cursor:pointer}.massi:hover{background:#c93b3a}"
           ".seccion{margin:0 0 26px}.shead{display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap;margin:0 0 10px}"
           ".shead h2{font-size:16px;margin:0}.shead .sub{margin:2px 0 0}"
           ".notifm{position:fixed;top:18px;left:50%;transform:translateX(-50%) translateY(-16px);z-index:140;display:flex;align-items:center;gap:10px;max-width:560px;padding:12px 16px;border-radius:12px;font-size:14px;box-shadow:0 8px 30px rgba(0,0,0,.25);opacity:0;transition:opacity .25s,transform .25s;pointer-events:none}"
           ".notifm.show{opacity:1;transform:translateX(-50%) translateY(0)}"
           ".notifm.msg{background:#eef4fd;color:#2a5fa0;border:1px solid #cfe0f6}.notifm .ni{font-size:18px}"
           "@media(max-width:820px){"
           "h1{font-size:19px}"
           ".shead{align-items:stretch}.shead .qbtn{margin-left:0}"
           ".fichabox{height:calc(100vh - 28px);max-width:100%}"
           ".notifm{left:14px;right:14px;transform:translateY(-16px);max-width:none}"
           ".notifm.show{transform:translateY(0)}"
           # tablas densas -> se apilan como tarjetas (Etiqueta: valor) en vez de aplastarse.
           # Patron de etiqueta absoluta: sirve con cualquier contenido (badges, botones, texto).
           ".card{overflow:visible;border:0;background:transparent;border-radius:0}"
           "table,thead,tbody,tr,td{display:block;width:auto}"
           "thead{position:absolute;left:-9999px}"           # cabecera oculta (cada celda lleva su etiqueta)
           "tbody tr{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 10px;padding:8px 12px}"
           "tbody tr:hover{background:#fff}"
           "tbody td{border:0;border-top:1px solid #f4f3f0;padding:7px 0 7px 42%;position:relative;text-align:left;min-height:20px}"
           "tbody td:first-child{border-top:0}"
           "tbody td::before{content:attr(data-label);position:absolute;left:0;top:7px;width:38%;color:#52514e;font-weight:600;font-size:12px;white-space:nowrap}"
           "tbody td.mot{padding-left:0}"
           "tbody td.mot::before{position:static;display:block;width:auto;margin-bottom:4px}"
           "tbody td[colspan]{padding-left:0;text-align:center}tbody td[colspan]::before{display:none}"
           ".mot{max-width:none}.num{text-align:left}"
           "}"
           "</style>")
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Suricata</title>" + css + "</head><body><main>"
            "<h1>Cuarentena y control de CPEs</h1>"
            f"<p class='sub'>Ventana {vmin} min · lista de hace {edad}. Dos categorias: <b>infectados</b> (malware/CnC) "
            "y <b>DNS sospechoso</b> (consultan dominios de botnet), cada una a su address-list del MikroTik.</p>"
            + _salud_html() + flash + estado + sec_fp + sec_inf + sec_dns + sec_dst + sec_manual +
            "<div id=fichamodal class=fichaov onclick=\"if(event.target===this)this.style.display='none'\">"
            "<div class=fichabox><button type=button class=fichax "
            "onclick=\"document.getElementById('fichamodal').style.display='none'\">&times;</button>"
            "<iframe id=fichafr class=fichafr></iframe></div></div>"
            "<script>function verFicha(ip){var m=document.getElementById('fichamodal');"
            "document.getElementById('fichafr').src='/cuarentena/ficha?embed=1&ip='+encodeURIComponent(ip);"
            "m.style.display='flex';}"
            "document.addEventListener('keydown',function(e){if(e.key==='Escape')"
            "document.getElementById('fichamodal').style.display='none';});"
            "(function(){var n=document.getElementById('notif');if(!n)return;"
            "setTimeout(function(){n.classList.add('show');},60);"
            "setTimeout(function(){n.classList.remove('show');},3600);})();"
            # --- quitado masivo: seleccion + modal de confirmacion ---
            # mientras se estan quitando no se cierra: cerrarlo esconderia el avance
            # y el proceso seguiria corriendo por detras sin que se vea
            "function masCerrar(){if(window.masRun)return;"
            "var m=document.getElementById('mmasivo');if(m)m.style.display='none';}"
            "(function(){var b=document.getElementById('bmasivo');if(!b)return;"
            "function sel(){return Array.prototype.filter.call("
            "document.querySelectorAll('input.selm'),function(c){return c.checked;});}"
            "function refresca(){var n=sel().length;"
            "document.getElementById('nmasivo').textContent='('+n+')';b.disabled=n===0;"
            "var t=document.getElementById('selall');"
            "if(t){var tot=document.querySelectorAll('input.selm').length;"
            "t.checked=tot>0&&n===tot;t.indeterminate=n>0&&n<tot;}}"
            "document.addEventListener('change',function(e){var t=e.target;"
            "if(t.id==='selall'){Array.prototype.forEach.call(document.querySelectorAll('input.selm'),"
            "function(c){c.checked=t.checked;});refresca();}"
            "else if(t.classList&&t.classList.contains('selm'))refresca();});"
            "var filas=[];"
            "b.addEventListener('click',function(){var s=sel();if(!s.length)return;"
            "var ul=document.getElementById('maslista'),campos=document.getElementById('mascampos');"
            "ul.innerHTML='';campos.innerHTML='';filas=[];"
            "s.forEach(function(c){var p=c.value.split('|');"
            "var li=document.createElement('li');"
            "var e=document.createElement('span');e.className='est';e.textContent='\\u00b7';"
            "var t=document.createElement('span');t.textContent=p[1]+(p[0]==='dns'?'  (DNS)':'');"
            "li.appendChild(e);li.appendChild(t);ul.appendChild(li);"
            "filas.push({val:c.value,ip:p[1],li:li,est:e});"
            # el form sigue existiendo como respaldo: si el navegador no puede con fetch,
            # el envio normal hace el quitado en bloque por /cuarentena/quitar-varios
            "var h=document.createElement('input');h.type='hidden';h.name='sel';h.value=c.value;"
            "campos.appendChild(h);});"
            "document.getElementById('mmasivo').style.display='flex';});"
            # --- quitado de una en una, mostrando el avance ---
            # cada IP es una llamada al MikroTik; en bloque tardaba y la pantalla quedaba
            # colgada sin decir nada. Ahora se ve cual va saliendo y cual fallo.
            "var f=document.getElementById('fmasivo');"
            "if(f&&window.fetch)f.addEventListener('submit',function(ev){ev.preventDefault();"
            "var bs=document.getElementById('massi'),bn=document.getElementById('masno');"
            "var prog=document.getElementById('masprog'),barra=document.getElementById('masbar');"
            "var sub=document.getElementById('massub');"
            "bs.disabled=true;bn.disabled=true;prog.classList.add('on');window.masRun=true;"
            "var i=0,ok=0,mal=0;"
            "function pinta(){barra.style.width=Math.round(i/filas.length*100)+'%';"
            "sub.innerHTML='Quitando <b>'+i+'</b> de <b>'+filas.length+'</b>\\u2026';}"
            "function fin(){window.masRun=false;bn.disabled=false;refresca();"
            "sub.innerHTML='Listo: <b>'+ok+'</b> quitada(s)'"
            "+(mal?', <b>'+mal+'</b> con error':'')+'. Actualizando\\u2026';"
            # esta recarga no es un submit ni un refresco del navegador, asi que _POS_JS no
            # restauraria la posicion y la pagina saltaria arriba: se deja marcada a mano
            "try{sessionStorage.setItem('pos:'+location.pathname,String(window.scrollY||0));"
            "sessionStorage.setItem('posact:'+location.pathname,'1');}catch(e){}"
            "setTimeout(function(){location.href='/cuarentena?msg='"
            "+encodeURIComponent(ok+' entrada(s) quitada(s)'+(mal?'; '+mal+' con error':''));},900);}"
            "function paso(){if(i>=filas.length)return fin();var fila=filas[i];"
            "fila.li.classList.add('yendo');fila.est.textContent='\\u2026';"
            "var cuerpo='sel='+encodeURIComponent(fila.val);"
            "fetch('/cuarentena/quitar-uno',{method:'POST',credentials:'same-origin',"
            "headers:{'Content-Type':'application/x-www-form-urlencoded'},body:cuerpo})"
            ".then(function(r){return r.json();}).catch(function(){return {ok:false,err:'sin respuesta'};})"
            ".then(function(d){fila.li.classList.remove('yendo');"
            "if(d&&d.ok){ok++;fila.li.classList.add('hecho');fila.est.textContent='\\u2713';"
            "var cb=document.querySelector('input.selm[value=\"'+fila.val+'\"]');"
            "if(cb){cb.checked=false;var tr=cb.parentNode&&cb.parentNode.parentNode;"
            "if(tr&&tr.style)tr.style.opacity='.45';}}"
            "else{mal++;fila.li.classList.add('fallo');fila.est.textContent='\\u2715';"
            "var e=document.createElement('span');e.className='err';"
            "e.textContent=(d&&d.err)||'error';fila.li.appendChild(e);}"
            "i++;pinta();paso();});}"
            "pinta();paso();});"
            "document.addEventListener('keydown',function(e){if(e.key==='Escape')masCerrar();});"
            "refresca();})();</script>"
            "</main></body></html>")
    return wrap(body, refresh=False, active="/cuarentena")

class H(BaseHTTPRequestHandler):
    server_version = "suricata-dashboard"
    # HTTP/1.1 con keep-alive: reutiliza la conexion en vez de reabrirla en cada
    # respuesta. Detras de un proxy inverso quita mucha latencia (login, redirect, POST).
    # Todas las respuestas mandan Content-Length, asi que es seguro.
    protocol_version = "HTTP/1.1"
    timeout = 30   # cierra conexiones keep-alive inactivas (evita acumular hilos)
    def _sid(self):
        c = self.headers.get("Cookie")
        if not c:
            return None
        try:
            m = SimpleCookie(c).get("sid")
            return m.value if m else None
        except Exception:
            return None
    def _peer_ip(self):
        try:
            return self.client_address[0]
        except Exception:
            return "?"
    def _proxy_confiable(self):
        return self._peer_ip() in PROXIES_OK
    def _cookie_secure(self):
        # Secure solo si la peticion llego por HTTPS; si no, el navegador descartaria
        # la cookie y no se podria entrar por HTTP. La cabecera del proxy solo cuenta
        # si el proxy es de confianza.
        if not self._proxy_confiable():
            return ""
        proto = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        if proto == "https":
            return "; Secure"
        return ""
    def _client_ip(self):
        # detras de un proxy inverso la IP real viene en X-Forwarded-For, pero esa
        # cabecera la pone quien quiera: solo se acepta si la conexion viene de un
        # proxy declarado en PROXIES. Si no, manda la IP del socket.
        if self._proxy_confiable():
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self._peer_ip()
    def _sesion(self):
        return SESSIONS.get(self._sid()) or {}
    def _sesion_ok(self):
        s = self._sesion()
        return bool(s and s.get("exp", 0) > time.time())
    def _rol(self):
        return self._sesion().get("role")
    def _admin(self):
        # admin real, o modo sin-auth (sin usuarios). operador/lectura -> False.
        return self._rol() in (None, "admin")
    def _operador(self):
        # puede gestionar cuarentenas/incidentes: admin, operador o modo sin-auth.
        return self._rol() in (None, "admin", "operador")
    def _set_ctx(self):
        s = self._sesion()
        CTX.user = s.get("user"); CTX.role = s.get("role"); CTX.ip = self._client_ip()
    def _auth_ok(self):
        if not cargar_usuarios():
            return True  # sin usuarios (PASS vacia en .conf): sin auth, solo tras VPN/proxy
        # Solo sesion (cookie del formulario). NO se acepta auth basica del navegador:
        # el navegador la cachea de por vida y anularia el boton Salir. Para scripts,
        # hacer login por POST /login y reutilizar la cookie sid.
        return self._sesion_ok()
    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def _json(self, obj, code=200):
        """Respuesta JSON corta, para las acciones que el panel llama con fetch()."""
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def _deny(self):
        # sin sesion -> a la pagina de login (no el popup del navegador)
        self._redirect("/login")
    def _html(self, s, code=200):
        b = s.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def send_response(self, code, message=None):
        # deja constancia de que ya empezo a responder: la red de seguridad de abajo no
        # debe intentar escribir una segunda respuesta encima de una a medias
        self._respondido = True
        BaseHTTPRequestHandler.send_response(self, code, message)

    def _seguro(self, fn):
        """Red de seguridad de TODA peticion.

        Si una pagina reventaba, el hilo moria y la conexion se cerraba sin responder
        nada. Detras de un proxy inverso (nginx/openresty) eso llega al navegador como
        un escueto "502 Bad Gateway" que no dice que fallo ni donde mirar. Ahora se
        responde 500 con una explicacion y el fallo queda en el log y en la bitacora."""
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            raise                       # el cliente se fue: no hay a quien responderle
        except Exception:
            det = traceback.format_exc()
            ruta = self.path.split("?", 1)[0]
            try:
                sys.stderr.write("ERROR en %s %s\n%s" % (self.command, self.path, det))
                sys.stderr.flush()
            except Exception:
                pass
            try:
                bitacora("ERROR-PANEL", "%s %s: %s" % (self.command, ruta,
                                                       det.strip().splitlines()[-1][:200]))
            except Exception:
                pass
            if getattr(self, "_respondido", False):
                self.close_connection = True   # ya iba una respuesta a medias: cortar
                return
            try:
                self._html(
                    "<!doctype html><html lang=es><head><meta charset=utf-8>"
                    "<title>Error del panel</title><style>body{margin:0;padding:40px 24px;"
                    "font:15px/1.6 system-ui,Segoe UI,sans-serif;color:#33322f;background:#fcfcfb}"
                    "div{max-width:620px;margin:0 auto}h1{font-size:20px;margin:0 0 10px;color:#b52a2a}"
                    "code{background:#f1f1ef;border:1px solid #e0dfda;border-radius:4px;padding:1px 6px;"
                    "font:13px ui-monospace,Consolas,monospace}p{margin:10px 0}</style></head><body><div>"
                    "<h1>Esta pagina del panel fallo</h1>"
                    "<p>La peticion <code>" + html.escape(ruta) + "</code> no se pudo generar. "
                    "El resto del panel sigue funcionando.</p>"
                    "<p>El detalle queda en el registro del servicio:<br>"
                    "<code>journalctl -u suricata-dashboard -n 50</code></p>"
                    "</div></body></html>", 500)
            except Exception:
                self.close_connection = True

    def do_GET(self):
        self._seguro(self._get)

    def do_POST(self):
        self._seguro(self._post)

    def _get(self):
        path = self.path.split("?", 1)[0]
        if path in ("/logo.png", "/favicon.ico"):
            # publico y cacheable: el navegador lo guarda y el login pesa ~3 KB.
            # el favicon es un PNG cuadrado 64x64 aparte para que no salga estirado
            img = FAVICON_BYTES if path == "/favicon.ico" else LOGO_BYTES
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "public, max-age=604800, immutable")
            self.send_header("Content-Length", str(len(img)))
            self.end_headers()
            self.wfile.write(img)
            return
        if path.startswith("/vendor/mapa/"):
            # assets del mapa mundial (TopoJSON + topojson-client), publicos y cacheables
            fname = path.rsplit("/", 1)[-1]
            ct = {"countries-110m.json": "application/json",
                  "topojson-client.min.js": "application/javascript"}.get(fname)
            if ct:
                try:
                    with open(os.path.join("/var/lib/suricata-mapa", fname), "rb") as f:
                        data = f.read()
                except OSError:
                    self.send_error(404); return
                self.send_response(200)
                self.send_header("Content-Type", ct + "; charset=utf-8")
                self.send_header("Cache-Control", "public, max-age=604800, immutable")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers(); self.wfile.write(data); return
            self.send_error(404); return
        if path == "/destinos.rsc":
            # bloqueo PREVENTIVO de destinos. Se la baja el propio MikroTik, asi que no
            # puede pedir sesion: se abre solo a las IPs de los routers dados de alta.
            quien = self._client_ip()
            permitidas = {(r.get("HOST") or "").strip()
                          for r in cargar_routers() if (r.get("HOST") or "").strip()}
            if quien not in permitidas:
                return self._html("<h1>No autorizado</h1>", 403)
            cuerpo = destinos_rsc().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers(); self.wfile.write(cuerpo)
            return
        if path == "/blocklist.rsc":
            # La descarga el propio MikroTik con /tool fetch, asi que no puede pedir
            # sesion. Se abre SOLO a las IPs de los routers dados de alta: nada de meter
            # un token en la configuracion del router.
            quien = self._client_ip()
            permitidas = {(r.get("HOST") or "").strip()
                          for r in cargar_routers() if (r.get("HOST") or "").strip()}
            if quien not in permitidas:
                return self._html("<h1>No autorizado</h1>", 403)
            cuerpo = blocklist_rsc().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers(); self.wfile.write(cuerpo)
            return
        if not ip_confiable(self._client_ip()):
            return self._html("<!doctype html><meta charset=utf-8><title>Acceso restringido</title>"
                              "<div style='font:15px system-ui;max-width:520px;margin:60px auto;padding:24px;text-align:center'>"
                              "<h2>Acceso restringido</h2><p style='color:#52514e'>Tu IP no esta en la lista de "
                              "IPs de confianza del panel.</p></div>", 403)
        if path == "/login":
            if self._auth_ok():
                return self._redirect("/")
            return self._html(login_page())
        if path == "/logout":
            sid = self._sid()
            if sid:
                SESSIONS.pop(sid, None); _guardar_sesiones()
            return self._redirect("/login", cookie="sid=; Path=/; Max-Age=0")
        if not self._auth_ok():
            return self._deny()
        self._set_ctx()
        if path in ("/", "/index.html"):
            feed = live_feed_html()
            head_css, resumen_inner, _ = partes_reporte()   # resumen SIN la tabla de detalle
            ahora_ec = datetime.now(TZ_EC).strftime("%d/%m/%Y %H:%M")
            # selector de ventana (solo admin): elegir cuanto tiempo abarca el resumen
            wsel = ""
            if getattr(CTX, "role", None) in (None, "admin"):
                va = ventana_actual()
                opts = "".join(f"<option value={v}{' selected' if v == va else ''}>{t}</option>"
                               for v, t in VENTANAS)
                wsel = ("<form method=post action='/ventana' class='wsel'>"
                        "<span class='wlbl'>Ventana</span>"
                        f"<select name='min' onchange='this.form.submit()'>{opts}</select></form>")
            if resumen_inner.strip():
                cabecera = (
                    "<header class='pageh'><div>"
                    "<h1>Resumen</h1>"
                    "<p class='ph-sub'>Panel IDS Suricata &middot; alertas graves salientes &middot; "
                    f"actualizado {ahora_ec} (hora de Ecuador) "
                    "<span class='ph-live'><span class='dotlive'></span>en vivo &middot; "
                    f"refresca en <span id='cd'>20</span>s</span></p></div>{wsel}</header>")
                resumen = f"{cabecera}<main>{resumen_inner}</main>"
            else:
                cabecera = (
                    "<header class='pageh'><div><h1>Resumen</h1>"
                    f"<p class='ph-sub'>Panel IDS Suricata &middot; actualizado {ahora_ec} (hora de Ecuador)</p></div>{wsel}</header>")
                resumen = (cabecera + "<main style='padding:8px 28px 24px'><p style='color:#52514e'>El resumen se "
                           "esta generando en segundo plano; aparecera aqui en unos minutos. "
                           "El feed de abajo ya esta en vivo.</p></main>")
            page = (f"<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
                    f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                    f"<meta http-equiv=refresh content=20><title>Suricata</title>"
                    f"{_PAGEH_CSS}{head_css}"
                    "<style>main{max-width:1360px;margin:0 auto;padding-top:8px}</style>"
                    f"</head><body>{nav('/')}{resumen}{feed}"
                    "<script>(function(){var s=20,e=document.getElementById('cd');"
                    "var t=setInterval(function(){s--;if(s<0)s=0;if(e)e.textContent=s;"
                    "if(s<=0)clearInterval(t);},1000);})();</script></body></html>")
            return self._html(page)
        if path == "/top":
            return self._html(top_page())
        if path == "/detalle":
            head_css, _, detalle = partes_reporte()
            if not detalle.strip():
                detalle = ("<section class='card' style='margin:16px 28px'><p class='muted'>El detalle se "
                           "esta generando; aparecera en unos minutos.</p></section>")
            page = (f"<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
                    f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                    # se recarga solo cada 2 min para tomar el reporte nuevo (cada 5 min);
                    # el filtro de busqueda persiste en sessionStorage, no se pierde al recargar
                    f"<meta http-equiv=refresh content=120>"
                    f"<title>Suricata</title>{head_css}</head><body>{nav('/detalle')}"
                    f"<main>{detalle}</main></body></html>")
            return self._html(page)
        if path == "/historico":
            _qh = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            try:
                _dn = int(_qh.get("d", ["30"])[0])
            except (ValueError, TypeError):
                _dn = 30
            if _dn not in (7, 30, 90, 365):
                _dn = 30
            return self._html(historico_page(_dn))
        if path == "/cuarentena":
            _qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._html(cuarentena_page(msg=_qs.get("msg", [""])[0], es_admin=self._operador()))
        if path == "/cuarentena/ficha":
            if not self._operador():
                return self._redirect("/")
            _qs = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._html(ficha_page(_qs.get("ip", [""])[0],
                                         embed=("embed=1" in (self.path.split("?", 1)[1] if "?" in self.path else ""))))
        if path == "/log":
            if not self._admin():
                return self._redirect("/")   # lectura no ve el log de accesos
            return self._html(log_page(embed=("embed=1" in (self.path.split("?", 1)[1] if "?" in self.path else ""))))
        if path == "/bitacora":
            if not self._admin():
                return self._redirect("/")   # la bitacora (auditoria) es solo de admin
            return self._html(bitacora_page(embed=("embed=1" in (self.path.split("?", 1)[1] if "?" in self.path else ""))))
        if path == "/perfil":
            return self._redirect("/ajustes")
        if path == "/ajustes":
            return self._html(perfil_page())
        if path == "/exclusiones/export":
            if not self._admin():
                return self._redirect("/")
            propias = [r for r in cargar_exclusiones() if r.get("motivo") != "(conf)"]
            data = json.dumps(propias, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=exclusiones.json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/exclusiones":
            if not self._admin():
                return self._redirect("/")   # lectura no gestiona exclusiones
            edit = None
            if "?" in self.path:
                try:
                    edit = int(_up.parse_qs(self.path.split("?", 1)[1]).get("edit", [""])[0])
                except (ValueError, TypeError):
                    edit = None
            return self._html(exclusiones_page(edit_idx=edit))
        if path == "/reputacion":
            if not self._operador():
                return self._deny()
            # ?ips=... para poder enlazar una IP concreta desde la tabla de una red
            _qr = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            _t = (_qr.get("ips", [""])[0]).strip()
            if _t:
                _res, _av = aidb_lote(_t, refrescar=bool(_qr.get("refrescar")))
                return self._html(reputacion_page(res=_res, texto=_t, msg=_av, ok=not _av,
                                                  es_admin=self._admin(),
                                                  volver=(_qr.get("volver", [""])[0]).strip()))
            return self._html(reputacion_page(es_admin=self._admin()))
        if path == "/documentacion":
            _qd = _up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            return self._html(documentacion_page(embed=("1" in _qd.get("embed", [])),
                                                 pagina=(_qd.get("p", [""])[0])))
        m = re.match(r"^/r/(report-[0-9A-Za-z_-]+\.html)$", path)
        if m:
            f = os.path.join(LOGDIR, m.group(1))
            if os.path.isfile(f):
                try:
                    return self._html(wrap(open(f, encoding="utf-8", errors="replace").read(), refresh=False))
                except OSError:
                    pass
            return self._html("<h1>No encontrado</h1>", 404)
        return self._html("<h1>No encontrado</h1>", 404)
    def _post(self):
        ruta = self.path.split("?", 1)[0]
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        except Exception:
            body = ""
        q = urllib.parse.parse_qs(body)
        if not ip_confiable(self._client_ip()):
            return self._html("<h1>Acceso restringido</h1>", 403)
        if ruta == "/login":
            ip = self._client_ip()
            u = q.get("usuario", [""])[0]; p = q.get("clave", [""])[0]
            # el bloqueo por fuerza bruta solo aplica cuando NO hay lista de confianza;
            # con lista, el acceso ya esta restringido a IPs de confianza (no hay que bloquearlas)
            espera = login_bloqueado(ip) if not cargar_confianza() else 0
            if espera > 0:
                login_registrar(ip, u, "BLOQUEADO")
                time.sleep(1)
                return self._html(login_page(f"Demasiados intentos fallidos. Espera {espera//60 + 1} min e intenta de nuevo."))
            role = verificar_login(u, p)
            if role:
                LOGIN_FAILS.pop(ip, None)   # login correcto: limpia el contador
                login_registrar(ip, u, "OK")
                bitacora("LOGIN", f"rol={role}", quien=u, ip=ip)
                token = secrets.token_urlsafe(24)
                SESSIONS[token] = {"user": u, "role": role, "exp": time.time() + SESSION_TTL}
                for k in [k for k, v in SESSIONS.items() if v.get("exp", 0) < time.time()]:
                    SESSIONS.pop(k, None)
                _guardar_sesiones()   # persistir: sobrevive al reinicio del panel (no re-login)
                return self._redirect("/", cookie=f"sid={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{self._cookie_secure()}")
            if not cargar_confianza():
                login_fallo(ip)   # solo se cuenta para bloquear si no hay lista de confianza
            login_registrar(ip, u, "FAIL")
            time.sleep(1)   # ralentiza la fuerza bruta
            return self._html(login_page("Usuario o clave incorrectos."))
        if not self._auth_ok():
            return self._deny()
        self._set_ctx()
        if ruta == "/update-reglas":
            if not self._admin():
                return self._deny()   # accion de admin
            if not UPDATE["running"]:
                UPDATE["running"] = True; UPDATE["started"] = time.time(); UPDATE["msg"] = ""
                threading.Thread(target=_run_rules_update, daemon=True).start()
            return self._redirect("/documentacion#reglas")
        if ruta == "/ventana":
            if not self._admin():
                return self._deny()
            try:
                m = int(q.get("min", ["1440"])[0])
            except ValueError:
                m = 1440
            if m not in [v for v, _ in VENTANAS]:
                m = 1440
            set_ventana(m)
            global FORCE_REGEN
            FORCE_REGEN = True   # el refrescador regenera el resumen con la nueva ventana en <=10 s
            return self._redirect("/")
        if ruta == "/buscar-update":
            if not self._admin():
                return self._deny()
            try:
                chequear_update()
                d = update_info()
                msg = ("Hay una version nueva disponible." if d.get("disponible")
                       else "Estas en la ultima version.")
                ok = True
            except Exception:
                msg, ok = "No se pudo consultar GitHub (sin red o limite de la API).", False
            return self._html(perfil_page(msg, ok=ok))
        if ruta == "/update-panel":
            if not self._admin():
                return self._deny()
            registrar_update_inicio(getattr(CTX, "user", ""))  # de-que-SHA y quien, para el registro
            bitacora("ACTUALIZAR-PANEL", "disparo actualizacion del panel")
            # el actualizador reinicia el panel: se lanza DESACOPLADO (systemd-run) para
            # que sobreviva al reinicio; si no hay systemd-run, con setsid como respaldo.
            try:
                subprocess.Popen(["systemd-run", "--no-block", "--collect",
                                  "--unit=suricata-panel-update-run",
                                  "/usr/local/bin/suricata-panel-update"])
            except Exception:
                try:
                    subprocess.Popen(["setsid", "/usr/local/bin/suricata-panel-update"])
                except Exception:
                    pass
            return self._html(
                "<!doctype html><html lang=es><head><meta charset=utf-8><title>Actualizando panel</title>"
                "<meta http-equiv=refresh content='50;url=/ajustes'>"
                "<link rel=icon type=image/png href=/favicon.ico>"
                "<style>"
                "body{margin:0;background:#fcfcfb;font:15px system-ui,-apple-system,Segoe UI,sans-serif;color:#0b0b0b}"
                ".wrap{max-width:560px;margin:64px auto;padding:30px 28px;text-align:center;"
                "border:1px solid #e7e6e2;border-radius:14px;background:#fff}"
                ".wrap h2{margin:0 0 6px;font-size:21px}"
                ".spin{width:34px;height:34px;margin:2px auto 14px;border:3px solid #e7e6e2;"
                "border-top-color:#2a78d6;border-radius:50%;animation:sp .8s linear infinite}"
                "@keyframes sp{to{transform:rotate(360deg)}}"
                ".sub{color:#52514e;margin:0 0 20px;line-height:1.5}"
                ".track{height:14px;background:#ecebe7;border-radius:20px;overflow:hidden}"
                ".fill{height:100%;width:0;border-radius:20px;"
                "background:linear-gradient(90deg,#2a78d6,#4c9bf0);transition:width .25s linear}"
                ".row{display:flex;justify-content:space-between;margin-top:9px;font-size:13px;color:#52514e}"
                ".pct{font-weight:800;color:#2a78d6}"
                "</style></head><body>"
                "<div class='wrap'>"
                "<div class='spin'></div>"
                "<h2>Actualizando el panel&hellip;</h2>"
                "<p class='sub'>Bajando la ultima version y reiniciando el panel. "
                "Tu configuracion no se toca. Al terminar volveras a Ajustes solo.</p>"
                "<div class='track'><div class='fill' id='f'></div></div>"
                "<div class='row'><span class='pct' id='p'>0%</span>"
                "<span id='t'>faltan ~50 s</span></div>"
                "</div>"
                "<script>"
                "var T=50,ini=Date.now(),f=document.getElementById('f'),"
                "p=document.getElementById('p'),t=document.getElementById('t');"
                "var iv=setInterval(function(){"
                " var s=(Date.now()-ini)/1000, r=Math.max(0,T-s);"
                " var pc=Math.min(96,s/T*100);"          # tope 96%: el 100% real es cuando recarga
                " f.style.width=pc.toFixed(1)+'%';"
                " p.textContent=Math.round(pc)+'%';"
                " t.textContent = r>1 ? ('faltan ~'+Math.ceil(r)+' s') : 'casi listo, recargando';"
                " if(s>=T){clearInterval(iv);f.style.width='100%';p.textContent='100%';"
                "  location.href='/ajustes';}"
                "},250);"
                "</script></body></html>")
        if ruta == "/exclusiones":
            if not self._admin():
                return self._deny()   # lectura no gestiona exclusiones
            return self._post_exclusiones(q)
        if ruta == "/perfil":
            return self._post_perfil(q)
        if ruta == "/empresa":
            if not self._admin():
                return self._deny()
            nombre = (q.get("nombre", [""])[0]).strip()[:60]
            logo = q.get("logo", [""])[0]
            actual = cargar_empresa()
            if logo == "__BORRAR__":
                logo = ""
            elif not logo:
                logo = actual.get("logo", "")          # sin logo nuevo: conservar el actual
            elif not logo.startswith("data:image/") or len(logo) > 400_000:
                return self._html(perfil_page("El logo no es una imagen valida o pesa demasiado.", ok=False))
            try:
                guardar_empresa({"nombre": nombre, "logo": logo})
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            return self._html(perfil_page("Datos de la empresa guardados.", ok=True))
        if ruta == "/mikrotik":
            if not self._admin():
                return self._deny()
            m = cargar_mk()
            m["HOST"] = (q.get("host", [""])[0]).strip()[:80]
            m["PORT"] = (q.get("port", [""])[0]).strip()[:6] or "8728"
            m["USER"] = (q.get("user", [""])[0]).strip()[:64]
            npass = q.get("pass", [""])[0]
            if npass:                                   # vacio = conservar la clave actual
                m["PASS"] = npass
            m["LIST"] = (q.get("list", [""])[0]).strip()[:64] or "suricata-cuarentena"
            m["TTL"] = (q.get("ttl", [""])[0]).strip()[:16]
            m["LIST_DNS"] = (q.get("list_dns", [""])[0]).strip()[:64] or "suricata-dns-sospechoso"
            m["TTL_DNS"] = (q.get("ttl_dns", [""])[0]).strip()[:16]
            m["AUTO_MANTENER"] = "1" if q.get("auto") else "0"
            _va = {"nada", "cuarentena", "dns", "notificar"}
            m["POL_BAJO"] = (q.get("pol_bajo", ["nada"])[0]) if (q.get("pol_bajo", ["nada"])[0]) in _va else "nada"
            m["POL_MEDIO"] = (q.get("pol_medio", ["nada"])[0]) if (q.get("pol_medio", ["nada"])[0]) in _va else "nada"
            m["POL_ALTO"] = (q.get("pol_alto", ["nada"])[0]) if (q.get("pol_alto", ["nada"])[0]) in _va else "nada"
            m["POL_AUTO"] = "1" if q.get("pol_auto") else "0"
            m["TLS"] = "1" if q.get("tls") else "0"
            m["ENABLED"] = "1" if q.get("enabled") else "0"
            try:
                guardar_mk(m)
                # la conexion vive en el registro de nodos; este formulario edita el primero
                _rs = cargar_routers()
                for _k in ("HOST", "PORT", "TLS", "USER", "PASS", "LIST", "TTL",
                           "LIST_DNS", "TTL_DNS", "ENABLED"):
                    _rs[0][_k] = m.get(_k, "")
                if not _rs[0].get("nombre"):
                    _rs[0]["nombre"] = m.get("HOST", "") or "Nodo principal"
                guardar_routers(_rs)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            conf_dash_set("DOBLE_SENAL", "1" if q.get("doble") else "0")   # doble senal (lo lee el generador)
            guardar_nunca(q.get("nunca", [""])[0])                         # allowlist 'nunca bloquear'
            bitacora("CONFIG-MIKROTIK", f"host={m.get('HOST','')} enviar={'si' if m.get('ENABLED')=='1' else 'no'} "
                                        f"doble_senal={'si' if q.get('doble') else 'no'}")
            return self._html(perfil_page("Conexion al MikroTik guardada.", ok=True))
        if ruta == "/routers/guardar":
            # Alta o edicion de un nodo. El primero se edita desde la tarjeta de MikroTik;
            # aqui se gestionan los demas (y se puede renombrar cualquiera).
            if not self._admin():
                return self._deny()
            rid = (q.get("rid", [""])[0]).strip()[:16]
            rs = cargar_routers()
            r = None
            for x in rs:
                if x.get("id") == rid:
                    r = x
                    break
            if r is None:
                if len(rs) >= 8:
                    return self._html(perfil_page("Maximo 8 nodos por sensor.", ok=False))
                r = _router_vacio(len(rs) + 1)
                rs.append(r)
            r["nombre"] = (q.get("nombre", [""])[0]).strip()[:40] or r.get("HOST", "") or r["id"]
            r["HOST"] = (q.get("host", [""])[0]).strip()[:80]
            r["PORT"] = (q.get("port", [""])[0]).strip()[:6] or "8728"
            r["USER"] = (q.get("user", [""])[0]).strip()[:64]
            _np = q.get("pass", [""])[0]
            if _np:                                   # vacio = conservar la clave actual
                r["PASS"] = _np
            r["LIST"] = (q.get("list", [""])[0]).strip()[:64] or "suricata-cuarentena"
            r["LIST_DNS"] = (q.get("list_dns", [""])[0]).strip()[:64] or "suricata-dns-sospechoso"
            r["TTL"] = (q.get("ttl", [""])[0]).strip()[:16] or "1h"
            r["TTL_DNS"] = (q.get("ttl_dns", [""])[0]).strip()[:16] or "1d"
            r["TLS"] = "1" if q.get("tls") else "0"
            r["ENABLED"] = "1" if q.get("enabled") else "0"
            if not r.get("HOST"):
                return self._html(perfil_page("Falta la IP del MikroTik del nodo.", ok=False))
            try:
                guardar_routers(rs)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            bitacora("CONFIG-NODO", f"nodo={r['nombre']} host={r['HOST']} "
                                    f"enviar={'si' if r['ENABLED'] == '1' else 'no'}")
            return self._html(perfil_page(
                f"Nodo '{r['nombre']}' guardado. Para que su espejo se capture, re-ejecuta "
                f"el instalador con -m incluyendo {r['HOST']}.", ok=True))
        if ruta == "/routers/quitar":
            if not self._admin():
                return self._deny()
            rid = (q.get("rid", [""])[0]).strip()[:16]
            rs = cargar_routers()
            if len(rs) <= 1:
                return self._html(perfil_page("No se puede quitar el unico nodo.", ok=False))
            quedan = [x for x in rs if x.get("id") != rid]
            if len(quedan) == len(rs):
                return self._html(perfil_page("Ese nodo ya no existe.", ok=False))
            # OJO: no se tocan sus entradas de cuarentena. Si el nodo se quita sin
            # liberarlas antes, siguen bloqueadas en ese router y el panel ya no las
            # gestiona. Se avisa en el mensaje.
            try:
                guardar_routers(quedan)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            bitacora("QUITAR-NODO", f"nodo={rid}")
            return self._html(perfil_page(
                "Nodo quitado del panel. Si tenia CPEs en cuarentena, siguen bloqueados en "
                "ese MikroTik: quitalos desde el propio router.", ok=True))
        if ruta == "/mikrotik/test":
            if not self._admin():
                return self._deny()
            m = cargar_mk()                              # guarda lo que este en el form antes de probar
            m["HOST"] = (q.get("host", [""])[0]).strip()[:80] or m.get("HOST", "")
            m["PORT"] = (q.get("port", [""])[0]).strip()[:6] or m.get("PORT", "8728")
            m["USER"] = (q.get("user", [""])[0]).strip()[:64] or m.get("USER", "")
            npass = q.get("pass", [""])[0]
            if npass:
                m["PASS"] = npass
            m["LIST"] = (q.get("list", [""])[0]).strip()[:64] or m.get("LIST", "suricata-cuarentena")
            m["TTL"] = (q.get("ttl", [""])[0]).strip()[:16]
            m["LIST_DNS"] = (q.get("list_dns", [""])[0]).strip()[:64] or m.get("LIST_DNS", "suricata-dns-sospechoso")
            m["TTL_DNS"] = (q.get("ttl_dns", [""])[0]).strip()[:16]
            m["AUTO_MANTENER"] = "1" if q.get("auto") else "0"
            m["TLS"] = "1" if q.get("tls") else "0"
            m["ENABLED"] = "1" if q.get("enabled") else "0"
            try:
                guardar_mk(m)
            except OSError:
                pass
            ok, msg = mk_probar()
            if not ok:
                if "ssl" in msg.lower() or "handshake" in msg.lower() or "tls" in msg.lower():
                    msg += (" — Verifica que el servicio api-ssl este habilitado (/ip service enable api-ssl) y el puerto (8729). "
                            "No necesitas certificado (se usan cifrados ADH). Si sigue, prueba API plano: desmarca API-SSL y usa 8728.")
                else:
                    msg += " — Revisa host, puerto, usuario, clave, que el servicio API este activo y permitido desde este servidor."
            if q.get("ajax"):   # desde el modal: texto plano, sin recargar la pagina
                b = (("OK " if ok else "ERR: ") + msg).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b); return
            return self._html(perfil_page(("Prueba: " + msg), ok=ok))
        if ruta == "/feeds":
            if not self._admin():
                return self._deny()
            ak = q.get("authkey", [""])[0]
            if ak.strip() == "BORRAR":
                feeds_auth_set(""); bitacora("CONFIG-FEEDS-AUTHKEY", "borrada")
                return self._html(perfil_page("Auth-Key borrada. URLhaus/ThreatFox quedaran 'sin-clave'.", ok=True))
            if not ak.strip():
                return self._html(perfil_page("Sin cambios en la Auth-Key.", ok=True))
            estado, det = feeds_auth_probar(ak)      # validar ANTES de guardar (rechaza basura)
            if estado is False:
                bitacora("CONFIG-FEEDS-AUTHKEY", f"rechazada ({det})")
                return self._html(perfil_page(f"No se guardo: la Auth-Key no es valida — {det}.", ok=False))
            feeds_auth_set(ak); actualizar_feeds_async()
            if estado is True:
                bitacora("CONFIG-FEEDS-AUTHKEY", "validada y guardada")
                return self._html(perfil_page("Auth-Key VALIDA y guardada (solo en este servidor). Actualizando feeds.", ok=True))
            bitacora("CONFIG-FEEDS-AUTHKEY", f"guardada sin validar ({det})")
            return self._html(perfil_page(f"Auth-Key guardada, pero {det}. Se reintentara en la proxima actualizacion.", ok=True))
        if ruta == "/reputacion":
            if not self._operador():
                return self._deny()
            texto = q.get("ips", [""])[0]
            res, aviso = aidb_lote(texto, refrescar=bool(q.get("refrescar")))
            if res:
                bitacora("CONSULTA-ABUSEIPDB", f"{len(res)} entrada(s)")
            return self._html(reputacion_page(res=res, texto=texto, msg=aviso, ok=not aviso,
                                              es_admin=self._admin()))
        if ruta == "/reputacion/denunciar":
            if not self._operador():
                return self._deny()
            ip = (q.get("ip", [""])[0]).strip()
            okd, det = aidb_denunciar(ip, firma=q.get("firma", [""])[0],
                                      dport=q.get("dport", [""])[0],
                                      proto=q.get("proto", [""])[0],
                                      n=(q.get("n", ["0"])[0] or "0"),
                                      quien=getattr(CTX, "user", "?"))
            b = (("OK " if okd else "ERR: ") + det).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
            return
        if ruta == "/feeds/reportar":
            if not self._admin():
                return self._deny()
            on = bool(q.get("reportar"))
            aidb_set_reportar(on)
            bitacora("CONFIG-ABUSEIPDB-REPORTAR", "activadas" if on else "desactivadas")
            return self._html(perfil_page(
                "Denuncias a AbuseIPDB ACTIVADAS: aparecera un boton en cada atacante entrante."
                if on else "Denuncias a AbuseIPDB desactivadas.", ok=True))
        if ruta == "/publicas":
            if not self._admin():
                return self._deny()
            rid = (q.get("rid", [""])[0]).strip()
            if not router_por_id(rid):
                return self._redirect("/reputacion")
            ok_l, mal = guardar_publicas_de(rid, q.get("entradas", [""])[0])
            bitacora("CONFIG-PUBLICAS", f"nodo={rid} {len(ok_l)} entrada(s)"
                                        + (f"; rechazadas: {', '.join(mal[:3])}" if mal else ""))
            threading.Thread(target=vigilar_publicas, daemon=True).start()
            return self._redirect("/reputacion")
        if ruta == "/publicas/agregar":
            if not self._admin():
                return self._deny()
            rid = (q.get("rid", [""])[0]).strip()
            if not router_por_id(rid):
                return self._redirect("/reputacion")
            actuales = cargar_publicas().get(rid, [])
            ok_l, mal = guardar_publicas_de(
                rid, "\n".join(actuales + [q.get("entrada", [""])[0]]))
            bitacora("CONFIG-PUBLICAS", f"nodo={rid} +1 ({len(ok_l)} en total)"
                                        + (f"; rechazada: {mal[0]}" if mal else ""))
            if not mal:
                threading.Thread(target=vigilar_dnsbl, daemon=True).start()
            return self._redirect("/reputacion" + ("?msg=" + _up.quote("No se agrego: " + mal[0])
                                                   if mal else ""))
        if ruta == "/publicas/quitar":
            if not self._admin():
                return self._deny()
            rid = (q.get("rid", [""])[0]).strip()
            fuera = (q.get("entrada", [""])[0]).strip()
            quedan_e = [e for e in cargar_publicas().get(rid, []) if e != fuera]
            guardar_publicas_de(rid, "\n".join(quedan_e))
            bitacora("CONFIG-PUBLICAS", f"nodo={rid} -{fuera}")
            return self._redirect("/reputacion")
        if ruta == "/publicas/detectar":
            if not self._admin():
                return self._deny()
            rid = (q.get("rid", [""])[0]).strip()
            r = router_por_id(rid)
            if not r:
                return self._redirect("/reputacion")
            try:
                halladas = mk_publicas_detectadas(r)
            except Exception as ex:
                return self._redirect("/reputacion?msg=" + _up.quote(
                    f"No se pudo preguntar al MikroTik: {ex}"))
            if not halladas:
                return self._redirect("/reputacion?msg=" + _up.quote(
                    "El MikroTik no devolvio ninguna direccion publica. "
                    "Si el enlace lo termina otro equipo, agregalas a mano."))
            actuales = cargar_publicas().get(rid, [])
            nuevas = [x for x in halladas if x not in actuales]
            guardar_publicas_de(rid, "\n".join(actuales + nuevas))
            bitacora("CONFIG-PUBLICAS", f"nodo={rid} detectadas={len(halladas)} nuevas={len(nuevas)}")
            if nuevas:
                threading.Thread(target=vigilar_dnsbl, daemon=True).start()
                threading.Thread(target=vigilar_publicas, daemon=True).start()
            return self._redirect("/reputacion?msg=" + _up.quote(
                f"{len(nuevas)} publica(s) nueva(s) del MikroTik" if nuevas
                else "El MikroTik no tiene ninguna publica que no estuviera ya"))
        if ruta == "/publicas/revisar":
            if not self._operador():
                return self._deny()
            # en segundo plano: revisar un /24 en 6 listas son ~1.500 consultas DNS y la
            # peticion se quedaria colgada
            threading.Thread(target=vigilar_dnsbl, daemon=True).start()
            threading.Thread(target=vigilar_publicas, daemon=True).start()
            return self._redirect("/reputacion")
        if ruta == "/feeds/aidb":
            if not self._admin():
                return self._deny()
            k = q.get("aidbkey", [""])[0]
            if k.strip() == "BORRAR":
                aidb_set(""); bitacora("CONFIG-ABUSEIPDB", "borrada")
                return self._html(perfil_page("Clave de AbuseIPDB borrada.", ok=True))
            if not k.strip():
                return self._html(perfil_page("Sin cambios en la clave de AbuseIPDB.", ok=True))
            estado, det = aidb_probar(k)          # validar ANTES de guardar (rechaza basura)
            if estado is False:
                bitacora("CONFIG-ABUSEIPDB", f"rechazada ({det})")
                return self._html(perfil_page(f"No se guardo: la clave no es valida — {det}.", ok=False))
            aidb_set(k); actualizar_feeds_async()
            if estado is True:
                bitacora("CONFIG-ABUSEIPDB", "validada y guardada")
                return self._html(perfil_page("Clave de AbuseIPDB VALIDA y guardada (solo en este servidor).", ok=True))
            bitacora("CONFIG-ABUSEIPDB", f"guardada sin validar ({det})")
            return self._html(perfil_page(f"Clave guardada, pero {det}.", ok=True))
        if ruta == "/feeds/actualizar":
            if not self._admin():
                return self._deny()
            actualizar_feeds_async(); bitacora("ACTUALIZAR-FEEDS", "manual")
            return self._html(perfil_page("Actualizando feeds en segundo plano; recarga en un momento para ver el estado.", ok=True))
        if ruta == "/cuarentena/enviar":
            if not self._operador():
                return self._deny()
            ajax = bool(q.get("ajax"))   # desde el Top: responde texto plano y NO redirige
            def _fin(okr, texto):
                if ajax:
                    b = (("OK " if okr else "ERR: ") + texto).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers(); self.wfile.write(b)
                    return
                return self._redirect("/cuarentena?msg=" + _up.quote(texto))
            # Llega la IDENTIDAD del CPE ("IP" con un solo nodo, "router|IP" con varios).
            # Guardarla pelada era el fallo: el registro y los candidatos van por identidad,
            # asi que el Top y la pestana seguian mostrando "sin enviar" algo ya bloqueado,
            # y el bloqueo salia siempre hacia el router por defecto.
            clave = (q.get("ip", [""])[0]).strip()
            ip = ip_de(clave)
            score = (q.get("score", [""])[0]).strip()[:8]
            try:
                ipaddress.ip_address(ip)
            except Exception:
                return _fin(False, "IP invalida")
            if not es_mi_cpe(ip):
                # una IP de internet no es un abonado: la cuarentena de CPEs no la frena
                return _fin(False, f"{ip} no es de tus redes: es un atacante externo, "
                                   f"se corta en el firewall de borde, no en la cuarentena de CPEs")
            if nunca_bloquear(ip):
                return _fin(False, f"{ip} esta en la lista 'Nunca bloquear' (no se envia)")
            _pub = es_publica_declarada(ip)
            if _pub:
                return _fin(False, f"{ip} es una de TUS publicas ({_pub}): mandarla a la "
                                   f"cuarentena dejaria sin internet a todos los abonados "
                                   f"que salen por ahi")
            r = router_de_clave(clave); m = cargar_mk_de(r)
            if not mk_listo(m):
                return _fin(False, f"Configura y HABILITA el MikroTik "
                                   f"{m.get('ROUTER_NOMBRE') or ''} en Ajustes primero".replace("  ", " "))
            try:   # si la IP no es candidato actual, es un envio MANUAL (no lo libera el auto)
                cand_ips = {clave_cpe(c.get("ip", ""), c.get("router", ""))
                            for c in json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8")).get("candidatos", [])}
            except Exception:
                cand_ips = set()
            # a la lista de SU categoria: no es lo mismo una botnet que P2P, y cada
            # lista se trata distinto en el firewall
            _cat = categoria_cpe(clave)
            _lst = lista_de_categoria(_cat)
            try:
                ok, err = mk_add(ip, comment=f"suricata {_cat} riesgo {score} {time.strftime('%Y-%m-%d %H:%M')}",
                                 lista=_lst, ttl=_ttl_efectivo(m, "TTL"), router=r)
            except Exception as ex:
                ok, err = False, str(ex)
            if ok:
                env = cargar_enviados()
                # se guarda la LISTA usada: si manana cambia la categoria del CPE o el
                # nombre de la lista, hay que poder sacarlo de donde esta de verdad
                env[clave] = {"cuando": int(time.time()), "score": score, "por": getattr(CTX, "user", "?"),
                              "router": r.get("id", ""), "categoria": _cat, "lista": _lst,
                              "manual": clave not in cand_ips, "motivo": _motivo_bloqueo(clave)}
                guardar_enviados(env)
                mk_log("ENVIADO", ip, getattr(CTX, "user", "?"), f"lista={_lst} ttl={m.get('TTL')}"
                       + (" (manual)" if clave not in cand_ips else "") + _suf_nodo(clave))
                notificar_cuarentena(ip, "Infeccion CnC", m.get("LIST", ""), quien=getattr(CTX, "user", "?"))
                globals()["FORCE_REGEN"] = True   # regenerar pronto para que el Top muestre 'En cuarentena'
                nota = " (ya estaba en la lista)" if err else ""
                return _fin(True, f"{ip} en {_lst} ({nombre_categoria(_cat)}){nota}")
            mk_log("ERROR-ENVIO", ip, getattr(CTX, "user", "?"), err)
            return _fin(False, f"No se pudo enviar {ip}: {err}")
        if ruta in ("/cuarentena/destino/bloquear", "/cuarentena/destino/quitar"):
            if not self._operador():
                return self._deny()
            ip = (q.get("ip", [""])[0]).strip()
            ok_d, porque = destino_bloqueable(ip)
            if not ok_d:
                return self._redirect("/cuarentena?msg=" + _up.quote(f"{ip}: {porque}"))
            quitar = ruta.endswith("/quitar")
            hechos, errores = 0, []
            # se manda a TODOS los nodos: el destino es malo para todos los abonados,
            # no solo para los de un router
            for r in cargar_routers():
                d = cargar_mk_de(r)
                if not mk_listo(d):
                    continue
                lst = d.get("LIST_DST", "suricata-destinos-malos")
                try:
                    if quitar:
                        ok, err = mk_remove(ip, lista=lst, router=r)
                    else:
                        ok, err = mk_add(ip, comment=f"suricata destino malo {time.strftime('%Y-%m-%d %H:%M')}",
                                         lista=lst, ttl=_ttl_efectivo(d, "TTL_DST"), router=r)
                except Exception as ex:
                    ok, err = False, str(ex)
                if ok:
                    hechos += 1
                else:
                    errores.append(f"{r.get('nombre') or r.get('id')}: {err}")
            if hechos:
                env = cargar_enviados(MK_SENT_DST)
                if quitar:
                    env.pop(ip, None)
                else:
                    dd = (cargar_destinos_malos().get(ip) or {})
                    env[ip] = {"cuando": int(time.time()), "por": getattr(CTX, "user", "?"),
                               "fuente": dd.get("fuente", ""), "categoria": dd.get("categoria", ""),
                               "nodos": hechos}
                guardar_enviados(env, MK_SENT_DST)
                mk_log("DESTINO-QUITADO" if quitar else "DESTINO-BLOQUEADO", ip,
                       getattr(CTX, "user", "?"), f"nodos={hechos}")
            msg = (f"{ip}: {'desbloqueado' if quitar else 'bloqueado'} en {hechos} nodo(s)"
                   if hechos else f"No se pudo: {'; '.join(errores[:2]) or 'ningun MikroTik habilitado'}")
            return self._redirect("/cuarentena?msg=" + _up.quote(msg))
        if ruta == "/cuarentena/graduada":
            # Corte PARCIAL: se le cortan los puertos de abuso y se le deja el resto. El
            # abonado sigue navegando, no llama a soporte, y por eso el corte aguanta.
            if not self._operador():
                return self._deny()
            ajax_g = bool(q.get("ajax"))
            def _fin_g(okr, texto):
                if ajax_g:
                    b = (("OK " if okr else "ERR: ") + texto).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers(); self.wfile.write(b)
                    return
                return self._redirect("/cuarentena?msg=" + _up.quote(texto))
            clave = (q.get("ip", [""])[0]).strip()
            ip = ip_de(clave)
            score = (q.get("score", [""])[0]).strip()[:8]
            try:
                ipaddress.ip_address(ip)
            except Exception:
                return _fin_g(False, "IP invalida")
            if not es_mi_cpe(ip):
                return _fin_g(False, f"{ip} no es de tus redes")
            if nunca_bloquear(ip):
                return _fin_g(False, f"{ip} esta en la lista 'Nunca bloquear'")
            _pub = es_publica_declarada(ip)
            if _pub:
                return _fin_g(False, f"{ip} es una de TUS publicas ({_pub}): cortarla "
                                     f"dejaria sin servicio a todos los abonados de ese NAT")
            r = router_de_clave(clave); m = cargar_mk_de(r)
            if not mk_listo(m):
                return _fin_g(False, "Configura y HABILITA el MikroTik en Ajustes primero")
            lst = m.get("LIST_GRAD", "suricata-graduada")
            try:
                ok, err = mk_add(ip, comment=f"suricata graduada riesgo {score} {time.strftime('%Y-%m-%d %H:%M')}",
                                 lista=lst, ttl=_ttl_efectivo(m, "TTL_GRAD"), router=r)
            except Exception as ex:
                ok, err = False, str(ex)
            if not ok:
                mk_log("ERROR-GRADUADA", ip, getattr(CTX, "user", "?"), err)
                return _fin_g(False, f"No se pudo enviar {ip}: {err}")
            env = cargar_enviados(MK_SENT_GRAD)
            env[clave] = {"cuando": int(time.time()), "score": score,
                          "por": getattr(CTX, "user", "?"), "router": r.get("id", ""),
                          "grad": True, "motivo": _motivo_bloqueo(clave)}
            guardar_enviados(env, MK_SENT_GRAD)
            mk_log("GRADUADA", ip, getattr(CTX, "user", "?"), f"lista={lst}" + _suf_nodo(clave))
            aviso = ""
            try:
                if not mk_lista_en_uso(lst, router=r):
                    aviso = (f" ATENCION: ninguna regla del firewall usa '{lst}', asi que "
                             f"ahora mismo no corta nada. Pegalas desde Ajustes -> MikroTik.")
            except Exception:
                pass
            return _fin_g(True, f"{ip} con corte parcial en {lst}{aviso}")
        if ruta == "/cuarentena/graduada/quitar":
            if not self._operador():
                return self._deny()
            clave = (q.get("ip", [""])[0]).strip()
            ip = ip_de(clave); rt = router_de_clave(clave)
            try:
                ipaddress.ip_address(ip)
            except Exception:
                return self._redirect("/cuarentena?msg=" + _up.quote("IP invalida"))
            lst = cargar_mk_de(rt).get("LIST_GRAD", "suricata-graduada")
            try:
                ok, err = mk_remove(ip, lista=lst, router=rt)
            except Exception as ex:
                ok, err = False, str(ex)
            if ok:
                quitar_enviados([clave], MK_SENT_GRAD)
            mk_log("GRADUADA-QUITADA" if ok else "ERROR-QUITAR", ip,
                   getattr(CTX, "user", "?"), f"lista={lst} {err}" + _suf_nodo(clave))
            return self._redirect("/cuarentena?msg=" + _up.quote(
                f"{ip}: corte parcial retirado" if ok else f"No se pudo quitar {ip}: {err}"))
        if ruta == "/cuarentena/enviar-todos":
            if not self._operador():
                return self._deny()
            m = cargar_mk()
            if not (mk_configurado() and m.get("ENABLED") == "1"):
                return self._redirect("/cuarentena?msg=" + _up.quote("Configura y HABILITA el MikroTik en Ajustes primero"))
            try:
                cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8")).get("candidatos", [])
            except Exception:
                cq = []
            env = cargar_enviados()
            # masivo: solo ALTA CONFIANZA (evidencia independiente); los sospechosos van a mano
            pend = [c for c in cq
                    if clave_cpe(c.get("ip", ""), c.get("router", "")) not in env
                    and c.get("confianza") == "alta"][:50]
            ok_n = err_n = 0; ult_err = ""
            for c in pend:
                clave = clave_cpe(c.get("ip", ""), c.get("router", "")); ip = ip_de(clave)
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    continue
                r = router_de_clave(clave); dr = cargar_mk_de(r)
                if not mk_listo(dr):
                    continue            # ese nodo esta en dry-run: no se le manda nada
                _cat = categoria_cpe(clave)
                _lst = lista_de_categoria(_cat)
                try:
                    ok, err = mk_add(ip, comment=f"suricata {_cat} riesgo {c.get('riesgo',0)} {time.strftime('%Y-%m-%d %H:%M')}",
                                     lista=_lst, ttl=_ttl_efectivo(dr, "TTL"), router=r)
                except Exception as ex:
                    ok, err = False, str(ex)
                if ok:
                    env[clave] = {"cuando": int(time.time()), "score": c.get("riesgo", 0), "por": getattr(CTX, "user", "?"),
                                  "router": r.get("id", ""), "categoria": _cat, "lista": _lst,
                                  "motivo": _motivo_bloqueo(clave)}
                    mk_log("ENVIADO", ip, getattr(CTX, "user", "?"), f"lista={_lst} (masivo)" + _suf_nodo(clave))
                    ok_n += 1
                else:
                    mk_log("ERROR-ENVIO", ip, getattr(CTX, "user", "?"), err); err_n += 1; ult_err = err
                    if "conexion" in (err or "").lower() or "login" in (err or "").lower():
                        break   # si el router no responde, no seguir intentando
            guardar_enviados(env)
            if ok_n:
                enviar_telegram(f"\U0001f6a8 Cuarentena masiva [{_hostname()}]: {ok_n} CPE de alta confianza "
                                f"a la lista '{m.get('LIST')}' por {getattr(CTX, 'user', '?')}")
            resumen = f"Enviados {ok_n} a cuarentena" + (f", {err_n} con error ({ult_err})" if err_n else "")
            return self._redirect("/cuarentena?msg=" + _up.quote(resumen))
        if ruta == "/cuarentena/quitar":
            if not self._operador():
                return self._deny()
            # primero se separa la identidad y luego se valida la IP: al reves, un
            # "router|IP" se rechazaba como "IP invalida" y el CPE no se podia liberar
            clave = (q.get("ip", [""])[0]).strip()
            ip = ip_de(clave); rt = router_de_clave(clave)
            try:
                ipaddress.ip_address(ip)
            except Exception:
                return self._redirect("/cuarentena?msg=" + _up.quote("IP invalida"))
            # de la lista donde esta DE VERDAD, no de la que toque hoy por categoria
            _guardada = (cargar_enviados(MK_SENT).get(clave) or {}).get("lista", "")
            try:
                ok, err = mk_remove(ip, lista=_guardada or cargar_mk_de(rt).get("LIST", ""),
                                    router=rt)
            except Exception as ex:
                ok, err = False, str(ex)
            # solo se saca del registro si el router confirmo: si falla y se borraba
            # igual, el CPE quedaba bloqueado en el router pero invisible en el panel,
            # sin forma de reintentarlo ni de liberarlo
            if ok:
                quitar_enviados([clave])
            mk_log("QUITADO" if ok else "ERROR-QUITAR", ip, getattr(CTX, "user", "?"), err)
            return self._redirect("/cuarentena?msg=" + _up.quote(f"{ip}: {err}" if ok else f"No se pudo quitar {ip}: {err}"))
        if ruta == "/cuarentena/quitar-uno":
            # Quita UNA IP y responde JSON enseguida. La usa el quitado masivo para ir
            # marcando el avance: cada IP es una llamada al MikroTik y en bloque puede
            # tardar bastante; asi se ve cual va saliendo en vez de una pantalla colgada.
            if not self._operador():
                return self._json({"ok": False, "err": "sin permiso"}, 403)
            # la seleccion llega como "cuar|IP" o, con varios nodos, "cuar|router|IP":
            # primero se separa el tipo de lista, y lo que queda ES la identidad del CPE
            tipo, _, clave = (q.get("sel", [""])[0] or "").partition("|")
            clave = clave.strip()
            ip = ip_de(clave)
            try:
                ipaddress.ip_address(ip)
            except Exception:
                return self._json({"ok": False, "ip": ip, "err": "IP invalida"})
            es_dns = (tipo == "dns")
            reg = MK_SENT_DNS if es_dns else MK_SENT
            rt = router_de_clave(clave)
            # La IP debe estar en ESE registro. Si no, mk_remove consultaria la otra
            # address-list, no encontraria nada y devolveria "0 entradas quitadas" como
            # exito: saldria un visto bueno sin haber quitado nada del router.
            if clave not in cargar_enviados(reg):
                return self._json({"ok": False, "ip": ip,
                                   "err": "no esta en esa lista del panel"})
            lst = cargar_mk_de(rt).get("LIST_DNS", "suricata-dns-sospechoso") if es_dns else ""
            try:
                ok, err = (mk_remove(ip, lista=lst, router=rt) if es_dns
                           else mk_remove(ip, router=rt))
            except Exception as ex:
                ok, err = False, str(ex)
            if ok:
                quitar_enviados([clave], reg)
            mk_log("QUITADO" if ok else "ERROR-QUITAR", ip, getattr(CTX, "user", "?"),
                   (f"lista={lst} " if es_dns else "") + f"masivo {err}" + _suf_nodo(clave))
            return self._json({"ok": bool(ok), "ip": ip, "err": "" if ok else (err or "fallo")})
        if ruta == "/cuarentena/quitar-varios":
            # quitado masivo desde la tabla "Enviados manualmente". Cada seleccion llega como
            # "cuar|IP" o "dns|IP" porque cada una vive en una address-list distinta.
            if not self._operador():
                return self._deny()
            sels = q.get("sel", [])
            if not sels:
                return self._redirect("/cuarentena?msg=" + _up.quote("No seleccionaste ninguna IP"))
            m = cargar_mk(); lst_dns = m.get("LIST_DNS", "suricata-dns-sospechoso")
            quien = getattr(CTX, "user", "?")
            TOPE = 500                          # tope defensivo por si llega un POST enorme
            sobran = max(0, len(sels) - TOPE)
            en_reg = {MK_SENT: cargar_enviados(MK_SENT), MK_SENT_DNS: cargar_enviados(MK_SENT_DNS)}
            quitadas = {MK_SENT: [], MK_SENT_DNS: []}
            errores = []; corte = ""
            for s in sels[:TOPE]:
                tipo, _, clave = (s or "").partition("|")
                clave = clave.strip(); ip = ip_de(clave)
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    errores.append(f"{ip or '?'} (IP invalida)"); continue
                reg = MK_SENT_DNS if tipo == "dns" else MK_SENT
                rt = router_de_clave(clave)
                if clave not in en_reg[reg]:   # evita el falso exito de "0 entradas quitadas"
                    errores.append(f"{ip} (no esta en esa lista)"); continue
                _ld = cargar_mk_de(rt).get("LIST_DNS", lst_dns)
                try:
                    ok, err = (mk_remove(ip, lista=_ld, router=rt) if reg == MK_SENT_DNS
                               else mk_remove(ip, router=rt))
                except Exception as ex:
                    ok, err = False, str(ex)
                if ok:
                    quitadas[reg].append(clave)
                else:
                    errores.append(f"{ip} ({err})")
                mk_log("QUITADO" if ok else "ERROR-QUITAR", ip, quien,
                       (f"lista={lst_dns} " if reg == MK_SENT_DNS else "") + f"masivo {err}")
                if not ok and ("conexion" in (err or "") or "login" in (err or "")):
                    # el router no responde: seguir seria esperar el timeout por cada IP
                    # (500 x 6 s = mas de 45 min con el navegador esperando). Igual que
                    # hace "Enviar todos".
                    corte = " Se corto: el MikroTik no responde."
                    break
            # Se sacan del registro releyendo dentro del cerrojo: entre el primer mk_remove
            # y este punto pueden haber pasado minutos, y guardar la foto de antes borraria
            # lo que el hilo de fondo anoto mientras tanto.
            n_ok = 0
            for reg, ips in quitadas.items():
                n_ok += len(quitar_enviados(ips, reg))
            resumen = f"{n_ok} entrada(s) quitada(s)"
            if errores:
                resumen += f"; {len(errores)} con error: " + ", ".join(errores[:3])
                if len(errores) > 3:
                    resumen += f" y {len(errores)-3} mas"
            if sobran:
                resumen += f". Quedan {sobran} sin procesar (tope de {TOPE} por peticion): repite la operacion."
            return self._redirect("/cuarentena?msg=" + _up.quote(resumen + corte))
        if ruta == "/cuarentena/excluir-destino":
            if not self._operador():
                return self._deny()
            n, msg = excluir_destino((q.get("destino", [""])[0]).strip())
            return self._redirect("/cuarentena?msg=" + _up.quote(msg))
        if ruta == "/cuarentena/quitar-destino":
            if not self._operador():
                return self._deny()
            d = (q.get("destino", [""])[0]).strip()
            cur = _dest_ok_set(); cur.discard(d); guardar_dest_ok_set(cur)
            globals()["FORCE_REGEN"] = True
            bitacora("QUITAR-DESTINO-CONFIABLE", d)
            return self._redirect("/cuarentena?msg=" + _up.quote(f"'{d}' ya no es destino confiable"))
        if ruta in ("/cuarentena/dns/enviar", "/cuarentena/dns/quitar", "/cuarentena/dns/enviar-todos"):
            if not self._operador():
                return self._deny()
            m = cargar_mk(); lst = m.get("LIST_DNS", "suricata-dns-sospechoso"); ttl = _ttl_efectivo(m, "TTL_DNS")
            if ruta == "/cuarentena/dns/quitar":
                clave = (q.get("ip", [""])[0]).strip()
                ip = ip_de(clave); rt = router_de_clave(clave)
                try: ipaddress.ip_address(ip)
                except Exception: return self._redirect("/cuarentena?msg=" + _up.quote("IP invalida"))
                lst = cargar_mk_de(rt).get("LIST_DNS", lst)
                try: ok, err = mk_remove(ip, lista=lst, router=rt)
                except Exception as ex: ok, err = False, str(ex)
                if ok:                      # igual que la de infectados: solo si el router confirmo
                    quitar_enviados([clave], MK_SENT_DNS)
                mk_log("QUITADO" if ok else "ERROR-QUITAR", ip, getattr(CTX, "user", "?"), f"lista={lst} {err}")
                return self._redirect("/cuarentena?msg=" + _up.quote(f"{ip}: {err}" if ok else f"No se pudo quitar {ip}: {err}"))
            if not (mk_configurado() and m.get("ENABLED") == "1"):
                return self._redirect("/cuarentena?msg=" + _up.quote("Configura y HABILITA el MikroTik en Ajustes primero"))
            if ruta == "/cuarentena/dns/enviar":
                clave = (q.get("ip", [""])[0]).strip()
                ip = ip_de(clave); score = (q.get("score", [""])[0]).strip()[:8]
                try: ipaddress.ip_address(ip)
                except Exception: return self._redirect("/cuarentena?msg=" + _up.quote("IP invalida"))
                if not es_mi_cpe(ip):
                    return self._redirect("/cuarentena?msg=" + _up.quote(
                        f"{ip} no es de tus redes: se corta en el borde, no en la cuarentena de CPEs"))
                if nunca_bloquear(ip):
                    return self._redirect("/cuarentena?msg=" + _up.quote(f"{ip} esta en la lista 'Nunca bloquear'"))
                rt = router_de_clave(clave); dr = cargar_mk_de(rt)
                if not mk_listo(dr):
                    return self._redirect("/cuarentena?msg=" + _up.quote("Ese MikroTik no esta habilitado para enviar"))
                lst = dr.get("LIST_DNS", lst); ttl = _ttl_efectivo(dr, "TTL_DNS")
                try: ok, err = mk_add(ip, comment=f"suricata DNS-sospechoso riesgo {score} {time.strftime('%Y-%m-%d %H:%M')}", lista=lst, ttl=ttl, router=rt)
                except Exception as ex: ok, err = False, str(ex)
                if ok:
                    env = cargar_enviados(MK_SENT_DNS)
                    env[clave] = {"cuando": int(time.time()), "score": score, "por": getattr(CTX, "user", "?"),
                                  "router": rt.get("id", ""), "motivo": _motivo_bloqueo(clave)}
                    guardar_enviados(env, MK_SENT_DNS)
                    mk_log("ENVIADO", ip, getattr(CTX, "user", "?"), f"lista={lst} (dns)" + _suf_nodo(clave))
                    notificar_cuarentena(ip, "DNS sospechoso", lst, quien=getattr(CTX, "user", "?"))
                    return self._redirect("/cuarentena?msg=" + _up.quote(f"{ip} enviado a la lista {lst}"))
                mk_log("ERROR-ENVIO", ip, getattr(CTX, "user", "?"), f"lista={lst} {err}")
                return self._redirect("/cuarentena?msg=" + _up.quote(f"No se pudo enviar {ip}: {err}"))
            # enviar-todos DNS
            try:
                cq = json.load(open(f"{LOGDIR}/cuarentena.json", encoding="utf-8")).get("dns_candidatos", [])
            except Exception:
                cq = []
            env = cargar_enviados(MK_SENT_DNS)
            pend = [c for c in cq
                    if clave_cpe(c.get("ip", ""), c.get("router", "")) not in env
                    and c.get("confianza") == "alta"][:50]
            ok_n = err_n = 0; ult_err = ""
            for c in pend:
                clave = clave_cpe(c.get("ip", ""), c.get("router", "")); ip = ip_de(clave)
                try: ipaddress.ip_address(ip)
                except Exception: continue
                rt = router_de_clave(clave); dr = cargar_mk_de(rt)
                if not mk_listo(dr):
                    continue            # ese nodo esta en dry-run: no se le manda nada
                _ld = dr.get("LIST_DNS", lst)
                try: ok, err = mk_add(ip, comment=f"suricata DNS-sospechoso riesgo {c.get('riesgo',0)} {time.strftime('%Y-%m-%d %H:%M')}", lista=_ld, ttl=_ttl_efectivo(dr, "TTL_DNS"), router=rt)
                except Exception as ex: ok, err = False, str(ex)
                if ok:
                    env[clave] = {"cuando": int(time.time()), "score": c.get("riesgo", 0), "por": getattr(CTX, "user", "?"),
                                  "router": rt.get("id", ""), "motivo": _motivo_bloqueo(clave)}
                    mk_log("ENVIADO", ip, getattr(CTX, "user", "?"), f"lista={_ld} (dns masivo)" + _suf_nodo(clave)); ok_n += 1
                else:
                    mk_log("ERROR-ENVIO", ip, getattr(CTX, "user", "?"), f"lista={lst} {err}"); err_n += 1; ult_err = err
                    if "conexion" in (err or "").lower() or "login" in (err or "").lower():
                        break
            guardar_enviados(env, MK_SENT_DNS)
            if ok_n:
                enviar_telegram(f"\U0001f6a8 DNS sospechoso masivo [{_hostname()}]: {ok_n} CPE de alta confianza "
                                f"a la lista '{lst}' por {getattr(CTX, 'user', '?')}")
            return self._redirect("/cuarentena?msg=" + _up.quote(f"Enviados {ok_n} a {lst}" + (f", {err_n} con error ({ult_err})" if err_n else "")))
        return self._html("<h1>No encontrado</h1>", 404)

    def _post_perfil(self, q):
        accion = q.get("accion", ["mi_clave"])[0]
        yo = CTX.user
        # --- cambiar MI clave (cualquier usuario) ---
        if accion == "mi_clave":
            actual = q.get("actual", [""])[0]
            nueva = q.get("nueva", [""])[0]
            nueva2 = q.get("nueva2", [""])[0]
            if not yo or not verificar_login(yo, actual):
                return self._html(perfil_page("La clave actual no es correcta.", ok=False))
            if len(nueva) < 6:
                return self._html(perfil_page("La clave nueva debe tener al menos 6 caracteres.", ok=False))
            if nueva != nueva2:
                return self._html(perfil_page("Las dos claves nuevas no coinciden.", ok=False))
            us = cargar_usuarios()
            for r in us:
                if r.get("user") == yo:
                    r["salt"], r["hash"] = _hash_pw(nueva)
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            return self._html(perfil_page("Tu clave fue actualizada.", ok=True))
        # --- cambiar MI foto (cualquier usuario) ---
        if accion == "mi_foto":
            foto = q.get("avatar", [""])[0]
            if foto and foto != "__BORRAR__" and (not foto.startswith("data:image/") or len(foto) > 300_000):
                return self._html(perfil_page("La foto no es una imagen valida o pesa demasiado.", ok=False))
            if not foto:
                return self._html(perfil_page("Elige una imagen primero.", ok=False))
            us = cargar_usuarios()
            for r in us:
                if r.get("user") == yo:
                    r["avatar"] = "" if foto == "__BORRAR__" else foto
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            return self._html(perfil_page("Tu foto fue actualizada." if foto != "__BORRAR__" else "Foto quitada.", ok=True))
        # --- gestion de usuarios (solo admin) ---
        if not self._admin():
            return self._deny()
        if accion == "unlock_ip":
            ip = q.get("ip", [""])[0].strip()
            existia = LOGIN_FAILS.pop(ip, None)
            login_registrar(self._client_ip(), CTX.user or "?", f"DESBLOQUEO {ip}")
            return self._html(perfil_page(f"IP {ip} desbloqueada." if existia else f"La IP {ip} no estaba bloqueada.", ok=bool(existia)))
        if accion == "add_trust":
            import ipaddress
            val = q.get("ip", [""])[0].strip()
            try:
                ipaddress.ip_network(val, strict=False)
            except ValueError:
                return self._html(perfil_page("IP o CIDR invalido.", ok=False))
            lst = cargar_confianza()
            if val in lst:
                return self._html(perfil_page("Esa IP ya esta en la lista.", ok=False))
            nueva = lst + [val]
            # proteccion: no habilitar/ampliar la lista si tu IP actual queda fuera
            if not ip_en_lista(self._client_ip(), nueva):
                return self._html(perfil_page(
                    f"Agrega primero tu IP actual ({self._client_ip()}) o quedarias fuera del panel.", ok=False))
            try:
                guardar_confianza(nueva)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            return self._html(perfil_page(f"IP de confianza agregada: {val}. Ahora solo estas IPs pueden entrar.", ok=True))
        if accion == "del_trust":
            val = q.get("ip", [""])[0]
            nueva = [x for x in cargar_confianza() if x != val]
            if nueva and not ip_en_lista(self._client_ip(), nueva):
                return self._html(perfil_page("No puedes quitar tu propia IP mientras la lista siga activa.", ok=False))
            try:
                guardar_confianza(nueva)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            extra = " La lista quedo vacia: acceso abierto con bloqueo por fallos." if not nueva else ""
            return self._html(perfil_page(f"IP {val} quitada de confianza.{extra}", ok=True))
        if accion == "add_user":
            nu = (q.get("nuser", [""])[0]).strip()
            npw = q.get("npass", [""])[0]
            nrole = q.get("nrole", ["lectura"])[0]
            nombre = (q.get("nnombre", [""])[0]).strip()[:60]
            correo = (q.get("ncorreo", [""])[0]).strip()[:80]
            foto = q.get("avatar", [""])[0]
            if nrole not in ROLES:
                nrole = "lectura"
            if not nu or " " in nu or len(nu) > 40:
                return self._html(perfil_page("Usuario invalido (sin espacios, max 40).", ok=False))
            if len(npw) < 6:
                return self._html(perfil_page("La clave del usuario debe tener al menos 6 caracteres.", ok=False))
            if foto and (not foto.startswith("data:image/") or len(foto) > 300_000):
                return self._html(perfil_page("La foto no es una imagen valida o pesa demasiado.", ok=False))
            us = cargar_usuarios()
            if any(r.get("user") == nu for r in us):
                return self._html(perfil_page(f"Ya existe un usuario llamado {nu}.", ok=False))
            salt, h = _hash_pw(npw)
            us.append({"user": nu, "salt": salt, "hash": h, "role": nrole,
                       "nombre": nombre, "correo": correo, "activo": True, "avatar": foto})
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            bitacora("USUARIO-CREADO", f"{nu} rol={nrole}")
            return self._html(perfil_page(f"Usuario '{nu}' creado como {nrole}.", ok=True))
        if accion == "del_user":
            objetivo = q.get("user", [""])[0]
            us = cargar_usuarios()
            admins = [r for r in us if r.get("role") == "admin"]
            obj = next((r for r in us if r.get("user") == objetivo), None)
            if not obj:
                return self._html(perfil_page("Ese usuario no existe.", ok=False))
            if obj.get("role") == "admin" and len(admins) <= 1:
                return self._html(perfil_page("No puedes borrar el unico administrador.", ok=False))
            us = [r for r in us if r.get("user") != objetivo]
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            bitacora("USUARIO-ELIMINADO", objetivo)
            # si borra su propia cuenta, cerrar su sesion
            if objetivo == yo:
                SESSIONS.pop(self._sid(), None)
                return self._redirect("/login", cookie="sid=; Path=/; Max-Age=0")
            return self._html(perfil_page(f"Usuario '{objetivo}' eliminado.", ok=True))
        if accion == "rol_user":
            objetivo = q.get("user", [""])[0]
            nrole = q.get("role", ["lectura"])[0]
            if nrole not in ROLES:
                return self._html(perfil_page("Rol invalido.", ok=False))
            us = cargar_usuarios()
            admins = [r for r in us if r.get("role") == "admin"]
            obj = next((r for r in us if r.get("user") == objetivo), None)
            if not obj:
                return self._html(perfil_page("Ese usuario no existe.", ok=False))
            if obj.get("role") == "admin" and nrole != "admin" and len(admins) <= 1:
                return self._html(perfil_page("No puedes quitar el rol al unico administrador.", ok=False))
            obj["role"] = nrole
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            bitacora("USUARIO-ROL", f"{objetivo} -> {nrole}")
            return self._html(perfil_page(f"'{objetivo}' ahora es {nrole}.", ok=True))
        if accion == "edit_user":
            objetivo = q.get("user", [""])[0]
            nombre = (q.get("nombre", [""])[0]).strip()[:60]
            correo = (q.get("correo", [""])[0]).strip()[:80]
            nrole = q.get("role", ["lectura"])[0]
            npw = q.get("npass", [""])[0]
            if nrole not in ROLES:
                return self._html(perfil_page("Rol invalido.", ok=False))
            us = cargar_usuarios()
            admins = [r for r in us if r.get("role") == "admin"]
            obj = next((r for r in us if r.get("user") == objetivo), None)
            if not obj:
                return self._html(perfil_page("Ese usuario no existe.", ok=False))
            if obj.get("role") == "admin" and nrole != "admin" and len(admins) <= 1:
                return self._html(perfil_page("No puedes quitar el rol al unico administrador.", ok=False))
            foto = q.get("avatar", [""])[0]
            if npw:
                if len(npw) < 6:
                    return self._html(perfil_page("La clave nueva debe tener al menos 6 caracteres.", ok=False))
                obj["salt"], obj["hash"] = _hash_pw(npw)
            if foto == "__BORRAR__":
                obj["avatar"] = ""
            elif foto:
                if not foto.startswith("data:image/") or len(foto) > 300_000:
                    return self._html(perfil_page("La foto no es una imagen valida o pesa demasiado.", ok=False))
                obj["avatar"] = foto
            obj["nombre"] = nombre; obj["correo"] = correo; obj["role"] = nrole
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            bitacora("USUARIO-EDITADO", f"{objetivo} rol={nrole}")
            return self._html(perfil_page(f"Usuario '{objetivo}' actualizado.", ok=True))
        if accion == "toggle_user":
            objetivo = q.get("user", [""])[0]
            us = cargar_usuarios()
            obj = next((r for r in us if r.get("user") == objetivo), None)
            if not obj:
                return self._html(perfil_page("Ese usuario no existe.", ok=False))
            act_admins = [r for r in us if r.get("role") == "admin" and r.get("activo", True)]
            va_desactivar = obj.get("activo", True)
            if va_desactivar and obj.get("role") == "admin" and len(act_admins) <= 1:
                return self._html(perfil_page("No puedes desactivar el unico administrador activo.", ok=False))
            obj["activo"] = not va_desactivar
            try:
                guardar_usuarios(us)
            except OSError as ex:
                return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
            if not obj["activo"] and objetivo == yo:
                SESSIONS.pop(self._sid(), None); _guardar_sesiones()
                return self._redirect("/login", cookie="sid=; Path=/; Max-Age=0")
            estado = "activado" if obj["activo"] else "desactivado"
            return self._html(perfil_page(f"Usuario '{objetivo}' {estado}.", ok=True))
        return self._html(perfil_page("Accion no reconocida.", ok=False))

    def _post_exclusiones(self, q):
        import ipaddress
        accion = q.get("accion", [""])[0]
        # trabajar solo con las reglas propias (no las legacy del .conf); incluir vencidas
        # para que los indices coincidan con lo que muestra exclusiones_page.
        propias = [r for r in cargar_exclusiones(incluir_vencidas=True) if r.get("motivo") != "(conf)"]
        if accion == "import":
            try:
                data = json.loads(q.get("json", [""])[0])
            except Exception:
                return self._html(exclusiones_page("El archivo no es JSON valido.", ok=False))
            if not isinstance(data, list):
                return self._html(exclusiones_page("El JSON debe ser una lista de exclusiones.", ok=False))
            limpio = []
            for r in data:
                if not isinstance(r, dict):
                    continue
                ip = str(r.get("ip", "")).strip()
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                tipo = r.get("tipo", "dst"); tipo = tipo if tipo in ("src", "dst") else "dst"
                pts = []
                for p in (r.get("puertos") or []):
                    try:
                        p = int(p)
                        if 0 < p < 65536:
                            pts.append(p)
                    except (ValueError, TypeError):
                        pass
                sid = str(r.get("sid") or "").strip(); sid = sid if sid.isdigit() else ""
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                limpio.append({"tipo": tipo, "ip": ip, "motivo": str(r.get("motivo", ""))[:80],
                               "puertos": pts, "sid": sid, "hasta": hasta,
                               "autor": str(r.get("autor", ""))[:40], "creado": r.get("creado", 0)})
            try:
                guardar_exclusiones(limpio)
            except OSError as ex:
                return self._html(exclusiones_page(f"No se pudo guardar: {ex}", ok=False))
            return self._html(exclusiones_page(
                f"Importadas {len(limpio)} exclusiones (reemplazaron las anteriores).", ok=True))
        if accion == "del":
            try:
                idx = int(q.get("idx", ["-1"])[0])
                todas = cargar_exclusiones(incluir_vencidas=True)
                objetivo = todas[idx]
                if objetivo.get("motivo") == "(conf)":
                    return self._html(exclusiones_page("Esa exclusion esta en el archivo .conf; quitala alli.", ok=False))
                propias = [r for r in propias if not (r["ip"] == objetivo["ip"] and r["tipo"] == objetivo["tipo"]
                           and r["puertos"] == objetivo["puertos"] and r.get("sid", "") == objetivo.get("sid", ""))]
                guardar_exclusiones(propias)
                return self._html(exclusiones_page("Exclusion eliminada.", ok=True))
            except Exception:
                return self._html(exclusiones_page("No se pudo eliminar.", ok=False))
        # agregar
        tipo = q.get("tipo", ["dst"])[0]
        ip = (q.get("ip", [""])[0]).strip()
        motivo = (q.get("motivo", [""])[0]).strip()[:80]
        pts_raw = (q.get("puertos", [""])[0]).strip()
        sid = (q.get("sid", [""])[0]).strip()
        vig = (q.get("vigencia", ["0"])[0]).strip()
        if tipo not in ("dst", "src"):
            tipo = "dst"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self._html(exclusiones_page("IP invalida.", ok=False))
        if sid and not sid.isdigit():
            return self._html(exclusiones_page("La firma (SID) debe ser un numero (o vacio).", ok=False))
        puertos = []
        for p in pts_raw.replace(";", ",").split(","):
            p = p.strip()
            if p:
                if not p.isdigit() or not (0 < int(p) < 65536):
                    return self._html(exclusiones_page(f"Puerto invalido: {p}", ok=False))
                puertos.append(int(p))
        editar = q.get("editar", [""])[0]
        edit_idx = int(editar) if (editar.isdigit() and int(editar) < len(propias)) else None
        # vigencia -> hasta (epoch). "keep" conserva la de la regla que se edita.
        ahora = int(time.time())
        if vig == "keep" and edit_idx is not None:
            hasta = propias[edit_idx].get("hasta") or 0
        else:
            try: horas = int(vig)
            except ValueError: horas = 0
            hasta = (ahora + horas * 3600) if horas > 0 else 0
        autor = getattr(CTX, "user", "") or ""
        creado = (propias[edit_idx].get("creado") if edit_idx is not None else 0) or ahora
        nueva = {"tipo": tipo, "ip": ip, "motivo": motivo, "puertos": puertos,
                 "sid": sid, "hasta": hasta, "autor": autor, "creado": creado}
        tlabel = "origen" if tipo == "src" else "destino"

        def _redundante(ex_ports):
            # ¿la exclusion existente ya cubre lo que pide la nueva? (una exclusion puede ser por puerto)
            ex_ports = ex_ports or []
            if not ex_ports:
                return True, "todos los puertos"          # la existente cubre todo
            if not puertos:
                return False, ""                           # la nueva pide todos; la existente solo algunos
            inter = sorted(set(ex_ports) & set(puertos))
            if inter:
                que = "el puerto " if len(inter) == 1 else "los puertos "
                return True, que + ", ".join(str(x) for x in inter)
            return False, ""                               # misma IP pero puertos distintos: se permite

        # duplicado: misma IP + mismo tipo + puerto que se solapa (ignora la fila que se edita)
        for j, r in enumerate(propias):
            if j == edit_idx:
                continue
            if r.get("sid", "") != sid:                  # distinta firma = alcance distinto, se permite
                continue
            if r.get("ip") == ip and r.get("tipo") == tipo:
                dup, txt = _redundante(r.get("puertos"))
                if dup:
                    return self._html(exclusiones_page(
                        f"Esa IP ya esta excluida como {tlabel} en {txt}: {ip}. No se agrego para no duplicar.",
                        ok=False, edit_idx=edit_idx))
        # tambien si ya viene excluida por el archivo .conf (legacy, no editable aqui)
        for r in cargar_exclusiones():
            if sid:                                      # una regla por-firma no choca con las del .conf (globales)
                break
            if r.get("motivo") == "(conf)" and r.get("ip") == ip and r.get("tipo") == tipo:
                dup, txt = _redundante(r.get("puertos"))
                if dup:
                    return self._html(exclusiones_page(
                        f"Esa IP ya esta excluida por configuracion (.conf) como {tlabel} en {txt}: {ip}.", ok=False))
        if edit_idx is not None:
            propias[edit_idx] = nueva
            msg_ok = f"Exclusion actualizada: {ip}."
        else:
            propias.append(nueva)
            msg_ok = f"Exclusion agregada: {ip}."
        try:
            guardar_exclusiones(propias)
        except OSError as ex:
            return self._html(exclusiones_page(f"No se pudo guardar: {ex}", ok=False))
        return self._html(exclusiones_page(msg_ok, ok=True))

    def do_HEAD(self):
        # respuesta ligera para health-checks del proxy (evita el 501 y es instantanea)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass

def main():
    port = int(CFG.get("PORT", "5637"))
    cargar_usuarios()   # migra el usuario del .conf al almacen hasheado si aun no existe
    threading.Thread(target=refrescador, daemon=True).start()
    bind = CFG.get("BIND", "0.0.0.0") or "0.0.0.0"
    httpd = ThreadingHTTPServer((bind, port), H)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
DASH
chmod 755 /usr/local/bin/suricata-dashboard

# Actualizador del PANEL: baja la ultima version del repo y reemplaza SOLO el codigo del
# panel y del generador de reportes. NO toca configuracion (usuarios, exclusiones, empresa,
# IPs de confianza, .conf, suricata.yaml/HOME_NET ni las units systemd).
cat > /usr/local/bin/suricata-panel-update <<'UPDSH'
#!/bin/sh
set -e
REPO_USER="mtandazo35"; REPO_NAME="suricata-ids-lab"; REPO_BRANCH="main"
TMP="$(mktemp)"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> /tmp/suricata-panel-update.log; }
trap 'rm -f "$TMP"' EXIT
# raw.githubusercontent tiene cache CDN (~5 min): recien pusheado servia la version VIEJA.
# Se pide el SHA del ultimo commit por la API (sin ese cache) y se baja ESE commit exacto
# (URL inmutable => siempre lo ultimo). Si la API falla, se cae a main con nocache.
SHA="$(curl -fsSL -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/${REPO_USER}/${REPO_NAME}/commits/${REPO_BRANCH}" 2>/dev/null \
  | grep -m1 '"sha"' | cut -d'"' -f4)"
if [ -n "$SHA" ]; then
  URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${SHA}/install-suricata.sh"
  log "descargando commit ${SHA}"
else
  URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${REPO_BRANCH}/install-suricata.sh?nc=$(date +%s)"
  log "API sin SHA; bajando ${REPO_BRANCH} con nocache"
fi
curl -fsSL "$URL" -o "$TMP" || { log "descarga fallo"; exit 1; }
extraer() { # $1=linea-inicio (substr)  $2=marcador-fin  $3=destino  $4=validador(py|sh)
  # !f: solo marca el inicio la PRIMERA vez, asi las lineas del cuerpo que contengan el
  # marcador (p.ej. el propio actualizador) no rompen la extraccion.
  awk -v s="$1" -v e="$2" '!f && index($0,s){f=1;next} f&&$0==e{exit} f{print}' "$TMP" > "$3.new"
  [ -s "$3.new" ] || { log "extraccion vacia: $3"; return 1; }
  if [ "$4" = "sh" ]; then
    sh -n "$3.new" || { log "sh invalido: $3"; return 1; }
  else
    python3 -c "import ast,sys;ast.parse(open(sys.argv[1]).read())" "$3.new" || { log "py invalido: $3"; return 1; }
  fi
}
extraer "cat > /usr/local/bin/suricata-dashboard <<'DASH'" "DASH" /usr/local/bin/suricata-dashboard py || exit 1
extraer "cat > /usr/local/bin/suricata-html-report <<'HREP'" "HREP" /usr/local/bin/suricata-html-report py || exit 1
# feeds de reputacion: script + cron (si falla, se sigue con lo demas)
extraer "cat > /usr/local/bin/suricata-feeds-update <<'FEEDS'" "FEEDS" /usr/local/bin/suricata-feeds-update py || log "no se autoactualizo feeds-update"
# el actualizador se auto-actualiza tambien (si falla, se sigue con lo demas)
extraer "cat > /usr/local/bin/suricata-panel-update <<'UPDSH'" "UPDSH" /usr/local/bin/suricata-panel-update sh || log "no se autoactualizo el updater"
# respaldo de la version ACTUAL antes de sobrescribir, para poder revertir si el panel no levanta
BKP="/root/backups/panel/$(date +%F-%H%M%S)"
mkdir -p "$BKP"
for f in suricata-dashboard suricata-html-report suricata-panel-update suricata-feeds-update; do
  [ -f "/usr/local/bin/$f" ] && cp -p "/usr/local/bin/$f" "$BKP/$f" 2>/dev/null
done
[ -f /etc/suricata-dashboard.commit ] && cp -p /etc/suricata-dashboard.commit "$BKP/commit" 2>/dev/null
[ -f /etc/suricata-dashboard.updated ] && cp -p /etc/suricata-dashboard.updated "$BKP/updated" 2>/dev/null
ls -1dt /root/backups/panel/*/ 2>/dev/null | tail -n +6 | xargs -r rm -rf --   # conservar 5 respaldos
log "respaldo previo en $BKP"
# aplicar (dashboard y report son obligatorios; el updater si se pudo)
mv /usr/local/bin/suricata-dashboard.new     /usr/local/bin/suricata-dashboard
mv /usr/local/bin/suricata-html-report.new   /usr/local/bin/suricata-html-report
[ -f /usr/local/bin/suricata-panel-update.new ] && mv /usr/local/bin/suricata-panel-update.new /usr/local/bin/suricata-panel-update
[ -f /usr/local/bin/suricata-feeds-update.new ] && mv /usr/local/bin/suricata-feeds-update.new /usr/local/bin/suricata-feeds-update
chmod 755 /usr/local/bin/suricata-dashboard /usr/local/bin/suricata-html-report /usr/local/bin/suricata-panel-update
[ -f /usr/local/bin/suricata-feeds-update ] && chmod 755 /usr/local/bin/suricata-feeds-update
# cron de feeds (cada 15 min; intervalo minimo por fuente) y primera carga; migra el cron viejo
if [ -f /usr/local/bin/suricata-feeds-update ]; then
  printf '# Refresca los feeds de reputacion del panel Suricata (falla suave, intervalo por fuente)\n*/15 * * * * root /usr/local/bin/suricata-feeds-update >> /var/log/suricata-feeds.log 2>&1\n' > /etc/cron.d/suricata-feeds
  chmod 644 /etc/cron.d/suricata-feeds
fi
[ -f /var/lib/suricata-feeds/reputation.lst ] || /usr/local/bin/suricata-feeds-update >> /var/log/suricata-feeds.log 2>&1 || true
# re-generar reputation.lst con procedencia (indicador<TAB>fuente): si el box tiene el
# formato viejo (sin TAB) y hay fuentes, correr el actualizador una vez para migrar.
if [ -f /var/lib/suricata-feeds/reputation.lst ] && ! grep -q "$(printf '\t')" /var/lib/suricata-feeds/reputation.lst 2>/dev/null; then
  /usr/local/bin/suricata-feeds-update >> /var/log/suricata-feeds.log 2>&1 || true
fi
date '+%Y-%m-%d %H:%M:%S' > /etc/suricata-dashboard.updated
# registrar el SHA aplicado: el panel compara este valor con el ultimo commit de GitHub
# para saber si hay actualizacion disponible y listar las mejoras nuevas.
[ -n "$SHA" ] && printf '%s' "$SHA" > /etc/suricata-dashboard.commit
rm -f /var/log/suricata-update-check.json   # invalidar el cache: ya no hay update pendiente
log "actualizado OK (${SHA:-main}); regenerando reporte y reiniciando panel"
# provisionar (best-effort) los assets del mapa y la base GeoIP si faltan, para que las cajas
# que actualizan por el boton (no re-instalan) tengan el mapa "a donde atacan".
REF="${SHA:-$REPO_BRANCH}"
mkdir -p /var/lib/suricata-mapa /var/lib/suricata-geoip 2>/dev/null || true
for pair in "countries-110m.json a73ecc17bac82de28af19fa593f9e1a2e76619c51855490da735b7883ec48715" \
            "topojson-client.min.js ec362ac1599ef406ea9e79616a4ad47d4a3b3939882d47da7e4bc827a56f629c"; do
  fn=${pair%% *}; want=${pair##* }; dst="/var/lib/suricata-mapa/$fn"
  [ -f "$dst" ] && [ "$(sha256sum "$dst" 2>/dev/null | cut -d' ' -f1)" = "$want" ] && continue
  if curl -fsSL "https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${REF}/vendor/mapa/$fn" -o "$dst.new" 2>/dev/null \
     && [ "$(sha256sum "$dst.new" | cut -d' ' -f1)" = "$want" ]; then mv "$dst.new" "$dst"; log "mapa: $fn OK"; else rm -f "$dst.new"; log "mapa: no se pudo $fn"; fi
done
if [ ! -s /var/lib/suricata-geoip/ipv4.bin ]; then
  python3 - >/dev/null 2>&1 <<'GEOPY' && log "geoip: base construida" || log "geoip: no se construyo (mapa vacio hasta reconstruir)"
import urllib.request, ipaddress, array, struct, os
URL="https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"
data=urllib.request.urlopen(URL, timeout=180).read().decode("utf-8","replace")
rows=[]
for ln in data.splitlines():
    p=ln.split(",")
    if len(p)<3: continue
    cc=p[2].strip().upper()
    if len(cc)!=2 or not cc.isalpha(): continue
    try: s=int(ipaddress.IPv4Address(p[0].strip())); e=int(ipaddress.IPv4Address(p[1].strip()))
    except Exception: continue
    if e>=s: rows.append((s,e,cc))
assert len(rows)>=1000
rows.sort()
st=array.array("I",[r[0] for r in rows]); en=array.array("I",[r[1] for r in rows])
assert st.itemsize==4
cc=b"".join(r[2].encode("ascii") for r in rows)
tmp="/var/lib/suricata-geoip/ipv4.bin.tmp"
open(tmp,"wb").write(struct.pack("<I",len(rows))+st.tobytes()+en.tobytes()+cc)
os.replace(tmp,"/var/lib/suricata-geoip/ipv4.bin")
GEOPY
fi
# regenerar el reporte YA con el codigo nuevo (respetando la ventana VENTANA_MIN), para
# que los cambios (tablas/graficos) se vean sin esperar los 30 min del ciclo normal
VMIN=$(awk -F= '/^VENTANA_MIN=/{print $2}' /etc/suricata-dashboard.conf 2>/dev/null); [ -n "$VMIN" ] || VMIN=1440
/usr/local/bin/suricata-html-report "$VMIN" >/dev/null 2>&1 || true
systemctl restart suricata-dashboard
# health-check: esperar a que el panel LEVANTE y RESPONDA por su puerto; si no, revertir.
# Atrapa errores de ejecucion que la validacion ast/sh -n no ve (p.ej. un import que falla).
PORT=$(awk -F= '/^PORT=/{print $2}' /etc/suricata-dashboard.conf 2>/dev/null); [ -n "$PORT" ] || PORT=5637
ok=0; i=0
while [ "$i" -lt 15 ]; do
  sleep 2
  if systemctl is-active --quiet suricata-dashboard && \
     curl -s -o /dev/null --max-time 3 "http://127.0.0.1:${PORT}/login"; then
    ok=1; break
  fi
  i=$((i + 1))
done
if [ "$ok" = 1 ]; then
  log "panel OK tras actualizar (${SHA:-main})"
  printf '{"ok":true,"ts":%s,"to":"%s"}' "$(date +%s)" "${SHA:-main}" > /var/log/suricata-update-result.json 2>/dev/null || true
else
  log "EL PANEL NO LEVANTO tras actualizar -> ROLLBACK desde $BKP"
  printf '{"ok":false,"rollback":true,"ts":%s,"to":"%s"}' "$(date +%s)" "${SHA:-main}" > /var/log/suricata-update-result.json 2>/dev/null || true
  for f in suricata-dashboard suricata-html-report suricata-panel-update suricata-feeds-update; do
    [ -f "$BKP/$f" ] && cp -p "$BKP/$f" "/usr/local/bin/$f" && chmod 755 "/usr/local/bin/$f"
  done
  [ -f "$BKP/commit" ] && cp -p "$BKP/commit" /etc/suricata-dashboard.commit
  [ -f "$BKP/updated" ] && cp -p "$BKP/updated" /etc/suricata-dashboard.updated
  rm -f /var/log/suricata-update-check.json
  systemctl restart suricata-dashboard
  log "ROLLBACK aplicado: panel restaurado a la version previa (revisa el codigo nuevo antes de reintentar)"
fi
UPDSH
chmod 755 /usr/local/bin/suricata-panel-update

if [ ! -f /etc/suricata-dashboard.conf ]; then
  DASH_PASS="$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))')"
  cat > /etc/suricata-dashboard.conf <<CONF
# Panel de estadisticas de Suricata. Cambia PASS y reinicia: systemctl restart suricata-dashboard
PORT=5637
USER=admin
PASS=${DASH_PASS}
CONF
  chmod 600 /etc/suricata-dashboard.conf
fi
DASH_PORT="$(awk -F= '/^PORT=/{print $2}' /etc/suricata-dashboard.conf 2>/dev/null)"; DASH_PORT="${DASH_PORT:-5637}"
DASH_PASS_SHOWN="$(awk -F= '/^PASS=/{print $2}' /etc/suricata-dashboard.conf 2>/dev/null)"
cat > /etc/systemd/system/suricata-dashboard.service <<UNIT
[Unit]
Description=Panel de estadisticas de Suricata (apartado web)
After=suricata.service
[Service]
Nice=15
ExecStart=/usr/bin/python3 /usr/local/bin/suricata-dashboard
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now suricata-dashboard >/dev/null 2>&1 || systemctl restart suricata-dashboard
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw status | grep -qE "^${DASH_PORT}/tcp\s+ALLOW" || ufw allow "${DASH_PORT}/tcp" comment 'Suricata dashboard' >/dev/null 2>&1 || true
fi
sleep 1
# IP para mostrar (PUB_IP aun no esta definido en este punto del script)
DASH_IP="$(ip -o -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
[ -n "$DASH_IP" ] || DASH_IP="$(ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
if systemctl is-active --quiet suricata-dashboard; then
  ok "Panel de estadisticas: http://${DASH_IP:-<IP>}:${DASH_PORT}  (usuario admin, clave ${DASH_PASS_SHOWN})"
else
  warn "El panel de estadisticas no arranco; revisa: journalctl -u suricata-dashboard"
fi

# ============================================================================= TZSP (espejo MikroTik)
# MikroTik manda el espejo por TZSP (UDP 37008). Suricata no entiende TZSP: si lo
# escucha directo solo produce "truncated packet". Se instala un desencapsulador
# (python, stdlib) que saca la trama Ethernet del TZSP y la inyecta en un par veth
# ids-in -> ids-mon; Suricata captura ids-mon como segunda interfaz af-packet.
# El trafico espejeado trae checksums de offload rotos: se apaga su validacion.
TZSP_IN=ids-in; TZSP_MON=ids-mon
if [ "$TZSP" -eq 1 ]; then
  info "Configurando receptor TZSP (UDP ${TZSP_PORT}) -> ${TZSP_MON}..."
  cat > /usr/local/bin/tzsp-decap.py <<'PYD'
#!/usr/bin/env python3
"""tzsp-decap: recibe TZSP (UDP) y reinyecta las tramas Ethernet en una interfaz.

Formato TZSP: version(1)=1 | type(1) 0=recibido,1=tx | encap(2) 1=Ethernet |
tags: 0x00=padding (sin longitud), 0x01=END (sin longitud), otros: len(1)+data |
payload = trama Ethernet completa.
"""
import ipaddress, os, socket, struct, sys, time

PORT = int(os.environ.get("TZSP_PORT", "37008"))
OUT_IF = os.environ.get("TZSP_OUT_IF", "ids-in")
# --- Varios MikroTik: una interfaz por router ---
# TZSP_MAP = "10.0.0.1=ids-in,10.9.9.1=ids-in2" manda el espejo de cada router a SU
# interfaz. Es lo que permite despues saber de que nodo vino cada alerta (Suricata lo
# apunta como in_iface): sin esto todos los espejos caen en la misma interfaz y dos
# nodos que usan el mismo rango privado se vuelven indistinguibles, con el riesgo de
# culpar al cliente equivocado y de mandar el bloqueo al router que no es.
# Sin TZSP_MAP se usa TZSP_ALLOW + TZSP_OUT_IF, como siempre (un solo router).
MAPA = []          # [(red, interfaz)]
for _p in os.environ.get("TZSP_MAP", "").replace(" ", "").split(","):
    if not _p or "=" not in _p:
        continue
    _red, _if = _p.split("=", 1)
    try:
        MAPA.append((ipaddress.ip_network(_red, strict=False), _if))
    except ValueError:
        pass
# origenes autorizados del espejo (MikroTik). Vacio = NO arrancar (fail-closed):
# sin lista, cualquiera en la red podria inyectar tramas forjadas en el IDS.
ALLOW = [r for r, _ in MAPA]
for _c in os.environ.get("TZSP_ALLOW", "").replace(" ", "").split(","):
    if _c:
        try:
            ALLOW.append(ipaddress.ip_network(_c, strict=False))
        except ValueError:
            pass

def permitido(ip):
    if not ALLOW:
        return False        # fail-closed: sin lista de origenes no se acepta nada
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in ALLOW)

def decap(d):
    if len(d) < 5 or d[0] != 1 or d[1] not in (0, 1):
        return None
    if struct.unpack("!H", d[2:4])[0] != 1:
        return None
    i = 4
    n = len(d)
    while i < n:
        tag = d[i]
        if tag == 0x01:
            i += 1
            break
        if tag == 0x00:
            i += 1
            continue
        if i + 1 >= n:
            return None
        i += 2 + d[i + 1]
    return d[i:] if i < n else None

def main():
    if not ALLOW:
        for _m in ("tzsp-decap: TZSP_ALLOW vacio. Sin origenes autorizados,",
                   "cualquier host de la red podria inyectar trafico forjado en el",
                   "IDS, asi que no se arranca. Reinstala con -m <IP_MikroTik>",
                   "(acepta varios separados por coma)."):
            print(_m, file=sys.stderr, flush=True)
        return 2
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    rx.bind(("0.0.0.0", PORT))
    # un socket por interfaz de salida (una por router con TZSP_MAP; si no, una sola)
    salidas = {}
    for _red, _if in MAPA:
        if _if not in salidas:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((_if, 0))
            salidas[_if] = s
    if OUT_IF not in salidas:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((OUT_IF, 0))
        salidas[OUT_IF] = s
    _cache = {}                       # ip origen -> interfaz (se resuelve una vez por router)

    def salida_de(ip):
        s = _cache.get(ip)
        if s is None:
            s = OUT_IF
            if MAPA:
                try:
                    a = ipaddress.ip_address(ip)
                    for red, iface in MAPA:
                        if a.version == red.version and a in red:
                            s = iface
                            break
                except ValueError:
                    pass
            if len(_cache) < 1000:    # cota: los origenes son un punado de routers
                _cache[ip] = s
        return salidas.get(s) or salidas[OUT_IF]

    _destinos = ", ".join(f"{r}->{i}" for r, i in MAPA) or OUT_IF
    print(f"tzsp-decap: escuchando UDP {PORT} -> {_destinos}"
          f" (solo desde {os.environ.get('TZSP_MAP') or os.environ.get('TZSP_ALLOW')})", flush=True)
    rxn = txn = bad = big = rej = 0
    porif = {}
    last = time.time()
    while True:
        d, peer = rx.recvfrom(65535)
        rxn += 1
        if not permitido(peer[0]):
            rej += 1
            continue
        f = decap(d)
        if f is None or len(f) < 14:
            bad += 1
        else:
            try:
                tx = salida_de(peer[0])
                tx.send(f)
                txn += 1
                if MAPA:
                    porif[peer[0]] = porif.get(peer[0], 0) + 1
            except OSError:
                big += 1
        now = time.time()
        if now - last >= 60:
            # con varios routers interesa ver que TODOS estan mandando: si uno se calla,
            # ese nodo se queda sin vigilancia y no hay ningun otro aviso
            det = (" por_origen=" + ",".join(f"{k}:{v}" for k, v in sorted(porif.items()))) if porif else ""
            print(f"tzsp-decap: rx={rxn} tx={txn} descartados={bad} muy_grandes={big} "
                  f"rechazados_origen={rej} ultimo_origen={peer[0]}{det}", flush=True)
            porif.clear()
            last = now

if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(0)
PYD
  chmod 755 /usr/local/bin/tzsp-decap.py

  # --- Una interfaz por MikroTik ---
  # Con varios routers el espejo de cada uno entra por SU veth: asi Suricata anota un
  # in_iface distinto por nodo y se puede saber de cual vino cada alerta. Sin eso, dos
  # nodos que usan el mismo rango privado (10.0.0.x en los dos) serian indistinguibles.
  # El PRIMER router conserva ids-in/ids-mon de siempre: una caja con un solo MikroTik
  # no cambia de interfaz al actualizar (renombrarla la dejaria sin captura).
  TZSP_MAP=""; TZSP_MONS=""; TZSP_PRE=""
  _i=0
  for _src in $(printf '%s' "$MIRROR_SRC" | tr ',' ' '); do
    _i=$((_i+1))
    if [ "$_i" -eq 1 ]; then _din="$TZSP_IN"; _dmon="$TZSP_MON"
    else _din="${TZSP_IN}${_i}"; _dmon="${TZSP_MON}${_i}"; fi
    TZSP_MAP="${TZSP_MAP}${TZSP_MAP:+,}${_src}=${_din}"
    TZSP_MONS="${TZSP_MONS}${TZSP_MONS:+ }${_dmon}"
    TZSP_PRE="${TZSP_PRE}ExecStartPre=/bin/sh -c 'ip link show ${_dmon} >/dev/null 2>&1 || ip link add ${_din} type veth peer name ${_dmon}'
ExecStartPre=/bin/sh -c 'sysctl -qw net.ipv6.conf.${_din}.disable_ipv6=1 net.ipv6.conf.${_dmon}.disable_ipv6=1 net.ipv4.conf.${_dmon}.rp_filter=1 net.ipv4.conf.${_dmon}.forwarding=0 net.ipv4.conf.${_dmon}.arp_ignore=8 || true'
ExecStartPre=/sbin/ip link set ${_din} up mtu 65535
ExecStartPre=/sbin/ip link set ${_dmon} up mtu 65535 promisc on
"
  done
  [ -n "$TZSP_MONS" ] || { TZSP_MONS="$TZSP_MON"; TZSP_MAP="${MIRROR_SRC}=${TZSP_IN}"; }

  cat > /etc/systemd/system/tzsp-decap.service <<UNIT
[Unit]
Description=Receptor TZSP (MikroTik) -> ${TZSP_MONS} para Suricata
After=network.target
Before=suricata.service

[Service]
Environment=TZSP_PORT=${TZSP_PORT}
Environment=TZSP_OUT_IF=${TZSP_IN}
Environment=TZSP_ALLOW=${MIRROR_SRC}
# cada router a su interfaz (ver tzsp-decap.py); con uno solo equivale a lo de siempre
Environment=TZSP_MAP=${TZSP_MAP}
# crea los pares veth si no existen; sin IPv6 para que no metan ruido propio.
# Las tramas reinyectadas NO deben entrar a la pila IP del kernel ni reenviarse.
# mtu 65535 (maximo de veth): el router agrega segmentos (GRO) y manda tramas de hasta
# ~22 kB; con 1600/9000 se perdian con EMSGSIZE y cada trama perdida es un hueco mas
# en el reensamblado. Suricata dimensiona el snaplen por el MTU (block-size 128k).
${TZSP_PRE}# el SO_RCVBUF de 16 MB del receptor lo topa rmem_max
ExecStartPre=-/usr/sbin/sysctl -qw net.core.rmem_max=16777216
ExecStart=/usr/bin/python3 /usr/local/bin/tzsp-decap.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  install -d /etc/systemd/system/suricata.service.d
  cat > /etc/systemd/system/suricata.service.d/20-tzsp.conf <<UNIT
# Generado por install-suricata.sh: Suricata captura ${TZSP_MON}, que crea tzsp-decap.
[Unit]
Requires=tzsp-decap.service
After=tzsp-decap.service
UNIT
  systemctl daemon-reload
  systemctl enable tzsp-decap >/dev/null 2>&1 || true
  systemctl restart tzsp-decap
  sleep 1
  for _dmon in $TZSP_MONS; do
    ip link show "$_dmon" >/dev/null 2>&1 || { journalctl -u tzsp-decap --no-pager -n 20; die "No se creo ${_dmon}. Revisa: journalctl -u tzsp-decap"; }
  done

  # una entrada af-packet por interfaz de espejo en suricata.yaml (idempotente)
  for TZSP_MON_CFG in $TZSP_MONS; do
  if ! grep -qE "^\s*- interface: ${TZSP_MON_CFG}\s*$" "$CFG"; then
    python3 - "$CFG" "$TZSP_MON_CFG" <<'PY'
import sys, re
cfg, mon = sys.argv[1], sys.argv[2]
s = open(cfg, encoding="utf-8").read()
block = f"""  - interface: {mon}
    # espejo TZSP desde MikroTik (lo crea tzsp-decap.service)
    # el cluster-id definitivo lo asigna el renumerado de mas abajo
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    # tramas agregadas de hasta ~22 kB: el bloque debe ser mayor que el snaplen (MTU 65535)
    block-size: 131072
    checksum-checks: no
"""
# insertar antes del primer '- interface: default' de la seccion af-packet
m = re.search(r"^af-packet:\n(.*?)(^  - interface: default\s*$)", s, re.S | re.M)
if not m:
    sys.exit("no encontre la seccion af-packet")
s = s[:m.start(2)] + block + s[m.start(2):]
open(cfg, "w", encoding="utf-8").write(s)
PY
  fi
  # block-size en el bloque de esa interfaz aunque ya existiera de una corrida anterior
  if ! awk -v m="$TZSP_MON_CFG" '$0 ~ "^  - interface: "m"$"{f=1;next} f&&/^  - interface:/{exit} f&&/^    block-size: 131072/{ok=1} END{exit !ok}' "$CFG"; then
    sed -i "/^  - interface: ${TZSP_MON_CFG}\$/a\    block-size: 131072" "$CFG"
  fi
  done

  # --- CLUSTERID: un cluster-id distinto por interfaz de espejo -------------------
  # El fanout de af-packet es un grupo del kernel identificado por ese numero. Dos
  # interfaces con el mismo id piden entrar al mismo grupo y el kernel rechaza la
  # segunda con "failed to set fanout mode: Invalid argument": esa interfaz no
  # arranca y Suricata se cae entera. Con un solo MikroTik nunca se ve; aparece al
  # pasar un -m con varios origenes. Se renumera SIEMPRE, no solo al crear el
  # bloque, porque las cajas instaladas antes de este arreglo ya tienen el choque
  # y una reejecucion del instalador no las tocaria.
  python3 - "$CFG" <<'PY'
import re, sys
cfg = sys.argv[1]
lineas = open(cfg, encoding="utf-8").read().split("\n")
actual, asignados, cambios = None, {}, []
for i, l in enumerate(lineas):
    m = re.match(r"\s*-\s*interface:\s*(\S+)", l)
    if m:
        actual = m.group(1)
        continue
    m = re.match(r"(\s*)cluster-id:\s*(\d+)\s*$", l)
    if m and actual and actual.startswith("ids-mon"):
        if actual not in asignados:
            asignados[actual] = 98 + len(asignados)
        quiero = asignados[actual]
        if int(m.group(2)) != quiero:
            lineas[i] = "%scluster-id: %d" % (m.group(1), quiero)
            cambios.append("%s %s->%d" % (actual, m.group(2), quiero))
if cambios:
    open(cfg, "w", encoding="utf-8").write("\n".join(lineas))
    print("cluster-id corregido: " + ", ".join(cambios))
PY
  # CLUSTERID-FIN

  # En modo espejo, Suricata captura SOLO ${TZSP_MON} (veth estable que crea tzsp-decap).
  # El bloque af-packet de la NIC fisica (${IFACE}) se ELIMINA: su unico valor era el
  # trafico de gestion del propio sensor, y ademas ataba a Suricata al NOMBRE de la NIC.
  # Si la VM se recrea/migra y la NIC se renombra (ens18 -> eth0), ese bloque provocaba
  # "failed to find interface: No such device" -> Suricata en bucle de reinicios. Al no
  # nombrar nunca la NIC fisica, un renombrado ya no rompe el sensor. Tambien se retira
  # cualquier bpf-filter heredado de una corrida anterior (ya no aplica a ${TZSP_MON}).
  python3 - "$CFG" "$IFACE" "$TZSP_MON" <<'PY'
import sys, re
cfg, fis, mon = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(cfg, encoding="utf-8").read().split("\n")
out, i, n, quitado = [], 0, len(lines), False
in_af = False   # solo tocar la seccion af-packet, no las plantillas de pcap/netmap
while i < n:
    l = lines[i]
    if re.match(r"^af-packet:\s*$", l):
        in_af = True
    elif re.match(r"^\S", l):        # cualquier clave de primer nivel cierra af-packet
        in_af = False
    # ¿inicio del bloque af-packet de la NIC fisica? (no tocar el de ${mon})
    if in_af and fis != mon and re.match(r"^  - interface: " + re.escape(fis) + r"\s*$", l):
        i += 1  # saltar la linea de interface
        while i < n and not re.match(r"^  - \S", lines[i]) and not re.match(r"^\S", lines[i]):
            i += 1  # saltar el cuerpo hasta el siguiente '- interface:' o fin de seccion
        quitado = True
        continue
    out.append(l); i += 1
open(cfg, "w", encoding="utf-8").write("\n".join(out))
print("af-packet NIC fisica " + fis + (": eliminada (captura solo " + mon + ")" if quitado else ": no estaba"))
PY
  # checksums: el trafico espejeado llega con csum de offload -> no validar
  sed -i "s#^\(\s*checksum-validation:\)\s*yes#\1 no #" "$CFG"
  # eve.json: con espejo real 'flow' era el 76% del volumen, 'dns' el 15% y 'quic' el 6%
  # (15 MB/s = 1,3 TB/dia): llenaron el disco y EveBox (SQLite) solo ingiere ~600 ev/s.
  # eve.json queda para EveBox con alert/http/tls/ssh/files/stats; el DNS (solo
  # consultas) va aparte a dns.json, que rota con el mismo logrotate.
  python3 - "$CFG" flow dns quic anomaly ike bittorrent-dht <<'PY'
import sys, re
cfg, drop = sys.argv[1], set(sys.argv[2:])
lines = open(cfg, encoding="utf-8").read().split("\n")
out, i, n, changed = [], 0, len(lines), []
in_eve = False
while i < n:
    l = lines[i]
    if re.match(r"^  - eve-log:", l): in_eve = True
    elif in_eve and re.match(r"^  - \S", l): in_eve = False
    m = re.match(r"^(\s{8})- ([a-z0-9-]+):?\s*$", l)
    if in_eve and m and m.group(2) in drop:
        ind = len(m.group(1))
        out.append(m.group(1) + "#" + l[ind:] + "   # install-suricata.sh: fuera en modo espejo")
        changed.append(m.group(2)); i += 1
        while i < n and (lines[i].strip() == "" or (len(lines[i]) - len(lines[i].lstrip(" ")) > ind and not lines[i].lstrip().startswith("- "))):
            out.append(re.sub(r"^(\s*)", r"\1#", lines[i]) if lines[i].strip() else lines[i]); i += 1
        continue
    out.append(l); i += 1
open(cfg, "w", encoding="utf-8").write("\n".join(out))
print("eve-log sin: " + (", ".join(changed) if changed else "(ya estaban fuera)"))
PY
  # segunda salida EVE solo con consultas DNS (dns.json), antes de '- http-log:'
  if ! grep -qE '^\s*filename: dns\.json' "$CFG"; then
    python3 - "$CFG" <<'PY'
import sys, re
cfg = sys.argv[1]
s = open(cfg, encoding="utf-8").read()
block = """  - eve-log:
      # install-suricata.sh: DNS aparte (solo consultas) para no ahogar EveBox
      enabled: yes
      filetype: regular
      filename: dns.json
      types:
        - dns:
            requests: yes
            responses: no
"""
m = re.search(r"^  - http-log:", s, re.M)
if not m:
    sys.exit("no encontre '- http-log:' en outputs")
s = s[:m.start()] + block + s[m.start():]
open(cfg, "w", encoding="utf-8").write(s)
PY
  fi
  ok "eve.json solo alert/http/tls/ssh/files/stats (para EveBox); DNS en dns.json (solo consultas)."
  ok "Receptor TZSP activo: UDP ${TZSP_PORT} -> ${TZSP_MON} (Suricata lo captura)."
  if [ "$HOME_NET_GIVEN" -eq 0 ]; then
    warn "Con TZSP conviene pasar -n con las redes de tus clientes (ej: -n 172.16.0.0/12,10.0.0.0/8);"
    warn "ahora HOME_NET=${HOME_NET} y el trafico espejeado de otras redes no contara como 'saliente'."
  fi
else
  # si antes estuvo activo y ahora no se pide, dejarlo apagado (sin borrar la interfaz del yaml
  # para no romper: quitala a mano si quieres)
  if systemctl is-enabled tzsp-decap >/dev/null 2>&1; then
    warn "tzsp-decap estaba instalado; se deja como esta (re-ejecuta con -t para gestionarlo)."
  fi
fi

# ----------------------------------------------------------------------------- validar
info "Validando configuracion..."
if suricata -T -c "$CFG" -i "$IFACE" >/tmp/suricata-test.log 2>&1; then
  ok "Config valida."
else
  cat /tmp/suricata-test.log
  die "La validacion fallo. Revisa /tmp/suricata-test.log y ${CFG}.bak-${STAMP}"
fi

# ----------------------------------------------------------------------------- offloads NIC
# Con GRO/LRO (y rx-gro-hw en virtio) el kernel junta segmentos en tramas >1514
# bytes y Suricata las descarta como "truncated packet". Se apagan en la interfaz
# de captura ahora y en cada arranque del servicio (drop-in con ExecStartPre).
ETHTOOL="$(command -v ethtool || echo /usr/sbin/ethtool)"
OFFLOADS="gro off lro off tso off gso off rx-gro-hw off"
# Interfaz de captura real: en modo espejo es la veth estable ${TZSP_MON}; en modo
# directo es la NIC fisica actual. El drop-in NO hardcodea el nombre de la NIC fisica:
# lo resuelve por la ruta por defecto en CADA arranque, para que un renombrado de la
# NIC (ens18 -> eth0 al recrear/migrar la VM) no deje a Suricata sin apagar offloads.
if [ "$TZSP" -eq 1 ]; then
  # con varios routers hay una veth por nodo: apagar offloads en TODAS
  CAP_IF="${TZSP_MONS:-$TZSP_MON}"
  OFFLOAD_PRE=""
  for _dmon in ${TZSP_MONS:-$TZSP_MON}; do
    OFFLOAD_PRE="${OFFLOAD_PRE}${OFFLOAD_PRE:+ ; }${ETHTOOL} -K ${_dmon} ${OFFLOADS}"
  done
  OFFLOAD_PRE="/bin/sh -c '${OFFLOAD_PRE} || true'"
else
  CAP_IF="$IFACE"
  OFFLOAD_PRE="/bin/sh -c 'I=\$(ip -o -4 route show to default 2>/dev/null | awk \"{print \\\$5; exit}\"); [ -n \"\$I\" ] || I=\$(ip -o -4 addr show scope global 2>/dev/null | awk \"{print \\\$2; exit}\"); [ -n \"\$I\" ] && ${ETHTOOL} -K \"\$I\" ${OFFLOADS} || true'"
fi
# shellcheck disable=SC2086
for _ci in $CAP_IF; do "$ETHTOOL" -K "$_ci" $OFFLOADS >/dev/null 2>&1 || true; done
install -d /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/10-offload.conf <<UNIT
# Generado por install-suricata.sh: sin offloads en la interfaz de captura.
# La NIC fisica se resuelve en cada arranque (no se hardcodea el nombre).
[Service]
ExecStartPre=-${OFFLOAD_PRE}
UNIT
systemctl daemon-reload
ok "Offloads apagados en ${CAP_IF} (gro/lro/tso/gso/rx-gro-hw)."

# ----------------------------------------------------------------------------- servicio
info "Habilitando servicio..."
systemctl enable suricata >/dev/null 2>&1 || true
systemctl restart suricata || true
sleep 3
if systemctl is-active --quiet suricata; then
  # el daemon ya existe pero el motor tarda ~30-60 s en cargar 50k reglas:
  # esperar a que responda por el socket de control antes de declararlo listo
  info "Esperando a que el motor cargue las reglas..."
  for _ in $(seq 1 60); do
    suricatasc -c uptime >/dev/null 2>&1 && break
    systemctl is-active --quiet suricata || break
    sleep 2
  done
  if IFACES="$(suricatasc -c iface-list 2>/dev/null | python3 -c 'import sys,json; print(" ".join(json.load(sys.stdin)["message"]["ifaces"]))' 2>/dev/null)"; then
    ok "Suricata corriendo en modo IDS. Interfaces capturadas: ${IFACES}"
    if [ "$TZSP" -eq 1 ] && ! printf '%s' "$IFACES" | grep -qw "$TZSP_MON"; then
      warn "Suricata NO esta capturando ${TZSP_MON}; revisa el bloque af-packet en ${CFG}."
    fi
  else
    warn "Suricata activo pero el socket de control no respondio a tiempo; revisa /var/log/suricata/suricata.log"
  fi
else
  systemctl --no-pager -l status suricata || true
  die "El servicio no arranco."
fi

# ============================================================================= WEB (EveBox)
WEB_URL=""; WEB_USER="admin"; WEB_PASS_SHOWN=""; WEB_NOTE=""
if [ "$WEB" -eq 1 ]; then
  info "Instalando interfaz web EveBox..."

  # --- resolver .deb vigente (o el fijado) -----------------------------------
  DEB_FILE="$EVEBOX_PIN_FILE"; DEB_SHA="$EVEBOX_PIN_SHA"
  if PKGS="$(curl -fsSL --max-time 20 "$EVEBOX_PKGS" 2>/dev/null)"; then
    f="$(printf '%s\n' "$PKGS" | awk '/^Filename:/{print $2; exit}')"
    s="$(printf '%s\n' "$PKGS" | awk '/^SHA256:/{print $2; exit}')"
    if [ -n "$f" ] && [[ "$s" =~ ^[0-9a-f]{64}$ ]]; then DEB_FILE="$f"; DEB_SHA="$s"; fi
  else
    warn "No pude leer el indice de EveBox; uso la version fijada."
  fi
  DEB_URL="${EVEBOX_BASE}/${DEB_FILE}"
  DEB_NAME="$(basename "$DEB_FILE")"
  DEB_LOCAL="/root/${DEB_NAME}"
  DEB_VER="$(printf '%s' "$DEB_NAME" | sed -E 's/^evebox_([0-9.]+)_.*/\1/')"

  if ! dpkg -s evebox 2>/dev/null | grep -q "^Version: .*${DEB_VER}"; then
    if [ ! -f "$DEB_LOCAL" ] || ! echo "${DEB_SHA}  ${DEB_LOCAL}" | sha256sum -c --quiet - 2>/dev/null; then
      info "Descargando ${DEB_NAME}..."
      curl -fsSL --max-time 300 -o "${DEB_LOCAL}.part" "$DEB_URL" || die "No pude descargar $DEB_URL"
      echo "${DEB_SHA}  ${DEB_LOCAL}.part" | sha256sum -c --quiet - || { rm -f "${DEB_LOCAL}.part"; die "SHA256 del .deb no coincide. Abortando."; }
      mv -f "${DEB_LOCAL}.part" "$DEB_LOCAL"
    fi
    # el postinst del .deb corre con 'set -x': su traza va al log, no a pantalla
    if ! dpkg -i --force-confold "$DEB_LOCAL" </dev/null >/root/evebox-install.log 2>&1; then
      apt-get install -f -y -qq -o Dpkg::Options::=--force-confold </dev/null >>/root/evebox-install.log 2>&1 || { cat /root/evebox-install.log; die "dpkg -i fallo (ver /root/evebox-install.log)"; }
    fi
  fi
  ok "EveBox instalado: $(evebox version 2>/dev/null | head -1)"

  # --- permisos: evebox (usuario de sistema) debe leer eve.json ---------------
  # Suricata corre como root y crea eve.json 0644 (umask 022); el directorio de
  # logs de Debian es root:root. Se pone el grupo evebox con setgid para que
  # los archivos nuevos hereden el grupo y el servicio pueda leerlos.
  getent group evebox >/dev/null || groupadd --system evebox
  id evebox >/dev/null 2>&1 || useradd --system --home-dir "$EVEBOX_DATA" --gid evebox --shell /usr/sbin/nologin evebox
  install -d -o evebox -g evebox -m 750 "$EVEBOX_DATA"
  chgrp evebox /var/log/suricata
  chmod g+rxs /var/log/suricata
  find /var/log/suricata -maxdepth 1 -name 'eve*.json*' -exec chgrp evebox {} + -exec chmod g+r {} + 2>/dev/null || true

  # --- configuracion (SQLite local, auth, TLS autofirmado) --------------------
  [ -f "$EVEBOX_CFG" ] && cp -a "$EVEBOX_CFG" "${EVEBOX_CFG}.bak-${STAMP}"
  install -d -m 755 /etc/evebox
  cat > "$EVEBOX_CFG" <<YAML
# Generado por install-suricata.sh (${STAMP}). Backup del anterior junto a este archivo.
data-directory: ${EVEBOX_DATA}
config-directory: ${EVEBOX_DATA}

http:
  host: "0.0.0.0"
  port: ${WEB_PORT}
  tls:
    # Certificado autofirmado generado por EveBox en el primer arranque.
    enabled: true

authentication:
  required: true

database:
  type: sqlite
  retention:
    days: 7        # borra eventos de mas de 7 dias
    size: "5 GB"   # y nunca pasar de 5 GB en disco

input:
  enabled: true
  paths:
    - "/var/log/suricata/eve.json"
YAML
  cat > /etc/default/evebox <<DEF
# Opciones extra para 'evebox server' (la config vive en ${EVEBOX_CFG}).
EVEBOX_OPTS=""
DEF

  # --- usuario web -------------------------------------------------------------
  # 'users passwd' de EveBox es solo interactivo (exige TTY) y 'users rm' falla por
  # clave foranea en cuanto el usuario tiene sesiones web. Para fijar la clave de
  # un usuario existente se usa un ayudante que le da un pseudo-terminal.
  cat > /usr/local/bin/evebox-passwd <<'PYP'
#!/usr/bin/env python3
"""evebox-passwd USUARIO CLAVE  -  cambia la clave de un usuario EveBox sin TTY."""
import os, pty, select, sys
if len(sys.argv) != 3:
    sys.exit("uso: evebox-passwd USUARIO CLAVE")
user, pw = sys.argv[1], sys.argv[2]
d = "/var/lib/evebox"
cmd = ["runuser", "-u", "evebox", "--", "/usr/bin/evebox", "-D", d, "-C", d, "config", "users", "passwd", user]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
out, sent = b"", 0
while True:
    r, _, _ = select.select([fd], [], [], 20)
    if not r:
        os.kill(pid, 9)
        break
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    if sent < 2 and (b"assword" in data or b"onfirm" in data):
        os.write(fd, (pw + "\n").encode())
        sent += 1
try:
    os.close(fd)
except OSError:
    pass
_, st = os.waitpid(pid, 0)
okay = os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0 and b"updated" in out
if not okay:
    sys.stderr.write("".join(l + "\n" for l in out.decode(errors="replace").splitlines() if "INFO" not in l)[-600:])
sys.exit(0 if okay else 1)
PYP
  chmod 755 /usr/local/bin/evebox-passwd

  EVB="runuser -u evebox -- /usr/bin/evebox --data-directory ${EVEBOX_DATA} --config-directory ${EVEBOX_DATA}"
  systemctl stop evebox >/dev/null 2>&1 || true
  # HAS_ADMIN: 1 existe, 0 no existe, -1 no se pudo consultar (entonces no se toca nada)
  HAS_ADMIN=-1
  if USERS_OUT="$($EVB config users list 2>/dev/null)"; then
    if printf '%s\n' "$USERS_OUT" | grep -q "\"username\":\"${WEB_USER}\""; then HAS_ADMIN=1; else HAS_ADMIN=0; fi
  fi
  if [ "$HAS_ADMIN" -eq -1 ]; then
    warn "No pude consultar los usuarios de EveBox; no toco la clave."
    WEB_NOTE="No se pudo consultar/crear el usuario; si es la 1a instalacion EveBox genera 'admin' con clave aleatoria (journalctl -u evebox)."
  elif [ "$HAS_ADMIN" -eq 1 ] && [ -z "$WEB_PASS" ]; then
    WEB_NOTE="El usuario '${WEB_USER}' ya existia: clave sin cambios (para cambiarla re-ejecuta con -P 'NuevaClave')."
  elif [ "$HAS_ADMIN" -eq 1 ]; then
    if /usr/local/bin/evebox-passwd "$WEB_USER" "$WEB_PASS"; then
      WEB_PASS_SHOWN="$WEB_PASS"; WEB_NOTE="Clave de '${WEB_USER}' actualizada."
    else
      warn "No pude cambiar la clave de '${WEB_USER}' (ver salida arriba)."
      WEB_NOTE="La clave NO se cambio."
    fi
  else
    # (sin 'tr | head': bajo pipefail tr muere por SIGPIPE y abortaba el script)
    [ -n "$WEB_PASS" ] || WEB_PASS="$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))')"
    if $EVB config users add --username "$WEB_USER" --password "$WEB_PASS" >/dev/null 2>&1; then
      WEB_PASS_SHOWN="$WEB_PASS"
    else
      warn "No pude crear el usuario web por CLI; EveBox generara 'admin' con clave aleatoria (ver journalctl -u evebox)."
    fi
  fi

  # --- servicio ----------------------------------------------------------------
  systemctl daemon-reload
  systemctl enable evebox >/dev/null 2>&1 || true
  systemctl restart evebox || true
  sleep 3
  if systemctl is-active --quiet evebox; then
    ok "EveBox corriendo en el puerto ${WEB_PORT}."
  else
    journalctl -u evebox --no-pager -n 30 || true
    die "EveBox no arranco. Revisa: journalctl -u evebox"
  fi
  # si EveBox tuvo que autogenerar el admin, rescatar la clave del journal
  if [ -z "$WEB_PASS_SHOWN" ] && [ -z "$WEB_NOTE" ]; then
    auto="$(journalctl -u evebox --no-pager -n 100 2>/dev/null | grep -oE 'username=[^,]+, password=[^ ]+' | tail -1 || true)"
    if [ -n "$auto" ]; then WEB_PASS_SHOWN="${auto##*password=}"; WEB_NOTE="Clave autogenerada por EveBox (leida del journal)."; fi
  fi
  [ -n "${WEB_PASS_SHOWN}${WEB_NOTE}" ] || WEB_NOTE="Clave desconocida: fijala con evebox-passwd ${WEB_USER} 'Clave'."
  # comprobar que el usuario evebox puede leer eve.json
  if ! runuser -u evebox -- test -r /var/log/suricata/eve.json 2>/dev/null; then
    warn "El usuario 'evebox' no puede leer /var/log/suricata/eve.json: la web quedara vacia. Revisa permisos del directorio."
  fi

  # --- firewall ----------------------------------------------------------------
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    if ! ufw status | grep -qE "^${WEB_PORT}/tcp\s+ALLOW"; then
      ufw allow "${WEB_PORT}/tcp" comment 'EveBox web' >/dev/null && ok "UFW: abierto ${WEB_PORT}/tcp para la web."
    fi
  fi
fi

# IP de origen hacia internet (la que ve el MikroTik); si no hay ruta, la de la interfaz
PUB_IP="$(ip -o -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
[ -n "$PUB_IP" ] || PUB_IP="$(ip -o -4 addr show dev "$IFACE" scope global | awk '{split($4,a,"/"); print a[1]; exit}')"
WEB_URL="https://${PUB_IP:-<IP>}:${WEB_PORT}"

if [ "$TZSP" -eq 1 ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  if [ -n "$MIRROR_SRC" ]; then
    # abrir 37008/udp SOLO desde el/los origenes del espejo (MikroTik)
    OLD_IFS=$IFS; IFS=','
    for _src in $MIRROR_SRC; do
      _src="$(echo "$_src" | tr -d ' ')"; [ -n "$_src" ] || continue
      ufw status | grep -qE "^${TZSP_PORT}/udp\s+ALLOW\s+IN?\s+${_src}\b" \
        || ufw allow from "$_src" to any port "${TZSP_PORT}" proto udp comment 'TZSP MikroTik' >/dev/null \
        && ok "UFW: ${TZSP_PORT}/udp permitido solo desde ${_src}."
    done
    IFS=$OLD_IFS
  else
    # sin origen de espejo NO se abre el puerto: abrirlo a cualquiera permitiria
    # inyectar tramas forjadas en el IDS (el receptor tampoco arranca, ver -m).
    warn "UFW: ${TZSP_PORT}/udp NO se abre sin -m <IP_MikroTik>."
  fi
fi

# ----------------------------------------------------------------------------- resumen
cat <<EOF

${c_g}==================================================================${c_0}
 Suricata IDS listo
${c_g}==================================================================${c_0}
  Interfaz     : ${IFACE}
  HOME_NET     : ${HOME_NET}
  Config       : ${CFG}   (backup: ${CFG}.bak-${STAMP})
  Reglas       : /var/lib/suricata/rules/suricata.rules
  Logs         : /var/log/suricata/fast.log   (alertas legibles)
                 /var/log/suricata/eve.json   (JSON completo)
                 /var/log/suricata/stats.log  (drops/rendimiento)
EOF
if [ "$WEB" -eq 1 ]; then
cat <<EOF

  ${c_g}Interfaz web (EveBox)${c_0}
    URL        : ${WEB_URL}   (certificado autofirmado: acepta la advertencia)
    Usuario    : ${WEB_USER}
    Clave      : ${WEB_PASS_SHOWN:-<sin cambios>}
    ${WEB_NOTE}
    Config     : ${EVEBOX_CFG}    Datos: ${EVEBOX_DATA} (SQLite, 7 dias / 5 GB)
    Cambiar clave: evebox-passwd ${WEB_USER} 'NuevaClave'   (o re-ejecuta este instalador con -P)
    Si hay firewall externo (nube/Proxmox), abre ${WEB_PORT}/tcp.
EOF
fi
if systemctl is-active --quiet suricata-dashboard 2>/dev/null; then
cat <<EOF

  ${c_g}Panel de estadisticas (dashboard propio)${c_0}
    URL        : http://${DASH_IP:-<IP>}:${DASH_PORT}
    Usuario    : admin
    Clave      : ${DASH_PASS_SHOWN:-<ya configurada; cambiala en Ajustes>}
    Servicio   : suricata-dashboard   (systemctl status suricata-dashboard)
    Nota       : HTTP plano; publicalo detras de tu proxy (NPM) o por VPN. La clave
                 ya no queda en texto plano en el .conf (esta hasheada). Guardala.
EOF
fi
if [ "$TZSP" -eq 1 ]; then
cat <<EOF

  ${c_g}Receptor TZSP (espejo MikroTik)${c_0}
    Escucha    : UDP ${TZSP_PORT} en ${PUB_IP:-<IP>}  ->  ${TZSP_MON} (Suricata la captura)
    Servicio   : tzsp-decap   (journalctl -u tzsp-decap -f  muestra rx/tx cada 60 s)
    Probar     : ./test-tzsp.sh   (manda una trama TZSP sintetica y espera la alerta)
    Ruido      : reglas "SURICATA *" fuera; eve.json sin flow/dns/quic/anomaly (DNS en dns.json); BPF excluye TZSP en ${IFACE}
    Stream     : midstream=$(grep -cE '^  midstream: true' "$CFG") async-oneside=$(grep -cE '^  async-oneside: true' "$CFG") bypass=$(grep -cE '^  bypass: true' "$CFG") tls-bypass=$(grep -cE '^\s*encryption-handling: bypass' "$CFG") (1 = activo); memcaps segun RAM (${RAM_MB} MB)
    Vigila     : grep -E 'reassembly_memuse|kernel_drops' /var/log/suricata/stats.log | tail -2   (memuse debe quedar bajo el memcap)

    En el MikroTik (todo el trafico de una interfaz):
      /tool sniffer set streaming-enabled=yes streaming-server=${PUB_IP:-<IP>} filter-stream=yes filter-interface=<bridge-o-ether>
      /tool sniffer start
      /system scheduler add name=sniffer-start start-time=startup on-event="/tool sniffer start"
    O selectivo por regla (solo una red de clientes):
      /ip firewall mangle add chain=prerouting src-address=<red-clientes> action=sniff-tzsp sniff-target=${PUB_IP:-<IP>} sniff-target-port=${TZSP_PORT} passthrough=yes
EOF
fi
cat <<EOF

  Ver alertas en vivo:
    tail -f /var/log/suricata/fast.log

    tail -f /var/log/suricata/eve.json | \\
      jq 'select(.event_type=="alert") | {src:.src_ip,dst:.dest_ip,sig:.alert.signature}'

  Probar deteccion:
    ./test-alerts.sh

  Vigila drops (si aparecen, sube memcap/RAM):
    grep -E 'kernel_drops|memcap' /var/log/suricata/stats.log
${c_g}==================================================================${c_0}
EOF






































