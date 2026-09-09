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
Uso: sudo ./install-suricata.sh [-i IFACE] [-n HOME_NET] [-p PUERTO] [-P CLAVE] [-t] [-W] [-h]

  -i IFACE     interfaz a escuchar (default: auto-deteccion por ruta default)
  -n HOME_NET  red(es) "casa" en CIDR, separadas por coma (default: la de la interfaz)
  -p PUERTO    puerto de la web EveBox (default: 5636)
  -P CLAVE     clave del usuario web 'admin' (default: aleatoria, se muestra al final)
  -t           receptor TZSP (UDP 37008) para espejo desde MikroTik
  -W           sin web (solo Suricata + logs locales)
  -h           esta ayuda

One-liner:
  curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- [opciones]
USAGE
}

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root (sudo)."

# ----------------------------------------------------------------------------- args
IFACE=""; HOME_NET=""; HOME_NET_GIVEN=0; WEB=1; WEB_PORT=5636; WEB_PASS=""; TZSP=0; TZSP_PORT=37008
while getopts "i:n:p:P:tWh" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    n) HOME_NET="$OPTARG"; HOME_NET_GIVEN=1 ;;
    p) WEB_PORT="$OPTARG" ;;
    P) WEB_PASS="$OPTARG" ;;
    t) TZSP=1 ;;
    W) WEB=0 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
# por si el usuario pasa -n "[a,b]": el yaml ya pone los corchetes
HOME_NET="${HOME_NET#[}"; HOME_NET="${HOME_NET%]}"
{ [[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ]; } || die "Puerto invalido: $WEB_PORT"
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
suricata-update --no-test >/dev/null 2>&1 || suricata-update --no-test || warn "suricata-update reporto avisos (normal la 1a vez)."
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
set -e
suricata-update --no-test >/tmp/suricata-update.log 2>&1 || { echo "suricata-update fallo:"; cat /tmp/suricata-update.log; exit 1; }
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
import glob, gzip, io, json, os, socket, time, urllib.request, urllib.parse
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
    reglas = []
    try:
        data = json.load(open("/etc/suricata-exclusiones.json", encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if r.get("ip"):
                    reglas.append((r.get("tipo", "dst"), r["ip"],
                                   [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()]))
    except Exception:
        pass
    _c = conf()
    reglas += [("dst", x.strip(), []) for x in _c.get("IGNORAR_DESTINOS", "").split(",") if x.strip()]
    reglas += [("src", x.strip(), []) for x in _c.get("IGNORAR_ORIGENES", "").split(",") if x.strip()]
    return reglas
EXCL = cargar_exclusiones()
def excluido(src, dst, dport):
    for tipo, ip, pts in EXCL:
        quien = dst if tipo == "dst" else src
        if quien == ip and (not pts or (dport is not None and dport in pts)):
            return True
    return False

by_src_nivel = {}
by_src_expl = {}
by_src_accion = {}
by_src_total = Counter()
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
            if excluido(src, dst, e.get("dest_port")):   # exclusiones configuradas
                continue
            nivel, expl, accion = clasifica(sig)
            by_src_total[src] += 1
            pair[src][sig] += 1
            if src not in by_src_nivel or nivel < by_src_nivel[src]:
                by_src_nivel[src] = nivel; by_src_expl[src] = expl; by_src_accion[src] = accion
            total += 1
    except OSError:
        continue

host = socket.gethostname()
NOMBRE = {1: "INFECTADOS (actuar ya)", 2: "ATACANDO / ESCANEANDO (revisar)", 3: "SOSPECHOSOS (vigilar)"}
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
import glob, gzip, io, json, os, re, sys, html, time
from collections import Counter, defaultdict
from datetime import datetime

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
}.items()}

def campos(line):
    def g(k):
        m = _RE[k].search(line)
        return m.group(1) if m else ""
    return g

LOGDIR = "/var/log/suricata"
HOURS = int(sys.argv[1]) if len(sys.argv) > 1 else 24
cutoff = time.time() - HOURS * 3600
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

def cargar_exclusiones():
    """Reglas de exclusion: {tipo:'dst'|'src', ip, puertos:[int]}. Desde
    /etc/suricata-exclusiones.json (apartado Exclusiones) + lineas IGNORAR_* legacy."""
    reglas = []
    try:
        data = json.load(open("/etc/suricata-exclusiones.json", encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if r.get("ip"):
                    reglas.append((r.get("tipo", "dst"), r["ip"],
                                   [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()]))
    except Exception:
        pass
    try:
        for l in open("/etc/suricata-report.conf", encoding="utf-8"):
            l = l.strip()
            if l.startswith("IGNORAR_DESTINOS="):
                reglas += [("dst", x.strip(), []) for x in l.split("=", 1)[1].split(",") if x.strip()]
            elif l.startswith("IGNORAR_ORIGENES="):
                reglas += [("src", x.strip(), []) for x in l.split("=", 1)[1].split(",") if x.strip()]
    except OSError:
        pass
    return reglas

EXCL = cargar_exclusiones()

def excluido(src, dst, dport):
    for tipo, ip, pts in EXCL:
        quien = dst if tipo == "dst" else src
        if quien == ip and (not pts or (dport is not None and dport in pts)):
            return True
    return False

def parse_ts(s):
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    except Exception:
        return None

by_dport = Counter()
by_src = Counter()
by_dst = Counter()
by_hour = Counter()
flujos = {}            # (src,sport,dst,dport,proto,sig) -> [count, first, last]
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
            g = campos(line)
            sig = g("sig"); cat = g("cat")
            if sig.startswith("ET INFO") or "Not Suspicious" in cat or "Misc activity" in cat:
                continue
            ts = parse_ts(g("ts"))
            if ts and ts < cutoff:
                continue
            src = g("src_ip") or "?"; dst = g("dest_ip") or "?"
            sport = g("src_port"); dport = g("dest_port")
            proto = g("proto")
            if excluido(src, dst, int(dport) if dport else None):   # exclusiones configuradas
                continue
            by_dst[dst] += 1
            by_src[src] += 1
            if dport != "":
                by_dport[f"{dport}/{proto}"] += 1
            if ts:
                by_hour[int(ts // 3600)] += 1
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

def esc(x): return html.escape(str(x))

def hbar(titulo, pares, unidad="alertas", fmt=str, lblw=150, barw=460, card_class="card", label_above=False):
    """Barras horizontales rankeadas, un solo tono, etiqueta de valor directa.
    label_above=True: el nombre va ENCIMA de la barra (a todo el ancho), no en una
    columna a la izquierda; asi los nombres largos (firmas) no se recortan nunca."""
    if not pares:
        return f'<section class="{card_class}"><h2>{esc(titulo)}</h2><p class="muted">Sin datos.</p></section>'
    mx = max(v for _, v in pares) or 1
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
            w = max(2, int(barmax * v / mx))
            etq = name if len(name) <= maxch else name[:maxch - 1] + "…"
            rows.append(
                f'<text x="2" y="{top+13}" class="lbl">{esc(etq)}</text>'
                f'<rect x="2" y="{top+labh}" width="{w}" height="{barh}" rx="4" fill="{BLUE}"/>'
                f'<text x="{w+8}" y="{top+labh+barh*0.7:.0f}" class="val">{esc(fmt(v))}</text>')
    else:
        rowh, gap = 26, 8
        maxch = max(8, int(lblw / 6.3))
        h = len(pares) * (rowh + gap) + 8
        W = lblw + barw + 80
        for i, (name, v) in enumerate(pares):
            y = i * (rowh + gap) + 4
            w = max(2, int(barw * v / mx))
            etq = name if len(name) <= maxch else name[:maxch - 1] + "…"
            rows.append(
                f'<text x="{lblw-8}" y="{y+rowh*0.68:.0f}" text-anchor="end" class="lbl">{esc(etq)}</text>'
                f'<rect x="{lblw}" y="{y}" width="{w}" height="{rowh}" rx="4" fill="{BLUE}"/>'
                f'<text x="{lblw+w+6}" y="{y+rowh*0.68:.0f}" class="val">{esc(fmt(v))}</text>')
    return (f'<section class="{card_class}"><h2>{esc(titulo)}</h2>'
            f'<svg viewBox="0 0 {W} {h}" width="100%" role="img" aria-label="{esc(titulo)}">'
            f'{"".join(rows)}</svg><p class="muted">en {unidad}</p></section>')

def timeline(by_hour):
    if not by_hour:
        return ""
    hrs = sorted(by_hour)
    lo = hrs[0]
    n = hrs[-1] - lo + 1
    vals = [by_hour.get(lo + i, 0) for i in range(n)]
    mx = max(vals) or 1
    W, H, pad = 900, 180, 30
    bw = (W - 2 * pad) / max(1, n)
    bars, ticks = [], []
    for i, v in enumerate(vals):
        x = pad + i * bw
        bh = (H - 2 * pad) * v / mx
        bars.append(f'<rect x="{x:.1f}" y="{H-pad-bh:.1f}" width="{max(1,bw-2):.1f}" height="{bh:.1f}" rx="2" fill="{BLUE}"/>')
        if i % max(1, n // 12) == 0:
            hh = datetime.fromtimestamp((lo + i) * 3600).strftime("%Hh")
            ticks.append(f'<text x="{x+bw/2:.1f}" y="{H-pad+14:.0f}" text-anchor="middle" class="tick">{hh}</text>')
    return (f'<section class="card wide"><h2>Ataques por hora (ultimas {HOURS}h)</h2>'
            f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="alertas por hora">'
            f'<line x1="{pad}" y1="{H-pad}" x2="{W-pad}" y2="{H-pad}" stroke="{GRID}"/>'
            f'{"".join(bars)}{"".join(ticks)}</svg>'
            f'<p class="muted">pico: {mx} alertas/hora</p></section>')

def dur(a, b):
    if not a or not b or b < a:
        return "-"
    s = int(b - a)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m"
    return f"{s//3600}h{(s%3600)//60:02d}m"

host = os.uname().nodename if hasattr(os, "uname") else "suricata"
gen = datetime.now().strftime("%Y-%m-%d %H:%M")

top_flujos = sorted(flujos.items(), key=lambda kv: kv[1][0], reverse=True)[:150]
filas = []
for (src, sport, dst, dport, proto, sig), (cnt, first, last) in top_flujos:
    hp = datetime.fromtimestamp(first).strftime("%d/%m %H:%M") if first else "-"
    hu = datetime.fromtimestamp(last).strftime("%H:%M") if last else "-"
    filas.append(
        f"<tr><td class='mono'>{esc(src)}</td><td class='mono num'>{esc(sport)}</td>"
        f"<td class='mono dst'>{esc(dst)}</td><td class='mono num'>{esc(dport)}</td>"
        f"<td>{esc(proto)}</td><td>{esc(sig)}</td>"
        f"<td class='num'>{cnt}</td><td class='mono'>{hp} &rarr; {hu}</td><td>{dur(first,last)}</td></tr>")

def top(counter, n=12, fmt=str):
    return [(fmt(k), v) for k, v in counter.most_common(n)]

by_sig = Counter()
for _k, _v in flujos.items():
    by_sig[_k[5]] += _v[0]
firmas_top = [(s[:110], n) for s, n in by_sig.most_common(12)]

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
.tiles{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.tile{{border:1px solid {GRID};border-radius:10px;padding:14px 16px;background:#fff}}
.tile .big{{font-size:30px;font-weight:700;line-height:1}}
.tile .lab{{font-size:12px;color:{INK2};margin-top:6px;display:flex;align-items:center;gap:6px}}
.dot{{width:11px;height:11px;border-radius:3px;display:inline-block}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.card{{border:1px solid {GRID};border-radius:10px;padding:16px;background:#fff;margin-bottom:16px}}
.card.wide{{grid-column:1/-1}}
.lbl{{font-size:12px;fill:{INK2}}} .val{{font-size:12px;fill:{INK};font-weight:600}}
.tick{{font-size:11px;fill:{INK2}}}
.muted{{color:{INK2};font-size:12px;margin:8px 0 0}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid {GRID};vertical-align:top}}
th{{color:{INK2};font-weight:600;position:sticky;top:0;background:#fff}}
td.num,td.mono{{white-space:nowrap}} .mono{{font-family:ui-monospace,Consolas,monospace}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
.tablewrap{{overflow-x:auto}}
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
  <div class="sub">Ultimas {HOURS} horas &middot; {total:,} alertas graves &middot; generado {gen}</div></div>
</header>
<main>
  <div class="tiles">
    <div class="tile"><div class="big">{total:,}</div><div class="lab">alertas graves</div></div>
    <div class="tile"><div class="big">{len(by_src):,}</div><div class="lab"><span class="dot" style="background:#e34948"></span>IPs origen (atacantes)</div></div>
    <div class="tile"><div class="big">{len(by_dst):,}</div><div class="lab"><span class="dot" style="background:#eb6834"></span>IPs destino (objetivos)</div></div>
    <div class="tile"><div class="big">{len(by_dport):,}</div><div class="lab"><span class="dot" style="background:#eda100"></span>puertos destino distintos</div></div>
  </div>
  {timeline(by_hour)}
  <div class="grid">
    {hbar("Puertos de destino mas atacados", top(by_dport), "alertas")}
    {hbar("IPs origen (atacantes)", top(by_src), "alertas")}
    {hbar("IPs destino (objetivos)", top(by_dst), "alertas")}
  </div>
  {hbar("Firmas mas frecuentes (tipo de ataque)", firmas_top, "alertas", card_class="card wide", label_above=True)}
  <section class="card">
    <h2>Detalle: quien ataca, a donde, por que puerto, cuando y por cuanto tiempo</h2>
    <div class="tablewrap"><table id="detalle">
      <thead><tr><th>IP origen</th><th class="num">Puerto</th><th>IP destino (atacada)</th><th class="num">Puerto</th>
      <th>Protocolo</th><th>Firma (tipo de ataque)</th><th class="num">Veces</th><th>Primera &rarr; ultima</th><th>Duracion</th></tr></thead>
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
      var rows=[].slice.call(document.querySelectorAll('#detalle tbody tr'));
      if(rows.length<=20){{var pg=document.getElementById('pager'); if(pg) pg.style.display='none'; return;}}
      var per=20, n=Math.max(1,Math.ceil(rows.length/per)), p=1;
      function rd(){{var m=(location.hash||'').match(/p=(\\d+)/); return m?Math.min(n,Math.max(1,+m[1])):1;}}
      function draw(){{
        for(var i=0;i<rows.length;i++) rows[i].style.display=(i>=(p-1)*per&&i<p*per)?'':'none';
        document.getElementById('pgi').textContent='Pagina '+p+' de '+n;
        document.getElementById('prev').disabled=(p<=1);
        document.getElementById('next').disabled=(p>=n);
      }}
      function go(x){{p=Math.min(n,Math.max(1,x)); try{{location.hash='p='+p;}}catch(e){{}} draw();}}
      p=rd();
      document.getElementById('prev').onclick=function(){{go(p-1);}};
      document.getElementById('next').onclick=function(){{go(p+1);}};
      window.addEventListener('hashchange',function(){{p=rd();draw();}});
      draw();
    }})();
    </script>
    <p class="muted">Top {len(filas)} flujos por numero de alertas. Se excluye ruido informativo (ET INFO).</p>
  </section>
</main></body></html>"""

out = os.path.join(LOGDIR, "report-" + datetime.now().strftime("%Y%m%d-%H%M") + ".html")
open(out, "w", encoding="utf-8").write(doc)

# Historico acotado: conservar solo los 20 reportes HTML mas recientes (el panel genera
# uno cada 10 min, asi que sin esto se acumulan). Se corre en cada generacion.
try:
    hs = sorted(glob.glob(f"{LOGDIR}/report-*.html"), key=os.path.getmtime, reverse=True)
    for viejo in hs[20:]:
        try:
            os.remove(viejo)
        except OSError:
            pass
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
import base64, glob, html, json, os, re, secrets, subprocess, threading, time
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSIONS = {}          # token -> epoch de expiracion
SESSION_TTL = 12 * 3600

EVE = "/var/log/suricata/eve.json"

EXCL_FILE = "/etc/suricata-exclusiones.json"

def cargar_exclusiones():
    """Lista de reglas de exclusion. Cada una: {tipo:'dst'|'src', ip, motivo, puertos:[int]}.
    puertos vacio = todos los puertos. Tambien lee las lineas IGNORAR_* legacy del .conf."""
    reglas = []
    try:
        data = json.load(open(EXCL_FILE, encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if r.get("ip"):
                    reglas.append({"tipo": r.get("tipo", "dst"), "ip": r["ip"],
                                   "motivo": r.get("motivo", ""),
                                   "puertos": [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()]})
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
    tmp = EXCL_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump([r for r in reglas if r.get("motivo") != "(conf)"], f, ensure_ascii=False, indent=1)
    os.replace(tmp, EXCL_FILE)

def _excluido(reglas, src, dst, dport):
    for r in reglas:
        quien = dst if r["tipo"] == "dst" else src
        if quien == r["ip"] and (not r["puertos"] or (dport is not None and int(dport) in r["puertos"])):
            return True
    return False
_RE = {k: re.compile(p) for k, p in {
    "ts": r'"timestamp":"([^"]+)"', "src_ip": r'"src_ip":"([^"]+)"',
    "dest_ip": r'"dest_ip":"([^"]+)"', "src_port": r'"src_port":(\d+)',
    "dest_port": r'"dest_port":(\d+)', "proto": r'"proto":"([^"]+)"',
    "sig": r'"signature":"((?:[^"\\]|\\.)*)"',
}.items()}

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
        if _excluido(reglas, src, dst, int(dp) if dp else None):   # exclusiones configuradas
            continue
        vistos += 1
        ts = get("ts"); hh = ts[11:19] if len(ts) >= 19 else ""
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
            tr.append(
                f'<tr style="border-left:4px solid {color}">'
                f'<td class="mono t">{html.escape(hh)}</td>'
                f'<td><span class="badge" style="background:{color}">{etq}</span></td>'
                f'<td class="mono">{html.escape(src)}</td>'
                f'<td class="mono dst">{html.escape(dst)}</td>'
                f'<td class="mono">{html.escape(puerto)}</td>'
                f'<td>{html.escape(sig)} {veces}</td></tr>')
        cuerpo = "".join(tr)
    ahora = datetime.now().strftime("%H:%M:%S")
    return (
        '<style>'
        '.feed{margin:20px 28px}'
        '.feed h2{display:flex;align-items:center;gap:10px;margin:0 0 12px}'
        '.pulse{width:9px;height:9px;border-radius:50%;background:#e34948;display:inline-block;'
        'box-shadow:0 0 0 0 rgba(227,73,72,.6);animation:pulse 1.6s infinite}'
        '@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(227,73,72,.5)}70%{box-shadow:0 0 0 8px rgba(227,73,72,0)}100%{box-shadow:0 0 0 0 rgba(227,73,72,0)}}'
        '.feedwrap{max-height:420px;overflow:auto;border:1px solid #e7e6e2;border-radius:10px}'
        '.feed table{width:100%;border-collapse:collapse;font-size:12.5px}'
        '.feed thead th{position:sticky;top:0;background:#f4f4f2;color:#52514e;text-align:left;'
        'padding:9px 10px;font-weight:600;border-bottom:1px solid #e7e6e2;z-index:1}'
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
        f'<div class="feedwrap"><table>'
        f'<thead><tr><th>Hora</th><th>Tipo</th><th>Origen (equipo)</th><th>Destino</th><th>Puerto</th><th>Ataque</th></tr></thead>'
        f'<tbody>{cuerpo}</tbody></table></div>'
        f'<p class="muted" style="margin:8px 2px">Agrupado por equipo y tipo &middot; &times;N = veces repetido</p>'
        f'</section>')

LOGDIR = "/var/log/suricata"
GEN = "/usr/local/bin/suricata-html-report"
CONF = "/etc/suricata-dashboard.conf"
REFRESH_SECS = 600   # regeneracion en segundo plano (el reporte puede tardar en redes grandes)

def conf():
    d = {"PORT": "5637", "USER": "admin", "PASS": ""}
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); d[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return d

CFG = conf()

def newest_report():
    fs = sorted(glob.glob(f"{LOGDIR}/report-*.html"), key=os.path.getmtime, reverse=True)
    return fs[0] if fs else None

def refrescador():
    """Hilo de fondo: regenera el reporte periodicamente, NUNCA en el request.
    Asi 'En vivo' sirve siempre el ultimo archivo al instante aunque generar tarde."""
    while True:
        nr = newest_report()
        stale = (nr is None) or (time.time() - os.path.getmtime(nr) >= REFRESH_SECS)
        if stale:
            try:
                subprocess.run(["nice", "-n", "15", GEN], timeout=600,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        time.sleep(30)

NAV = """<style>
.nav{position:sticky;top:0;z-index:20;background:#0b0b0b;color:#fff;padding:0 22px;
font:14px system-ui,-apple-system,Segoe UI,sans-serif;display:flex;align-items:center;gap:6px;
box-shadow:0 1px 6px rgba(0,0,0,.15)}
.nav .brand{font-weight:700;font-size:15px;margin-right:18px;display:flex;align-items:center;gap:8px}
.nav .brand .sh{width:10px;height:10px;border-radius:3px;background:#2a78d6}
.nav a{color:#cfd8e3;text-decoration:none;padding:14px 12px;border-bottom:2px solid transparent}
.nav a:hover{color:#fff}
.nav a.on{color:#fff;border-bottom-color:#2a78d6}
.nav .sp{margin-left:auto}
</style>
<div class="nav"><span class="brand"><span class="sh"></span>Estadisticas Suricata</span>
<a href="/" class="on">En vivo</a>
<a href="/historico">Historico</a>
<a href="/exclusiones">Exclusiones</a>
<a href="/perfil">Perfil</a>
<a href="/documentacion">Documentacion</a>
<a href="/" class="sp">&#8635; Actualizar</a>
<a href="/logout">Salir</a></div>"""

def wrap(body_html, refresh=True):
    meta = '<meta http-equiv="refresh" content="300">' if refresh else ""
    # inserta la barra de navegacion justo despues de <body ...>
    def ins(m):
        return m.group(0) + NAV
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

def perfil_page(msg="", ok=False):
    u = html.escape(CFG.get("USER", "admin"))
    banner = ""
    if msg:
        col = "#1baf7a" if ok else "#e34948"
        banner = (f'<div style="background:{col};color:#fff;padding:10px 14px;border-radius:8px;'
                  f'margin-bottom:16px;font-size:13px">{html.escape(msg)}</div>')
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>Perfil</title>"
            "<style>body{margin:0;background:#fcfcfb;font:14px system-ui,-apple-system,Segoe UI,sans-serif;color:#0b0b0b}"
            "main{max-width:460px;margin:0 auto;padding:26px 20px}h1{font-size:20px;margin:0 0 4px}"
            ".sub{color:#52514e;font-size:13px;margin:0 0 20px}"
            ".card{border:1px solid #e7e6e2;border-radius:12px;padding:22px;background:#fff}"
            "label{display:block;font-size:13px;color:#52514e;margin:14px 0 5px;font-weight:600}"
            "input{width:100%;padding:9px 11px;border:1px solid #d7d6d2;border-radius:8px;font:14px system-ui;box-sizing:border-box}"
            "input:focus{outline:none;border-color:#2a78d6;box-shadow:0 0 0 3px rgba(42,120,214,.15)}"
            "button{margin-top:20px;width:100%;padding:11px;background:#2a78d6;color:#fff;border:0;"
            "border-radius:8px;font:600 14px system-ui;cursor:pointer}button:hover{background:#1c5cab}"
            ".hint{color:#8a8a86;font-size:12px;margin-top:6px}</style></head><body>"
            + NAV +
            "<main><h1>Perfil</h1><p class=sub>Cambia el usuario y la clave de acceso al panel.</p>"
            + banner +
            "<div class=card><form method=post action='/perfil'>"
            "<label>Clave actual</label><input type=password name=actual autocomplete=current-password required>"
            f"<label>Usuario</label><input type=text name=usuario value='{u}' autocomplete=username required>"
            "<label>Clave nueva</label><input type=password name=nueva autocomplete=new-password required>"
            "<div class=hint>Minimo 6 caracteres.</div>"
            "<label>Repetir clave nueva</label><input type=password name=nueva2 autocomplete=new-password required>"
            "<button type=submit>Guardar cambios</button></form></div>"
            "<p class=sub style='margin-top:16px'>Al guardar se cierra la sesion y tendras que entrar de nuevo con las credenciales nuevas.</p>"
            "</main></body></html>")
    return body

def exclusiones_page(msg="", ok=False):
    reglas = cargar_exclusiones()
    banner = ""
    if msg:
        col = "#1baf7a" if ok else "#e34948"
        banner = f'<div style="background:{col};color:#fff;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px">{html.escape(msg)}</div>'
    filas = []
    for i, r in enumerate(reglas):
        pts = ", ".join(str(p) for p in r["puertos"]) if r["puertos"] else "todos"
        tipo = "Destino" if r["tipo"] == "dst" else "Origen"
        legacy = r.get("motivo") == "(conf)"
        accion = ('<span class="muted">en .conf</span>' if legacy else
                  f'<form method=post action="/exclusiones" style="margin:0">'
                  f'<input type=hidden name=accion value=del><input type=hidden name=idx value="{i}">'
                  f'<button class="del" type=submit>Eliminar</button></form>')
        filas.append(f'<tr><td>{tipo}</td><td class="mono">{html.escape(r["ip"])}</td>'
                     f'<td>{html.escape(pts)}</td><td>{html.escape(r.get("motivo",""))}</td><td>{accion}</td></tr>')
    tabla = ("".join(filas) if filas else
             '<tr><td colspan=5 class="muted">No hay exclusiones. Todo el trafico se analiza.</td></tr>')
    body = f"""<!doctype html><html lang=es><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>Exclusiones</title>
<style>body{{margin:0;background:#fcfcfb;font:14px system-ui,-apple-system,Segoe UI,sans-serif;color:#0b0b0b}}
main{{max-width:820px;margin:0 auto;padding:24px 20px}}h1{{font-size:21px;margin:0 0 4px}}
.sub{{color:#52514e;font-size:13px;margin:0 0 18px}}h2{{font-size:15px;margin:24px 0 10px}}
.card{{border:1px solid #e7e6e2;border-radius:12px;padding:18px;background:#fff}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}}th,td{{padding:8px 10px;border-bottom:1px solid #eee;text-align:left}}
th{{color:#52514e;font-weight:600}}.mono{{font-family:ui-monospace,Consolas,monospace}}
.muted{{color:#8a8a86;font-size:12px}}
form.add{{display:grid;grid-template-columns:130px 1fr;gap:10px 12px;align-items:center}}
label{{font-size:13px;color:#52514e;font-weight:600}}
input,select{{padding:9px 11px;border:1px solid #d7d6d2;border-radius:8px;font:14px system-ui;width:100%;box-sizing:border-box}}
.hint{{grid-column:2;color:#8a8a86;font-size:12px;margin-top:-4px}}
button{{padding:9px 16px;border:0;border-radius:8px;font:600 13px system-ui;cursor:pointer}}
button[type=submit].primary{{background:#2a78d6;color:#fff;grid-column:2;justify-self:start;margin-top:4px}}
button.del{{background:#fbeaea;color:#c0392b;border:1px solid #f0c9c9;padding:5px 10px}}
button.del:hover{{background:#f5d5d5}}</style></head><body>{NAV}<main>
<h1>Exclusiones</h1><p class=sub>IPs que no quieres que aparezcan en el panel ni en los reportes
(tus DNS, tu monitoreo SNMP, etc.). Se aplica al instante.</p>
{banner}
<div class=card><table><thead><tr><th>Tipo</th><th>IP</th><th>Puertos</th><th>Motivo</th><th></th></tr></thead>
<tbody>{tabla}</tbody></table></div>
<h2>Agregar exclusion</h2>
<div class=card><form class=add method=post action="/exclusiones">
<input type=hidden name=accion value=add>
<label>Tipo</label><select name=tipo><option value=dst>Destino (a donde va)</option><option value=src>Origen (de donde sale)</option></select>
<label>IP</label><input name=ip placeholder="10.66.66.2" required>
<label>Puertos</label><input name=puertos placeholder="53, 161  (vacio = todos)">
<div class=hint>Para un DNS suele ser 53; para monitoreo SNMP, 161. Deja vacio para ignorar toda la IP.</div>
<label>Motivo</label><input name=motivo placeholder="DNS interno / monitoreo SNMP">
<button type=submit class=primary>Agregar</button>
</form></div>
<p class=sub style="margin-top:16px">Ejemplos: tu DNS interno como <b>Destino</b> puerto <b>53</b>; tu servidor de
monitoreo como <b>Origen</b> puerto <b>161</b>. Asi quitas el ruido sin perder de vista lo demas que hagan esas IPs.</p>
</main></body></html>"""
    return body

LOGO_IMG = "data:image/png;base64,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"

def login_page(msg=""):
    err = f'<div class="err">{html.escape(msg)}</div>' if msg else ""
    return f"""<!doctype html><html lang=es><head><meta charset=utf-8>
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
<img class="logo" src="{LOGO_IMG}" alt="Suricata">
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

def documentacion_page():
    port = CFG.get("PORT", "5637")
    css = ("body{margin:0;background:#fcfcfb;font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;color:#0b0b0b}"
           "main{max-width:820px;margin:0 auto;padding:24px 22px}h1{font-size:22px;margin:0 0 4px}"
           "h2{font-size:16px;margin:26px 0 8px;border-bottom:1px solid #e7e6e2;padding-bottom:6px}"
           "p,li{color:#33322f}code{background:#f0efec;padding:1px 6px;border-radius:5px;"
           "font-family:ui-monospace,Consolas,monospace;font-size:13px}"
           "pre{background:#0b0b0b;color:#e8e8e3;padding:12px 14px;border-radius:8px;overflow-x:auto;font-size:13px}"
           "pre code{background:none;color:inherit;padding:0}"
           ".b{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}"
           "table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #e7e6e2;padding:7px 10px;text-align:left;font-size:14px}"
           "th{background:#f4f4f2}")
    body = f"""<!doctype html><html lang=es><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>Documentacion</title>
<style>{css}</style></head><body>{NAV}<main>
<h1>Documentacion</h1>
<p>Guia rapida del panel de estadisticas de Suricata y como ajustarlo.</p>

<h2>Que muestra el panel</h2>
<ul>
<li><b>En vivo</b>: resumen de las ultimas 24h (puertos atacados, IPs origen y destino,
linea de tiempo, tabla de detalle) y, abajo, el feed de los ultimos ataques que se
actualiza solo cada 20 segundos.</li>
<li><b>Historico</b>: los ultimos 20 reportes guardados; el resto se borra solo.</li>
<li><b>Perfil</b>: cambiar el usuario y la clave de acceso a este panel.</li>
</ul>

<h2>Colores de gravedad</h2>
<table><tr><th>Etiqueta</th><th>Que significa</th><th>Que hacer</th></tr>
<tr><td><span class="b" style="background:#e34948">INFECTADO</span></td>
<td>El equipo habla con un centro de mando (CnC/botnet/troyano). Infeccion confirmada.</td>
<td>Aislar el equipo y avisar al cliente.</td></tr>
<tr><td><span class="b" style="background:#eb6834">ATAQUE</span></td>
<td>Escaneo o ataque saliente (SSH, puertos, exploits).</td><td>Revisar el equipo.</td></tr>
<tr><td><span class="b" style="background:#eda100">SOSPECHOSO</span></td>
<td>Consulta a dominios de mala fama (.su, .cc, .top, dyndns). El destino suele ser tu
propio DNS; el sospechoso es el equipo de origen.</td><td>Vigilar.</td></tr>
</table>

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

<h2>Cambiar la clave del panel</h2>
<p>Lo mas facil es el apartado <b>Perfil</b> de este mismo panel. Tambien se puede en la VM
editando <code>USER</code> y <code>PASS</code>:</p>
<pre><code>nano /etc/suricata-dashboard.conf
systemctl restart suricata-dashboard</code></pre>

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
</table>

<h2>Reinstalar o actualizar</h2>
<p>Todo esta en un instalador idempotente. Para actualizar a la ultima version:</p>
<pre><code>curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -t -n 172.19.1.0/24,10.0.0.0/8</code></pre>
</main></body></html>"""
    return body

def historico_page():
    fs = sorted(glob.glob(f"{LOGDIR}/report-*.html"), key=os.path.getmtime, reverse=True)
    rows = []
    for f in fs:
        b = os.path.basename(f)
        t = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(f)))
        kb = os.path.getsize(f) // 1024
        rows.append(f'<tr><td><a href="/r/{b}">{b}</a></td><td>{t}</td><td>{kb} KB</td></tr>')
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Historico</title><style>body{margin:0;background:#fcfcfb;"
            "font:14px system-ui,sans-serif;color:#0b0b0b}main{max-width:800px;margin:0 auto;padding:20px}"
            "table{width:100%;border-collapse:collapse}td{padding:8px;border-bottom:1px solid #e7e6e2}"
            "a{color:#2a78d6}</style></head><body>"
            "<main><h1>Reportes guardados</h1><table><tbody>"
            + ("".join(rows) or "<tr><td>Sin reportes todavia.</td></tr>")
            + "</tbody></table></main></body></html>")
    return wrap(body, refresh=False)

class H(BaseHTTPRequestHandler):
    server_version = "suricata-dashboard"
    def _sid(self):
        c = self.headers.get("Cookie")
        if not c:
            return None
        try:
            m = SimpleCookie(c).get("sid")
            return m.value if m else None
        except Exception:
            return None
    def _sesion_ok(self):
        sid = self._sid()
        if sid and SESSIONS.get(sid, 0) > time.time():
            return True
        return False
    def _auth_ok(self):
        pw = CFG.get("PASS", "")
        if not pw:
            return True  # sin PASS configurada, sin auth (solo detras de VPN/proxy)
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
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/login":
            if self._auth_ok():
                return self._redirect("/")
            return self._html(login_page())
        if path == "/logout":
            sid = self._sid()
            if sid:
                SESSIONS.pop(sid, None)
            return self._redirect("/login", cookie="sid=; Path=/; Max-Age=0")
        if not self._auth_ok():
            return self._deny()
        if path in ("/", "/index.html"):
            f = newest_report()   # instantaneo: nunca regenera en el request
            feed = live_feed_html()
            # cabeza/estilos y <main> (resumen 24h) del ultimo reporte, si existe
            head_css = ""; resumen = ""
            if f:
                try:
                    doc = open(f, encoding="utf-8", errors="replace").read()
                    mh = re.search(r"<style>(.*?)</style>", doc, re.S)
                    head_css = f"<style>{mh.group(1)}</style>" if mh else ""
                    mm = re.search(r"<main[^>]*>(.*?)</main>", doc, re.S)
                    resumen = ("<h2 style='margin:16px 28px 0'>Resumen de las ultimas 24h</h2>"
                               f"<main>{mm.group(1)}</main>") if mm else ""
                except OSError:
                    pass
            if not resumen:
                resumen = ("<main style='padding:24px'><p style='color:#52514e'>El resumen de 24h se "
                           "esta generando en segundo plano; aparecera aqui en unos minutos. "
                           "El feed de abajo ya esta en vivo.</p></main>")
            page = (f"<!doctype html><html lang=es><head><meta charset=utf-8>"
                    f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                    f"<meta http-equiv=refresh content=20><title>Estadisticas Suricata</title>"
                    f"{head_css}</head><body>{NAV}{resumen}{feed}</body></html>")
            return self._html(page)
        if path == "/historico":
            return self._html(historico_page())
        if path == "/perfil":
            return self._html(perfil_page())
        if path == "/exclusiones":
            return self._html(exclusiones_page())
        if path == "/documentacion":
            return self._html(documentacion_page())
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
    def do_POST(self):
        ruta = self.path.split("?", 1)[0]
        import urllib.parse
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        except Exception:
            body = ""
        q = urllib.parse.parse_qs(body)
        if ruta == "/login":
            u = q.get("usuario", [""])[0]; p = q.get("clave", [""])[0]
            if u == CFG.get("USER", "admin") and p == CFG.get("PASS", ""):
                token = secrets.token_urlsafe(24)
                SESSIONS[token] = time.time() + SESSION_TTL
                for k in [k for k, v in SESSIONS.items() if v < time.time()]:
                    SESSIONS.pop(k, None)
                return self._redirect("/", cookie=f"sid={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}")
            return self._html(login_page("Usuario o clave incorrectos."))
        if not self._auth_ok():
            return self._deny()
        if ruta not in ("/perfil", "/exclusiones"):
            return self._html("<h1>No encontrado</h1>", 404)
        if ruta == "/exclusiones":
            return self._post_exclusiones(q)
        actual = (q.get("actual", [""])[0])
        usuario = (q.get("usuario", [""])[0]).strip()
        nueva = (q.get("nueva", [""])[0])
        nueva2 = (q.get("nueva2", [""])[0])
        cur = CFG.get("PASS", "")
        if cur and actual != cur:
            return self._html(perfil_page("La clave actual no es correcta.", ok=False))
        if not usuario or " " in usuario or len(usuario) > 40:
            return self._html(perfil_page("Usuario invalido (sin espacios, max 40).", ok=False))
        if len(nueva) < 6:
            return self._html(perfil_page("La clave nueva debe tener al menos 6 caracteres.", ok=False))
        if nueva != nueva2:
            return self._html(perfil_page("Las dos claves nuevas no coinciden.", ok=False))
        try:
            save_conf(usuario, nueva)
        except OSError as ex:
            return self._html(perfil_page(f"No se pudo guardar: {ex}", ok=False))
        # las credenciales nuevas ya rigen; el navegador reintentara con las viejas -> 401 y re-login
        SESSIONS.clear()   # cerrar sesiones abiertas; hay que entrar con las nuevas
        return self._redirect("/login", cookie="sid=; Path=/; Max-Age=0")

    def _post_exclusiones(self, q):
        import ipaddress
        accion = q.get("accion", [""])[0]
        # trabajar solo con las reglas propias (no las legacy del .conf)
        propias = [r for r in cargar_exclusiones() if r.get("motivo") != "(conf)"]
        if accion == "del":
            try:
                idx = int(q.get("idx", ["-1"])[0])
                todas = cargar_exclusiones()
                objetivo = todas[idx]
                if objetivo.get("motivo") == "(conf)":
                    return self._html(exclusiones_page("Esa exclusion esta en el archivo .conf; quitala alli.", ok=False))
                propias = [r for r in propias if not (r["ip"] == objetivo["ip"] and r["tipo"] == objetivo["tipo"] and r["puertos"] == objetivo["puertos"])]
                guardar_exclusiones(propias)
                return self._html(exclusiones_page("Exclusion eliminada.", ok=True))
            except Exception:
                return self._html(exclusiones_page("No se pudo eliminar.", ok=False))
        # agregar
        tipo = q.get("tipo", ["dst"])[0]
        ip = (q.get("ip", [""])[0]).strip()
        motivo = (q.get("motivo", [""])[0]).strip()[:80]
        pts_raw = (q.get("puertos", [""])[0]).strip()
        if tipo not in ("dst", "src"):
            tipo = "dst"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self._html(exclusiones_page("IP invalida.", ok=False))
        puertos = []
        for p in pts_raw.replace(";", ",").split(","):
            p = p.strip()
            if p:
                if not p.isdigit() or not (0 < int(p) < 65536):
                    return self._html(exclusiones_page(f"Puerto invalido: {p}", ok=False))
                puertos.append(int(p))
        propias.append({"tipo": tipo, "ip": ip, "motivo": motivo, "puertos": puertos})
        try:
            guardar_exclusiones(propias)
        except OSError as ex:
            return self._html(exclusiones_page(f"No se pudo guardar: {ex}", ok=False))
        return self._html(exclusiones_page(f"Exclusion agregada: {ip}.", ok=True))

    def log_message(self, *a):
        pass

def main():
    port = int(CFG.get("PORT", "5637"))
    threading.Thread(target=refrescador, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), H)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
DASH
chmod 755 /usr/local/bin/suricata-dashboard
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
import os, socket, struct, sys, time

PORT = int(os.environ.get("TZSP_PORT", "37008"))
OUT_IF = os.environ.get("TZSP_OUT_IF", "ids-in")

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
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    rx.bind(("0.0.0.0", PORT))
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    tx.bind((OUT_IF, 0))
    print(f"tzsp-decap: escuchando UDP {PORT} -> {OUT_IF}", flush=True)
    rxn = txn = bad = big = 0
    last = time.time()
    while True:
        d, peer = rx.recvfrom(65535)
        rxn += 1
        f = decap(d)
        if f is None or len(f) < 14:
            bad += 1
        else:
            try:
                tx.send(f)
                txn += 1
            except OSError:
                big += 1
        now = time.time()
        if now - last >= 60:
            print(f"tzsp-decap: rx={rxn} tx={txn} descartados={bad} muy_grandes={big} ultimo_origen={peer[0]}", flush=True)
            last = now

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
PYD
  chmod 755 /usr/local/bin/tzsp-decap.py

  cat > /etc/systemd/system/tzsp-decap.service <<UNIT
[Unit]
Description=Receptor TZSP (MikroTik) -> ${TZSP_MON} para Suricata
After=network.target
Before=suricata.service

[Service]
Environment=TZSP_PORT=${TZSP_PORT}
Environment=TZSP_OUT_IF=${TZSP_IN}
# crea el par veth si no existe; sin IPv6 para que no meta ruido propio
# las tramas reinyectadas NO deben entrar a la pila IP del kernel ni reenviarse
ExecStartPre=/bin/sh -c 'ip link show ${TZSP_MON} >/dev/null 2>&1 || ip link add ${TZSP_IN} type veth peer name ${TZSP_MON}'
ExecStartPre=/bin/sh -c 'sysctl -qw net.ipv6.conf.${TZSP_IN}.disable_ipv6=1 net.ipv6.conf.${TZSP_MON}.disable_ipv6=1 net.ipv4.conf.${TZSP_MON}.rp_filter=1 net.ipv4.conf.${TZSP_MON}.forwarding=0 net.ipv4.conf.${TZSP_MON}.arp_ignore=8 || true'
# el SO_RCVBUF de 16 MB del receptor lo topa rmem_max
ExecStartPre=-/usr/sbin/sysctl -qw net.core.rmem_max=16777216
# mtu 65535 (maximo de veth): el router agrega segmentos (GRO) y manda tramas de hasta
# ~22 kB; con 1600/9000 se perdian con EMSGSIZE y cada trama perdida es un hueco mas
# en el reensamblado. Suricata dimensiona el snaplen por el MTU (block-size 128k en ids-mon).
ExecStartPre=/sbin/ip link set ${TZSP_IN} up mtu 65535
ExecStartPre=/sbin/ip link set ${TZSP_MON} up mtu 65535 promisc on
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
  ip link show "$TZSP_MON" >/dev/null 2>&1 || { journalctl -u tzsp-decap --no-pager -n 20; die "No se creo ${TZSP_MON}. Revisa: journalctl -u tzsp-decap"; }

  # segunda interfaz af-packet en suricata.yaml (idempotente)
  if ! grep -qE "^\s*- interface: ${TZSP_MON}\s*$" "$CFG"; then
    python3 - "$CFG" "$TZSP_MON" <<'PY'
import sys, re
cfg, mon = sys.argv[1], sys.argv[2]
s = open(cfg, encoding="utf-8").read()
block = f"""  - interface: {mon}
    # espejo TZSP desde MikroTik (lo crea tzsp-decap.service)
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
  # block-size en el bloque ids-mon aunque ya existiera de una corrida anterior
  if ! awk -v m="$TZSP_MON" '$0 ~ "^  - interface: "m"$"{f=1;next} f&&/^  - interface:/{exit} f&&/^    block-size: 131072/{ok=1} END{exit !ok}' "$CFG"; then
    sed -i "/^  - interface: ${TZSP_MON}\$/a\    block-size: 131072" "$CFG"
  fi
  # que Suricata no inspeccione en ${IFACE} el propio flujo TZSP (doble CPU + "truncated").
  # Los datagramas TZSP >1500 B llegan fragmentados y los fragmentos no iniciales no
  # tienen cabecera UDP: se excluyen tambien (ip[6:2] & 0x1fff = offset de fragmento).
  BPF="not (udp port ${TZSP_PORT} or (ip[6:2] \& 0x1fff != 0))"
  BPF_LINE="    bpf-filter: \"${BPF}\""
  sed -i "/^\s*bpf-filter: \"not udp port ${TZSP_PORT}\"\s*$/d; /^\s*bpf-filter: \"not (udp port ${TZSP_PORT} or/d" "$CFG"
  sed -i "0,/^  - interface: ${IFACE}\$/s//&\n${BPF_LINE}/" "$CFG"
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
# shellcheck disable=SC2086
"$ETHTOOL" -K "$IFACE" $OFFLOADS >/dev/null 2>&1 || true
install -d /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/10-offload.conf <<UNIT
# Generado por install-suricata.sh: sin offloads en la interfaz de captura.
[Service]
ExecStartPre=-${ETHTOOL} -K ${IFACE} ${OFFLOADS}
UNIT
systemctl daemon-reload
ok "Offloads apagados en ${IFACE} (gro/lro/tso/gso/rx-gro-hw)."

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
  if ! ufw status | grep -qE "^${TZSP_PORT}/udp\s+ALLOW"; then
    ufw allow "${TZSP_PORT}/udp" comment 'TZSP MikroTik' >/dev/null && ok "UFW: abierto ${TZSP_PORT}/udp para TZSP."
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
