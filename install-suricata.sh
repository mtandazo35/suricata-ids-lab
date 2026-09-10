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
}.items()}

def campos(line):
    def g(k):
        m = _RE[k].search(line)
        return m.group(1) if m else ""
    return g

LOGDIR = "/var/log/suricata"
HOURS = int(sys.argv[1]) if len(sys.argv) > 1 else 24
cutoff = time.time() - HOURS * 3600
BUCKET_MIN = 30                 # resolucion de la linea de tiempo (minutos por barra)
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
    (("go http client",), "Cliente HTTP Go"),
    (("fake wget", "wget 3.0"), "User-Agent falso"),
    (("user_agent", "user agent"), "User-Agent raro"),
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
    return sig

def parse_ts(s):
    # Parsea con el offset de la marca (eve.json trae -0500) para obtener el epoch absoluto.
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except (ValueError, TypeError):
            pass
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=TZ_EC).timestamp()
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
                by_hour[int(ts // BUCKET)] += 1
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

def hbar(titulo, pares, unidad="alertas", fmt=str, lblw=125, barw=470, card_class="card", label_above=False):
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
    # Ventana FIJA de 24h en intervalos de BUCKET_MIN minutos (detalle hora:minuto),
    # terminando en el intervalo actual, rellenando con 0 los vacios. Tooltip por barra.
    n = HOURS * 3600 // BUCKET                      # p.ej. 48 barras de 30 min
    ahora_b = int(time.time() // BUCKET)
    lo = ahora_b - (n - 1)
    vals = [by_hour.get(lo + i, 0) for i in range(n)]
    mx = max(vals) or 1
    W, H, pad = 1120, 190, 30
    bw = (W - 2 * pad) / n
    tick_every = max(1, (60 // BUCKET_MIN) * 2)     # una etiqueta cada 2 horas
    bars, ticks = [], []
    for i, v in enumerate(vals):
        x = pad + i * bw
        bh = (H - 2 * pad) * v / mx
        t0 = datetime.fromtimestamp((lo + i) * BUCKET, TZ_EC)
        t1 = datetime.fromtimestamp((lo + i + 1) * BUCKET, TZ_EC)
        rango = t0.strftime("%H:%M") + "-" + t1.strftime("%H:%M")
        bars.append(
            f'<rect x="{x:.1f}" y="{H-pad-bh:.1f}" width="{max(1,bw-1.5):.1f}" height="{bh:.1f}" rx="1.5" fill="{BLUE}">'
            f'<title>{rango}  ·  {v:,} alertas</title></rect>')
        # etiquetas ancladas a la DERECHA: la ultima barra (intervalo actual) siempre
        # lleva su hora, para que se vea que el eje llega hasta "ahora" y no se corta antes
        if (n - 1 - i) % tick_every == 0:
            ticks.append(f'<text x="{x+bw/2:.1f}" y="{H-pad+14:.0f}" text-anchor="middle" class="tick">{t0.strftime("%H:%M")}</text>')
    pico_t = datetime.fromtimestamp((lo + vals.index(mx)) * BUCKET, TZ_EC).strftime("%H:%M") if mx else ""
    return (f'<section class="card wide"><h2>Ataques por hora y minuto (ultimas {HOURS}h)</h2>'
            f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="alertas por intervalo" style="cursor:default">'
            f'<line x1="{pad}" y1="{H-pad}" x2="{W-pad}" y2="{H-pad}" stroke="{GRID}"/>'
            f'{"".join(bars)}{"".join(ticks)}</svg>'
            f'<p class="muted">1 barra cada {BUCKET_MIN} min &middot; pasa el raton para ver el rango y el conteo &middot; pico: {mx:,} alertas a las {pico_t}</p></section>')

def dur(a, b):
    if not a or not b or b < a:
        return "-"
    s = int(b - a)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m"
    return f"{s//3600}h{(s%3600)//60:02d}m"

host = os.uname().nodename if hasattr(os, "uname") else "suricata"
gen = datetime.now(TZ_EC).strftime("%Y-%m-%d %H:%M")

def ipnum(s):
    # convierte una IPv4 en entero para ordenar bien (10 antes que 9 no; 9<10 numerico)
    p = s.split(".")
    if len(p) == 4 and all(x.isdigit() for x in p):
        try:
            return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
        except ValueError:
            return 0
    return 0

top_flujos = sorted(flujos.items(), key=lambda kv: kv[1][0], reverse=True)[:150]
filas = []
for (src, sport, dst, dport, proto, sig), (cnt, first, last) in top_flujos:
    hp = datetime.fromtimestamp(first, TZ_EC).strftime("%d/%m %H:%M") if first else "-"
    hu = datetime.fromtimestamp(last, TZ_EC).strftime("%H:%M") if last else "-"
    dursec = int((last - first)) if (first and last) else 0
    sig_es = traducir(sig)
    filas.append(
        f"<tr><td class='mono' data-s='{ipnum(src)}'>{esc(src)}</td>"
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
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (sp, dst, dp, pr), c in sub)
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(src)}</span>"
            f"<span class='tot'>{tot:,} alertas</span>"
            f"<span class='meta'>&rarr; {len(dsts):,} IP destino &middot; {len(dports):,} puertos destino</span></div>"
            f"<div class='tablewrap'><table><thead><tr>"
            f"<th>Puerto origen</th><th>IP destino (a donde)</th><th class='num'>Puerto destino</th>"
            f"<th>Protocolo</th><th class='num'>Peticiones</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></div>")
    return (
        "<!--TOP_INI-->"
        "<style>"
        ".topwrap .tcard{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 14px;overflow:hidden}"
        ".topwrap .thd{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:11px 15px;background:#f4f4f2;border-bottom:1px solid #e7e6e2}"
        ".topwrap .rank{font-weight:800;color:#2a78d6;font-size:15px}"
        ".topwrap .ipx{font-weight:700;font-size:15px}"
        ".topwrap .tot{background:#e34948;color:#fff;font-size:12px;font-weight:700;padding:3px 9px;border-radius:20px}"
        ".topwrap .meta{color:#52514e;font-size:12px;margin-left:auto}"
        "</style>"
        "<section class=\"card\"><h2>Top 5 IPs origen que mas peticionan</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">Quien ataca mas, hacia que IP destino, desde que puerto origen y hacia que puerto destino.</p>"
        f"<div class=\"topwrap\">{''.join(cards)}</div></section>"
        "<!--TOP_FIN-->")

top_sec = top_origenes_section()

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
th.sortable{{cursor:pointer;user-select:none;white-space:nowrap}}
th.sortable:hover{{color:{BLUE}}}
th.sortable .ar{{opacity:.35;font-size:10px;margin-left:3px}}
th.sortable.asc .ar,th.sortable.desc .ar{{opacity:1;color:{BLUE}}}
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
    {hbar("Firmas mas frecuentes (tipo de ataque)", firmas_top, "alertas")}
  </div>
  {top_sec}
  <section class="card">
    <h2>Detalle: quien ataca, a donde, por que puerto, cuando y por cuanto tiempo</h2>
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
      var rows=[].slice.call(tbody.querySelectorAll('tr'));
      var per=20, n=Math.max(1,Math.ceil(rows.length/per)), p=1;
      var pager=document.getElementById('pager');
      var small=rows.length<=per;
      if(small && pager) pager.style.display='none';
      function rd(){{var m=(location.hash||'').match(/p=(\\d+)/); return m?Math.min(n,Math.max(1,+m[1])):1;}}
      function draw(){{
        if(small){{for(var i=0;i<rows.length;i++) rows[i].style.display=''; return;}}
        for(var i=0;i<rows.length;i++) rows[i].style.display=(i>=(p-1)*per&&i<p*per)?'':'none';
        document.getElementById('pgi').textContent='Pagina '+p+' de '+n;
        document.getElementById('prev').disabled=(p<=1);
        document.getElementById('next').disabled=(p>=n);
      }}
      function go(x){{p=Math.min(n,Math.max(1,x)); try{{location.hash='p='+p;}}catch(e){{}} draw();}}
      // ordenar al pulsar un encabezado: 1er clic ascendente, 2do descendente
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
      if(!small){{
        p=rd();
        document.getElementById('prev').onclick=function(){{go(p-1);}};
        document.getElementById('next').onclick=function(){{go(p+1);}};
        window.addEventListener('hashchange',function(){{p=rd();draw();}});
      }}
      draw();
    }})();
    </script>
    <p class="muted">Top {len(filas)} flujos por numero de alertas. Se excluye ruido informativo (ET INFO).</p>
  </section>
</main></body></html>"""

out = os.path.join(LOGDIR, "report-" + datetime.now(TZ_EC).strftime("%Y%m%d-%H%M") + ".html")
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
    (("go http client",), "Cliente HTTP Go"),
    (("fake wget", "wget 3.0"), "User-Agent falso"),
    (("user_agent", "user agent"), "User-Agent raro"),
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
    return sig

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
            tr.append(
                f'<tr style="border-left:4px solid {color}">'
                f'<td class="mono t">{html.escape(hh)}</td>'
                f'<td><span class="badge" style="background:{color}">{etq}</span></td>'
                f'<td class="mono">{html.escape(src)}</td>'
                f'<td class="mono dst">{html.escape(dst)}</td>'
                f'<td class="mono">{html.escape(puerto)}</td>'
                f'<td title="{html.escape(sig)}">{html.escape(traducir(sig))} {veces}</td></tr>')
        cuerpo = "".join(tr)
    ahora = datetime.now(TZ_EC).strftime("%H:%M:%S")
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
        if _excluido(reglas, src, dst, int(dp) if dp else None):
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
        cuerpo, nota = top_html, "Ultimas 24h &middot; se actualiza junto con el reporte (cada ~5 min)."
    else:
        cuerpo, procesados = _top_cards_tail()
        nota = (f"Muestra reciente ({procesados:,} alertas) mientras se genera el reporte de 24h; "
                "recarga en unos minutos para el ranking completo.")
    css = (css_rep +
           "<style>"
           "body{margin:0;background:#fcfcfb;font:14px system-ui,-apple-system,Segoe UI,sans-serif;color:#0b0b0b}"
           "main{max-width:1000px;margin:0 auto;padding:18px 22px}"
           "h1{font-size:20px;margin:0 0 2px}.subx{color:#52514e;font-size:13px;margin:0 0 18px}"
           ".topwrap .tcard{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 14px;overflow:hidden}"
           ".topwrap .thd{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:11px 15px;background:#f4f4f2;border-bottom:1px solid #e7e6e2}"
           ".topwrap .rank{font-weight:800;color:#2a78d6;font-size:15px}"
           ".topwrap .ipx{font-weight:700;font-size:15px;font-family:ui-monospace,Consolas,monospace}"
           ".topwrap .tot{background:#e34948;color:#fff;font-size:12px;font-weight:700;padding:3px 9px;border-radius:20px}"
           ".topwrap .meta{color:#52514e;font-size:12px;margin-left:auto}"
           ".topwrap table{width:100%;border-collapse:collapse;font-size:13px}"
           ".topwrap thead th{text-align:left;color:#52514e;font-weight:600;padding:8px 14px;border-bottom:1px solid #eee;background:#fbfbfa}"
           ".topwrap tbody td{padding:7px 14px;border-bottom:1px solid #f2f1ee}"
           ".topwrap tbody tr:hover{background:#eef4fd}"
           ".topwrap .num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}"
           ".topwrap .mono{font-family:ui-monospace,Consolas,monospace}"
           ".topwrap .tablewrap{overflow-x:auto}"
           "</style>")
    body = (f"<!doctype html><html lang=es><head><meta charset=utf-8>"
            f"<link rel=icon type=image/png href=/favicon.ico>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv=refresh content=60><title>Top origenes</title>{css}</head><body>"
            + NAV.replace('<a href="/" class="on">En vivo</a>', '<a href="/">En vivo</a>')
                 .replace('<a href="/top">Top origenes</a>', '<a href="/top" class="on">Top origenes</a>') +
            f"<main><h1>Top 5 IPs origen que mas peticionan</h1>"
            f"<p class='subx'>Quien ataca mas, hacia que IP destino, desde que puerto origen y hacia que puerto destino. "
            f"{nota}</p>{cuerpo}</main></body></html>")
    return body

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
<a href="/top">Top origenes</a>
<a href="/detalle">Detalle</a>
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
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
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

def exclusiones_page(msg="", ok=False, edit_idx=None):
    reglas = cargar_exclusiones()
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
                     f'<td>{html.escape(pts)}</td><td>{html.escape(r.get("motivo",""))}</td><td>{accion}</td></tr>')
    tabla = ("".join(filas) if filas else
             '<tr><td colspan=5 class="muted">No hay exclusiones. Todo el trafico se analiza.</td></tr>')
    titulo_form = "Editar exclusion" if ed else "Agregar exclusion"
    val_ip = html.escape(ed["ip"]) if ed else ""
    val_pts = ", ".join(str(p) for p in ed["puertos"]) if ed else ""
    val_mot = html.escape(ed.get("motivo", "")) if ed else ""
    sel_src = "selected" if ed and ed["tipo"] == "src" else ""
    sel_dst = "selected" if not ed or ed["tipo"] == "dst" else ""
    hid_edit = f'<input type=hidden name=editar value="{edit_idx}">' if ed else ""
    btn_txt = "Guardar cambios" if ed else "Agregar"
    cancelar = '<a class="cancel" href="/exclusiones">Cancelar</a>' if ed else ""
    body = f"""<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>
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
button.del:hover{{background:#f5d5d5}}
a.edit{{background:#eef4fd;color:#1c5cab;border:1px solid #cfe0fb;padding:5px 12px;border-radius:8px;
text-decoration:none;font-size:13px;font-weight:600}}a.edit:hover{{background:#dceafb}}
a.cancel{{color:#8a8a86;text-decoration:none;font-size:13px}}a.cancel:hover{{color:#52514e}}
@keyframes fadeout{{0%,74%{{opacity:1;transform:translateY(0)}}100%{{opacity:0;transform:translateY(-10px);visibility:hidden;margin:0;padding:0;height:0}}}}</style></head><body>{NAV}<main>
<h1>Exclusiones</h1><p class=sub>IPs que no quieres que aparezcan en el panel ni en los reportes
(tus DNS, tu monitoreo SNMP, etc.). Se aplica al instante.</p>
{banner}
<div class=card><table><thead><tr><th>Tipo</th><th>IP</th><th>Puertos</th><th>Motivo</th><th></th></tr></thead>
<tbody>{tabla}</tbody></table></div>
<h2>{titulo_form}</h2>
<div class=card><form class=add method=post action="/exclusiones">
<input type=hidden name=accion value=add>{hid_edit}
<label>Tipo</label><select name=tipo><option value=dst {sel_dst}>Destino (a donde va)</option><option value=src {sel_src}>Origen (de donde sale)</option></select>
<label>IP</label><input name=ip placeholder="10.66.66.2" value="{val_ip}" required>
<label>Puertos</label><input name=puertos placeholder="53, 161  (vacio = todos)" value="{val_pts}">
<div class=hint>Para un DNS suele ser 53; para monitoreo SNMP, 161. Deja vacio para ignorar toda la IP.</div>
<label>Motivo</label><input name=motivo placeholder="DNS interno / monitoreo SNMP" value="{val_mot}">
<div style="grid-column:2;display:flex;gap:10px;align-items:center;margin-top:4px">
<button type=submit class=primary>{btn_txt}</button>{cancelar}</div>
</form></div>
<p class=sub style="margin-top:16px">Ejemplos: tu DNS interno como <b>Destino</b> puerto <b>53</b>; tu servidor de
monitoreo como <b>Origen</b> puerto <b>161</b>. Asi quitas el ruido sin perder de vista lo demas que hagan esas IPs.</p>
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
    body = f"""<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>
<meta name=viewport content='width=device-width,initial-scale=1'><title>Documentacion</title>
<style>{css}</style></head><body>{NAV}<main>
<h1>Documentacion</h1>
<p>Guia rapida del panel de estadisticas de Suricata y como ajustarlo.</p>

<h2>Las pestañas del menu</h2>
<table><tr><th>Pestaña</th><th>Que hace</th></tr>
<tr><td><b>En vivo</b></td><td>Vista principal. Arriba, el <b>resumen de las ultimas 24h</b>:
puertos de destino mas atacados, IPs origen (atacantes), IPs destino (objetivos) y la
linea de tiempo por intervalos de 30 minutos. Abajo, el <b>feed de los ultimos ataques</b>,
que se actualiza solo cada 20 segundos.</td></tr>
<tr><td><b>Detalle</b></td><td>La tabla completa de ataques: quien ataca, a que IP y puerto,
protocolo, tipo de ataque, cuantas veces y desde/hasta cuando. Paginada de 20 en 20; al
imprimir a PDF salen todas las filas.</td></tr>
<tr><td><b>Historico</b></td><td>Los ultimos 20 reportes guardados, cada uno abrible. Se
generan cada 10 minutos y los mas viejos se borran solos.</td></tr>
<tr><td><b>Exclusiones</b></td><td>Gestiona las IPs que NO quieres ver en el panel (tus DNS,
tu monitoreo SNMP). Agregar, editar y eliminar; se explica mas abajo.</td></tr>
<tr><td><b>Perfil</b></td><td>Cambiar el usuario y la clave de acceso a este panel.</td></tr>
<tr><td><b>Documentacion</b></td><td>Esta pagina.</td></tr>
<tr><td><b>Salir</b></td><td>Cierra la sesion.</td></tr>
</table>

<h2>Cada cuanto se actualiza</h2>
<ul>
<li><b>Feed de ultimos ataques</b> (En vivo, abajo): cada <b>20 segundos</b>.</li>
<li><b>Resumen de 24h, Detalle e Historico</b>: se regeneran en segundo plano cada
<b>10 minutos</b>. Por eso los graficos casi no cambian entre recargas y el feed si.</li>
<li><b>Reglas ET</b>: se actualizan solas cada dia a las 04:30. <b>Informe por Telegram</b>: 07:30.</li>
<li>Todas las horas del panel estan en <b>hora de Ecuador</b> (UTC-5).</li>
</ul>

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
    body = ("<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
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
            feed = live_feed_html()
            head_css, resumen_inner, _ = partes_reporte()   # resumen SIN la tabla de detalle
            if resumen_inner.strip():
                resumen = ("<h2 style='margin:16px 28px 0'>Resumen de las ultimas 24h</h2>"
                           f"<main>{resumen_inner}</main>")
            else:
                resumen = ("<main style='padding:24px'><p style='color:#52514e'>El resumen de 24h se "
                           "esta generando en segundo plano; aparecera aqui en unos minutos. "
                           "El feed de abajo ya esta en vivo.</p></main>")
            page = (f"<!doctype html><html lang=es><head><meta charset=utf-8><link rel=icon type=image/png href=/favicon.ico>"
                    f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                    f"<meta http-equiv=refresh content=20><title>Estadisticas Suricata</title>"
                    f"{head_css}</head><body>{NAV}{resumen}{feed}</body></html>")
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
                    f"<title>Detalle de ataques</title>{head_css}</head><body>{NAV}"
                    f"<main>{detalle}</main></body></html>")
            return self._html(page)
        if path == "/historico":
            return self._html(historico_page())
        if path == "/perfil":
            return self._html(perfil_page())
        if path == "/exclusiones":
            edit = None
            if "?" in self.path:
                import urllib.parse
                try:
                    edit = int(urllib.parse.parse_qs(self.path.split("?", 1)[1]).get("edit", [""])[0])
                except (ValueError, TypeError):
                    edit = None
            return self._html(exclusiones_page(edit_idx=edit))
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
        nueva = {"tipo": tipo, "ip": ip, "motivo": motivo, "puertos": puertos}
        editar = q.get("editar", [""])[0]
        if editar.isdigit() and int(editar) < len(propias):
            propias[int(editar)] = nueva
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

