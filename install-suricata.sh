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

# IPs de infraestructura propia (DNS, etc.) a excluir (conf: IGNORAR_DESTINOS/ORIGENES)
_c = conf()
IGN_DST = {x.strip() for x in _c.get("IGNORAR_DESTINOS", "").split(",") if x.strip()}
IGN_SRC = {x.strip() for x in _c.get("IGNORAR_ORIGENES", "").split(",") if x.strip()}

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
            if dst in IGN_DST or src in IGN_SRC:   # excluir infraestructura propia (DNS, etc.)
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

def leer_ignorar():
    """IPs de infraestructura (DNS propios, etc.) a excluir; desde /etc/suricata-report.conf
    linea IGNORAR_DESTINOS=ip1,ip2 (y/o IGNORAR_ORIGENES=...)."""
    dst, src = set(), set()
    try:
        for l in open("/etc/suricata-report.conf", encoding="utf-8"):
            l = l.strip()
            if l.startswith("IGNORAR_DESTINOS="):
                dst = {x.strip() for x in l.split("=", 1)[1].split(",") if x.strip()}
            elif l.startswith("IGNORAR_ORIGENES="):
                src = {x.strip() for x in l.split("=", 1)[1].split(",") if x.strip()}
    except OSError:
        pass
    return dst, src

IGN_DST, IGN_SRC = leer_ignorar()

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
            if dst in IGN_DST or src in IGN_SRC:   # excluir infraestructura propia (DNS, etc.)
                continue
            sport = g("src_port"); dport = g("dest_port")
            proto = g("proto")
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
import base64, glob, html, os, re, subprocess, threading, time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EVE = "/var/log/suricata/eve.json"

def _leer_ignorar():
    dst, src = set(), set()
    try:
        for l in open("/etc/suricata-report.conf", encoding="utf-8"):
            l = l.strip()
            if l.startswith("IGNORAR_DESTINOS="):
                dst = {x.strip() for x in l.split("=", 1)[1].split(",") if x.strip()}
            elif l.startswith("IGNORAR_ORIGENES="):
                src = {x.strip() for x in l.split("=", 1)[1].split(",") if x.strip()}
    except OSError:
        pass
    return dst, src
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
    ign_dst, ign_src = _leer_ignorar()
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
        if dst in ign_dst or src in ign_src:   # excluir infraestructura propia (DNS, etc.)
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
<a href="/perfil">Perfil</a>
<a href="/documentacion">Documentacion</a>
<a href="/" class="sp">&#8635; Actualizar</a></div>"""

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
            "<p class=sub style='margin-top:16px'>Al guardar, el navegador te pedira entrar de nuevo con las credenciales nuevas.</p>"
            "</main></body></html>")
    return body

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

<h2>Excluir tus DNS y otra infraestructura</h2>
<p>Las consultas de clientes a dominios sospechosos van dirigidas a tu servidor DNS y
ensucian el panel. Para que tus DNS (u otras IPs propias) no aparezcan, edita en la VM:</p>
<pre><code>nano /etc/suricata-report.conf</code></pre>
<p>Agrega tus IPs separadas por coma:</p>
<pre><code>IGNORAR_DESTINOS=10.66.66.2,205.235.3.8
IGNORAR_ORIGENES=</code></pre>
<p>Y aplica:</p>
<pre><code>systemctl restart suricata-dashboard</code></pre>
<p><code>IGNORAR_DESTINOS</code> excluye trafico hacia esas IPs (tus DNS); <code>IGNORAR_ORIGENES</code>
excluye un equipo concreto como origen. Nota: al excluir tus DNS dejas de ver que un
cliente consulto un dominio malicioso; esa senal sigue en EveBox filtrando por origen.</p>

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
    def _auth_ok(self):
        pw = CFG.get("PASS", "")
        if not pw:
            return True  # sin PASS configurada, sin auth (solo detras de VPN/proxy)
        want = "Basic " + base64.b64encode(f"{CFG['USER']}:{pw}".encode()).decode()
        return self.headers.get("Authorization") == want
    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Estadisticas Suricata"')
        self.end_headers()
    def _html(self, s, code=200):
        b = s.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if not self._auth_ok():
            return self._deny()
        path = self.path.split("?", 1)[0]
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
        if not self._auth_ok():
            return self._deny()
        if self.path.split("?", 1)[0] != "/perfil":
            return self._html("<h1>No encontrado</h1>", 404)
        import urllib.parse
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        except Exception:
            body = ""
        q = urllib.parse.parse_qs(body)
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
        return self._html(perfil_page("Credenciales actualizadas. Vuelve a entrar con el usuario y clave nuevos.", ok=True))

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
