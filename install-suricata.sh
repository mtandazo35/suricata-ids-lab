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
apt-get install -y -qq -o Dpkg::Options::=--force-confold suricata suricata-update jq python3 curl ca-certificates ethtool </dev/null >/dev/null
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
  for line in '# install-suricata.sh: con espejo TZSP (asimetrico) estas reglas solo son ruido' \
              'group:stream-events.rules' \
              'group:app-layer-events.rules'; do
    grep -qxF -- "$line" "$DISABLE_CONF" || echo "$line" >> "$DISABLE_CONF"
  done
  ok "Reglas de ruido stream/app-layer desactivadas (espejo TZSP)."
fi
suricata-update --no-test >/dev/null 2>&1 || suricata-update --no-test || warn "suricata-update reporto avisos (normal la 1a vez)."
RULES_COUNT="$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null || true)"; RULES_COUNT="${RULES_COUNT:-?}"
ok "Reglas cargadas: ${RULES_COUNT}"

# ----------------------------------------------------------------------------- config
CFG=/etc/suricata/suricata.yaml
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo backup)"
cp -a "$CFG" "${CFG}.bak-${STAMP}"
info "Backup de config: ${CFG}.bak-${STAMP}"

# HOME_NET
sed -i "s#^\(\s*HOME_NET:\).*#\1 \"[${HOME_NET}]\"#" "$CFG"

# stream: el espejo puede llegar asimetrico o con sesiones ya empezadas
if [ "$TZSP" -eq 1 ]; then
  sed -i "s/^\(\s*midstream:\)\s*false/\1 true/; s/^\(\s*async-oneside:\)\s*false/\1 true/" "$CFG"
fi

# interfaz af-packet (primer bloque 'interface: ...')
sed -i "0,/^\(\s*\)- interface:.*/s//\1- interface: ${IFACE}/" "$CFG"

# memcap sanos para lab (ajusta segun ancho de banda espejeado)
sed -i "s#^\(\s*memcap:\)\s*[0-9].*mb\s*#\1 512mb  #I" "$CFG" 2>/dev/null || true

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
  ok "logrotate: diario, maxsize 2G, 7 copias (eve.json crece rapido con espejo)."
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
# mtu 9000: ~1% de las tramas espejeadas superan 1600 B (GRO/jumbo en el router) y se
# perdian con EMSGSIZE; ademas Suricata dimensiona el snaplen por el MTU de la interfaz
ExecStartPre=/sbin/ip link set ${TZSP_IN} up mtu 9000
ExecStartPre=/sbin/ip link set ${TZSP_MON} up mtu 9000 promisc on
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
  # que Suricata no inspeccione en ${IFACE} el propio flujo TZSP (doble CPU + "truncated")
  if ! grep -qE "^\s*bpf-filter: \"not udp port ${TZSP_PORT}\"" "$CFG"; then
    sed -i "0,/^  - interface: ${IFACE}\$/s//&\n    bpf-filter: \"not udp port ${TZSP_PORT}\"/" "$CFG"
  fi
  # checksums: el trafico espejeado llega con csum de offload -> no validar
  sed -i "s#^\(\s*checksum-validation:\)\s*yes#\1 no #" "$CFG"
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
    Ruido      : reglas stream/app-layer desactivadas; midstream+async-oneside activos; BPF excluye UDP ${TZSP_PORT} en ${IFACE}

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
