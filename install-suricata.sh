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
#   Uso:   sudo ./install-suricata.sh [-i IFACE] [-n HOME_NET] [-p PUERTO] [-P CLAVE] [-W] [-h]
#
#     -i IFACE     interfaz a escuchar (default: auto-deteccion por ruta default)
#     -n HOME_NET  red "casa" en CIDR (default: la de la interfaz elegida)
#     -p PUERTO    puerto de la web EveBox (default: 5636)
#     -P CLAVE     clave del usuario web 'admin' (default: aleatoria, se muestra al final)
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

usage(){
  cat <<'USAGE'
Uso: sudo ./install-suricata.sh [-i IFACE] [-n HOME_NET] [-p PUERTO] [-P CLAVE] [-W] [-h]

  -i IFACE     interfaz a escuchar (default: auto-deteccion por ruta default)
  -n HOME_NET  red "casa" en CIDR (default: la de la interfaz elegida)
  -p PUERTO    puerto de la web EveBox (default: 5636)
  -P CLAVE     clave del usuario web 'admin' (default: aleatoria, se muestra al final)
  -W           sin web (solo Suricata + logs locales)
  -h           esta ayuda

One-liner:
  curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- [opciones]
USAGE
}

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root (sudo)."

# ----------------------------------------------------------------------------- args
IFACE=""; HOME_NET=""; WEB=1; WEB_PORT=5636; WEB_PASS=""
while getopts "i:n:p:P:Wh" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    n) HOME_NET="$OPTARG" ;;
    p) WEB_PORT="$OPTARG" ;;
    P) WEB_PASS="$OPTARG" ;;
    W) WEB=0 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
{ [[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ]; } || die "Puerto invalido: $WEB_PORT"

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
  [ -n "$HOME_NET" ] || HOME_NET="10.0.0.0/8"
fi
ok "HOME_NET: $HOME_NET"

# ----------------------------------------------------------------------------- install
export DEBIAN_FRONTEND=noninteractive
info "Instalando suricata y utilidades..."
apt-get update -qq
apt-get install -y -qq suricata suricata-update jq python3 curl ca-certificates >/dev/null
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
suricata-update --no-test >/dev/null 2>&1 || suricata-update --no-test || warn "suricata-update reporto avisos (normal la 1a vez)."
RULES_COUNT="$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo '?')"
ok "Reglas cargadas: ${RULES_COUNT}"

# ----------------------------------------------------------------------------- config
CFG=/etc/suricata/suricata.yaml
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo backup)"
cp -a "$CFG" "${CFG}.bak-${STAMP}"
info "Backup de config: ${CFG}.bak-${STAMP}"

# HOME_NET
sed -i "s#^\(\s*HOME_NET:\).*#\1 \"[${HOME_NET}]\"#" "$CFG"

# interfaz af-packet (primer bloque 'interface: ...')
sed -i "0,/^\(\s*\)- interface:.*/s//\1- interface: ${IFACE}/" "$CFG"

# memcap sanos para lab (ajusta segun ancho de banda espejeado)
sed -i "s#^\(\s*memcap:\)\s*[0-9].*mb\s*#\1 512mb  #I" "$CFG" 2>/dev/null || true

# archivo de interfaz para el servicio de Debian
if [ -f /etc/default/suricata ]; then
  sed -i "s#^IFACE=.*#IFACE=${IFACE}#" /etc/default/suricata || true
  sed -i "s#^LISTENMODE=.*#LISTENMODE=af-packet#" /etc/default/suricata || true
fi

# ----------------------------------------------------------------------------- validar
info "Validando configuracion..."
if suricata -T -c "$CFG" -i "$IFACE" >/tmp/suricata-test.log 2>&1; then
  ok "Config valida."
else
  cat /tmp/suricata-test.log
  die "La validacion fallo. Revisa /tmp/suricata-test.log y ${CFG}.bak-${STAMP}"
fi

# ----------------------------------------------------------------------------- servicio
info "Habilitando servicio..."
systemctl enable suricata >/dev/null 2>&1 || true
systemctl restart suricata
sleep 3
if systemctl is-active --quiet suricata; then
  ok "Suricata corriendo en modo IDS sobre $IFACE."
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
    dpkg -i "$DEB_LOCAL" >/dev/null || apt-get install -f -y -qq >/dev/null
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
  EVB="runuser -u evebox -- /usr/bin/evebox --data-directory ${EVEBOX_DATA} --config-directory ${EVEBOX_DATA}"
  systemctl stop evebox >/dev/null 2>&1 || true
  HAS_ADMIN=0
  $EVB config users list 2>/dev/null | grep -qw "$WEB_USER" && HAS_ADMIN=1
  if [ "$HAS_ADMIN" -eq 1 ] && [ -z "$WEB_PASS" ]; then
    WEB_NOTE="El usuario '${WEB_USER}' ya existia: clave sin cambios (cambiala con -P o con 'evebox config users passwd')."
  else
    [ -n "$WEB_PASS" ] || WEB_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
    if [ "$HAS_ADMIN" -eq 1 ]; then $EVB config users rm "$WEB_USER" >/dev/null 2>&1 || true; fi
    if $EVB config users add --username "$WEB_USER" --password "$WEB_PASS" >/dev/null 2>&1; then
      WEB_PASS_SHOWN="$WEB_PASS"
    else
      warn "No pude crear el usuario web por CLI; EveBox generara 'admin' con clave aleatoria (ver journalctl -u evebox)."
    fi
  fi

  # --- servicio ----------------------------------------------------------------
  systemctl daemon-reload
  systemctl enable evebox >/dev/null 2>&1 || true
  systemctl restart evebox
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

  PUB_IP="$(ip -o -4 addr show dev "$IFACE" scope global | awk '{split($4,a,"/"); print a[1]; exit}')"
  WEB_URL="https://${PUB_IP:-<IP>}:${WEB_PORT}"
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
    Cambiar clave: evebox --data-directory ${EVEBOX_DATA} --config-directory ${EVEBOX_DATA} config users passwd ${WEB_USER}
    Si hay firewall externo (nube/Proxmox), abre ${WEB_PORT}/tcp.
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
