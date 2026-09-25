#!/usr/bin/env bash
#
# Con que valores nace una instalacion nueva.
#
#   Lo que protege: que una caja recien instalada quede como la que ya funciona, sin
#   tener que descubrir a mano lo que costo descubrir la primera vez.
#
#   - MIS_REDES decide que IP puede entrar a la cuarentena de CPEs. Por defecto el panel
#     asume las privadas RFC1918, y eso es falso en cuanto das IP publica a tus clientes
#     o espejas despues del NAT: los abonados dejan de reconocerse como tuyos y no
#     aparece ninguno. Si se declaro -n, esas son las redes buenas.
#   - la ventana: con 30 min el detector queda casi ciego (un CPE que actua a rafagas no
#     acumula lo suficiente) y con 1440 cada generacion lee mucho log.
#   - y el firewall NO puede abrir la web a todo internet: ahi dentro va el trafico de
#     los abonados del cliente y una clave que viaja sin cifrar.
#
set -uo pipefail
cd "$(dirname "$0")/.."

c_g=$'\e[32m'; c_r=$'\e[31m'; c_0=$'\e[0m'
[ -t 1 ] || { c_g=; c_r=; c_0=; }

fallos=0
check() { # $1=descripcion $2=obtenido $3=esperado
  if [ "$2" = "$3" ]; then
    printf '  OK   %s\n' "$1"
  else
    printf ' FALLA %s\n        esperado: %s\n        obtenido: %s\n' "$1" "$3" "$2"
    fallos=$((fallos+1))
  fi
}

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# --- el trozo REAL que crea la configuracion, con la ruta redirigida al temporal ---
CONF_DEST="$TMPD/dash.conf"
TROZO="$(awk '/^if \[ ! -f \/etc\/suricata-dashboard.conf \]; then$/,/^fi$/' install-suricata.sh \
         | sed "s#/etc/suricata-dashboard.conf#$CONF_DEST#g")"
[ -n "$TROZO" ] || { echo "no se encontro el bloque de configuracion inicial"; exit 1; }

crear() { # $1=HOME_NET  $2=HOME_NET_GIVEN
  rm -f "$CONF_DEST"
  HOME_NET="$1" HOME_NET_GIVEN="$2" bash -c "$TROZO" >/dev/null 2>&1
  cat "$CONF_DEST" 2>/dev/null
}

# --- con -n: las redes declaradas son las de los abonados -------------------------
out="$(crear "192.168.0.0/19,172.17.0.0/20" 1)"
check "con -n, MIS_REDES queda escrito desde el primer arranque" \
      "$(printf '%s' "$out" | grep -c '^MIS_REDES=192.168.0.0/19,172.17.0.0/20$')" "1"
check "la ventana no se deja al azar" \
      "$(printf '%s' "$out" | grep -c '^VENTANA_MIN=360$')" "1"
check "y se genera una clave, no una fija" \
      "$(printf '%s' "$out" | grep -cE '^PASS=.{12,}$')" "1"

# --- sin -n: no se inventa nada ----------------------------------------------------
out="$(crear "" 0)"
check "sin -n no se inventa MIS_REDES" \
      "$(printf '%s' "$out" | grep -c '^MIS_REDES=')" "0"
check "pero la ventana sigue puesta" \
      "$(printf '%s' "$out" | grep -c '^VENTANA_MIN=360$')" "1"

# --- el firewall no publica la web -------------------------------------------------
check "nunca se abre el puerto del panel a todo internet" \
      "$(grep -cE 'ufw allow "\$\{DASH_PORT\}/tcp"' install-suricata.sh)" "0"
check "ni el de EveBox" \
      "$(grep -cE 'ufw allow "\$\{WEB_PORT\}/tcp"' install-suricata.sh)" "0"
check "se permite solo desde las redes de -a" \
      "$(grep -cE 'ufw allow from "\$_g" to any port "\$\{DASH_PORT\}"' install-suricata.sh)" "1"
check "y sin -a se avisa en vez de abrir" \
      "$(grep -c 'UFW activo y sin -a' install-suricata.sh)" "1"

# --- la ayuda lo cuenta ------------------------------------------------------------
check "el flag -a esta en getopts" \
      "$(grep -cE '^while getopts "[^"]*a:[^"]*" opt; do$' install-suricata.sh)" "1"
check "y explicado en la ayuda" \
      "$(grep -c -- '-a REDES' install-suricata.sh)" "1"

printf '\n'
if [ "$fallos" -eq 0 ]; then echo "TODO OK"; exit 0; else
  printf '%sDefectos del instalador: %d fallo(s).%s\n' "$c_r" "$fallos" "$c_0"; exit 1; fi
