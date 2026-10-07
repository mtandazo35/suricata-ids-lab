#!/usr/bin/env bash
#
# Como se decide si el espejo llega en local o por VPN.
#
#   De la respuesta cuelgan tres cosas que tienen que ser coherentes entre si: el recorte
#   por flujo, las reglas que se le dan al MikroTik y la proteccion de los extremos del
#   tunel. Hoy habia que acertar con -e, -m y -b a la vez.
#
#   Lo que de verdad protege esta prueba es que la pregunta NO cuelgue una instalacion
#   desatendida. El one-liner es `curl ... | bash`, y ahi stdin es el PROPIO SCRIPT: un
#   `read` normal no lee del teclado, recibe EOF y sigue de largo — o peor, se come una
#   linea del script y lo que se ejecuta ya no es lo que se descargo. Por eso se lee de
#   /dev/tty, y sin terminal no se pregunta nada.
#
set -uo pipefail
cd "$(dirname "$0")/.."

c_g=$'\e[32m'; c_r=$'\e[31m'; c_0=$'\e[0m'
[ -t 1 ] || { c_g=; c_r=; c_0=; }
fallos=0
check() { # $1=descripcion  $2=condicion ya evaluada (0 ok)  $3=detalle
  if [ "$2" -eq 0 ]; then printf '%s  OK %s %s\n' "$c_g" "$c_0" "$1"
  else printf '%s FALLA%s %s  -> %s\n' "$c_r" "$c_0" "$1" "${3:-}"; fallos=$((fallos+1)); fi
}

SRC=install-suricata.sh
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT

# Se extrae SOLO el trozo que decide el modo, con lo justo alrededor. Ejecutar el
# instalador entero instalaria Suricata en esta maquina.
awk '/^# Si no se dijo con -e/{f=1} f{print} f&&/^fi$/{exit}' "$SRC" > "$TMPD/trozo.sh"
grep -q 'dev/tty' "$TMPD/trozo.sh" || { echo "no se extrajo el bloque"; exit 1; }

cat > "$TMPD/correr.sh" <<'CAB'
#!/usr/bin/env bash
set -uo pipefail
c_b=; c_0=
info() { :; }
TZSP=1
ESPEJO_DONDE="local"
ESPEJO_DADO="${FORZADO:-0}"
[ "$ESPEJO_DADO" -eq 1 ] && ESPEJO_DONDE="${MODO:-vpn}"
CAB
cat "$TMPD/trozo.sh" >> "$TMPD/correr.sh"
printf 'printf "RESULTADO=%%s\\n" "$ESPEJO_DONDE"\n' >> "$TMPD/correr.sh"
chmod +x "$TMPD/correr.sh"

# --- 1) sin terminal NO se puede colgar -------------------------------------------------
# Es el caso del one-liner y el de cualquier deploy automatizado. Con timeout: si se
# cuelga, la prueba falla en vez de quedarse esperando para siempre.
out="$(printf 'esto es el script, no una respuesta\n' | timeout 10 "$TMPD/correr.sh" < /dev/null 2>&1)"
rc=$?
check "sin terminal no se queda esperando una respuesta" \
      "$([ $rc -ne 124 ] && echo 0 || echo 1)" "se colgo (timeout)"
check "y se queda en local, que es lo seguro" \
      "$(printf '%s' "$out" | grep -q 'RESULTADO=local' && echo 0 || echo 1)" "$out"

# --- 2) lo que viene por stdin NO se consume como respuesta -----------------------------
# Si se leyera de stdin, esa linea seria la respuesta Y desapareceria del script.
out2="$(printf '2\n' | timeout 10 "$TMPD/correr.sh" < /dev/null 2>&1)"
check "una linea en stdin no se toma por respuesta" \
      "$(printf '%s' "$out2" | grep -q 'RESULTADO=local' && echo 0 || echo 1)" "$out2"

# --- 3) con -e no se pregunta nada ------------------------------------------------------
# Es lo que permite seguir automatizando: los flags mandan sobre la pregunta.
out3="$(FORZADO=1 MODO=vpn timeout 10 "$TMPD/correr.sh" < /dev/null 2>&1)"
check "si se paso -e vpn, se respeta y no se pregunta" \
      "$(printf '%s' "$out3" | grep -q 'RESULTADO=vpn' && echo 0 || echo 1)" "$out3"
out4="$(FORZADO=1 MODO=local timeout 10 "$TMPD/correr.sh" < /dev/null 2>&1)"
check "y si se paso -e local, tambien" \
      "$(printf '%s' "$out4" | grep -q 'RESULTADO=local' && echo 0 || echo 1)" "$out4"

# --- 4) la pregunta solo tiene sentido si hay espejo que recibir ------------------------
grep -q 'ESPEJO_DADO" -eq 0 \] && \[ "\$TZSP" -eq 1' "$SRC"
check "no se pregunta si no se va a recibir espejo (-t)" $? ""

# --- 5) los extremos del tunel no pueden acabar en cuarentena ---------------------------
# Por defecto el panel considera abonados a RFC1918 + 100.64.0.0/10, y los tuneles suelen
# vivir justo ahi: un paquete espejado con ese origen pondria al router en la lista de
# candidatos a cortar. O sea, el panel proponiendo cortar el enlace por el que recibe.
grep -q 'ESPEJO_DONDE" = "vpn" \] && \[ -n "\$MIRROR_SRC"' "$SRC"
check "en VPN se protege el origen del espejo" $? ""
grep -q 'suricata-nunca-bloquear.lst' "$SRC"
check "usando la lista de nunca bloquear que ya existia" $? ""
grep -q 'grep -qxF "\$_s" "\$_NUNCA"' "$SRC"
check "sin duplicar si se reinstala" $? ""

# --- 6) el instalador sigue siendo valido ----------------------------------------------
bash -n "$SRC"
check "el instalador no tiene errores de sintaxis" $? ""

echo
if [ "$fallos" -eq 0 ]; then echo "TODO OK"; else echo "$fallos fallo(s)"; fi
[ "$fallos" -eq 0 ]
