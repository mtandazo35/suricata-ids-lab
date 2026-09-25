#!/usr/bin/env bash
#
# Banco de regresion de deteccion: pasa cada captura por Suricata con las reglas
# instaladas y compara con lo que ese caso DEBE dar.
#
#   Por que existe: las 36 pruebas funcionales comprueban la logica del panel, no que
#   el IDS detecte. Una actualizacion de ET Open puede dejar de detectar una amenaza, o
#   empezar a alertar por trafico normal, y todo seguiria en verde. Esto es lo unico
#   que lo caza.
#
#   Los casos BENIGNOS son los obligatorios. Un falso positivo rompe clientes hoy; un
#   falso negativo es un riesgo futuro. Si la navegacion normal genera alertas, el panel
#   deja de ser util porque nadie se cree los avisos.
#
#   Los casos de ATAQUE son informativos: dependen de que reglas traiga ET Open ese dia,
#   y no se hace fallar la suite porque upstream retire una firma. Se avisa y punto.
#
#   Uso:   tests/pcap/run.sh          (necesita suricata instalado; si no, se omite)
#
set -uo pipefail
cd "$(dirname "$0")"

c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
[ -t 1 ] || { c_g=; c_r=; c_y=; c_0=; }

PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "No hay python3/python en el PATH."; exit 1; }

if ! command -v suricata >/dev/null 2>&1; then
  printf '%s omitido%s banco de PCAP: suricata no esta instalado en esta maquina.\n' "$c_y" "$c_0"
  printf '         Corre esto en el sensor, antes y despues de actualizar reglas.\n'
  echo "TODO OK"      # omitido no es fallo: el CI no lleva Suricata
  exit 0
fi

REGLAS="${REGLAS:-/var/lib/suricata/rules/suricata.rules}"
if [ ! -s "$REGLAS" ]; then
  printf '%s omitido%s no encuentro las reglas en %s\n' "$c_y" "$c_0" "$REGLAS"
  echo "TODO OK"; exit 0
fi

# las capturas se generan si faltan: son deterministas, no hace falta versionar binarios
$PY generar.py >/dev/null || { echo "no se pudieron generar las capturas"; exit 1; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

fallos=0; avisos=0
for dir in */; do
  caso="${dir%/}"
  [ -f "$caso/expected.json" ] || continue
  out="$TMPD/$caso"; mkdir -p "$out"
  suricata -r "$caso/captura.pcap" -S "$REGLAS" -l "$out" \
           --set default-rule-path=/var/lib/suricata/rules >/dev/null 2>&1
  if ! res="$($PY comparar.py "$caso/expected.json" "$out/eve.json" 2>&1)"; then
    estado="$(printf '%s' "$res" | head -1)"
    if printf '%s' "$res" | grep -q "^AVISO"; then
      printf '%s aviso %s %-18s %s\n' "$c_y" "$c_0" "$caso" "$estado"
      avisos=$((avisos+1))
    else
      printf '%s FALLA %s %-18s %s\n' "$c_r" "$c_0" "$caso" "$estado"
      fallos=$((fallos+1))
    fi
  else
    printf '%s  OK   %s %-18s %s\n' "$c_g" "$c_0" "$caso" "$res"
  fi
done

printf '\n'
[ "$avisos" -eq 0 ] || printf '%s%d aviso(s)%s: casos de ataque sin deteccion. Revisa si ET Open retiro la firma.\n' "$c_y" "$avisos" "$c_0"
if [ "$fallos" -eq 0 ]; then
  echo "TODO OK"; exit 0
else
  printf '%sBanco de PCAP: %d fallo(s).%s\n' "$c_r" "$fallos" "$c_0"; exit 1
fi
