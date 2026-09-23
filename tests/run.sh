#!/usr/bin/env bash
#
# Pruebas funcionales del panel y del reporte.
#
#   No hacen falta ni Suricata ni un MikroTik: cada prueba extrae la pieza real de
#   install-suricata.sh (ver extraer.py) y la ejecuta contra dobles. Comprueban
#   COMPORTAMIENTO, no que el texto este presente: que el router caido no borre el
#   registro, que el orden de una tabla sobreviva a una recarga, que el mapa no pinte
#   paises de negro al cerrar, etc. Varias nacieron de fallos reales ya corregidos.
#
#   Uso:  tests/run.sh          (lo llama validar.sh y el CI)
#
set -uo pipefail
cd "$(dirname "$0")/.."

c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
[ -t 1 ] || { c_g=; c_r=; c_y=; c_0=; }

PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "No hay python3/python en el PATH."; exit 1; }

if ! command -v node >/dev/null 2>&1; then
  printf '%s aviso%s node no esta instalado: se omiten las pruebas de navegador\n' "$c_y" "$c_0"
  SIN_NODE=1
else
  SIN_NODE=0
fi

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

"$PY" tests/extraer.py "$TMPD" >/dev/null || { echo "fallo la extraccion de artefactos"; exit 1; }

fallos=0
correr() { # $1=descripcion  $2=comando...
  local desc="$1"; shift
  local salida
  if salida="$("$@" 2>&1)" && printf '%s' "$salida" | grep -q "TODO OK"; then
    printf '%s  OK %s %s\n' "$c_g" "$c_0" "$desc"
  else
    printf '%s FALLA%s %s\n' "$c_r" "$c_0" "$desc"
    printf '%s\n' "$salida" | grep -E "FALLA|Error:|error:" | head -5 | sed 's/^/        /'
    fallos=$((fallos+1))
  fi
}

# --- navegador (DOM simulado) ---
if [ "$SIN_NODE" = 0 ]; then
  correr "mapa: zoom por pais, detalle y sin bordes negros" node tests/test_mapa.js "$TMPD/mapa.js"
  correr "tablas: orden ascendente/descendente y fechas por tiempo real" node tests/test_orden.js "$TMPD/sort.js"
  correr "tablas: el orden sobrevive a la recarga" node tests/test_orden_persiste.js "$TMPD/sort.js"
  correr "pagina: conserva la posicion tras una accion" node tests/test_posicion.js "$TMPD/pos.js"
  correr "quitado masivo: seleccion y contenido del modal" node tests/test_masivo_ui.js "$TMPD/masivo.js"
  correr "quitado masivo: avance, fallo a mitad y cierre" node tests/test_masivo_progreso.js "$TMPD/masivo.js"
fi

# --- rutas del panel (dobles, sin MikroTik ni disco) ---
correr "ruta /cuarentena/quitar-uno" "$PY" tests/test_ruta_quitar_uno.py "$TMPD"
correr "ruta /cuarentena/quitar-varios" "$PY" tests/test_ruta_quitar_varios.py "$TMPD"
correr "solo tus redes entran a la cuarentena de CPEs" "$PY" tests/test_mis_redes.py
correr "registro de routers y migracion del nodo unico" "$PY" tests/test_routers.py
correr "receptor TZSP: cada MikroTik a su interfaz" "$PY" tests/test_tzsp_multi.py
correr "instalador: una interfaz por router" bash tests/test_instalador_multi.sh
correr "identidad (router, IP): dos nodos no se confunden" "$PY" tests/test_identidad_nodo.py
correr "alta, edicion y baja de nodos" "$PY" tests/test_rutas_nodos.py
correr "enviar/quitar de cuarentena van por identidad (router, IP)" "$PY" tests/test_cuarentena_identidad.py
correr "AbuseIPDB: cuota, cache, privacidad y categorias" "$PY" tests/test_abuseipdb.py
correr "denuncias a AbuseIPDB: apagadas por defecto y con frenos" "$PY" tests/test_abuseipdb_denuncia.py
correr "documentacion: paginas, categorias, buscador y modal" "$PY" tests/test_documentacion.py
correr "una pagina que revienta da 500 explicado, no 502 mudo" "$PY" tests/test_error_500.py

printf '\n'
if [ "$fallos" -eq 0 ]; then
  printf '%sPruebas: todo correcto.%s\n' "$c_g" "$c_0"; exit 0
else
  printf '%sPruebas: %d fallo(s).%s\n' "$c_r" "$fallos" "$c_0"; exit 1
fi
