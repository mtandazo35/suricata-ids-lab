#!/usr/bin/env bash
#
# validar.sh — Valida el repositorio SIN instalar ni tocar nada.
#
#   Todo el proyecto vive en un solo archivo (install-suricata.sh) que lleva dentro,
#   como heredocs, varios programas en Python y en shell. Un error de sintaxis ahi no
#   se nota al hacer commit: se nota cuando revienta en un servidor. Este script hace
#   la misma comprobacion que se haria a mano, pero completa y de una pasada:
#
#     1) sintaxis de los .sh del repo            (bash -n)
#     2) cada heredoc extraido y validado        (python: ast + pyflakes | sh: sh -n)
#     3) el JavaScript del mapa                  (node --check)
#     4) finales de linea LF                     (un CRLF rompe los scripts en Linux)
#     5) SHA256 de los assets vendorizados       (deben cuadrar con los del instalador)
#
#   Uso:  ./validar.sh          Sale 0 si todo esta bien, 1 si algo falla.
#
#   Lo corre GitHub Actions en cada push (.github/workflows/validar.yml), y conviene
#   correrlo en local antes de subir cambios.
#
set -uo pipefail
cd "$(dirname "$0")"

c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_b=$'\e[36m'; c_0=$'\e[0m'
[ -t 1 ] || { c_g=; c_r=; c_y=; c_b=; c_0=; }
fallos=0
ok()   { printf '%s  OK %s %s\n' "$c_g" "$c_0" "$*"; }
mal()  { printf '%s FALLA%s %s\n' "$c_r" "$c_0" "$*"; fallos=$((fallos+1)); }
avisa(){ printf '%s aviso%s %s\n' "$c_y" "$c_0" "$*"; }
paso() { printf '\n%s== %s ==%s\n' "$c_b" "$*" "$c_0"; }

# python3 en Linux/CI, python en Git-Bash de Windows
PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "No hay python3/python en el PATH."; exit 1; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ---------------------------------------------------------------- 1) sintaxis shell
paso "Sintaxis de los scripts shell"
for f in *.sh; do
  if bash -n "$f" 2>"$TMPD/err"; then ok "bash -n $f"
  else mal "bash -n $f"; sed 's/^/        /' "$TMPD/err"; fi
done

# ------------------------------------------------- 2) heredocs incrustados (py y sh)
# Se descubren solos: cualquier "cat > /usr/local/bin/X <<'MARCA'" entra, y el
# validador se elige por el shebang. Asi un programa nuevo queda cubierto sin
# tocar este script.
paso "Programas incrustados en install-suricata.sh"
encontrados=0
while IFS=: read -r ln linea; do
  marca=$(printf '%s' "$linea" | sed "s/.*<<'\([A-Za-z0-9_]*\)'.*/\1/")
  nombre=$(printf '%s' "$linea" | sed "s|^cat > /usr/local/bin/\([a-z0-9-]*\).*|\1|")
  dst="$TMPD/$nombre"
  # el cuerpo va desde la linea siguiente hasta la marca de cierre sola en su linea
  awk -v L="$ln" -v E="$marca" 'NR>L && $0==E{exit} NR>L{print}' install-suricata.sh > "$dst"
  if [ ! -s "$dst" ]; then mal "$nombre: extraccion vacia (marca $marca)"; continue; fi
  encontrados=$((encontrados+1))
  lineas=$(wc -l <"$dst" | tr -d ' ')
  if head -1 "$dst" | grep -q python; then
    if "$PY" -c 'import ast,sys;ast.parse(open(sys.argv[1],encoding="utf-8").read())' "$dst" 2>"$TMPD/err"; then
      ok "$nombre — sintaxis Python ($lineas lineas)"
    else
      mal "$nombre — Python invalido"; sed 's/^/        /' "$TMPD/err"
    fi
    if "$PY" -m pyflakes "$dst" >"$TMPD/pf" 2>&1; then
      ok "$nombre — pyflakes limpio"
    elif grep -q "No module named" "$TMPD/pf"; then
      avisa "$nombre — pyflakes no instalado, se omite (pip install pyflakes)"
    else
      # pyflakes detecta nombres no definidos e imports rotos: eso SI rompe en runtime
      mal "$nombre — pyflakes reporta problemas"; sed 's/^/        /' "$TMPD/pf"
    fi
  else
    if sh -n "$dst" 2>"$TMPD/err"; then ok "$nombre — sintaxis sh ($lineas lineas)"
    else mal "$nombre — sh invalido"; sed 's/^/        /' "$TMPD/err"; fi
  fi
done < <(grep -n "^cat > /usr/local/bin/[a-z0-9-]* <<'[A-Za-z0-9_]*'$" install-suricata.sh)
[ "$encontrados" -ge 4 ] || mal "solo se extrajeron $encontrados programas (se esperaban 4 o mas): revisa el patron"

# --------------------------------------------------------- 3) JavaScript del mapa
# El mapa se arma concatenando strings en Python, asi que un parentesis suelto no
# lo ve nadie hasta que el navegador deja la seccion en blanco.
paso "JavaScript del mapa"
if command -v node >/dev/null 2>&1; then
  if "$PY" - "$TMPD" <<'PYEOF' 2>"$TMPD/err"
import ast,re,sys,os
d=sys.argv[1]
src=open("install-suricata.sh",encoding="utf-8").read()
ini=src.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
cuerpo=src[ini:].split("\n",1)[1].split("\nHREP\n",1)[0]
arbol=ast.parse(cuerpo)
fn=[n for n in ast.walk(arbol) if isinstance(n,ast.FunctionDef) and n.name=="mapa_ataques_section"]
if not fn: sys.exit("no se encontro mapa_ataques_section")
ret=[n for n in ast.walk(fn[0]) if isinstance(n,ast.Return)][-1]
def ev(n):   # se resuelven solo los literales; los datos embebidos van como marcador
    if isinstance(n,ast.Constant) and isinstance(n.value,str): return n.value
    if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add): return ev(n.left)+ev(n.right)
    if isinstance(n,ast.Name) and n.id in ("_MAP_NUM2ISO","_MAP_NAMES"): return "{}"
    if isinstance(n,ast.Name): return ""
    return "0" if (isinstance(n,ast.Call) and getattr(n.func,"id","")=="str") else "{}"
html=ev(ret.value)
js=[s for s in re.findall(r"<script>(.*?)</script>",html,re.S) if "(function(){" in s]
if not js: sys.exit("no se encontro el <script> del mapa")
open(os.path.join(d,"mapa.js"),"w",encoding="utf-8").write(js[0])
PYEOF
  then
    if node --check "$TMPD/mapa.js" 2>"$TMPD/err"; then ok "node --check del mapa"
    else mal "JavaScript del mapa invalido"; sed 's/^/        /' "$TMPD/err"; fi
  else
    mal "no se pudo extraer el JS del mapa"; sed 's/^/        /' "$TMPD/err"
  fi
else
  avisa "node no esta instalado, se omite la revision del JavaScript"
fi

# ------------------------------------------------------------- 4) finales de linea
# Un CRLF hace que Linux no encuentre el interprete ("bad interpreter: ^M") y git
# no lo delata. .gitattributes fuerza LF; esto comprueba que de verdad se cumplio.
paso "Finales de linea (LF)"
# se revisa TODO lo versionado menos vendor/ (ahi hay binarios marcados como tal)
malos=""
for f in $(git ls-files 2>/dev/null | grep -v '^vendor/'); do
  if grep -qU $'\r' "$f" 2>/dev/null; then malos="$malos $f"; fi
done
if [ -n "$malos" ]; then mal "archivos con CRLF:$malos"; else ok "todos los archivos de texto usan LF"; fi

# ------------------------------------------------- 5) assets vendorizados del mapa
# El instalador verifica el SHA256 al descargar. Si alguien cambia el archivo del
# repo y no actualiza la constante (o al reves), las cajas se quedan sin mapa.
paso "Assets del mapa (SHA256)"
for f in countries-110m.json topojson-client.min.js; do
  ruta="vendor/mapa/$f"
  if [ ! -f "$ruta" ]; then mal "falta $ruta"; continue; fi
  suma=$(sha256sum "$ruta" | cut -d' ' -f1)
  veces=$(grep -c "$suma" install-suricata.sh || true)
  if [ "$veces" -ge 3 ]; then
    ok "$f — SHA256 coincide en las $veces referencias del instalador"
  elif [ "$veces" -eq 0 ]; then
    mal "$f — su SHA256 ($suma) no aparece en install-suricata.sh"
  else
    mal "$f — SHA256 solo en $veces de las 3 referencias: quedaron constantes desactualizadas"
  fi
done

# ------------------------------------------------- 6) pruebas de comportamiento
# La sintaxis no dice si el codigo HACE lo correcto. Estas pruebas ejecutan las
# piezas reales contra dobles (ver tests/run.sh).
paso "Pruebas funcionales"
if [ -x tests/run.sh ] || [ -f tests/run.sh ]; then
  if bash tests/run.sh >"$TMPD/tests" 2>&1; then
    grep -E "^\s*(OK|\s)" "$TMPD/tests" | sed 's/^/ /'
  else
    mal "fallaron pruebas funcionales"; sed 's/^/        /' "$TMPD/tests"
  fi
else
  avisa "no hay tests/run.sh"
fi

# ----------------------------------------------------------------------- resumen
printf '\n'
if [ "$fallos" -eq 0 ]; then
  printf '%sTodo correcto.%s\n' "$c_g" "$c_0"; exit 0
else
  printf '%s%d comprobacion(es) fallaron.%s\n' "$c_r" "$fallos" "$c_0"; exit 1
fi
