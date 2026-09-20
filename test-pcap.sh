#!/usr/bin/env bash
#
# test-pcap.sh — Reproduce una captura (.pcap) contra Suricata y dice que detecto.
#
#   A diferencia de test-alerts.sh (que genera trafico real por la red), esto es
#   OFFLINE y DETERMINISTA: 'suricata -r' solo LEE el archivo, no manda un solo
#   paquete a la red. Sirve para comprobar que el set de reglas cargado detecta lo
#   que deberia, y para comparar antes/despues de tocar reglas o exclusiones.
#
#   Uso:
#     ./test-pcap.sh captura.pcap                    reproduce una captura local
#     ./test-pcap.sh captura.zip                     zip protegido (clave 'infected')
#     ./test-pcap.sh --url URL --sha256 HASH         descarga verificada y reproduce
#     ./test-pcap.sh --url URL --sha256 HASH -n 10.0.0.0/8
#     ./test-pcap.sh --fuentes                       de donde sacar capturas
#
#   Opciones:
#     -n REDES     HOME_NET a usar (ej. 10.0.0.0/8,192.168.0.0/16). Importa: si la
#                  red de la captura no cae en HOME_NET, muchas reglas no disparan.
#     -m N         exige al menos N alertas para dar exito (por defecto 1)
#     -k           conserva el directorio de trabajo con eve.json para inspeccionarlo
#
#   SOBRE CAPTURAS CON MALWARE
#   Las capturas publicas de trafico malicioso (Malware Traffic Analysis y similares)
#   contienen payloads de malware REAL y se distribuyen en ZIP con clave 'infected'.
#   Por eso:
#     - NUNCA se guardan en este repositorio; se descargan bajo demanda a un
#       directorio temporal y se borran al terminar.
#     - Se exige el SHA256 al descargar: si no cuadra, se aborta.
#     - Reproducirlas con 'suricata -r' NO ejecuta el malware (solo se parsean
#       paquetes), pero el archivo en disco si es malware: usa una maquina de
#       pruebas o un runner efimero, no tu equipo de trabajo, y no habilites la
#       extraccion de archivos (file-store) de Suricata al hacerlo.
#
set -uo pipefail

c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_b=$'\e[36m'; c_0=$'\e[0m'
[ -t 1 ] || { c_g=; c_r=; c_y=; c_b=; c_0=; }
info(){ printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
ok()  { printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }
die() { printf '%s[x]%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }

fuentes() {
  cat <<'EOF'
Capturas para probar (descargalas tu, con su SHA256):

  Sin malware — seguras en cualquier maquina:
    - Suricata Verify: capturas pequenas del propio proyecto, pensadas para tests.
      https://github.com/OISF/suricata-verify  (tests/*/*.pcap)
    - Wireshark sample captures: trafico de protocolos, util para ver que el
      motor parsea, aunque casi no dispara alertas.
      https://wiki.wireshark.org/SampleCaptures

  Con malware REAL — solo en maquina de pruebas o runner efimero:
    - Malware Traffic Analysis (ZIP con clave 'infected')
      https://www.malware-traffic-analysis.net/
    - The Honeynet Project / capturas de CTF forenses

Obten el SHA256 del archivo descargado y pasalo con --sha256, para que una
descarga alterada o incompleta no pase desapercibida:

    sha256sum captura.zip
EOF
}

PCAP=""; URL=""; SHA=""; HOME_NET=""; MIN=1; KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --fuentes|--listar) fuentes; exit 0 ;;
    --url)    URL="${2:-}"; shift 2 ;;
    --sha256) SHA="${2:-}"; shift 2 ;;
    -n)       HOME_NET="${2:-}"; shift 2 ;;
    -m)       MIN="${2:-1}"; shift 2 ;;
    -k)       KEEP=1; shift ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)       die "opcion desconocida: $1 (usa -h)" ;;
    *)        PCAP="$1"; shift ;;
  esac
done

command -v suricata >/dev/null 2>&1 || die "Suricata no esta instalado en esta maquina."
CONF=/etc/suricata/suricata.yaml
[ -f "$CONF" ] || die "No existe $CONF. Instala Suricata primero (install-suricata.sh)."

WORK="$(mktemp -d)"
limpiar(){
  if [ "$KEEP" = 1 ]; then
    warn "Directorio conservado: $WORK  (contiene la captura; borralo tu: rm -rf $WORK)"
  else
    rm -rf "$WORK"
  fi
}
trap limpiar EXIT

# ------------------------------------------------------------ obtener la captura
if [ -n "$URL" ]; then
  [ -n "$SHA" ] || die "Con --url hay que pasar --sha256 (una descarga sin verificar no se reproduce)."
  info "Descargando a un temporal (no al repositorio)..."
  curl -fsSL "$URL" -o "$WORK/descarga" || die "No se pudo descargar $URL"
  real="$(sha256sum "$WORK/descarga" | cut -d' ' -f1)"
  if [ "$real" != "$SHA" ]; then
    die "SHA256 NO coincide. Esperado: $SHA  Obtenido: $real  -> se aborta y se borra."
  fi
  ok "SHA256 verificado."
  case "$URL" in
    *.zip) mv "$WORK/descarga" "$WORK/captura.zip"; PCAP="$WORK/captura.zip" ;;
    *)     mv "$WORK/descarga" "$WORK/captura.pcap"; PCAP="$WORK/captura.pcap" ;;
  esac
fi

[ -n "$PCAP" ] || { fuentes; echo; die "Falta la captura. Uso: ./test-pcap.sh captura.pcap  (o --url ... --sha256 ...)"; }
[ -f "$PCAP" ] || die "No existe el archivo: $PCAP"

# ZIP protegido: asi distribuye sus capturas Malware Traffic Analysis
case "$PCAP" in
  *.zip)
    command -v unzip >/dev/null 2>&1 || die "Hace falta unzip para abrir el .zip (apt install unzip)."
    warn "ZIP de captura: suele contener MALWARE REAL. Se extrae solo en $WORK."
    unzip -P infected -o -q -d "$WORK/extraido" "$PCAP" 2>/dev/null \
      || unzip -o -q -d "$WORK/extraido" "$PCAP" \
      || die "No se pudo extraer (clave distinta de 'infected'?)"
    PCAP="$(find "$WORK/extraido" -type f \( -name '*.pcap' -o -name '*.pcapng' \) | head -1)"
    [ -n "$PCAP" ] || die "El zip no traia ningun .pcap"
    ok "Extraido: $(basename "$PCAP")"
    ;;
esac

# --------------------------------------------------------------------- reproducir
mkdir -p "$WORK/salida"
set -- -r "$PCAP" -l "$WORK/salida" -c "$CONF"
# -k none: las capturas suelen traer checksums "malos" por el offload de la tarjeta
# donde se tomaron; sin esto Suricata descarta esos paquetes y no detecta nada.
set -- "$@" -k none
if [ -n "$HOME_NET" ]; then
  set -- "$@" --set "vars.address-groups.HOME_NET=[$HOME_NET]"
  info "HOME_NET para esta prueba: $HOME_NET"
else
  warn "Sin -n se usa el HOME_NET del servidor. Si la captura es de otra red, muchas reglas no dispararan."
fi

info "Reproduciendo $(basename "$PCAP") ($(du -h "$PCAP" | cut -f1))... no se envia nada a la red."
if ! suricata "$@" >"$WORK/suricata.out" 2>&1; then
  warn "Suricata termino con error; su salida:"
  sed 's/^/        /' "$WORK/suricata.out" | tail -20
fi

EVE="$WORK/salida/eve.json"
[ -f "$EVE" ] || die "Suricata no genero eve.json. Revisa la salida: $WORK/suricata.out"

# ------------------------------------------------------------------- resultados
total=$(grep -c '"event_type":"alert"' "$EVE" 2>/dev/null || echo 0)
printf '\n'
if [ "$total" -eq 0 ]; then
  warn "0 alertas."
  echo "     Posibles causas: las reglas no cubren ese trafico, la red de la captura"
  echo "     no cae en HOME_NET (prueba con -n), o la captura es benigna."
else
  ok "$total alertas. Firmas detectadas (las mas frecuentes):"
  # se usa python si esta, para leer el JSON bien; si no, un grep razonable
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$EVE" <<'PYEOF'
import json,sys
from collections import Counter
c=Counter(); sv={}
for linea in open(sys.argv[1],encoding='utf-8',errors='ignore'):
    if '"event_type":"alert"' not in linea: continue
    try: d=json.loads(linea)
    except Exception: continue
    a=d.get('alert',{}); s=a.get('signature','?')
    c[s]+=1; sv[s]=a.get('severity',3)
for s,n in c.most_common(15):
    print("        %5d  [sev %s]  %s" % (n, sv.get(s,'?'), s))
if len(c)>15: print("        ... y %d firmas mas" % (len(c)-15))
PYEOF
  else
    grep -o '"signature":"[^"]*"' "$EVE" | sort | uniq -c | sort -rn | head -15 | sed 's/^/       /'
  fi
fi

printf '\n'
if [ "$total" -ge "$MIN" ]; then
  ok "Resultado: $total alertas (minimo exigido: $MIN)."
  exit 0
else
  die "Resultado: $total alertas, se exigian al menos $MIN."
fi
