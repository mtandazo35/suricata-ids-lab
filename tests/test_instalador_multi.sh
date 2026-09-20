#!/usr/bin/env bash
#
# Comprueba que el instalador genera bien el multi-nodo SIN instalar nada: se extrae
# solo el trozo que calcula las interfaces por router y se ejecuta con distintos -m.
#
# Lo que protege: que el PRIMER router conserve ids-in/ids-mon. Si una actualizacion le
# cambiara el nombre a la interfaz, las cajas ya instaladas se quedarian sin captura y
# sin ningun aviso.
#
set -uo pipefail
cd "$(dirname "$0")/.."

fallos=0
check() { # $1=descripcion $2=obtenido $3=esperado
  if [ "$2" = "$3" ]; then
    printf '  OK   %s\n' "$1"
  else
    printf ' FALLA %s\n        esperado: %s\n        obtenido: %s\n' "$1" "$3" "$2"
    fallos=$((fallos+1))
  fi
}

# --- trozo real del instalador: el bucle que arma TZSP_MAP / TZSP_MONS / TZSP_PRE ---
TROZO="$(awk '/^  TZSP_MAP=""; TZSP_MONS=""; TZSP_PRE=""$/,/^  \[ -n "\$TZSP_MONS" \]/' install-suricata.sh)"
[ -n "$TROZO" ] || { echo "no se encontro el bloque de interfaces por router"; exit 1; }

calcular() { # $1 = valor de -m
  MIRROR_SRC="$1"; TZSP_IN=ids-in; TZSP_MON=ids-mon
  eval "$TROZO"
  printf '%s|%s' "$TZSP_MAP" "$TZSP_MONS"
}

# --- un solo MikroTik: debe quedar EXACTAMENTE como siempre ---
r="$(calcular "10.87.87.1")"
check "un router: mapea a la interfaz de siempre" "${r%%|*}" "10.87.87.1=ids-in"
check "un router: Suricata captura ids-mon" "${r##*|}" "ids-mon"

# --- tres MikroTik: una interfaz por nodo ---
r="$(calcular "10.0.0.1,10.9.9.1,192.0.2.1")"
check "tres routers: cada uno a su interfaz" "${r%%|*}" \
      "10.0.0.1=ids-in,10.9.9.1=ids-in2,192.0.2.1=ids-in3"
check "tres routers: Suricata captura las tres" "${r##*|}" "ids-mon ids-mon2 ids-mon3"

# --- el primero NUNCA cambia de nombre (si no, las cajas existentes pierden captura) ---
case "$(calcular "10.0.0.1,10.9.9.1")" in
  10.0.0.1=ids-in,*) printf '  OK   el primer router conserva ids-in al agregar otros\n' ;;
  *) printf ' FALLA el primer router cambio de interfaz\n'; fallos=$((fallos+1)) ;;
esac

# --- rangos CIDR ---
r="$(calcular "10.0.0.0/24,10.9.9.0/24")"
check "acepta rangos CIDR" "${r%%|*}" "10.0.0.0/24=ids-in,10.9.9.0/24=ids-in2"

# --- las lineas del servicio: un par veth por router ---
MIRROR_SRC="10.0.0.1,10.9.9.1"; TZSP_IN=ids-in; TZSP_MON=ids-mon
eval "$TROZO"
n_add="$(printf '%s' "$TZSP_PRE" | grep -c 'ip link add')"
check "crea un par veth por router" "$n_add" "2"
printf '%s' "$TZSP_PRE" | grep -q 'ip link add ids-in2 type veth peer name ids-mon2' \
  && printf '  OK   el segundo par se llama ids-in2/ids-mon2\n' \
  || { printf ' FALLA no crea el par del segundo router\n'; fallos=$((fallos+1)); }
n_promisc="$(printf '%s' "$TZSP_PRE" | grep -c 'promisc on')"
check "todas las interfaces quedan en modo promiscuo" "$n_promisc" "2"

printf '\n'
if [ "$fallos" -eq 0 ]; then echo "TODO OK"; else echo "$fallos fallo(s)"; fi
exit $([ "$fallos" -eq 0 ] && echo 0 || echo 1)
