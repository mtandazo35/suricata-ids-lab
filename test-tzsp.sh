#!/usr/bin/env bash
#
# test-tzsp.sh — Prueba el receptor TZSP sin MikroTik.
#
#   Fabrica una trama Ethernet/IPv4/UDP con una consulta DNS a un dominio .top,
#   la envuelve en TZSP y la manda al receptor (UDP 37008). Si el pipeline
#   TZSP -> tzsp-decap -> ids-mon -> Suricata funciona, aparece la alerta
#   "ET DNS Query to a *.top domain" (sid 2023883) con in_iface ids-mon.
#
#   Uso:  ./test-tzsp.sh [ip_receptor] [puerto]      (default: 127.0.0.1 37008)
#
set -uo pipefail
c_g=$'\e[32m'; c_y=$'\e[33m'; c_b=$'\e[36m'; c_0=$'\e[0m'
info(){ printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
ok(){   printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }

DST="${1:-127.0.0.1}"; PORT="${2:-37008}"
EVE=/var/log/suricata/eve.json
TAG="tzsp-test-$RANDOM"

if systemctl is-active --quiet tzsp-decap 2>/dev/null; then ok "tzsp-decap activo"; else warn "tzsp-decap no esta activo (instala con -t)"; fi
ip link show ids-mon >/dev/null 2>&1 && ok "interfaz ids-mon presente" || warn "no existe ids-mon"

# Suricata tarda ~30-60 s en cargar reglas tras un (re)inicio: esperar al motor
if command -v suricatasc >/dev/null 2>&1; then
  for _ in $(seq 1 45); do suricatasc -c uptime >/dev/null 2>&1 && break; sleep 2; done
  if IFACES="$(suricatasc -c iface-list 2>/dev/null)"; then
    printf '%s' "$IFACES" | grep -q '"ids-mon"' && ok "Suricata captura ids-mon" || warn "Suricata NO captura ids-mon (interfaces: $IFACES)"
  else
    warn "el motor de Suricata no responde (¿arrancando?); el test puede fallar por eso"
  fi
fi

info "Enviando trama TZSP sintetica (DNS ${TAG}.example.top) a ${DST}:${PORT}..."
python3 - "$DST" "$PORT" "$TAG" <<'PY'
import socket, struct, sys, random
dst, port, tag = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

qname = b"".join(bytes([len(l)]) + l.encode() for l in f"{tag}.example.top".split(".")) + b"\0"
dns = struct.pack("!HHHHHH", random.randint(1, 65535), 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
udp = struct.pack("!HHHH", 40000 + random.randint(0, 20000), 53, 8 + len(dns), 0) + dns
src_ip, dst_ip = bytes([10, 200, 200, 10]), bytes([8, 8, 8, 8])
ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), random.randint(1, 65535), 0x4000, 64, 17, 0, src_ip, dst_ip)
ip_hdr = ip_hdr[:10] + struct.pack("!H", csum(ip_hdr)) + ip_hdr[12:]
eth = bytes.fromhex("bc2411aaaaaa") + bytes.fromhex("bc2411bbbbbb") + b"\x08\x00"
frame = eth + ip_hdr + udp
tzsp = bytes([1, 0]) + struct.pack("!H", 1) + bytes([0x01]) + frame   # ver1, tipo 0, encap Ethernet, tag END
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(tzsp, (dst, port))
print(f"  trama de {len(frame)} bytes (TZSP {len(tzsp)} bytes) enviada; origen simulado 10.200.200.10 -> 8.8.8.8:53")
PY

info "Esperando a Suricata (5s)..."
sleep 5
if [ -r "$EVE" ] && grep -q "$TAG" "$EVE"; then
  ok "Suricata vio la trama en eve.json:"
  python3 - "$EVE" "$TAG" <<'PY'
import sys, json
eve, tag = sys.argv[1], sys.argv[2]
for l in open(eve, encoding="utf-8", errors="replace"):
    if tag not in l:
        continue
    e = json.loads(l)
    extra = e["alert"]["signature"] if e["event_type"] == "alert" else e.get("dns", {}).get("rrname", "")
    print("  - %-6s in_iface=%s %s -> %s  %s" % (e["event_type"], e.get("in_iface"), e["src_ip"], e["dest_ip"], extra))
PY
  grep "$TAG" "$EVE" | grep -q '"event_type":"alert"' && ok "Alerta generada: el pipeline TZSP funciona (mirala en EveBox)." \
    || warn "Se vio el DNS pero sin alerta: revisa que las reglas ET esten cargadas (sid 2023883)."
else
  warn "Suricata no registro la trama. Revisa:"
  echo "    journalctl -u tzsp-decap -n 20     (debe haber tx>0; si rx=0 la trama no llego al puerto ${PORT})"
  echo "    grep -n 'interface: ids-mon' /etc/suricata/suricata.yaml   (Suricata debe capturar ids-mon)"
  echo "    systemctl status suricata"
fi
