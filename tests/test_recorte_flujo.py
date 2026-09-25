# -*- coding: utf-8 -*-
"""Recorte por flujo en el receptor: el connection-bytes de quien no manda en el router.

Lo correcto es filtrar en el MikroTik. Cuando no se tiene acceso al router, el espejo
llega entero igual y lo unico que queda es no ahogar al sensor. Pero recortar mal es
peor que no recortar: crea puntos ciegos silenciosos, que es justo lo que este proyecto
intenta evitar.

Lo que se protege:
  - que el DNS no se recorte NUNCA (es el 0,04% de los bytes y donde mas se detecta);
  - que el arranque de cada conexion pase entero (ahi estan el SYN, el SNI, el HTTP);
  - que lo que no sepamos interpretar se reenvie, en vez de tirarlo a ciegas;
  - que apagado (0) no descarte ni un paquete.
"""
import ast
import os
import struct
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/tzsp-decap.py <<'PYD'")
PYD = SRC[_i:].split("\n", 1)[1].split("\nPYD\n", 1)[0]
ARBOL = ast.parse(PYD)

PIEZAS = ("RECORTE_TTL", "RECORTE_MAX", "_flujos", "_ultima_limpia",
          "_clave_flujo", "recortar")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(limite):
    ns = {"os": os, "time": time, "RECORTE": limite}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(PYD, n) or "", ns)
    return ns


def trama(sp, dp, proto=6, relleno=0, src="192.0.2.10", dst="198.51.100.20"):
    """Una trama Ethernet/IPv4/TCP o UDP con el relleno pedido."""
    def ip4(t):
        return bytes(int(x) for x in t.split("."))
    eth = b"\x02" * 6 + b"\x03" * 6 + b"\x08\x00"
    cab = struct.pack("!BBHHHBBH", 0x45, 0, 20 + 8 + relleno, 1, 0, 64, proto, 0) \
        + ip4(src) + ip4(dst)
    l4 = struct.pack("!HH", sp, dp) + b"\x00" * 4
    return eth + cab + l4 + b"\x00" * relleno


def main():
    ahora = time.time()

    # --- apagado: no se toca nada ----------------------------------------------------
    ns = entorno(0)
    check("con el recorte apagado no se descarta ni un paquete",
          not any(ns["recortar"](trama(1234, 443, relleno=1400), ahora) for _ in range(50)))

    # --- el DNS nunca se recorta -----------------------------------------------------
    ns = entorno(1000)
    dns = [ns["recortar"](trama(50000 + i, 53, proto=17, relleno=400), ahora)
           for i in range(40)]
    check("el DNS no se recorta nunca, por mucho que haya", not any(dns), sum(dns))
    check("ni las respuestas de DNS (puerto 53 de origen)",
          not any(ns["recortar"](trama(53, 50000 + i, proto=17, relleno=400), ahora)
                  for i in range(20)))

    # --- el arranque pasa, el payload no ---------------------------------------------
    ns = entorno(3000)
    paso = [not ns["recortar"](trama(40000, 443, relleno=1400), ahora) for _ in range(10)]
    check("el arranque de la conexion pasa entero", all(paso[:2]), paso)
    check("y a partir del limite se deja de reenviar", not any(paso[3:]), paso)
    check("no se recorta el primer paquete de un flujo nuevo", paso[0])

    # el mismo flujo en sentido contrario es EL MISMO flujo
    ns = entorno(3000)
    for _ in range(5):
        ns["recortar"](trama(40000, 443, relleno=1400), ahora)
    check("la vuelta cuenta en el mismo flujo, no empieza de cero",
          ns["recortar"](trama(443, 40000, relleno=1400,
                               src="198.51.100.20", dst="192.0.2.10"), ahora))

    # otro flujo distinto arranca limpio
    check("un flujo distinto no hereda el limite del anterior",
          not ns["recortar"](trama(40001, 443, relleno=1400), ahora))

    # --- lo que no se entiende se reenvia --------------------------------------------
    ns = entorno(100)
    arp = b"\x02" * 6 + b"\x03" * 6 + b"\x08\x06" + b"\x00" * 40
    check("lo que no es IPv4 se reenvia siempre, no se tira a ciegas",
          not any(ns["recortar"](arp, ahora) for _ in range(30)))
    icmp = trama(0, 0, proto=1, relleno=1400)
    check("lo que no es TCP ni UDP tambien se reenvia",
          not any(ns["recortar"](icmp, ahora) for _ in range(30)))
    check("una trama cortada no rompe el receptor",
          ns["_clave_flujo"](b"\x02" * 10) is None)

    # --- memoria acotada ---------------------------------------------------------------
    ns = entorno(100)
    ns["RECORTE_TTL"] = 1
    for i in range(50):
        ns["recortar"](trama(1000 + i, 443, relleno=200), ahora)
    n1 = len(ns["_flujos"])
    ns["recortar"](trama(9999, 443, relleno=200), ahora + 3600)   # dispara la limpieza
    check("los flujos viejos se olvidan y la tabla no crece sin fin",
          len(ns["_flujos"]) < n1, (n1, len(ns["_flujos"])))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
