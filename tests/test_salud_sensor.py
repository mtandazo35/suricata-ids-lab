# -*- coding: utf-8 -*-
"""Salud completa del sensor: mirar solo kernel_drops deja ciego al peor caso.

Un memcap agotado es mas enganoso que una perdida de captura: el kernel no tira NADA
-kernel_drops sigue en cero- y quien tira los flujos es Suricata, por quedarse sin
memoria. Las alertas que faltan no dejan rastro en ningun sitio.

Y la regla que da sentido a todo lo demas: con cobertura incompleta el panel NO puede
decir "sin amenazas". No hay alertas porque no estamos mirando, y quien lo lee entiende
que la red esta limpia. Es la afirmacion mas cara que puede hacer un IDS.
"""
import ast
import json
import os
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("SALUD_DROPS", "SALUD_EVE_MUDO", "SALUD_DISCO", "SALUD_COBERTURA",
          "suricata_stats", "salud_memcaps")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"json": json, "os": os, "time": time, "LOGDIR": tmp}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def eve(tmp, *lineas):
    with open(os.path.join(tmp, "eve.json"), "w", encoding="utf-8") as f:
        f.writelines(lineas)


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    alerta = json.dumps({"event_type": "alert", "src_ip": "192.168.1.1"}) + "\n"
    stats_ok = json.dumps({"event_type": "stats", "stats": {
        "capture": {"kernel_packets": 1000000, "kernel_drops": 0},
        "flow": {"memcap": 0}, "tcp": {"ssn_memcap_drop": 0}}}) + "\n"

    # --- leer los contadores ---------------------------------------------------------
    eve(tmp, alerta, stats_ok, alerta)
    st = ns["suricata_stats"]()
    check("se leen los contadores del ultimo stats, aunque no sea la ultima linea",
          (st.get("capture") or {}).get("kernel_packets") == 1000000, st)
    check("sin memcaps agotados no se inventa un problema",
          ns["salud_memcaps"](st) == {}, ns["salud_memcaps"](st))

    # el ULTIMO stats manda: un contador viejo daria una foto que ya no es
    eve(tmp, stats_ok,
        json.dumps({"event_type": "stats", "stats": {
            "capture": {"kernel_packets": 2000000, "kernel_drops": 7}}}) + "\n")
    check("gana el stats mas reciente, no el primero que aparece",
          (ns["suricata_stats"]().get("capture") or {}).get("kernel_drops") == 7)

    # --- EL CASO ENGANOSO: memcap agotado con kernel_drops en CERO -------------------
    st_mem = {"capture": {"kernel_packets": 5000000, "kernel_drops": 0},
              "flow": {"memcap": 48211},
              "tcp": {"ssn_memcap_drop": 0, "reassembly_memcap_drop": 12}}
    m = ns["salud_memcaps"](st_mem)
    check("un memcap agotado se detecta aunque el kernel no haya tirado nada",
          len(m) == 2, m)
    check("y se dice CUANTO se perdio, no solo que paso",
          48211 in m.values() and 12 in m.values(), m)
    check("se nombra en castellano, no con el contador crudo",
          any("flujos descartados" in k for k in m), list(m))

    # --- sin eve.json no se afirma nada ----------------------------------------------
    os.remove(os.path.join(tmp, "eve.json"))
    check("sin eve.json no se reportan contadores falsos", ns["suricata_stats"]() == {})
    check("y sin contadores no se inventan memcaps", ns["salud_memcaps"]({}) == {})

    # una linea de stats rota no puede tumbar la salud
    eve(tmp, '{"event_type":"stats", roto\n', stats_ok)
    check("una linea corrupta no rompe la lectura",
          (ns["suricata_stats"]().get("capture") or {}).get("kernel_packets") == 1000000)

    # --- umbrales coherentes -----------------------------------------------------------
    check("el umbral de perdida es un porcentaje bajo, no un valor simbolico",
          0 < ns["SALUD_DROPS"] <= 0.05, ns["SALUD_DROPS"])
    check("la cobertura exigida para decir 'sin amenazas' es alta",
          ns["SALUD_COBERTURA"] >= 90, ns["SALUD_COBERTURA"])
    check("el disco avisa antes de llenarse, no al llenarse",
          70 <= ns["SALUD_DISCO"] < 100, ns["SALUD_DISCO"])
    check("el silencio de eve se mide en minutos, no en horas",
          60 <= ns["SALUD_EVE_MUDO"] <= 900, ns["SALUD_EVE_MUDO"])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
