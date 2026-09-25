# -*- coding: utf-8 -*-
"""Cobertura del sensor: sin alertas no es lo mismo que sin ataques.

Esto nace de un caso real. El MikroTik empezo a mandar el espejo a otra direccion; el
receptor lo rechazo entero por no estar en la lista de origenes autorizados; Suricata
dejo de ver practicamente todo. Y el panel siguio diciendo "viendo trafico" durante
horas, porque SI entraban algunos paquetes. Una red sin alertas parecia limpia y era
un sensor ciego.

Lo que se comprueba aqui es que ese estado se detecta y se dice con todas las letras,
y que un nodo que deja de mandar espejo no pasa desapercibido.
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

PIEZAS = ("TZSP_ESTADO", "COBERTURA_MUDO", "COBERTURA_RECHAZO", "cobertura_tzsp")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"json": json, "os": os, "time": time}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["TZSP_ESTADO"] = os.path.join(tmp, "tzsp.json")
    return ns


def estado(ns, aceptados, rechazados, ultimo_visto, esperados, edad=10):
    with open(ns["TZSP_ESTADO"], "w", encoding="utf-8") as f:
        json.dump({"ts": int(time.time() - edad),
                   "ventana": {"aceptados": aceptados, "rechazados": rechazados},
                   "ultimo_visto": ultimo_visto, "esperados": esperados}, f)


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    ahora = time.time()

    # --- todo bien ------------------------------------------------------------------
    estado(ns, {"100.64.0.2": 1900000}, {}, {"100.64.0.2": int(ahora - 5)},
           ["100.64.0.2/32"])
    c = ns["cobertura_tzsp"](ahora)
    check("con un nodo sano la cobertura es del 100%", c["cobertura"] == 100.0, c)
    check("y no hay nodos mudos", c["mudos"] == [], c["mudos"])
    check("ni rechazo", c["ratio_rechazo"] == 0.0, c["ratio_rechazo"])

    # --- EL CASO REAL: el espejo llega, pero de quien no debe -------------------------
    estado(ns, {"100.64.0.2": 2547}, {"203.0.113.9": 3773590},
           {"100.64.0.2": int(ahora - 5)}, ["100.64.0.2/32"])
    c = ns["cobertura_tzsp"](ahora)
    check("se detecta que casi todo el espejo se esta tirando",
          c["ratio_rechazo"] > 0.99, c["ratio_rechazo"])
    check("y se dice DE QUIEN llega, para poder arreglarlo",
          c["intrusos"] == ["203.0.113.9"], c["intrusos"])
    check("el umbral de aviso se cruza de sobra",
          c["ratio_rechazo"] >= ns["COBERTURA_RECHAZO"])
    check("aunque el nodo bueno siga mandando algo, no lo tapa",
          c["aceptados"] == 2547 and c["rechazados"] == 3773590, c)

    # --- un nodo se calla -------------------------------------------------------------
    estado(ns, {"100.64.0.2": 1000}, {},
           {"100.64.0.2": int(ahora - 5), "100.64.0.3": int(ahora - 3600)},
           ["100.64.0.2/32", "100.64.0.3/32"])
    c = ns["cobertura_tzsp"](ahora)
    check("un nodo que lleva una hora sin mandar sale como mudo",
          c["mudos"] == ["100.64.0.3/32"], c["mudos"])
    check("y la cobertura deja de ser del 100%", c["cobertura"] == 50.0, c["cobertura"])
    check("el nodo que si manda no se marca",
          "100.64.0.2/32" not in c["mudos"], c["mudos"])

    # un silencio corto no es un nodo caido: no se avisa por cada microcorte
    estado(ns, {"100.64.0.2": 10}, {},
           {"100.64.0.2": int(ahora - 60)}, ["100.64.0.2/32"])
    check("un silencio de un minuto no dispara el aviso",
          ns["cobertura_tzsp"](ahora)["mudos"] == [])

    # --- sin receptor TZSP no se inventa nada ------------------------------------------
    os.remove(ns["TZSP_ESTADO"])
    check("si no hay receptor, no se reporta cobertura falsa",
          ns["cobertura_tzsp"](ahora) == {})

    # --- el aviso envejece -------------------------------------------------------------
    estado(ns, {"100.64.0.2": 5}, {}, {"100.64.0.2": int(ahora - 5)},
           ["100.64.0.2/32"], edad=900)
    check("se sabe cuando se midio, para no confiar en un dato viejo",
          ns["cobertura_tzsp"](ahora)["edad"] >= 890)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
