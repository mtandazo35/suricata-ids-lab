# -*- coding: utf-8 -*-
"""'Ver que hace' se despliega en la tabla, sin cambiar de pagina.

De donde sale: para mirar una direccion de un rango habia que irse a otra pantalla y
volver, y el "volver" no llevaba donde estabas sino a la consulta del rango. Con nueve
direcciones denunciadas eso son dieciocho navegaciones para revisar un /28.

Lo que se protege:
  - que la ficha se pueda servir SUELTA, que es lo que permite desplegarla;
  - que se consulte al ABRIR y no antes. Cada ficha gasta una consulta de la cuota de
    AbuseIPDB: pintar las nueve de un /28 por si acaso se comeria nueve por mirar una;
  - que lo ya traido no se vuelva a pedir al cerrar y abrir;
  - y que no quede ningun enlace que se lleve al usuario a otra pagina, que es lo que se
    venia a quitar.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("RANGO_TOPE", "_RANGO_JS", "rango_detalle_html", "ficha_ip_html",
          "AIDB_CATS", "AIDB_REMEDIO")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno():
    import time as _t
    # el cruce con los CPEs tiene su propia prueba (test_culpables_ficha); aqui solo
    # estorbaria, porque esta ficha se mira por lo que trae de AbuseIPDB
    ns = {"html": __import__("html"), "time": _t,
          "culpables_ficha_html": lambda ip, cats, esc=None, tope=6: ""}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


RANGO = {"tipo": "red", "red": "203.0.113.0/28", "hosts": 16,
         "denunciadas": [["203.0.113.6", 35, 10, "2026-09-19", "EC"],
                         ["203.0.113.9", 21, 3, "2026-09-19", "EC"]]}


def main():
    ns = entorno()

    # --- la ficha, suelta -----------------------------------------------------------
    d = {"ip": "203.0.113.6", "score": 35, "isp": "ISP de prueba", "pais": "EC",
         "reportes": 14, "denunciantes": 7, "ultimo": "2026-09-21",
         "cats": [[4, 12], [21, 3]], "ejemplos": ["Web bot: flood"], "ts": 1790000000}
    f = ns["ficha_ip_html"](d)
    check("la ficha se puede armar sola, sin la pagina", "203.0.113.6" in f, f[:120])
    check("dice quien es el operador", "ISP de prueba" in f, "")
    check("cuantas denuncias y de cuantos", "14" in f and "7" in f, "")
    check("y que suele haber detras", "Que suele haber detras" in f, "")
    check("sin nada denunciado lo dice, no deja el hueco",
          "sin denuncias" in ns["ficha_ip_html"]({"ip": "203.0.113.1", "score": 0}), "")

    # --- la tabla del rango ------------------------------------------------------------
    t = ns["rango_detalle_html"](RANGO)
    # se cuentan los onclick, no el nombre: _RANGO_JS tambien lo lleva (la definicion)
    check("cada direccion trae su desplegable", t.count("onclick=") == 2, t.count("onclick="))
    check("con una fila oculta donde cargarla", t.count("class=fichafila hidden") == 2, "")
    check("y ya NO se enlaza a otra pagina, que es lo que se venia a quitar",
          "?ips=" not in t, t[:300])

    # --- la cuota --------------------------------------------------------------------------
    js = ns["_RANGO_JS"]
    check("la ficha se pide al abrir, no al pintar la tabla",
          "/reputacion/ficha?ip=" in js and "fetch" in js, "")
    check("y no se vuelve a pedir lo ya traido",
          "cargado" in js, "")
    check("cerrar oculta sin gastar otra consulta",
          "fila.hidden = true" in js, "")

    # --- el tope ----------------------------------------------------------------------------
    grande = dict(RANGO, hosts=4096,
                  denunciadas=[["198.51.100.%d" % (i % 250), 20, 1, "2026-09-01", "EC"]
                               for i in range(ns["RANGO_TOPE"] + 30)])
    tg = ns["rango_detalle_html"](grande)
    check("con muchas direcciones se corta y se dice",
          tg.count("onclick=") == ns["RANGO_TOPE"] and "peores" in tg,
          tg.count("onclick="))

    # --- un rango limpio ----------------------------------------------------------------------
    limpio = {"tipo": "red", "red": "203.0.113.0/28", "hosts": 16, "denunciadas": []}
    check("un rango sin denuncias lo dice en verde, sin tabla",
          "Ninguna" in ns["rango_detalle_html"](limpio), ns["rango_detalle_html"](limpio))
    check("y lo que no es una red no pinta nada",
          ns["rango_detalle_html"]({"tipo": "ip"}) == "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
