# -*- coding: utf-8 -*-
"""parse_ts con memoria: mismo resultado, mucho mas barato.

De donde sale: en un nodo real el generador tardaba 9 minutos al 99 % de CPU por corrida.
El grueso era `parse_ts`, que hace `strptime` y se llama UNA VEZ POR LINEA sobre millones
de lineas. Se memoriza por SEGUNDO, asi que miles de lineas del mismo segundo colapsan en
un unico strptime.

El riesgo de un cache de timestamps es que devuelva la marca de otra linea: eso
desplazaria eventos de sitio sin que nadie lo note. Por eso aqui se comprueba primero que
el resultado sea el MISMO que sin cache, y solo despues que sea mas rapido.
"""
import ast
import os
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
ARBOL = ast.parse(GEN)

PIEZAS = ("parse_ts", "_parse_ts_lento", "_TS_CACHE", "_TS_CACHE_MAX", "TZ_EC")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas():
    import datetime as _dt
    ns = {"datetime": _dt.datetime, "timezone": _dt.timezone, "timedelta": _dt.timedelta,
          "time": time, "os": os, "re": __import__("re")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(GEN, n) or "", ns)
    return ns


def main():
    ns = piezas()
    parse_ts, lento = ns["parse_ts"], ns["_parse_ts_lento"]

    # --- lo primero: el resultado tiene que ser el mismo ---
    base = "2026-09-23T11:48:39"
    casos = [base + ".123456-0500", base + ".000001-0500", base + "-0500",
             "2026-01-01T00:00:00.000000+0000", "2026-12-31T23:59:59.999999-0500"]
    for c in casos:
        v = parse_ts(c)
        ref = lento(c[:19] + c[26:] if len(c) > 26 else c)
        check("%s da el mismo epoch que sin cache" % c[:26], v == ref, (v, ref))

    # --- el cache es POR SEGUNDO: dos marcas del mismo segundo dan lo mismo ---
    a = parse_ts(base + ".000001-0500")
    b = parse_ts(base + ".999999-0500")
    check("dos marcas del mismo segundo dan el mismo epoch", a == b, (a, b))
    check("y un segundo mas es exactamente un segundo mas",
          parse_ts("2026-09-23T11:48:40.000000-0500") - a == 1.0,
          parse_ts("2026-09-23T11:48:40.000000-0500") - a)

    # --- NO se confunden marcas con distinta zona horaria ---
    z1 = parse_ts("2026-09-23T11:48:39.000000-0500")
    z2 = parse_ts("2026-09-23T11:48:39.000000+0000")
    check("la zona horaria forma parte de la clave: no se mezclan",
          z1 - z2 == 5 * 3600, (z1, z2, z1 - z2))

    # --- basura y vacios ---
    check("una marca vacia no revienta", parse_ts("") is None)
    check("None tampoco", parse_ts(None) is None)
    check("una cadena que no es fecha da None", parse_ts("no-es-una-fecha") is None)

    # --- el cache no crece sin fin ---
    tope = ns["_TS_CACHE_MAX"]
    check("hay un tope para que el cache no se coma la RAM", tope and tope <= 500000, tope)

    # --- y la ganancia, que es el motivo de todo esto ---
    marcas = ["2026-09-23T%02d:%02d:%02d.%06d-0500" % (h, m, sg, us)
              for h in range(4) for m in range(60) for sg in range(10) for us in (1, 2, 3, 4, 5)]
    ns["_TS_CACHE"].clear()
    t0 = time.perf_counter()
    for m in marcas:
        parse_ts(m)
    con = time.perf_counter() - t0
    t0 = time.perf_counter()
    for m in marcas:
        lento(m)
    sin = time.perf_counter() - t0
    check("con cache es al menos 2 veces mas rapido sobre marcas repetidas",
          con * 2 < sin, "con=%.3fs sin=%.3fs (%d marcas, %d segundos distintos)"
          % (con, sin, len(marcas), len(ns["_TS_CACHE"])))
    print("       ganancia real: %.3fs -> %.3fs (%.1fx) en %d marcas"
          % (sin, con, sin / con if con else 0, len(marcas)))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
