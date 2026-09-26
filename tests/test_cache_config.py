# -*- coding: utf-8 -*-
"""La cache de configuracion: rapida, pero sin quedarse con datos viejos.

Por que existe: es_mi_cpe() -> mis_redes() -> conf() ABRIA el archivo en cada llamada, y
es_mi_cpe se llama dentro del bucle de casi todo (el recolector del informe lo llama por
CADA evento de log). Medido: 64 us por llamada; con la cache, 2 us.

Lo que se protege aqui no es la velocidad, es lo que la cache puede romper:
  - que un cambio en el .conf se note (si no, cambias MIS_REDES y el panel sigue con las
    de antes, sin decir nada: el fallo mudo mas caro que puede tener esto);
  - que dos escrituras dentro del mismo tick del reloj no pasen por la misma (por eso el
    sello lleva el tamano y no solo el mtime);
  - que quien recibe el dict de conf() pueda meterle claves suyas sin envenenar la cache;
  - y que la lista de redes no se pueda modificar por error, porque se comparte.
"""
import ast
import io
import ipaddress
import os
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_SELLO_VISTO", "_SELLO_CADA", "_sello", "_CONF_CACHE", "_REDES_CACHE",
          "conf", "mis_redes", "es_mi_cpe")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"os": os, "time": time, "ipaddress": ipaddress}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["CONF"] = os.path.join(tmp, "dash.conf")
    # sin freno, para no dormir un segundo en cada comprobacion; el freno se comprueba
    # aparte, como valor
    ns["_SELLO_CADA"] = 0
    return ns


def escribir(ruta, texto):
    io.open(ruta, "w", encoding="utf-8", newline="\n").write(texto)


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    CONF = ns["CONF"]

    escribir(CONF, "PASS=x\nMIS_REDES=192.168.0.0/19\n")
    check("lee la configuracion", ns["conf"]().get("MIS_REDES") == "192.168.0.0/19",
          ns["conf"]())
    check("y la IP de esa red es un CPE tuyo", ns["es_mi_cpe"]("192.168.5.5") is True)
    check("una de fuera, no", ns["es_mi_cpe"]("8.8.8.8") is False)

    # --- lo que la cache NO puede hacer: quedarse con lo viejo -------------------------
    escribir(CONF, "PASS=x\nMIS_REDES=10.9.0.0/16\n")
    check("al cambiar el .conf, conf() devuelve lo nuevo",
          ns["conf"]().get("MIS_REDES") == "10.9.0.0/16", ns["conf"]())
    check("y mis_redes() tambien",
          [str(r) for r in ns["mis_redes"]()] == ["10.9.0.0/16"],
          [str(r) for r in ns["mis_redes"]()])
    check("la red vieja deja de ser tuya", ns["es_mi_cpe"]("192.168.5.5") is False)
    check("y la nueva pasa a serlo", ns["es_mi_cpe"]("10.9.1.1") is True)

    # --- mismo tick del reloj, distinto contenido --------------------------------------
    # Si el sello fuese solo el mtime, dos escrituras seguidas dentro de la resolucion del
    # reloj darian por bueno el valor viejo. Por eso lleva tambien el tamaño.
    escribir(CONF, "MIS_REDES=172.20.0.0/14\n")
    a = ns["_sello"](CONF)
    escribir(CONF, "MIS_REDES=172.20.0.0/14,10.1.0.0/16\n")
    b = ns["_sello"](CONF)
    check("dos versiones distintas nunca comparten sello", a != b, (a, b))
    check("y el cambio se ve", len(ns["mis_redes"]()) == 2,
          [str(r) for r in ns["mis_redes"]()])

    # --- lo que devuelve no puede envenenar la cache ------------------------------------
    d = ns["conf"]()
    d["MIS_REDES"] = "1.2.3.0/24"
    d["INVENTADO"] = "si"
    check("quien recibe conf() puede tocar su copia sin afectar a la siguiente",
          ns["conf"]().get("MIS_REDES") == "172.20.0.0/14,10.1.0.0/16",
          ns["conf"]().get("MIS_REDES"))
    check("y sin dejar claves de su cosecha", "INVENTADO" not in ns["conf"](), "")
    check("la lista de redes se comparte, asi que es inmutable",
          isinstance(ns["mis_redes"](), tuple), type(ns["mis_redes"]()))

    # --- el archivo que no esta ---------------------------------------------------------
    os.unlink(CONF)
    check("sin archivo se vuelve a los valores por defecto",
          ns["conf"]().get("PORT") == "5637", ns["conf"]())
    check("y las redes por defecto son las privadas",
          len(ns["mis_redes"]()) == 4, [str(r) for r in ns["mis_redes"]()])
    escribir(CONF, "MIS_REDES=192.0.2.0/24\n")
    check("y si vuelve a aparecer, se lee",
          [str(r) for r in ns["mis_redes"]()] == ["192.0.2.0/24"],
          [str(r) for r in ns["mis_redes"]()])

    # --- el freno del stat ---------------------------------------------------------------
    # el valor REAL, no el que esta prueba pone a 0 para no dormir
    _real = {}
    for n in ARBOL.body:
        if (isinstance(n, ast.Assign) and n.targets
                and getattr(n.targets[0], "id", "") == "_SELLO_CADA"):
            exec(ast.get_source_segment(DASH, n), _real)
    check("no se pregunta al disco mas de una vez por segundo",
          0 < _real.get("_SELLO_CADA", 0) <= 2, _real.get("_SELLO_CADA"))

    # --- una sola version viva ------------------------------------------------------------
    # Si la cache creciera con cada version del archivo, un panel de meses acabaria
    # guardando cientos de configuraciones muertas.
    ns3 = entorno(tmp)
    for i in range(12):
        escribir(ns3["CONF"], "MIS_REDES=10.%d.0.0/16\n" % i)
        ns3["conf"]()
        ns3["mis_redes"]()
    check("la cache de conf no acumula versiones", len(ns3["_CONF_CACHE"]) == 1,
          len(ns3["_CONF_CACHE"]))
    check("ni la de redes", len(ns3["_REDES_CACHE"]) == 1, len(ns3["_REDES_CACHE"]))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
