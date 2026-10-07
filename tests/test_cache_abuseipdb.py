# -*- coding: utf-8 -*-
"""La cache de AbuseIPDB se parsea una vez, pero sin servir datos viejos.

De donde sale: con la cache llena (20.000 entradas, 2,9 MB) cada json.load cuesta 22 ms, y
se hacia uno POR CONSULTA. El precargador recorre todos los destinos de todos los
candidatos cada 5 minutos: con 200 destinos son 4,4 s de CPU con el GIL cogido. El panel
vive en el mismo proceso, asi que durante ese rato cambiar de pagina se queda colgado — y
empeora segun se llena la cache.

El riesgo de arreglarlo es el clasico de toda cache: **servir algo viejo**. Y aqui lo
viejo no es cosmetico, porque de esta cache sale la reputacion con la que se decide si un
destino es malicioso. Por eso lo que se prueba no es que sea rapido, sino que:

  - si el archivo cambia, se vuelve a leer (nunca se sirve lo anterior);
  - si lo escribe este mismo proceso, lo que queda en memoria es lo que se escribio;
  - si el archivo esta roto o desaparece, se devuelve vacio sin reventar y sin dejar
    pegada la version anterior como si fuera buena.
"""
import ast
import json
import os
import sys
import tempfile
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_AIDB_MEM", "_aidb_sello", "_aidb_cache", "_aidb_guardar_cache")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(ruta):
    """El modulo con un contador de cuantas veces se parsea de verdad el archivo."""
    cuenta = {"n": 0}
    _real = json.load

    def _load(f, **k):
        cuenta["n"] += 1
        return _real(f, **k)

    json_falso = type("J", (), {"load": staticmethod(_load),
                                "dump": staticmethod(json.dump)})
    ns = {"json": json_falso, "os": os, "threading": threading, "AIDB_CACHE": ruta}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["_cuenta"] = cuenta
    return ns


def escribir(ruta, d):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(d, f)


def main():
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "abuseipdb.json")

    # =====================================================================================
    # Se parsea una vez, no una por consulta
    # =====================================================================================
    escribir(p, {"198.51.100.7": {"score": 90, "ts": 1000}})
    ns = entorno(p)
    for _ in range(50):
        ns["_aidb_cache"]()
    check("cincuenta consultas, un solo parseo", ns["_cuenta"]["n"] == 1, ns["_cuenta"])
    check("y los datos son los correctos",
          ns["_aidb_cache"]()["198.51.100.7"]["score"] == 90, "")

    # =====================================================================================
    # LO IMPORTANTE: si el archivo cambia, no se sirve lo viejo
    # =====================================================================================
    # De esta cache sale la reputacion con la que se decide si un destino es malicioso.
    # Servir una version anterior no es un detalle de rendimiento.
    time.sleep(0.01)
    escribir(p, {"198.51.100.7": {"score": 0, "ts": 2000}})
    d = ns["_aidb_cache"]()
    check("si otro proceso reescribe el archivo, se vuelve a leer",
          d["198.51.100.7"]["score"] == 0, d)
    check("y el parseo nuevo se hizo de verdad", ns["_cuenta"]["n"] == 2, ns["_cuenta"])

    # el mismo contenido pero con otro tamaño tambien tiene que detectarse
    time.sleep(0.01)
    escribir(p, {"198.51.100.7": {"score": 0, "ts": 2000},
                 "203.0.113.9": {"score": 44, "ts": 2001}})
    check("una entrada nueva se ve en la siguiente consulta",
          "203.0.113.9" in ns["_aidb_cache"](), ns["_aidb_cache"]().keys())

    # =====================================================================================
    # Guardar desde este proceso: lo escrito es lo que queda en memoria
    # =====================================================================================
    antes = ns["_cuenta"]["n"]
    nuevo = {"192.0.2.1": {"score": 7, "ts": 3000}}
    ns["_aidb_guardar_cache"](nuevo)
    d = ns["_aidb_cache"]()
    check("tras guardar, se devuelve lo que se acaba de escribir",
          d == nuevo, d)
    check("sin volver a parsear el archivo que uno mismo escribio",
          ns["_cuenta"]["n"] == antes, (antes, ns["_cuenta"]["n"]))
    check("y en disco esta lo mismo",
          json.load(open(p, encoding="utf-8")) == nuevo, "")

    # =====================================================================================
    # Lo que no puede pasar: quedarse pegado a una version buena cuando ya no hay archivo
    # =====================================================================================
    os.remove(p)
    check("sin archivo se devuelve vacio, no la copia anterior",
          ns["_aidb_cache"]() == {}, ns["_aidb_cache"]())

    escribir(p, {"x": 1})
    with open(p, "w", encoding="utf-8") as f:
        f.write("{roto")
    check("con el archivo roto tampoco se sirve lo de antes",
          ns["_aidb_cache"]() == {}, ns["_aidb_cache"]())

    # y una vez arreglado, se recupera solo
    time.sleep(0.01)
    escribir(p, {"198.51.100.8": {"score": 1, "ts": 4000}})
    check("y cuando el archivo vuelve a estar bien, se lee otra vez",
          "198.51.100.8" in ns["_aidb_cache"](), "")

    # un archivo que no es un diccionario no puede colarse como cache
    time.sleep(0.01)
    escribir(p, ["no", "soy", "un", "diccionario"])
    check("una lista donde deberia haber un diccionario se descarta",
          ns["_aidb_cache"]() == {}, ns["_aidb_cache"]())

    # =====================================================================================
    # Lo que la cadena de llamadas promete
    # =====================================================================================
    check("el precargador pide no guardar en cada IP",
          "aidb_consultar(ip, auto=True, guardar=False)" in DASH, "")
    check("y guarda una sola vez al final del ciclo",
          "if hechas:" in DASH and "_aidb_guardar_cache(_aidb_cache())" in DASH, "")
    check("y se salta lo que ya esta fresco antes de entrar a consultar",
          "pend.append(ip)" in DASH, "")
    # la bitacora leia el archivo entero para quedarse con 1500 lineas
    check("la bitacora lee solo la cola",
          "_cola_lineas(BITACORA_LOG" in DASH and "f.readlines()[-1500:]" not in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
