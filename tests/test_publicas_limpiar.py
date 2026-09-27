# -*- coding: utf-8 -*-
"""Vaciar de una vez las publicas declaradas de un nodo.

"Detectar del MikroTik" puede dejar veinte entradas de golpe, y quitarlas con la x de cada
chip son veinte recargas de pagina.

Lo que se protege:
  - que solo vacie el nodo que se pide, no los demas;
  - que NO borre el historial de listas negras ya medido: eso no se puede reconstruir, y
    si se vuelve a declarar la misma red tiene que seguir ahi;
  - que quede constancia en la bitacora de cuantas se quitaron;
  - y que sea de administrador, porque deja al panel sin nada que vigilar.
"""
import ast
import io
import json
import os
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("PUBLICAS_CONF", "cargar_publicas", "guardar_publicas",
          "guardar_publicas_de", "publicas_texto")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"os": os, "json": json, "re": __import__("re"),
          "ipaddress": __import__("ipaddress"),
          # la validacion de IP/red tiene su propia prueba; aqui solo estorba
          "aidb_ip_valida": lambda x: True,
          "aidb_red_valida": lambda x: (x, "")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["PUBLICAS_CONF"] = os.path.join(tmp, "publicas.json")
    json.dump({"nodos": {"r1": ["203.0.113.0/28", "203.0.113.5", "203.0.113.6"],
                         "r2": ["198.51.100.0/24"]}},
              open(ns["PUBLICAS_CONF"], "w", encoding="utf-8"))
    return ns


def ruta_limpiar():
    """El cuerpo de la ruta, tal cual esta en el manejador POST."""
    for n in ast.walk(ARBOL):
        if not isinstance(n, ast.If):
            continue
        seg = ast.get_source_segment(DASH, n) or ""
        if seg.startswith('if ruta == "/publicas/limpiar"'):
            return seg
    return ""


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    # --- vaciar uno no toca el otro ------------------------------------------------------
    ns["guardar_publicas_de"]("r1", "")
    d = ns["cargar_publicas"]()
    check("el nodo pedido queda vacio", d.get("r1", []) == [], d.get("r1"))
    check("y el otro nodo no se toca", d.get("r2") == ["198.51.100.0/24"], d.get("r2"))

    # --- se puede volver a declarar --------------------------------------------------------
    ns["guardar_publicas_de"]("r1", "203.0.113.0/28")
    check("y se puede volver a declarar despues",
          ns["cargar_publicas"]().get("r1") == ["203.0.113.0/28"], "")

    # --- lo que la ruta hace y lo que NO --------------------------------------------------
    r = ruta_limpiar()
    check("la ruta existe", bool(r), "")
    check("es solo de administrador: deja al panel sin nada que vigilar",
          "self._admin()" in r, r[:200])
    check("vacia el nodo que se pide", 'guardar_publicas_de(rid, "")' in r, "")
    check("deja constancia en la bitacora", "bitacora(" in r, "")
    check("y dice cuantas eran, que es lo que no se puede deshacer",
          "_cuantas" in r, "")
    # El historial de listas negras y las mediciones no se pueden reconstruir: si se
    # borraran al limpiar, volver a declarar la red empezaria de cero y se perderia la
    # prueba de cuanto tardo en salir de cada lista.
    check("NO toca el historial de listas negras",
          "DNSBL_HIST" not in r and "_dnsbl" not in r, r[:300])
    check("ni el historial de reputacion",
          "PUB_HIST" not in r and "_pub_hist" not in r, "")

    # --- el boton -----------------------------------------------------------------------------
    check("el boton pide confirmacion antes de borrar",
          "confirm('Quitar las" in DASH, "")
    check("y avisa de que el historial no se pierde",
          "historial de listas" in DASH.split("confirm('Quitar las", 1)[-1][:200], "")
    check("se ve que es destructivo", "class=delbtn" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
