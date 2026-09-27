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
          "cubrir_publicas", "guardar_publicas_de", "publicas_texto")

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
          "aidb_ip_valida": lambda x: (True, ""),
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

    # --- lo que ya queda cubierto sobra ------------------------------------------------
    # Cada entrada declarada gasta UNA consulta de AbuseIPDB en cada revision, y
    # "Detectar del MikroTik" saca a la vez la direccion de la interfaz y su red: un /28
    # acababa acompanado de sus hosts y de media docena de subredes. Veinte consultas para
    # ver lo que una de red ya trae. Consultar la red no pierde nada: la respuesta incluye
    # cada direccion denunciada de dentro, que es justo lo que se pinta desplegado.
    cubrir = ns["cubrir_publicas"]

    quedan, sobran = cubrir(["203.0.113.0/28", "203.0.113.5", "203.0.113.6/31"])
    check("un host dentro de un rango declarado sobra",
          quedan == ["203.0.113.0/28"], (quedan, sobran))
    check("y se dice cuales se quitaron, no se tiran en silencio",
          sorted(sobran) == ["203.0.113.5", "203.0.113.6/31"], sobran)

    quedan, _s = cubrir(["203.0.113.0/24", "203.0.113.0/28"])
    check("entre dos redes se queda la que cubre", quedan == ["203.0.113.0/24"], quedan)

    quedan, sobran = cubrir(["203.0.113.0/28", "198.51.100.0/24"])
    check("dos rangos que no se tocan se quedan los dos", len(quedan) == 2, quedan)
    check("y no sobra ninguno", sobran == [], sobran)

    check("una sola entrada no se quita a si misma",
          cubrir(["203.0.113.0/28"])[0] == ["203.0.113.0/28"], "")
    check("dos iguales dejan una",
          len(cubrir(["203.0.113.7", "203.0.113.7"])[0]) == 1, "")

    # Lo que no se sabe leer no se toca: tirarlo en silencio seria perder una entrada que
    # alguien escribio a proposito.
    quedan, _s = cubrir(["203.0.113.0/28", "esto-no-es-una-ip"])
    check("lo que no se puede interpretar se conserva",
          "esto-no-es-una-ip" in quedan, quedan)

    # --- y al guardar, lo mismo -----------------------------------------------------------
    ok, mal, tap = ns["guardar_publicas_de"]("r3", "203.0.113.0/28 203.0.113.5")
    check("guardar tambien descarta lo cubierto", ok == ["203.0.113.0/28"], ok)
    check("y lo devuelve aparte de lo rechazado, que es otra cosa",
          tap == ["203.0.113.5"] and mal == [], (tap, mal))


    # --- quitar las marcadas, no todas -------------------------------------------------
    # "Limpiar todas" resulto demasiado romo: una deteccion mala metio trece entradas
    # basura y al limpiarlas se llevo por delante la unica buena, que era la que tenia
    # historial de listas negras detras.
    def ruta(nombre):
        for n in ast.walk(ARBOL):
            if isinstance(n, ast.If):
                seg = ast.get_source_segment(DASH, n) or ""
                if seg.startswith('if ruta == "%s"' % nombre):
                    return seg
        return ""

    rv = ruta("/publicas/quitar-varias")
    check("existe la ruta de quitar varias", bool(rv), "")
    check("es de administrador", "self._admin()" in rv, "")
    check("quita SOLO las marcadas, no la lista entera",
          "e not in fuera" in rv, rv[:300])
    check("si no marcas nada, no borra nada", "No marcaste ninguna" in rv, "")
    check("y avisa de que el historial se conserva",
          "historial de listas negras se conserva" in rv, "")

    # La x de un chip manda 'solo'. Va aparte de 'entrada' porque los chips son casillas
    # con ESE nombre: al pulsar la x el navegador envia tambien todas las marcadas, y sin
    # distinguirlo quitar una se llevaria las demas por delante.
    ru = ruta("/publicas/quitar")
    check("la x de un chip usa su propio campo", '"solo"' in ru, ru[:200])
    check("y se lee antes que las marcadas", ru.index('"solo"') < ru.index('"entrada"'), "")


    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
