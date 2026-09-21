# -*- coding: utf-8 -*-
"""Identidad (router, IP): dos nodos con el MISMO rango no se confunden.

Es el motivo de todo el multi-nodo. Con 3 MikroTik usando 10.0.0.x cada uno,
"10.0.0.5" no identifica a nadie: hay tres clientes distintos. Si se mezclaran,
se sumarian sus alertas, se culparia al abonado equivocado y el bloqueo podria
acabar en el router que no es.
"""
import ast
import json
import os
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
REP = SRC[_i:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
ARBOL = ast.parse(REP)

PIEZAS = ("ROUTERS_MAP", "_IFACE_ROUTER", "_ROUTER_NOMBRE", "MULTI_ROUTER",
          "router_de", "nombre_router", "clave_cpe", "ip_de", "rid_de")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def cargar(mapa):
    """Monta las funciones de identidad con el mapa de routers dado."""
    tmp = tempfile.mkdtemp()
    ruta = os.path.join(tmp, "routers-map.json")
    if mapa is not None:
        json.dump(mapa, open(ruta, "w", encoding="utf-8"))
    ns = {"json": json, "ROUTERS_MAP": ruta}
    for n in ARBOL.body:
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in PIEZAS or (isinstance(n, ast.Try) and "_IFACE_ROUTER" in (ast.get_source_segment(REP, n) or "")):
            seg = ast.get_source_segment(REP, n) or ""
            if "ROUTERS_MAP = " in seg:      # no pisar la ruta temporal
                continue
            exec(seg, ns)
    return ns


def main():
    # --- tres nodos, como el caso del cliente ---
    ns = cargar([{"id": "r1", "nombre": "Nodo Centro", "iface": "ids-mon"},
                 {"id": "r2", "nombre": "Nodo Norte", "iface": "ids-mon2"},
                 {"id": "r3", "nombre": "Nodo Sur", "iface": "ids-mon3"}])

    check("reconoce que hay varios MikroTik", ns["MULTI_ROUTER"] is True)
    check("resuelve el nodo por la interfaz del espejo",
          [ns["router_de"](i) for i in ("ids-mon", "ids-mon2", "ids-mon3")] == ["r1", "r2", "r3"])
    check("una interfaz desconocida no inventa nodo", ns["router_de"]("eth0") == "")
    check("muestra el nombre legible del nodo", ns["nombre_router"]("r2") == "Nodo Norte")

    # --- EL caso: la misma IP en dos nodos distintos ---
    a = ns["clave_cpe"]("10.0.0.5", ns["router_de"]("ids-mon"))
    b = ns["clave_cpe"]("10.0.0.5", ns["router_de"]("ids-mon2"))
    check("la MISMA IP en dos nodos son dos clientes distintos", a != b, (a, b))
    check("y de cada uno se recupera su IP para bloquear",
          (ns["ip_de"](a), ns["ip_de"](b)) == ("10.0.0.5", "10.0.0.5"), (a, b))
    check("y a que router hay que mandar cada bloqueo",
          (ns["rid_de"](a), ns["rid_de"](b)) == ("r1", "r2"), (a, b))

    # si se usaran como claves de un contador, no se sumarian entre si
    cont = {}
    for k in (a, a, b):
        cont[k] = cont.get(k, 0) + 1
    check("sus alertas NO se suman entre nodos", sorted(cont.values()) == [1, 2], cont)

    # --- una caja con un solo MikroTik: todo como siempre ---
    uno = cargar([{"id": "r1", "nombre": "MikroTik", "iface": "ids-mon"}])
    check("con un solo nodo no se compone nada", uno["MULTI_ROUTER"] is False)
    k = uno["clave_cpe"]("10.0.0.5", uno["router_de"]("ids-mon"))
    check("la identidad sigue siendo la IP pelada", k == "10.0.0.5", k)
    check("y ip_de la devuelve igual", uno["ip_de"](k) == "10.0.0.5")
    check("sin nodo que mostrar", uno["rid_de"](k) == "")

    # --- sin mapa publicado (instalacion que aun no lo escribio) ---
    sin = cargar(None)
    check("sin mapa no revienta y asume un solo nodo", sin["MULTI_ROUTER"] is False)
    check("y la identidad sigue siendo la IP",
          sin["clave_cpe"]("10.0.0.5", sin["router_de"]("ids-mon")) == "10.0.0.5")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
