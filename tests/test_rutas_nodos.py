# -*- coding: utf-8 -*-
"""Alta, edicion y baja de nodos (varios MikroTik) desde Ajustes."""
import ast
import json
import os
import sys
import tempfile
import textwrap

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_router_vacio", "_mk_globales", "cargar_routers", "guardar_routers",
          "router_por_id", "router_defecto", "publicar_routers_map", "CAMPOS_ROUTER",
          "IFACE_BASE")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def cuerpo_ruta(ruta):
    for n in ast.walk(ARBOL):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and getattr(n.test.left, "id", "") == "ruta" and n.test.comparators
                and getattr(n.test.comparators[0], "value", "") == ruta):
            ls = DASH.split("\n")[n.body[0].lineno - 1:n.body[-1].end_lineno]
            return textwrap.dedent("\n".join(ls))
    raise SystemExit("no se encontro la ruta " + ruta)


def entorno(tmp):
    ns = {"json": json, "os": os, "html": __import__("html"),
          "MK_CONF": os.path.join(tmp, "mikrotik.conf"),
          "ROUTERS_CONF": os.path.join(tmp, "routers.json"),
          "ROUTERS_MAP": os.path.join(tmp, "map.json")}
    for n in ARBOL.body:
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["MK_CONF"] = os.path.join(tmp, "mikrotik.conf")
    ns["ROUTERS_CONF"] = os.path.join(tmp, "routers.json")
    ns["ROUTERS_MAP"] = os.path.join(tmp, "map.json")
    return ns


def llamar(ns, ruta, campos, admin=True):
    """Ejecuta el cuerpo de la ruta y devuelve el mensaje que se le muestra al usuario."""
    visto = {}
    class Self:
        def _admin(self): return admin
        def _deny(self): return ("DENY", 403)
        def _html(self, x, code=200): return x
    ns2 = dict(ns)
    ns2.update({"self": Self(), "q": {k: [v] for k, v in campos.items()},
                "perfil_page": lambda m="", ok=False, **kw: visto.update({"msg": m, "ok": ok}) or m,
                "bitacora": lambda *a, **k: None})
    exec(compile("def _f():\n" + textwrap.indent(cuerpo_ruta(ruta), "    "), "<r>", "exec"), ns2)
    ns2["_f"]()
    return visto


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    open(ns["MK_CONF"], "w", encoding="utf-8").write("HOST=10.0.0.1\nUSER=a\nPASS=b\nENABLED=1\n")

    # --- alta de un segundo nodo ---
    v = llamar(ns, "/routers/guardar", {"rid": "", "nombre": "Nodo Norte", "host": "10.9.9.1",
                                        "user": "sur", "pass": "clave2", "enabled": "on"})
    rs = ns["cargar_routers"]()
    check("se da de alta el segundo nodo", len(rs) == 2, rs)
    check("con su nombre, IP y clave",
          (rs[1]["nombre"], rs[1]["HOST"], rs[1]["PASS"]) == ("Nodo Norte", "10.9.9.1", "clave2"), rs[1])
    check("y su propia interfaz de espejo", rs[1]["iface"] == "ids-mon2", rs[1])
    check("el aviso recuerda que hay que capturar su espejo",
          "-m" in v.get("msg", ""), v)

    # --- editar sin reescribir la clave ---
    llamar(ns, "/routers/guardar", {"rid": "r2", "nombre": "Norte", "host": "10.9.9.2",
                                    "user": "sur", "pass": "", "enabled": "on"})
    rs = ns["cargar_routers"]()
    check("editar sin poner clave la conserva", rs[1]["PASS"] == "clave2", rs[1])
    check("y actualiza lo demas", (rs[1]["nombre"], rs[1]["HOST"]) == ("Norte", "10.9.9.2"), rs[1])
    check("no se duplico el nodo", len(rs) == 2, rs)

    # --- un nodo sin IP no sirve de nada ---
    v = llamar(ns, "/routers/guardar", {"rid": "", "nombre": "Vacio", "host": ""})
    check("un nodo sin IP se rechaza", "Falta la IP" in v.get("msg", ""), v)
    check("y no se agrega", len(ns["cargar_routers"]()) == 2, ns["cargar_routers"]())

    # --- baja ---
    v = llamar(ns, "/routers/quitar", {"rid": "r2"})
    check("se puede quitar un nodo", len(ns["cargar_routers"]()) == 1, ns["cargar_routers"]())
    check("y se avisa que sus CPEs siguen bloqueados en ese router",
          "siguen bloqueados" in v.get("msg", ""), v)

    v = llamar(ns, "/routers/quitar", {"rid": "r1"})
    check("NO se puede quitar el unico nodo", "unico nodo" in v.get("msg", ""), v)
    check("y sigue estando", len(ns["cargar_routers"]()) == 1)

    # --- permisos ---
    r = llamar(ns, "/routers/guardar", {"rid": "", "host": "1.2.3.4"}, admin=False)
    check("un no-admin no puede tocar los nodos", r == {}, r)
    check("y no se agrego nada", len(ns["cargar_routers"]()) == 1)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
