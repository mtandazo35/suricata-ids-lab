# -*- coding: utf-8 -*-
"""La tabla de listas por categoria: no solo cuantos, tambien QUIENES.

Lo que se protege:
  - cpes_por_lista agrupa el registro de enviados por la lista REAL con la que se mando
    cada uno (no por la que le tocaria hoy), con ip/router/cuando/por/categoria, mas
    reciente primero; una entrada sin lista (anterior al enrutado) no se inventa una;
  - la seccion pinta un desplegable por fila con las IPs, el abonado, desde cuando y
    quien lo mando, y cada IP abre su ficha por IP (es lo que ficha_page busca);
  - una categoria vacia no tiene desplegable;
  - un nombre de abonado con angulos no rompe el HTML.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_d = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_d:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(nombres, extra=None):
    ns = {"time": __import__("time"), "html": __import__("html")}
    ns.update(extra or {})
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


ENV = {
    "r1|10.0.0.7": {"lista": "clientes-botnet", "cuando": 1700000000, "por": "politica", "router": "r1", "categoria": "botnet"},
    "r1|10.0.0.8": {"lista": "clientes-botnet", "cuando": 1700003600, "por": "admin", "router": "r1", "categoria": "botnet"},
    "r2|10.0.0.9": {"lista": "clientes-p2p", "cuando": 1700000100, "por": "politica-rapida", "router": "r2", "categoria": "p2p"},
    "r1|10.0.0.10": {"cuando": 1600000000, "por": "admin"},     # anterior al enrutado: sin lista
}


def main():
    ns = piezas(("cpes_por_lista",), {
        "cargar_enviados": lambda p: dict(ENV), "MK_SENT": "SENT",
        "ip_de": lambda k: k.split("|")[-1], "rid_de": lambda k: k.split("|")[0] if "|" in k else ""})
    d = ns["cpes_por_lista"]()
    check("agrupa por la lista con la que se mando", set(d) == {"clientes-botnet", "clientes-p2p"}, set(d))
    check("mas reciente primero", [e["ip"] for e in d["clientes-botnet"]] == ["10.0.0.8", "10.0.0.7"], d["clientes-botnet"])
    check("lleva clave, ip, router, cuando, por y categoria",
          d["clientes-p2p"][0] == {"clave": "r2|10.0.0.9", "ip": "10.0.0.9", "router": "r2", "cuando": 1700000100,
                                   "por": "politica-rapida", "categoria": "p2p"}, d["clientes-p2p"][0])
    check("la entrada sin lista no se inventa una", not any(e["ip"] == "10.0.0.10" for l in d.values() for e in l), "")

    # --- la seccion ---------------------------------------------------------------------
    sec = DASH[DASH.index("    def _sec_listas():"):]
    sec = sec[:sec.index("    sec_listas = _sec_listas()")]
    import textwrap
    codigo = textwrap.dedent(sec)
    ns2 = {"time": __import__("time"), "esc": __import__("html").escape,
           "cpes_por_lista": ns["cpes_por_lista"],
           "accion_de_clase": lambda c, m=None: "cortar" if c == "botnet" else "nada",
           "ACCIONES": {"cortar": "Cortar todo", "nada": "Nada"},
           "cargar_abonados": lambda: {"mapa": {"r1|10.0.0.7": {"nombre": "Juan <Perez>"}}},
           "cargar_routers": lambda: [{"id": "r1"}, {"id": "r2"}],
           "abonado_de": lambda ip, rid="", mapa=None: (mapa or {}).get("%s|%s" % (rid, ip), {}),
           "listas_en_uso": lambda: [("botnet", "Botnet / CnC", "clientes-botnet", 2),
                                     ("p2p", "P2P", "clientes-p2p", 1),
                                     ("spam", "Spam", "clientes-spam", 0)],
           "listas_cpe_reglas": lambda: "reglas"}
    exec(codigo, ns2)
    h = ns2["_sec_listas"]()
    check("la fila con CPEs tiene desplegable con el numero de IPs",
          "<details class=ldet" in h and "ver las 2 IPs" in h and "ver las 1 IPs" in h, "")
    check("la categoria vacia no tiene desplegable",
          "Spam" in h and h.count("<details class=ldet") == 2, h.count("<details class=ldet"))
    # la ficha (ficha_page) busca por IP, como el boton 'ver evidencia' de la tabla
    check("cada IP abre su ficha por IP, igual que el resto del panel",
          "verFicha('10.0.0.8')" in h and "verFicha('10.0.0.9')" in h and "verFicha('r1|" not in h, "")
    check("se ve el abonado, escapado", "Juan &lt;Perez&gt;" in h and "Juan <Perez>" not in h, "")
    check("y quien lo mando", "a mano (admin)" in h and h.count(">politica<") == 2, h.count(">politica<"))
    check("con varios routers se dice el nodo", "&middot; r2</span>" in h, "")
    check("el total sigue sumando", "<b>3 CPE enviados</b>" in h, "")
    check("la tabla dice la accion configurada por clase", "Accion en el router" in h and "Cortar todo" in h
          and "sin accion" in h, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
