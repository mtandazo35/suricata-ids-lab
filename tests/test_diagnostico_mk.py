# -*- coding: utf-8 -*-
"""Diagnostico del MikroTik: que le falta para poder cortar.

Con un espejo TZSP, Suricata NUNCA bloquea: ve una copia y el paquete ya paso. El que
corta es el router, asi que lo que importa es si el router esta en condiciones. Lo que
se protege aqui es que el diagnostico no mienta: el fallo mas caro es decir "todo bien"
cuando la address-list no la usa ninguna regla, porque entonces el panel dice "enviado"
y el abonado sigue atacando.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_mk_print", "mk_diagnostico")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tablas):
    """mk_diagnostico contra un router de mentira que devuelve las tablas dadas."""
    ns = {"cargar_mk_de": lambda r: {"LIST": "suricata-cuarentena",
                                     "LIST_GRAD": "suricata-graduada"},
          "cargar_mk": lambda: {"LIST": "suricata-cuarentena",
                                "LIST_GRAD": "suricata-graduada"},
          "mk_conectar": lambda d: type("S", (), {"close": lambda self: None})(),
          "_mk_send": lambda s, w: None,
          "_mk_reply": lambda s: (True, [], "")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None)
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["_mk_print"] = lambda s_, cmd, props: tablas.get(cmd, [])
    return ns


def estados(checks):
    return {t: e for e, t, _d, _f in checks}


def main():
    # --- router recien montado: le falta todo ---
    ns = entorno({})
    c = ns["mk_diagnostico"]()
    txt = " | ".join(t for _e, t, _d, _f in c)
    check("sin espejo se dice lo primero de todo",
          any(e == "falta" and "espejo" in t for e, t, _d, _f in c), txt)
    check("y se avisa de que la lista de cuarentena no corta nada",
          any(e == "falta" and "cuarentena NO corta" in t for e, t, _d, _f in c), txt)
    fix = [f for _e, t, _d, f in c if "cuarentena NO corta" in t][0]
    check("con la regla exacta para arreglarlo",
          "src-address-list=suricata-cuarentena" in fix and "action=drop" in fix, fix)
    check("se avisa del origen falsificado", any("falsificada" in t for _e, t, _d, _f in c), txt)
    check("y de que el router no detecta escaneos",
          any("no detecta escaneos" in t for _e, t, _d, _f in c), txt)

    # --- router bien montado ---
    ns2 = entorno({
        "/tool/sniffer/print": [{"running": "true", "streaming-enabled": "true",
                                 "streaming-server": "10.0.0.9:37008",
                                 "filter-interface": "bridge1"}],
        "/ip/firewall/filter/print": [
            {"chain": "forward", "action": "drop", "src-address-list": "suricata-cuarentena"},
            {"chain": "forward", "action": "drop", "src-address-list": "suricata-graduada"},
            {"chain": "forward", "action": "add-src-to-address-list", "psd": "21,3s,3,1"},
            {"chain": "forward", "action": "drop", "connection-limit": "200,32"},
        ],
        "/ip/firewall/raw/print": [{"action": "drop", "src-address-list": "suricata-cuarentena"}],
        "/ip/settings/print": [{"rp-filter": "strict"}],
    })
    c2 = ns2["mk_diagnostico"]()
    check("un router bien montado no tiene ningun 'falta'",
          not [t for e, t, _d, _f in c2 if e == "falta"],
          [t for e, t, _d, _f in c2 if e == "falta"])
    check("se reconoce el espejo activo", any("espejo esta activo" in t for _e, t, _d, _f in c2))
    check("y que detecta escaneos por si solo",
          any("detecta escaneos por si solo" in t for _e, t, _d, _f in c2))

    # --- el fallo mas caro: la regla EXISTE pero esta desactivada ---
    ns3 = entorno({
        "/ip/firewall/filter/print": [
            {"chain": "forward", "action": "drop",
             "src-address-list": "suricata-cuarentena", "disabled": "true"},
        ],
    })
    c3 = ns3["mk_diagnostico"]()
    check("una regla DESACTIVADA no cuenta como que corta",
          any(e == "falta" and "cuarentena NO corta" in t for e, t, _d, _f in c3),
          [t for e, t, _d, _f in c3 if "cuarentena" in t])

    # --- cortar en raw tambien vale ---
    ns4 = entorno({
        "/ip/firewall/raw/print": [{"action": "drop", "src-address-list": "suricata-cuarentena"}],
    })
    c4 = ns4["mk_diagnostico"]()
    check("cortar en raw cuenta igual que en filter",
          not any("cuarentena NO corta" in t for _e, t, _d, _f in c4),
          [t for e, t, _d, _f in c4 if "cuarentena" in t])

    # --- rp-filter a medias ---
    ns5 = entorno({"/ip/settings/print": [{"rp-filter": "loose"}]})
    c5 = ns5["mk_diagnostico"]()
    check("'loose' no se da por bueno", any("falsificada" in t for _e, t, _d, _f in c5))
    det = [d for _e, t, d, _f in c5 if "falsificada" in t][0]
    check("y se avisa de que 'strict' rompe con rutas asimetricas",
          "asimetric" in det.lower(), det[:120])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
