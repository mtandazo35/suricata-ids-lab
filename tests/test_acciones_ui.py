# -*- coding: utf-8 -*-
"""Acciones por categoria: la UI de Ajustes y las rutas que hablan con el router.

Lo que se protege:
  - la tarjeta trae, por categoria, la lista, el select de accion con la accion guardada
    marcada, el bloque de reglas propias (visible solo con 'propias' y con lo guardado
    dentro), el limite solo en P2P/minado y el resolutor solo en DNS; los botones de ver/
    aplicar/quitar; con varios routers, el selector de router;
  - la ruta de guardado acepta solo acciones de la clase, valida el limite y el resolutor,
    y guarda las reglas propias (si no parsean, lo dice y no las guarda);
  - las rutas plan/aplicar/quitar exigen admin, rechazan una clase desconocida y un router
    sin conexion, eligen el router por id, responden "OK cabecera\\nrsc" y dejan bitacora;
  - nada en la tarjeta o el modal usa dialogos nativos.
"""
import ast
import os
import re
import sys
import tempfile
import textwrap

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
    ns = {"html": __import__("html"), "re": re, "os": os}
    ns.update(extra or {})
    for n in ARBOL.body:
        noms = set()
        if getattr(n, "name", None):
            noms.add(n.name)
        elif isinstance(n, ast.Assign):
            for tg in n.targets:
                for el in (tg.elts if isinstance(tg, ast.Tuple) else [tg]):
                    if isinstance(el, ast.Name):
                        noms.add(el.id)
        if noms & set(nombres):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def cuerpo_ruta_in(rutas):
    """El cuerpo del `if ruta in (...)` que contiene esas rutas."""
    for n in ast.walk(ARBOL):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and getattr(n.test.left, "id", "") == "ruta" and isinstance(n.test.comparators[0], ast.Tuple)
                and rutas[0] in [getattr(e, "value", "") for e in n.test.comparators[0].elts]):
            ls = DASH.split("\n")[n.body[0].lineno - 1:n.body[-1].end_lineno]
            return textwrap.dedent("\n".join(ls))
    raise SystemExit("no se encontro la ruta " + rutas[0])


def main():
    # ---------- la tarjeta ----------
    ns = piezas(("CAT_CPE", "CAT_OTROS", "ACCIONES", "ACCIONES_POR_CAT", "ACCION_DEFECTO", "accion_de_clase", "_card_listas"),
                {"cargar_routers": lambda: [{"id": "r1", "HOST": "192.0.2.1", "nombre": "Centro"}],
                 "cargar_reglas_propias": lambda c: "/ip firewall raw\nadd chain=prerouting action=drop src-address-list={LISTA}" if c == "botnet" else "",
                 "_mk_globales": lambda: {}})
    h = ns["_card_listas"]({"ACCION_BOTNET": "propias", "ACCION_P2P": "limitar", "ACCION_LIMITE_P2P": "2M",
                            "ACCION_DNS": "redirigir-dns", "ACCION_DNS_IP": "192.0.2.53"})
    check("un select de accion por categoria (8)", h.count("<select name=accion_") == 8, h.count("<select name=accion_"))
    def sel(cat):   # el <select> de esa categoria (el JS tambien menciona 'accion_dns_ip')
        i = h.index("<select name=accion_%s " % cat); return h[i:h.index("</select>", i)]
    check("la accion guardada sale marcada", "<option value='propias' selected>" in sel("botnet"), sel("botnet"))
    check("el defecto se marca cuando no hay nada guardado (escaneo -> cortar)",
          "<option value='cortar' selected>" in sel("escaneo"), sel("escaneo"))
    tb = h[h.index("id=reglas_botnet"):]
    check("las reglas propias guardadas van en su textarea, visible", "style='display:block'" in tb[:200]
          and "src-address-list={LISTA}" in tb[:400], tb[:300])
    te = h[h.index("id=reglas_escaneo"):]
    check("sin 'propias' el textarea esta oculto", "style='display:none'" in te[:200], te[:200])
    check("el limite solo en P2P/minado, visible si 'limitar'", "name=limite_p2p" in h and "name=limite_minado" in h
          and "name=limite_botnet" not in h and 'name=limite_p2p class=acclim value="2M"' in h, "")
    check("el resolutor solo en DNS, visible si 'redirigir-dns'", h.count("<input type=text name=accion_dns_ip") == 1
          and 'value="192.0.2.53"' in h, "")
    check("botones de ver/aplicar y quitar por categoria", h.count("reglasPlan('") == 8 and h.count("reglasQuitar('") == 8, "")
    check("quitar pasa por el modal propio (ask), nunca confirm()", "ask(this,'Quitar del router" in h and "confirm(" not in h, "")
    check("con un solo router no hay selector", "id=accrid" not in h, "")
    ns["cargar_routers"] = lambda: [{"id": "r1", "HOST": "192.0.2.1", "nombre": "Centro"}, {"id": "r2", "HOST": "192.0.2.2", "nombre": "Norte"}]
    h2 = ns["_card_listas"]({})
    check("con dos routers, selector de router", "id=accrid" in h2 and "Norte" in h2, "")
    check("el modal usa fromCharCode, no escapes que se rompen al incrustar", "String.fromCharCode(10)" in h and "\\n" not in h[h.index("<script>"):h.index("</script>")], "")

    # ---------- la ruta de guardado ----------
    ruta = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta = ruta[:ruta.index('if ruta == "/routers/')]
    check("guarda la accion solo si es de esa clase", '_a in ACCIONES_POR_CAT.get(_cat, ())' in ruta, "")
    check("valida el limite con una expresion", 'ACCION_LIMITE_' in ruta and "re.match(" in ruta, "")
    check("valida el resolutor como IP", 'ipaddress.ip_address(_dip)' in ruta, "")
    check("guarda las reglas propias y avisa si no parsean",
          "guardar_reglas_propias(_cat" in ruta and "_err_reglas.append" in ruta and "NO se guardaron porque no" in ruta, "")

    # ---------- plan / aplicar / quitar ----------
    cuerpo = cuerpo_ruta_in(("/mikrotik/reglas/plan",))
    llamadas = []; logs = []
    def ejecutar(ruta_, campos, admin=True):
        visto = {}
        class Self:
            def _admin(self): return admin
            def _deny(self): visto["deny"] = True
            def send_response(self, *a): pass
            def send_header(self, *a): pass
            def end_headers(self, *a): pass
            wfile = type("W", (), {"write": lambda self, b: visto.update({"texto": b.decode("utf-8")})})()
        n2 = piezas(("ACCIONES", "ACCIONES_POR_CAT"))
        n2.update({"self": Self(), "q": {k: [v] for k, v in campos.items()}, "ruta": ruta_,
                   "CTX": type("C", (), {"user": "admin"})(),
                   "cargar_routers": lambda: [{"id": "r1", "HOST": "h", "USER": "u", "PASS": "p", "nombre": "Centro"},
                                              {"id": "r2", "HOST": "h2", "USER": "", "PASS": ""}],
                   "router_defecto": lambda: {"id": "r1", "HOST": "h", "USER": "u", "PASS": "p", "nombre": "Centro"},
                   "plan_reglas": lambda r, cat: {"cambios": 2, "accion": "cortar", "lista": "clientes-" + cat, "aviso": "",
                                                  "rsc": ["# ADD /ip firewall raw add chain=prerouting action=drop"], "acciones": []},
                   "aplicar_reglas": lambda r, cat, quien="?": (llamadas.append(("aplicar", r["id"], cat, quien)) or (True, "aplicado: 1 nueva(s)", {})),
                   "quitar_reglas": lambda r, cat, quien="?": (llamadas.append(("quitar", r["id"], cat, quien)) or (True, "aplicado: 0 nueva(s), 0 corregida(s), 1 quitada(s)", {})),
                   "bitacora": lambda a, d="": logs.append((a, d))})
        exec(compile("def _f():\n" + textwrap.indent(cuerpo, "    "), "<r>", "exec"), n2)
        n2["_f"]()
        return visto
    v = ejecutar("/mikrotik/reglas/plan", {"cat": "botnet", "rid": ""}, admin=False)
    check("sin admin: denegado", v.get("deny") is True, v)
    v = ejecutar("/mikrotik/reglas/plan", {"cat": "zzz", "rid": ""})
    check("clase desconocida: ERR", v.get("texto", "").startswith("ERR: clase desconocida"), v)
    v = ejecutar("/mikrotik/reglas/plan", {"cat": "botnet", "rid": "r2"})
    check("router sin conexion: ERR claro", "ERR:" in v.get("texto", "") and "guarda primero" in v["texto"], v)
    v = ejecutar("/mikrotik/reglas/plan", {"cat": "botnet", "rid": ""})
    check("plan: OK, cabecera con cambios/accion/lista y las lineas RSC debajo",
          v.get("texto", "").startswith("OK 2 cambio(s) en Centro") and "lista: clientes-botnet" in v["texto"]
          and v["texto"].split("\n")[1].startswith("# ADD /ip firewall raw"), v)
    v = ejecutar("/mikrotik/reglas/aplicar", {"cat": "spam", "rid": "r1"})
    check("aplicar: llama al motor con el router elegido y quien lo hizo",
          v.get("texto", "").startswith("OK aplicado") and ("aplicar", "r1", "spam", "admin") in llamadas, (v, llamadas))
    v = ejecutar("/mikrotik/reglas/quitar", {"cat": "spam", "rid": "r1"})
    check("quitar: idem", ("quitar", "r1", "spam", "admin") in llamadas and "quitada" in v.get("texto", ""), v)
    check("queda en la bitacora", any(a == "REGLAS-ROUTER" and "spam" in d for a, d in logs), logs)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
