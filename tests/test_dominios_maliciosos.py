# -*- coding: utf-8 -*-
"""Que dominios maliciosos se consultan y desde que IP de la red.

El generador contaba las consultas a dominios malos POR CPE, no POR DOMINIO: no se podia
responder "que se esta preguntando y quien". Lo que se protege:
  - cada consulta suma al dominio, al CPE que la hizo y al resolutor por el que paso;
  - el 'por que' se queda con el primero que lo fichó (feed o firma), no se pisa;
  - esta acotado: dominios nuevos hasta MAX_DOM (DGA), CPEs por dominio hasta MAX_CARD;
  - los dos sitios reales (cruce de dns.json con feeds, y alertas DNS con rrname) apuntan;
  - la seccion pinta dominio, por que, consultas, CPEs, IPs de la red con sus veces y el
    resolutor; con mas de n dominios lo dice; sin dominios no pinta nada;
  - deja el JSON para el panel y va entre Top destinos y Ataques entrantes.
"""
import ast
import json
import os
import sys
import tempfile
import time
from collections import Counter, defaultdict

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(nombres, extra=None):
    arbol = ast.parse(GEN)
    ns = {"json": json, "os": os, "time": time, "html": __import__("html"),
          "Counter": Counter, "defaultdict": defaultdict}
    ns.update(extra or {})
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(GEN, n) or "", ns)
    return ns


def main():
    td = tempfile.mkdtemp()
    ns = piezas(("dom_cnt", "dom_src", "dom_por", "dom_res", "MAX_DOM", "MAX_CARD",
                 "_apuntar_dominio", "esc", "dominios_section"),
                {"ip_de": lambda k: k.split("|")[-1], "VENTANA_MIN": 360})
    ns["DOMINIOS_FILE"] = os.path.join(td, "dom.json")
    ap = ns["_apuntar_dominio"]

    # --- apuntar ---------------------------------------------------------------------
    ap("malo.example", "r1|10.0.0.7", "1.1.1.2", "feed: urlhaus")
    ap("malo.example", "r1|10.0.0.7", "1.1.1.2", "firma: ET DNS otra cosa")   # no pisa el por que
    ap("malo.example", "r1|10.0.0.8", "8.8.8.8", "feed: urlhaus")
    ap("otro.example", "r1|10.0.0.9", "", "firma: ET MALWARE DNS Query x")
    ap("", "r1|10.0.0.9", "1.1.1.1", "feed: x")                                # vacio: nada
    check("el dominio suma sus consultas", ns["dom_cnt"]["malo.example"] == 3, dict(ns["dom_cnt"]))
    check("y sabe quien: dos CPEs, uno con dos consultas",
          ns["dom_src"]["malo.example"] == Counter({"r1|10.0.0.7": 2, "r1|10.0.0.8": 1}), "")
    check("y por que resolutor", ns["dom_res"]["malo.example"] == Counter({"1.1.1.2": 2, "8.8.8.8": 1}), "")
    check("el 'por que' se queda con el primero", ns["dom_por"]["malo.example"] == "feed: urlhaus", "")
    check("sin resolutor no se inventa uno", "otro.example" not in ns["dom_res"] or not ns["dom_res"]["otro.example"], "")
    check("un dominio vacio no entra", "" not in ns["dom_cnt"], "")

    # tope de dominios: los nuevos se descartan, los ya vistos siguen sumando
    ns["MAX_DOM"] = 2
    exec("def _apuntar_dominio(dom, src, dst, por):\n" + "\n".join(
        l for l in ast.get_source_segment(GEN, [n for n in ast.parse(GEN).body
                                                 if getattr(n, "name", "") == "_apuntar_dominio"][0]).split("\n")[1:]), ns)
    ns["_apuntar_dominio"]("tercero.example", "r1|10.0.0.1", "", "feed: x")
    ns["_apuntar_dominio"]("malo.example", "r1|10.0.0.1", "", "feed: x")
    check("con MAX_DOM alcanzado, un dominio nuevo no entra", "tercero.example" not in ns["dom_cnt"], "")
    check("pero uno conocido sigue sumando", ns["dom_cnt"]["malo.example"] == 4, "")

    # --- los dos sitios reales apuntan -------------------------------------------------
    camino_b = GEN[GEN.index("# Camino B: consulta DNS a dominio malo"):]
    camino_b = camino_b[:camino_b.index("dns_sig[_s] = ")]
    check("el cruce de dns.json con feeds apunta el dominio, el CPE y el resolutor",
          '_apuntar_dominio(_dom, _s, _mdd.group(1) if _mdd else "",' in camino_b
          and '"feed: " + dominio_malo(_dom)' in camino_b, "")
    alerta = GEN[GEN.index("if _es_dns:                            # consulta DNS a dominio malicioso"):]
    alerta = alerta[:alerta.index("# evidencia por alerta")]
    check("la alerta DNS con rrname apunta con la firma como 'por que'",
          '_apuntar_dominio(_rr, src, dst, "firma: " + sig[:70])' in alerta, "")

    # --- la seccion -------------------------------------------------------------------
    h = ns["dominios_section"](n=1, n_ips=1)
    check("pinta el dominio y por que", "malo.example" in h and "feed: urlhaus" in h, "")
    check("la IP de la red con sus veces, y cuantos mas",
          "10.0.0.7 (2)" in h and "+2 mas" in h, h[h.find("10.0.0.7") - 40:][:120])
    check("el resolutor", "1.1.1.2" in h, "")
    check("con mas dominios de los que ensena, lo dice", "Se muestran 1 de 2 dominios" in h, "")
    check("el resolutor se presenta como canal, no como victima", "no una victima" in h, "")
    j = json.load(open(ns["DOMINIOS_FILE"], encoding="utf-8"))
    check("deja el JSON con el top para el panel",
          j["total_dominios"] == 2 and j["dominios"][0]["dominio"] == "malo.example"
          and j["dominios"][0]["ips"][0] == ["10.0.0.7", 2] and j["dominios"][0]["resolutores"][0] == "1.1.1.2", j)
    ns["dom_cnt"].clear()
    check("sin dominios, no pinta nada", ns["dominios_section"]() == "", "")

    # --- en el reporte, entre destinos y entrantes --------------------------------------
    check("la seccion va entre Top destinos y Ataques entrantes",
          "+ top_destinos_section() + dominios_section() + entrantes_section() +" in GEN, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
