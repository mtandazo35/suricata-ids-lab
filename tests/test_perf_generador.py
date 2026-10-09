# -*- coding: utf-8 -*-
"""Rendimiento del generador: las tres piezas que se comian el tiempo, sin cambiar resultados.

Medido en un banco sintetico de 1,5 M de lineas / 50k CPEs: riesgo() recorria los 200k
flujos enteros por CADA candidato (41% del tiempo), es_mi_cpe() construia un ipaddress por
evento (12%) y traducir() recorria la tabla entera por alerta (7%).

Lo que se protege:
  - flujos_de(src) devuelve exactamente lo que daba filtrar `flujos` a mano, y riesgo()
    calcula la misma correlacion de flota que la version lenta;
  - nadie vuelve a meter un `for k in flujos` filtrando por `k[0] == src` (es lo que escala
    con candidatos x flujos);
  - es_mi_cpe con memoria da lo mismo que sin ella, no revienta con basura y no crece sin
    tope;
  - traducir con memoria da lo mismo que la version lenta, tambien para firmas sin traduccion.
"""
import ast
import ipaddress
import os
import re
import sys
from collections import Counter, defaultdict

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
ARBOL = ast.parse(GEN)

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(nombres, extra=None):
    ns = {"re": re, "defaultdict": defaultdict, "Counter": Counter, "_ipm": ipaddress}
    ns.update(extra or {})
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(GEN, n) or "", ns)
    return ns


def main():
    # ================= 1) indice de flujos por CPE =================
    flujos = {}
    for i in range(3000):
        src = "10.0.0.%d" % (i % 40)
        flujos[(src, 40000 + i, "203.0.113.%d" % (i % 9), 23 if i % 3 else 445, "TCP", "SIG-%d" % (i % 7))] = (1, 0, 0)
    patron_src = defaultdict(set)
    for k in flujos:
        patron_src[(k[5], k[3])].add(k[0])
    ns = piezas(("_FLUJOS_POR_SRC", "flujos_de", "riesgo", "es_malo_firme"),
                {"flujos": flujos, "patron_src": patron_src, "sev_by_src": {}, "dst_by_src": {},
                 "dpt_by_src": {}, "n5_by_src": {}, "n1h_by_src": {}, "by_src": {}, "REP_OK": False,
                 "REP_META": {}, "REP_CONTEXTO": (), "es_malo": lambda ip: "", "REP_INFO": ""})
    for src in ("10.0.0.3", "10.0.0.39", "10.9.9.9"):
        esperado = [k for k in flujos if k[0] == src]
        check("flujos_de(%s) = filtrar a mano (%d)" % (src, len(esperado)),
              list(ns["flujos_de"](src)) == esperado, "")
    # la correlacion de flota, como la calculaba la version lenta
    def cor_lenta(src):
        otros = 0
        for k in flujos:
            if k[0] == src:
                n = len(patron_src.get((k[5], k[3]), ())) - 1
                otros = max(otros, n)
        return min(5, otros)
    ok = True
    for src in sorted({k[0] for k in flujos}):
        _sc, _b, _c, desg = ns["riesgo"](src)
        m = re.search(r"Correlacion flota (\d+)/5", desg)
        if not m or int(m.group(1)) != cor_lenta(src):
            ok = False; break
    check("riesgo() da la misma correlacion de flota que la version lenta (40 CPEs)", ok, src)
    check("el indice se construye una sola vez", ns["_FLUJOS_POR_SRC"] is not None and len(ns["_FLUJOS_POR_SRC"]) == 40, "")
    # guardia: que nadie vuelva a recorrer flujos por candidato
    patron_malo = re.compile(r"for k in flujos:\s*\n\s*if k\[0\] == src")
    check("no queda ningun recorrido de `flujos` filtrando por k[0] == src", not patron_malo.search(GEN), "")
    check("_reputacion_src usa el indice", "for k in flujos_de(src))" in GEN, "")

    # ================= 2) es_mi_cpe con memoria =================
    nets = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("100.64.0.0/10")]
    n2 = piezas(("_MI_CPE_CACHE", "_MI_CPE_CACHE_MAX", "es_mi_cpe"), {"_MIS_NETS": nets})
    f = n2["es_mi_cpe"]
    def lenta(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in nets)
    casos = ["10.1.2.3", "100.64.5.5", "100.128.0.1", "8.8.8.8", "basura", "", "::1", "fd00::1", "10.1.2.3"]
    check("es_mi_cpe con memoria = sin memoria en %d casos" % len(casos), all(f(c) == lenta(c) for c in casos), "")
    check("la segunda vez sale de la memoria", "10.1.2.3" in n2["_MI_CPE_CACHE"] and n2["_MI_CPE_CACHE"]["10.1.2.3"] is True, "")
    n2["_MI_CPE_CACHE_MAX"] = 3
    n2["_MI_CPE_CACHE"].clear()
    for i in range(10):
        f("10.0.0.%d" % i)
    check("la memoria no crece por encima del tope", len(n2["_MI_CPE_CACHE"]) == 3, len(n2["_MI_CPE_CACHE"]))
    check("y por encima del tope sigue respondiendo bien", f("10.0.0.9") is True and f("1.1.1.1") is False, "")

    # ================= 3) traducir con memoria =================
    n3 = piezas(("_TRAD", "_TRAD_CACHE", "_TRAD_CACHE_MAX", "traducir", "_traducir_lento"))
    firmas = ["ET SCAN Potential SSH Scan", "ET MALWARE Win32/Mirai Variant CnC Checkin",
              "ET POLICY BitTorrent DHT ping request", "ET HUNTING Terse Unencrypted Request for Google Something Very Long Indeed",
              "GPL ICMP_INFO PING", "cosa rara sin prefijo", ""]
    check("traducir con memoria = version lenta en %d firmas" % len(firmas),
          all(n3["traducir"](x) == n3["_traducir_lento"](x) for x in firmas), "")
    check("la segunda llamada sale de la memoria", firmas[0] in n3["_TRAD_CACHE"], "")
    n3["_TRAD_CACHE_MAX"] = 2; n3["_TRAD_CACHE"].clear()
    for x in firmas:
        n3["traducir"](x)
    check("la memoria de firmas respeta el tope", len(n3["_TRAD_CACHE"]) == 2, len(n3["_TRAD_CACHE"]))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
