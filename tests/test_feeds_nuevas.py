# -*- coding: utf-8 -*-
"""Tres fuentes mas; una de ellas es contexto y no puede pesar como prueba.

Lo que se protege:
  - ThreatFox por API: el parser se queda solo con ip:port de confianza suficiente; un
    dominio, una URL, una IPv6 o una confianza baja no entran. El POST lleva la clave en
    la cabecera Auth-Key y el cuerpo JSON (sin clave, la fuente queda 'sin-clave').
  - al rearmar, una fuente ip:port aporta la IP a reputation.lst (para que case con el
    cruce de siempre) y el puerto a c2ports.lst, sin repetir IPs;
  - tor-exit lleva categoria 'anonimizador' y esa categoria NO esta en ninguna lista de
    las que deciden (cortar destino, barrido rapido, C2 rapido);
  - en el generador, es_malo_firme devuelve '' para Tor y la fuente para Feodo; el riesgo,
    las evidencias y los destinos a cortar usan la version firme;
  - la ficha marca 'por su puerto de C2' cuando el flujo fue al puerto fichado;
  - SSLBL no esta: esta deprecada y vacia.
"""
import ast
import ipaddress
import json
import os
import sys
import tempfile
from collections import defaultdict

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_f = SRC.index("cat > /usr/local/bin/suricata-feeds-update <<'FEEDS'")
FEEDS = SRC[_f:].split("\n", 1)[1].split("\nFEEDS\n", 1)[0]
_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
_d = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_d:].split("\n", 1)[1].split("\nDASH\n", 1)[0]

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(fuente, nombres, extra=None):
    arbol = ast.parse(fuente)
    ns = {"json": json, "os": os, "ipaddress": ipaddress, "html": __import__("html"),
          "defaultdict": defaultdict}
    ns.update(extra or {})
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(fuente, n) or "", ns)
    return ns


class _Resp(object):
    def __init__(self, body):
        self._b = body.encode("utf-8"); self.headers = {"Content-Type": "application/json"}
    def read(self): return self._b
    def __enter__(self): return self
    def __exit__(self, *a): return False


def main():
    # ================= FEEDS =================
    f = piezas(FEEDS, ("TFX_CONFIANZA_MIN", "_parse_ipport", "_parse_ip", "_parse_dom", "PARSERS",
                       "CABECERA", "_fetch"),
               {"CLAVES": {"abusech": "CLAVE-TEST", "aidb": ""},
                "_clave_de": lambda a: {"abusech": "CLAVE-TEST"}.get(a, "")})

    tfx = json.dumps({"query_status": "ok", "data": [
        {"ioc": "203.0.113.7:4444", "ioc_type": "ip:port", "confidence_level": 100, "malware": "x"},
        {"ioc": "203.0.113.7:8080", "ioc_type": "ip:port", "confidence_level": 75},
        {"ioc": "198.51.100.9:443", "ioc_type": "ip:port", "confidence_level": 25},   # floja
        {"ioc": "malo.example", "ioc_type": "domain", "confidence_level": 100},
        {"ioc": "http://x.example/a", "ioc_type": "url", "confidence_level": 100},
        {"ioc": "[2001:db8::1]:443", "ioc_type": "ip:port", "confidence_level": 100},  # v6
        {"ioc": "basura", "ioc_type": "ip:port", "confidence_level": 100},
        {"ioc": "203.0.113.8:99999", "ioc_type": "ip:port", "confidence_level": 100},  # puerto
    ]})
    got = f["_parse_ipport"](tfx)
    check("ThreatFox: se quedan los ip:port con confianza suficiente (misma IP, dos puertos)",
          got == {"203.0.113.7:4444", "203.0.113.7:8080"}, got)
    check("una respuesta que no es JSON no revienta: vacio", f["_parse_ipport"]("<html>") == set(), "")
    check("un JSON sin 'data' tampoco", f["_parse_ipport"]('{"query_status":"no_result"}') == set(), "")
    check("PARSERS enruta ipport y dom; el resto cae a _parse_ip",
          f["PARSERS"]["ipport"] is f["_parse_ipport"] and f["PARSERS"]["dom"] is f["_parse_dom"]
          and "ip" not in f["PARSERS"], "")

    # el POST: clave en cabecera, cuerpo JSON
    visto = {}
    class _UR(object):
        class Request(object):
            def __init__(self, url, data=None, headers=None):
                visto["url"] = url; visto["data"] = data; visto["headers"] = dict(headers or {})
        @staticmethod
        def urlopen(req, timeout=30):
            return _Resp('{"data":[]}')
    f["urllib"] = type("U", (), {"request": _UR})
    f["_fetch"]("https://threatfox-api.abuse.ch/api/v1/", "abusech", {"query": "get_iocs", "days": 7})
    check("el POST manda el cuerpo JSON", json.loads(visto["data"].decode()) == {"query": "get_iocs", "days": 7}, visto)
    check("con la Auth-Key en la cabecera y Content-Type JSON",
          visto["headers"].get("Auth-Key") == "CLAVE-TEST"
          and visto["headers"].get("Content-Type") == "application/json", visto["headers"])
    f["_fetch"]("https://example.test/lista.txt", "")
    check("sin post, sigue siendo un GET (data=None)", visto["data"] is None, visto)

    # las fuentes: nombres, categorias, y SSLBL fuera
    check("et-compromised y tor-exit son fuentes de IP sin clave",
          '("et-compromised"' in FEEDS and '"atacante-observado", "", 720)' in FEEDS
          and '("tor-exit"' in FEEDS and '"anonimizador", "", 360)' in FEEDS, "")
    check("threatfox-c2 es ipport, con la Auth-Key de abuse.ch y cuerpo get_iocs",
          '("threatfox-c2"' in FEEDS and '"ipport", "c2-ioc", "abusech", 60,' in FEEDS
          and '{"query": "get_iocs", "days": 7}' in FEEDS, "")
    check("SSLBL no esta (deprecada y vacia)", 'sslbl.abuse.ch' not in FEEDS, "")
    check("procesar acepta el post opcional y lo pasa a _fetch",
          "def procesar(name, url, ttl_h, tipo, cat, auth, min_min, post=None):" in FEEDS
          and "_fetch(url, auth, post)" in FEEDS, "")

    # rearmado: IP a reputation.lst, puerto a c2ports.lst
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "src"))
        open(os.path.join(td, "src", "threatfox-c2.lst"), "w").write("203.0.113.7:4444\n203.0.113.7:8080\n198.51.100.2:443\n")
        open(os.path.join(td, "src", "tor-exit.lst"), "w").write("192.0.2.9\n")
        ini = FEEDS.index("rep_lines = []; dom_lines = []")
        fin = FEEDS.index("if rep_lines:", ini)
        bloque = FEEDS[ini:fin]
        ns = {"os": os, "DIR": td, "SRCDIR": os.path.join(td, "src"),
              "sources": {"threatfox-c2": {"vigente": True, "tipo": "ipport"},
                          "tor-exit": {"vigente": True, "tipo": "ip"},
                          "muerta": {"vigente": False, "tipo": "ip"}}}
        exec(ast.get_source_segment(FEEDS, [n for n in ast.parse(FEEDS).body if getattr(n, "name", "") == "_leer_src"][0]), ns)
        exec(bloque, ns)
        check("reputation.lst recibe la IP una sola vez por fuente, mas la de Tor",
              sorted(ns["rep_lines"]) == ["192.0.2.9\ttor-exit", "198.51.100.2\tthreatfox-c2", "203.0.113.7\tthreatfox-c2"]
              and ns["n_ip"] == 3, ns["rep_lines"])
        c2 = open(os.path.join(td, "c2ports.lst")).read().splitlines()
        check("c2ports.lst lleva ip:port con su fuente",
              sorted(c2) == ["198.51.100.2:443\tthreatfox-c2", "203.0.113.7:4444\tthreatfox-c2", "203.0.113.7:8080\tthreatfox-c2"], c2)

    # ================= generador =================
    g = piezas(GEN, ("REP_CONTEXTO", "_ip4_int", "es_malo", "es_malo_firme"),
               {"REP_IPS": {"192.0.2.9": "tor-exit", "203.0.113.7": "threatfox-c2", "198.51.100.5": "feodo"},
                "REP_CIDR": defaultdict(list), "REP_WIDE": [],
                "REP_META": {"tor-exit": {"categoria": "anonimizador"}, "threatfox-c2": {"categoria": "c2-ioc"},
                             "feodo": {"categoria": "c2-activo"}}})
    check("es_malo sigue viendo a Tor (para la celda del destino)", g["es_malo"]("192.0.2.9") == "tor-exit", "")
    check("es_malo_firme NO: Tor es contexto", g["es_malo_firme"]("192.0.2.9") == "", "")
    check("y si ve un C2", g["es_malo_firme"]("198.51.100.5") == "feodo" and g["es_malo_firme"]("203.0.113.7") == "threatfox-c2", "")
    check("una IP limpia sigue limpia", g["es_malo_firme"]("192.0.2.1") == "", "")

    riesgo = GEN[GEN.index("def riesgo(src):"):]
    riesgo = riesgo[:riesgo.index("\ndef ", 10)]
    check("el riesgo cuenta reputacion con la version firme", "if es_malo_firme(d):" in riesgo
          and "if es_malo(d):" not in riesgo, "")
    check("las evidencias (CnC y DNS) tambien",
          GEN.count('if es_malo_firme(d)]') == 2 and GEN.count('if es_malo(d)]') == 0, GEN.count('if es_malo(d)]'))
    dm = GEN[GEN.index('DESTINOS_FILE = "/var/log/suricata-destinos-malos.json"'):]
    dm = dm[:dm.index("os.replace(_tmpd, DESTINOS_FILE)")]
    check("los destinos a cortar excluyen el contexto", "not es_malo_firme(_d)" in dm, "")
    check("se cargan los puertos de C2 para la ficha", "c2ports.lst" in GEN and "REP_PORTS.setdefault(ip, set()).add(port)" in GEN, "")
    rs = GEN[GEN.index("def _reputacion_src(src):"):]
    rs = rs[:rs.index("\n    def ", 10)]
    check("la ficha sabe si el flujo fue por el puerto del C2",
          '"puerto_c2": _coincide' in rs and "str(k[3]) in _pc2" in rs, "")

    # ================= panel =================
    d = piezas(DASH, ("DST_CONFIABLES", "DST_FEED_OK", "_FAST_REP_C2", "_FAST_REP_CONTEXTO"))
    for nom in ("DST_CONFIABLES", "DST_FEED_OK", "_FAST_REP_C2"):
        check("'anonimizador' no esta en %s" % nom, "anonimizador" not in d[nom], d[nom])
    check("y si en _FAST_REP_CONTEXTO", "anonimizador" in d["_FAST_REP_CONTEXTO"], "")
    br = DASH[DASH.index("def barrido_alto_rapido"):]
    br = br[:br.index("\ndef ", 10)]
    check("el barrido rapido salta el contexto antes de contar", "_cat in _FAST_REP_CONTEXTO" in br, "")
    check("la ficha nombra 'por su puerto de C2' y el contexto",
          "por su puerto de C2" in DASH and "contexto: no suma al riesgo" in DASH, "")
    check("la documentacion explica fuentes, pesos y por que no esta SSLBL",
          "Fuentes y que pesa cada una" in SRC and "SSLBL" in SRC and "tor-exit" in SRC, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
