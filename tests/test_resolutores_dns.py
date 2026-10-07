# -*- coding: utf-8 -*-
"""Un resolutor DNS no es la victima: es por donde pasa la consulta.

Un CPE pregunta por un dominio de malware a 1.1.1.2. La alerta lleva dest_ip=1.1.1.2 y el
generador la sumaba a by_dst sin mirar nada: el DNS de Cloudflare que BLOQUEA malware
salia como "la IP mas atacada de la red". La prueba contra el CPE es el dominio, no el DNS.

Lo que se protege:
  - una consulta al puerto 53 a un resolutor de la lista NO entra en by_dst (victimas),
    entra en via_dns (resolutores usados), y el CPE CONSERVA la alerta (by_src);
  - al mismo resolutor por otro puerto SI entra en by_dst: eso es un ataque de verdad;
  - una IP que no esta en la lista sigue siendo victima aunque sea puerto 53;
  - sin archivo, los publicos vienen de serie (si no, el falso positivo volveria en una
    caja recien instalada); con archivo, manda el archivo;
  - una linea invalida en el archivo no rompe nada: se ignora;
  - la ficha dice "consulta DNS maliciosa: dominio, via resolutor", no "comunicacion a";
  - guardar valida (solo IP/CIDR), deja el archivo en 600 y devuelve cuantos quedan;
  - hay apartado DNS en Ajustes con su ruta, y la pagina de Top destinos los lista aparte.
"""
import ast
import ipaddress
import os
import stat
import sys
import tempfile
import textwrap
from collections import Counter, defaultdict

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

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
    ns = {"os": os, "html": __import__("html"), "ipaddress": ipaddress, "_ipr": ipaddress}
    ns.update(extra or {})
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(fuente, n) or "", ns)
    return ns


def main():
    # ================= generador: el criterio y la agregacion =================
    g = piezas(GEN, ("RESOLUTORES_DEFECTO", "es_via_resolutor", "es_dns_sospechoso", "DNS_MAL"))
    g["RESOLUTORES"] = [ipaddress.ip_network(x) for x in g["RESOLUTORES_DEFECTO"]]
    via = g["es_via_resolutor"]

    check("consulta al 53 a 1.1.1.2 (publico, de serie) es 'via resolutor'",
          via("1.1.1.2", "53") is True, "")
    check("al mismo 1.1.1.2 por el 443 NO lo es: eso es un ataque de verdad",
          via("1.1.1.2", "443") is False, "")
    check("a una IP fuera de la lista, aunque sea al 53, no lo es",
          via("203.0.113.9", "53") is False, "")
    check("firma de DNS malicioso a un resolutor sin puerto 53 tambien cuenta como consulta",
          via("8.8.8.8", "", "ET DNS Query to a *.top domain - Likely Hostile", "") is True
          or via("8.8.8.8", "", "ET MALWARE DNS Query for known C2 domain", "Malware Command and Control Activity Detected") is True, "")
    check("sin destino ('?') no revienta y es False", via("?", "53") is False, "")
    check("un destino que no es IP no revienta", via("basura", "53") is False, "")

    # un CIDR del ISP en la lista: todo el rango es resolutor
    g["RESOLUTORES"] = [ipaddress.ip_network("203.0.113.0/29")]
    check("un CIDR en la lista cubre todo el rango", via("203.0.113.5", "53") is True, "")
    check("y fuera del rango no", via("203.0.113.9", "53") is False, "")
    g["RESOLUTORES"] = []
    check("lista vacia = comportamiento de antes (todo es victima)", via("1.1.1.2", "53") is False, "")

    # --- la agregacion: reproducimos el bloque tal cual esta en el generador ------------
    _i = GEN.index("if es_via_resolutor(dst, dport, sig, cat):")
    _i = GEN.rfind(chr(10), 0, _i) + 1                       # desde el inicio de la linea
    bloque = GEN[_i:]
    bloque = bloque[:bloque.index("by_src[src] += 1") + len("by_src[src] += 1")]
    bloque = textwrap.dedent(bloque)
    check("el generador consulta el criterio justo antes de contar la victima",
          "via_dns[dst] += 1" in bloque and "else:" in bloque and "by_dst[dst] += 1" in bloque, bloque)
    check("y el CPE conserva la alerta pase lo que pase (by_src fuera del if/else)",
          bloque.rstrip().endswith("by_src[src] += 1")
          and bloque.count("by_src[src] += 1") == 1, "")

    g["RESOLUTORES"] = [ipaddress.ip_network(x) for x in g["RESOLUTORES_DEFECTO"]]
    by_dst = Counter(); by_src = Counter(); via_dns = Counter(); via_dns_src = defaultdict(set)
    MAX_CARD = 2500
    eventos = [("10.0.0.7", "1.1.1.2", "53", "ET MALWARE DNS Query bad", "Malware"),
               ("10.0.0.7", "1.1.1.2", "53", "ET MALWARE DNS Query bad", "Malware"),
               ("10.0.0.8", "1.1.1.2", "53", "ET MALWARE DNS Query bad", "Malware"),
               ("10.0.0.7", "1.1.1.2", "443", "ET SCAN Nmap", "Attempted Information Leak"),
               ("10.0.0.9", "198.51.100.4", "53", "ET MALWARE DNS Query bad", "Malware")]
    for src, dst, dport, sig, cat in eventos:
        exec(bloque, dict(g, dst=dst, dport=dport, sig=sig, cat=cat, src=src, by_dst=by_dst,
                          by_src=by_src, via_dns=via_dns, via_dns_src=via_dns_src, MAX_CARD=MAX_CARD))
    check("3 consultas al 53 van al contador de resolutores, no al de victimas",
          via_dns["1.1.1.2"] == 3 and by_dst["1.1.1.2"] == 1, (dict(via_dns), dict(by_dst)))
    check("la del 443 al mismo DNS si es victima (1)", by_dst["1.1.1.2"] == 1, dict(by_dst))
    check("se sabe que CPEs lo usaron (2 distintos)", via_dns_src["1.1.1.2"] == {"10.0.0.7", "10.0.0.8"}, "")
    check("el DNS que NO esta en la lista sigue como victima", by_dst["198.51.100.4"] == 1, dict(by_dst))
    check("el CPE conserva TODAS sus alertas: 10.0.0.7 tiene 3", by_src["10.0.0.7"] == 3, dict(by_src))

    # --- carga desde archivo en el generador: manda el archivo, invalidas se ignoran -----
    carga = GEN[GEN.index('RESOLUTORES_FILE = "/etc/suricata-resolutores.lst"'):]
    carga = carga[:carga.index("def es_via_resolutor")]
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "r.lst")
        open(f, "w").write("# mios\n203.0.113.53\nno-es-ip\n203.0.113.0/29\n\n")
        ns = {"_ipr": ipaddress}
        exec(carga.replace('"/etc/suricata-resolutores.lst"', repr(f)), ns)
        check("con archivo manda el archivo: 2 redes validas, la basura se ignora",
              len(ns["RESOLUTORES"]) == 2 and ipaddress.ip_address("203.0.113.53") in ns["RESOLUTORES"][0], ns["RESOLUTORES"])
        ns2 = {"_ipr": ipaddress}
        exec(carga.replace('"/etc/suricata-resolutores.lst"', repr(f + ".no")), ns2)
        check("sin archivo vienen los publicos de serie (12, FamilyShield incluido)",
              len(ns2["RESOLUTORES"]) == 12 and ipaddress.ip_address("208.67.222.123") in ns2["RESOLUTORES"][-2],
              len(ns2["RESOLUTORES"]))

    # --- Top destinos los pinta aparte, con la lectura correcta -------------------------
    top = DASH if False else GEN
    sec = top[top.index("def top_destinos_section"):]
    sec = sec[:sec.index("\ndef ", 10)]
    check("Top destinos tiene el bloque de resolutores, aparte del ranking",
          "Resolutores DNS usados para consultar dominios maliciosos" in sec
          and "via_dns.most_common" in sec, "")
    check("y lo dice como es: no son blancos, la prueba es el dominio",
          "No son blancos" in sec and "La prueba es el dominio" in sec, "")
    check("y cuenta CPEs distintos por resolutor", "CPEs distintos" in sec and "via_dns_src" in sec, "")

    # ================= panel: lista, ficha, ajustes, ruta =================
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "res.lst")
        d = piezas(DASH, ("RESOLUTORES_DEFECTO", "cargar_resolutores", "_RESOL_CACHE",
                          "_resolutores_redes", "guardar_resolutores", "es_via_resolutor"),
                   {"_sello": lambda p: (os.stat(p).st_mtime_ns, os.stat(p).st_size) if os.path.exists(p) else None})
        d["RESOLUTORES_FILE"] = f

        check("sin archivo, el formulario ensena los publicos",
              "1.1.1.2" in d["cargar_resolutores"]() and "8.8.8.8" in d["cargar_resolutores"](), "")
        check("y el criterio ya los usa", d["es_via_resolutor"]("1.1.1.2", "53") is True, "")

        n = d["guardar_resolutores"]("# mios\n203.0.113.53\nbasura\n1.1.1.1\n203.0.113.0/29\n")
        check("guardar valida: 3 entradas, la basura fuera", n == 3, n)
        txt = open(f).read()
        check("el comentario se conserva y la basura no",
              "# mios" in txt and "basura" not in txt and "203.0.113.53" in txt, txt)
        if os.name != "nt":
            check("el archivo queda en 600", stat.S_IMODE(os.stat(f).st_mode) == 0o600, oct(os.stat(f).st_mode))
        check("ahora 8.8.8.8 ya NO es resolutor (manda el archivo) y 203.0.113.53 si",
              d["es_via_resolutor"]("8.8.8.8", "53") is False and d["es_via_resolutor"]("203.0.113.53", "53") is True, "")
        check("al 443 sigue sin serlo", d["es_via_resolutor"]("203.0.113.53", "443") is False, "")
        check("una prueba de tipo dns cuenta aunque no traiga puerto",
              d["es_via_resolutor"]("203.0.113.53", "", "dns") is True, "")
        # la cache se invalida al cambiar el archivo
        d["guardar_resolutores"]("9.9.9.9\n")
        check("cambiar el archivo invalida la cache", d["es_via_resolutor"]("203.0.113.53", "53") is False
              and d["es_via_resolutor"]("9.9.9.9", "53") is True, "")

    # --- la ficha --------------------------------------------------------------------
    ficha = DASH[DASH.index('for p in (c.get("pruebas") or [])[:8]:'):]
    ficha = ficha[:ficha.index("act_html = ")]
    check("la ficha consulta el criterio por prueba", "es_via_resolutor(p.get(\"dst\"" in ficha, "")
    check("una prueba DNS se dice como consulta maliciosa al DOMINIO, via el resolutor",
          "Consulta DNS maliciosa:" in ficha and "(resolutor conocido)" in ficha, "")
    check("puerto 53 a un resolutor sin dominio no es 'Comunicacion a': es consulta a traves de el",
          "Consulta DNS a traves de" in ficha and "no es la victima" in ficha, "")
    check("lo que no es DNS sigue siendo 'Comunicacion a'", "Comunicacion a <span class=mono>" in ficha, "")

    # --- Ajustes -> DNS y la ruta ---------------------------------------------------------
    check("hay tarjeta DNS en Ajustes", "DNS &mdash; resolutores conocidos" in DASH, "")
    check("con su tile", '_tile("dns", "DNS", _IC_DNS' in DASH, "")
    check("y su modal", '_mcard("dns", card_dns)' in DASH, "")
    check("el formulario envia a /dns", "action='/dns'" in DASH and "name=resolutores" in DASH, "")
    ruta = DASH[DASH.index('if ruta == "/dns":'):]
    ruta = ruta[:ruta.index('if ruta == "/feeds/groq":')]
    check("la ruta exige admin", "self._admin()" in ruta, "")
    check("guarda con validacion y deja bitacora", "guardar_resolutores(q.get(\"resolutores\"" in ruta
          and 'bitacora("CONFIG-DNS"' in ruta, "")
    check("explica que el CPE sigue contando",
          "cuentan contra el CPE, no como ataque al DNS" in ruta, "")

    # --- instalador y documentacion -------------------------------------------------------
    check("el instalador crea la lista con los publicos sin pisarla",
          '_RESOL="/etc/suricata-resolutores.lst"' in SRC and 'if [ ! -f "$_RESOL" ]' in SRC
          and "208.67.220.123\nLST" in SRC, "")
    check("la documentacion lo explica y lo distingue de excluir destino",
          "Resolutores DNS: el DNS no es la victima" in SRC and "Es distinto de <i>excluir destino</i>" in SRC, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
