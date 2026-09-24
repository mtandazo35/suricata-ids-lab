# -*- coding: utf-8 -*-
"""De "a tu IP publica la denuncian por X" a "este abonado es el que lo hace".

El espejo del MikroTik es PRE-NAT: Suricata ve 10.x y nunca la IP publica por la que
salio el ataque. Por eso las publicas se declaran a mano, y la mitigacion sale de cruzar
dos cosas que por separado no sirven:

  - la reputacion de la publica dice QUE tipo de abuso sale por ella (categorias),
  - Suricata dice QUIEN, dentro de ese nodo, hace ese tipo de trafico (puertos/firmas).

Lo que se protege aqui es ese cruce: que señale al CPE correcto, que no acuse al
inocente, y que no se mezclen los abonados de nodos distintos.
"""
import ast
import json
import os
import re
import sys
import tempfile
import types
import urllib.error
import urllib.parse

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("PUBLICAS_CONF", "PUB_HIST", "PUB_HIST_DIAS", "PUB_UMBRAL_AVISO", "_PUB_LOCK",
          "AIDB_SENAL", "AIDB_CATS", "AIDB_CUOTA", "AIDB_CUOTA_BLOQUE", "AIDB_PREFIJO_MIN",
          "AIDB_TTL_LIMPIA", "AIDB_TTL_SUCIA", "AIDB_CACHE", "AIDB_ESTADO", "AIDB_MAX_CACHE",
          "AIDB_RESERVA_MANUAL", "_AIDB_LOCK", "FEEDS_CONF",
          "_feeds_conf_get", "_feeds_conf_set", "aidb_key", "aidb_configurada", "aidb_set",
          "aidb_ip_valida", "aidb_red_valida", "_aidb_cache", "_aidb_guardar_cache",
          "_aidb_estado", "_aidb_guardar_estado", "_aidb_pedir", "_aidb_resumen",
          "aidb_consultar", "_aidb_pedir_red", "_aidb_resumen_red", "aidb_consultar_red",
          "cargar_publicas", "guardar_publicas", "publicas_texto", "guardar_publicas_de",
          "_pub_hist", "_guardar_pub_hist", "_peor_de", "_cats_de", "vigilar_publicas",
          "senal_de_categorias", "_cpes_del_nodo", "culpables_de", "es_publica_declarada",
          "DNSBL", "DNSBL_HIST", "DNSBL_MAX_IPS", "DNSBL_HILOS", "DNSBL_DIAS",
          "ZEN_COD", "_PBL", "_invertida", "dnsbl_una", "dnsbl_revisar",
          "_dnsbl_hist", "vigilar_dnsbl")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class Red:
    def __init__(self):
        self.llamadas = []
        self.guion = []

    def Request(self, url, data=None, headers=None):
        return {"url": url, "data": data, "headers": headers or {}}

    def urlopen(self, req, timeout=None):
        self.llamadas.append(req)
        r = self.guion.pop(0) if self.guion else {"data": {"abuseConfidenceScore": 0}}
        if isinstance(r, Exception):
            raise r
        cuerpo = json.dumps(r).encode("utf-8")

        class Resp:
            def read(self_in, n=None):
                return cuerpo
            def __enter__(self_in):
                return self_in
            def __exit__(self_in, *a):
                return False
        return Resp()


def entorno(tmp, red, enviados=()):
    avisos = []
    ns = {"json": json, "os": os, "re": re, "time": __import__("time"),
          "threading": __import__("threading"), "ipaddress": __import__("ipaddress"),
          "socket": __import__("socket"),
          "ThreadPoolExecutor": __import__("concurrent.futures", fromlist=["futures"]).ThreadPoolExecutor,
          "urllib": types.SimpleNamespace(request=red, error=urllib.error, parse=urllib.parse),
          "LOGDIR": tmp,
          "MK_SENT": "cuar", "MK_SENT_DNS": "dns",
          "cargar_enviados": lambda path=None: {k: 1 for k in enviados} if path == "cuar" else {},
          "clave_cpe": lambda ip, rid: (rid + "|" + ip) if rid else ip,
          "ip_de": lambda k: k.split("|", 1)[1] if "|" in k else k,
          "router_por_id": lambda r: {"id": r, "nombre": "Nodo " + r},
          "enviar_telegram": lambda t: avisos.append(t) or True,
          "bitacora": lambda *a, **k: None,
          "_hostname": lambda: "sensor"}
    for n in ARBOL.body:
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["FEEDS_CONF"] = os.path.join(tmp, "feeds.conf")
    ns["PUBLICAS_CONF"] = os.path.join(tmp, "publicas.json")
    ns["PUB_HIST"] = os.path.join(tmp, "pub-hist.json")
    ns["DNSBL_HIST"] = os.path.join(tmp, "dnsbl.json")
    ns["AIDB_CACHE"] = os.path.join(tmp, "aidb.json")
    ns["AIDB_ESTADO"] = os.path.join(tmp, "estado.json")
    ns["_avisos"] = avisos
    return ns


# Reporte con CPEs de dos nodos. El de r1 hace SSH; el de r1 tambien hace spam por 25;
# y un tercero, del OTRO nodo, tambien hace SSH (no debe salir al mirar r1).
CUARENTENA = {
    "candidatos": [
        {"ip": "10.6.1.10", "router": "r1", "riesgo": 80, "banda": "ALTO",
         "puertos_top": {"22/tcp": 900, "443/tcp": 12},
         "cats_top": {"Escaneo SSH": 700, "Fuerza bruta": 200}},
    ],
    "dns_candidatos": [],
    "top_riesgo": [
        {"ip": "10.6.1.10", "router": "r1", "riesgo": 80},
        {"ip": "10.6.1.44", "router": "r1", "riesgo": 60,
         "puertos_top": {"25/tcp": 1500}, "cats_top": {"Spam": 1400}},
        {"ip": "10.6.1.99", "router": "r1", "riesgo": 20,
         "puertos_top": {"443/tcp": 400}, "cats_top": {"Anomalia TLS/SSL": 400}},
        {"ip": "10.9.9.5", "router": "r2", "riesgo": 90,
         "puertos_top": {"22/tcp": 5000}, "cats_top": {"Escaneo SSH": 5000}},
    ],
}


def main():
    tmp = tempfile.mkdtemp()
    json.dump(CUARENTENA, open(os.path.join(tmp, "cuarentena.json"), "w", encoding="utf-8"))
    red = Red()
    ns = entorno(tmp, red)
    ns["aidb_set"]("CLAVE-DE-PRUEBA-NO-REAL")

    # --- 1) declarar las publicas del cliente ---
    ok, mal = ns["guardar_publicas_de"]("r1", "200.0.0.0/24\n190.0.2.7")
    check("se declaran IPs y redes publicas del nodo",
          ns["cargar_publicas"]().get("r1") == ["190.0.2.7", "200.0.0.0/24"] and not mal,
          (ns["cargar_publicas"](), mal))
    check("y se releen tal cual para editarlas",
          set(ns["publicas_texto"]("r1").split()) == {"190.0.2.7", "200.0.0.0/24"},
          ns["publicas_texto"]("r1"))
    ok2, mal2 = ns["guardar_publicas_de"]("r2", "10.0.0.0/8, 192.168.1.5, basura")
    check("las privadas y la basura se rechazan", ok2 == [] and len(mal2) == 3, (ok2, mal2))
    check("y se explica cada rechazo", all("(" in m for m in mal2), mal2)

    # --- 2) la traduccion categoria -> señal que SI ve Suricata ---
    pu, fi = ns["senal_de_categorias"]([22, 18])       # SSH + fuerza bruta
    check("SSH y fuerza bruta se traducen al puerto 22", "22" in pu, pu)
    check("y a las firmas de escaneo/fuerza bruta", "Escaneo SSH" in fi and "Fuerza bruta" in fi, fi)
    pu2, _ = ns["senal_de_categorias"]([11])           # spam de correo
    check("el spam de correo se traduce al 25", "25" in pu2, pu2)
    check("una categoria sin traduccion no inventa señal", ns["senal_de_categorias"]([13]) == (set(), set()))

    # --- 3) EL CRUCE: quien ensucia la publica ---
    culp = ns["culpables_de"]("r1", [22, 18])
    claves = [k for k, _c, _p, _m, _e in culp]
    check("señala al CPE que habla por 22 de ese nodo", claves and claves[0] == "r1|10.6.1.10", claves)
    check("NO acusa al que solo hace TLS", "r1|10.6.1.99" not in claves, claves)
    check("NO mezcla el CPE del OTRO nodo, aunque haga lo mismo",
          "r2|10.9.9.5" not in claves, claves)
    check("explica POR QUE lo señala", culp and any("22/tcp" in m for m in culp[0][3]), culp[0][3] if culp else None)

    culp_spam = ns["culpables_de"]("r1", [11])
    check("con spam señala al del 25, no al del 22",
          [k for k, *_r in culp_spam] == ["r1|10.6.1.44"], [k for k, *_r in culp_spam])

    check("sin categorias no se acusa a nadie", ns["culpables_de"]("r1", []) == [])

    # el que ya esta en cuarentena se marca como tal, no se propone otra vez
    ns2 = entorno(tmp, red, enviados=("r1|10.6.1.10",))
    ns2["aidb_set"]("K")
    c2 = ns2["culpables_de"]("r1", [22, 18])
    check("el que ya esta en cuarentena sale marcado",
          c2 and c2[0][0] == "r1|10.6.1.10" and c2[0][4] is True, c2[0][:1] + c2[0][3:] if c2 else None)

    # --- 4) vigilancia: serie por dia y aviso al cruzar el umbral ---
    red.guion.append({"data": {"ipAddress": "190.0.2.7", "abuseConfidenceScore": 88,
                               "totalReports": 40, "numDistinctUsers": 9,
                               "reports": [{"categories": [22, 18], "comment": "ssh"}]}})
    red.guion.append({"data": {"networkAddress": "200.0.0.0", "numPossibleHosts": 256,
                               "reportedAddress": [{"ipAddress": "200.0.0.7",
                                                    "abuseConfidenceScore": 60,
                                                    "numReports": 5,
                                                    "mostRecentReport": "2026-09-22T00:00:00+00:00",
                                                    "countryCode": "EC"}]}})
    n = ns["vigilar_publicas"]()
    check("se revisan las publicas declaradas", n == 2, n)
    h = ns["_pub_hist"]()
    check("queda el puntaje de la IP", int(h.get("190.0.2.7", {}).get("ultimo_score", 0)) == 88, h)
    check("y el PEOR de la red, que es el que importa",
          int(h.get("200.0.0.0/24", {}).get("ultimo_score", 0)) == 60, h)
    check("con serie por dia para ver si baja", bool(h.get("190.0.2.7", {}).get("dias")), h)
    check("avisa al cruzar el umbral", any("190.0.2.7" in a for a in ns["_avisos"]), ns["_avisos"])
    check("el aviso dice donde mirar quien lo causa",
          any("abonado" in a or "Panel" in a for a in ns["_avisos"]), ns["_avisos"])

    # no vuelve a avisar de lo mismo en la siguiente vuelta
    antes = len(ns["_avisos"])
    ns["vigilar_publicas"]()
    check("no repite el aviso en cada vuelta", len(ns["_avisos"]) == antes, ns["_avisos"])

    # --- 4b) EL FRENO: tu propia publica no puede ir a cuarentena ---------------
    # Con un sensor POST-NAT (espejo de la WAN), HOME_NET son los rangos PUBLICOS y el
    # panel ve las publicas como si fueran CPEs. Mandar tu IP de NAT a la address-list
    # de cuarentena deja SIN INTERNET a todos los abonados que salen por ella.
    check("una IP dentro de una red publica declarada se reconoce como TUYA",
          ns["es_publica_declarada"]("200.0.0.7") == "200.0.0.0/24",
          ns["es_publica_declarada"]("200.0.0.7"))
    check("y una IP suelta declarada tambien",
          ns["es_publica_declarada"]("190.0.2.7") == "190.0.2.7",
          ns["es_publica_declarada"]("190.0.2.7"))
    check("una publica ajena NO se confunde con las tuyas",
          ns["es_publica_declarada"]("1.1.1.1") == "", ns["es_publica_declarada"]("1.1.1.1"))
    check("ni una privada", ns["es_publica_declarada"]("10.6.1.10") == "")
    check("ni una cadena que no es IP", ns["es_publica_declarada"]("basura") == "")
    check("el borde de la red tambien cuenta (la .255)",
          ns["es_publica_declarada"]("200.0.0.255") == "200.0.0.0/24")
    check("pero la red de al lado no",
          ns["es_publica_declarada"]("200.0.1.7") == "", ns["es_publica_declarada"]("200.0.1.7"))

    # --- 5) listas negras: lo que de verdad banea -------------------------------
    # Se sustituye la resolucion DNS por una tabla, asi la prueba no depende de internet.
    RESPUESTAS = {
        # una IP con problema de verdad (equipo infectado) y ademas en SpamCop
        "226.173.224.181.zen.spamhaus.org": ["127.0.0.4"],
        "226.173.224.181.bl.spamcop.net": ["127.0.0.2"],
        # otra SOLO en la PBL: en un rango residencial eso es lo NORMAL, no un problema
        "229.173.224.181.zen.spamhaus.org": ["127.0.0.10"],
        # y una lista que rechaza la consulta (resolutor publico): no es "limpia"
        "226.173.224.181.dnsbl.sorbs.net": ["127.255.255.254"],
        "229.173.224.181.dnsbl.sorbs.net": ["127.255.255.254"],
    }

    def _resolver(nombre):
        if nombre in RESPUESTAS:
            return (nombre, [], RESPUESTAS[nombre])
        raise __import__("socket").gaierror(-2, "Name or service not known")

    ns["socket"] = types.SimpleNamespace(gethostbyname_ex=_resolver,
                                         gaierror=__import__("socket").gaierror)

    est, cods = ns["dnsbl_una"]("181.224.173.226", "zen.spamhaus.org")
    check("una IP listada se detecta", est == "listada" and cods == ["127.0.0.4"], (est, cods))
    check("una IP limpia da NXDOMAIN y se lee como limpia",
          ns["dnsbl_una"]("181.224.173.99", "zen.spamhaus.org")[0] == "limpia")
    check("y una consulta RECHAZADA no se confunde con 'limpia'",
          ns["dnsbl_una"]("181.224.173.226", "dnsbl.sorbs.net")[0] == "rechazada")

    r = ns["dnsbl_revisar"]("181.224.173.224/29")
    check("se revisa la red entera", r and r["n_ips"] >= 6, r and r["n_ips"])
    check("cuenta como listada la que tiene problema real", r["n_listadas"] == 1, r["n_listadas"])
    check("y la que solo esta en PBL se cuenta APARTE (es normal en residencial)",
          r["n_pbl"] == 1, (r["n_pbl"], r["ips"]))
    det = r["ips"].get("181.224.173.226", {})
    check("se dice en que listas y por que",
          any("equipo infectado" in x for x in det.get("listas") or [])
          and "SpamCop" in (det.get("listas") or []), det)
    check("la lista que rechazo se nombra, no se da por buena",
          "SORBS" in (r.get("rechazadas") or []), r.get("rechazadas"))

    # y el aviso solo la primera vez
    ns["cargar_publicas"] and ns["guardar_publicas_de"]("r1", "181.224.173.224/29")
    antes = len(ns["_avisos"])
    ns["vigilar_dnsbl"]()
    check("avisa cuando aparece en una lista negra",
          len(ns["_avisos"]) > antes and any("Lista negra" in a for a in ns["_avisos"]), ns["_avisos"])
    medio = len(ns["_avisos"])
    ns["vigilar_dnsbl"]()
    check("y no repite el aviso en cada vuelta", len(ns["_avisos"]) == medio, ns["_avisos"])
    h = ns["_dnsbl_hist"]()
    check("queda la serie por dia para ver si baja",
          bool(h.get("181.224.173.224/29", {}).get("dias")), h)

    # --- 6) sin nada declarado no se gasta cuota ---
    tmp3 = tempfile.mkdtemp(); red3 = Red(); ns3 = entorno(tmp3, red3)
    ns3["aidb_set"]("K")
    check("sin publicas declaradas no se llama a nadie",
          ns3["vigilar_publicas"]() == 0 and red3.llamadas == [], red3.llamadas)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
