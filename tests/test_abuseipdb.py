# -*- coding: utf-8 -*-
"""Consultas a AbuseIPDB: cuota diaria, cache, privacidad y categorias.

La cuota gratuita es de 1.000 consultas al DIA. Lo que se protege aqui es que el panel
no se la gaste sola y que nunca mande al exterior una IP de un abonado:

  - una IP privada no sale del servidor (ni una peticion);
  - lo que ya esta en cache no gasta cuota;
  - lo automatico no puede comerse la reserva del operador;
  - un 429 corta las llamadas en vez de insistir;
  - sin clave no se llama a nadie;
  - y la clave no aparece jamas en el HTML.

Nota sobre las IPs de prueba: aqui NO se pueden usar los rangos de documentacion
(192.0.2.x, 198.51.100.x, 203.0.113.x) para el camino que SI consulta, porque el panel
los rechaza a proposito: no son direcciones publicas y AbuseIPDB las devolveria con un
error. Se usan resolutores publicos conocidos (1.1.1.1, 8.8.8.8, 9.9.9.9), que no son de
nadie del usuario; los rangos de documentacion se usan justo para comprobar que SE
RECHAZAN.
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

PIEZAS = ("FEEDS_CONF", "AIDB_CACHE", "AIDB_ESTADO", "AIDB_TTL_LIMPIA", "AIDB_TTL_SUCIA",
          "AIDB_CUOTA", "AIDB_RESERVA_MANUAL", "AIDB_MAX_LOTE", "AIDB_MAX_CACHE",
          "_AIDB_LOCK", "AIDB_CATS", "AIDB_REMEDIO",
          "_feeds_conf_get", "_feeds_conf_set", "aidb_key", "aidb_configurada", "aidb_set",
          "_aidb_estado", "_aidb_guardar_estado", "aidb_restantes", "_aidb_cache",
          "_aidb_guardar_cache", "aidb_ip_valida", "_aidb_pedir", "_aidb_resumen",
          "aidb_consultar", "aidb_cats_txt", "reputacion_page",
          "AIDB_CUOTA_BLOQUE", "AIDB_PREFIJO_MIN", "aidb_restantes_bloque",
          "aidb_red_valida", "_aidb_pedir_red", "_aidb_resumen_red", "aidb_consultar_red",
          "aidb_lote",
          # bloque "Tus IPs publicas" de la pagina
          "PUBLICAS_CONF", "PUB_HIST", "PUB_HIST_DIAS", "PUB_UMBRAL_AVISO", "_PUB_LOCK",
          "AIDB_SENAL", "cargar_publicas", "guardar_publicas", "publicas_texto",
          "guardar_publicas_de", "_pub_hist", "_guardar_pub_hist", "_peor_de", "_cats_de",
          "senal_de_categorias", "_cpes_del_nodo", "culpables_de",
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
    """AbuseIPDB de mentira: apunta cada llamada y devuelve lo que le digan."""
    def __init__(self):
        self.llamadas = []
        self.guion = []          # cola de respuestas: dict (ok) o HTTPError

    def Request(self, url, headers=None):
        return {"url": url, "headers": headers or {}}

    def urlopen(self, req, timeout=None):
        self.llamadas.append(req)
        r = self.guion.pop(0) if self.guion else {"data": {"ipAddress": "?",
                                                           "abuseConfidenceScore": 0}}
        if isinstance(r, Exception):
            raise r
        cuerpo = json.dumps(r).encode("utf-8")

        class Resp:
            def read(self, n=None):
                return cuerpo
            def __enter__(self_in):
                return self_in
            def __exit__(self_in, *a):
                return False
        return Resp()


def http(code, cabeceras=None):
    return urllib.error.HTTPError("https://api.abuseipdb.com/", code, "x",
                                  cabeceras or {}, None)


def entorno(tmp, red):
    ns = {"json": json, "os": os, "re": re, "time": __import__("time"), "html": __import__("html"),
          "threading": __import__("threading"), "ipaddress": __import__("ipaddress"),
          "socket": __import__("socket"),
          "ThreadPoolExecutor": __import__("concurrent.futures", fromlist=["futures"]).ThreadPoolExecutor,
          "urllib": types.SimpleNamespace(request=red, error=urllib.error, parse=urllib.parse),
          "BASE_CSS": "", "nav": lambda a="": "<!--nav-->",
          "cargar_routers": lambda: [], "cargar_enviados": lambda *a, **k: {},
          "MK_SENT": "", "MK_SENT_DNS": "", "LOGDIR": tmp,
          "clave_cpe": lambda ip, rid: (rid + "|" + ip) if rid else ip,
          "ip_de": lambda k: k.split("|", 1)[1] if "|" in k else k}
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
    ns["AIDB_ESTADO"] = os.path.join(tmp, "aidb-estado.json")
    return ns


FICHA = {"data": {
    "ipAddress": "1.1.1.1", "abuseConfidenceScore": 100, "countryCode": "NL",
    "usageType": "Data Center/Web Hosting/Transit", "isp": "Ejemplo Hosting BV",
    "domain": "ejemplo.test", "isTor": False, "isWhitelisted": False,
    "totalReports": 412, "numDistinctUsers": 90, "lastReportedAt": "2026-09-20T10:00:00+00:00",
    "reports": [
        {"categories": [18, 22], "comment": "Invalid user oracle from 1.1.1.1"},
        {"categories": [22], "comment": "sshd: failed password"},
        {"categories": [14], "comment": "port scan"},
    ]}}


def main():
    tmp = tempfile.mkdtemp()
    red = Red()
    ns = entorno(tmp, red)

    # --- 1) sin clave no se llama a nadie ---
    d, orig, err = ns["aidb_consultar"]("1.1.1.1")
    check("sin clave no se hace ninguna peticion", red.llamadas == [] and d is None, (red.llamadas, err))
    check("y se dice por que", err == "sin clave", err)

    ns["aidb_set"]("CLAVE-DE-PRUEBA-NO-REAL")
    check("la clave queda guardada en el .conf", ns["aidb_configurada"]() is True)
    check("con permisos y sin mostrarse", isinstance(ns["aidb_configurada"](), bool))

    # --- 2) una IP privada NUNCA sale del servidor ---
    for priv in ("10.6.1.165", "192.168.1.1", "172.19.1.3", "100.64.0.9"):
        d, orig, err = ns["aidb_consultar"](priv)
        check("la IP de abonado %s no se envia" % priv, red.llamadas == [] and d is None, red.llamadas)
    for doc in ("192.0.2.1", "198.51.100.10", "203.0.113.7"):
        d, orig, err = ns["aidb_consultar"](doc)
        check("el rango de documentacion %s tampoco (no es publico)" % doc,
              red.llamadas == [] and d is None, red.llamadas)
    d, orig, err = ns["aidb_consultar"]("no-es-una-ip")
    check("una cadena que no es IP se rechaza sin llamar", red.llamadas == [] and "no es una IP" in err, err)

    # --- 3) consulta real: categorias en castellano y que corregir ---
    red.guion.append(FICHA)
    d, orig, err = ns["aidb_consultar"]("1.1.1.1")
    check("se consulta la API", len(red.llamadas) == 1 and orig == "api", (len(red.llamadas), orig, err))
    check("la clave viaja en la cabecera Key",
          red.llamadas[0]["headers"].get("Key") == "CLAVE-DE-PRUEBA-NO-REAL", red.llamadas[0]["headers"])
    check("se pide el detalle (verbose): sin el no hay categorias",
          "verbose" in red.llamadas[0]["url"], red.llamadas[0]["url"])
    check("sale el puntaje", d.get("score") == 100, d)
    check("y el operador", d.get("isp") == "Ejemplo Hosting BV", d)
    cats = dict((int(c), int(n)) for c, n in d.get("cats") or [])
    check("cuenta las categorias denunciadas", cats.get(22) == 2 and cats.get(18) == 1 and cats.get(14) == 1, cats)
    txt = ns["aidb_cats_txt"](d["cats"])
    check("y las traduce: eso es 'que ataques hace'", "SSH" in txt and "Fuerza bruta" in txt, txt)
    check("guarda ejemplos del texto de las denuncias", len(d.get("ejemplos") or []) == 3, d.get("ejemplos"))

    # --- 4) la cache no gasta cuota ---
    antes = len(red.llamadas)
    d2, orig2, _ = ns["aidb_consultar"]("1.1.1.1")
    check("repetir la misma IP sale de cache", orig2 == "cache" and len(red.llamadas) == antes,
          (orig2, len(red.llamadas)))
    check("y devuelve lo mismo", d2.get("score") == 100, d2)
    check("la cuota gastada es 1, no 2", ns["aidb_restantes"]() == ns["AIDB_CUOTA"] - 1,
          ns["aidb_restantes"]())

    # --- 5) forzar ignora la cache (y entonces si gasta) ---
    red.guion.append(FICHA)
    _d, orig3, _ = ns["aidb_consultar"]("1.1.1.1", refrescar=True)
    check("se puede forzar una consulta nueva", orig3 == "api" and len(red.llamadas) == antes + 1,
          (orig3, len(red.llamadas)))

    # --- 6) lo automatico no se come la reserva del operador ---
    est = ns["_aidb_estado"]()
    est["gastadas"] = ns["AIDB_CUOTA"] - ns["AIDB_RESERVA_MANUAL"]
    ns["_aidb_guardar_estado"](est)
    antes = len(red.llamadas)
    d4, _o, err4 = ns["aidb_consultar"]("8.8.8.8", auto=True)
    check("el enriquecimiento automatico se frena en la reserva",
          len(red.llamadas) == antes and d4 is None, (len(red.llamadas), err4))
    check("y lo dice", "automatico" in err4, err4)
    red.guion.append(FICHA)
    _d5, orig5, _e = ns["aidb_consultar"]("8.8.8.8")
    check("pero el operador SI puede seguir consultando a mano",
          orig5 == "api" and len(red.llamadas) == antes + 1, (orig5, len(red.llamadas)))

    # --- 7) un 429 corta, no insiste ---
    red.guion.append(http(429, {"Retry-After": "1800"}))
    _d6, _o6, err6 = ns["aidb_consultar"]("9.9.9.9")
    check("un 429 se traduce a 'cuota agotada'", "cuota" in (err6 or ""), err6)
    antes = len(red.llamadas)
    _d7, _o7, err7 = ns["aidb_consultar"]("9.9.9.10")
    check("y a partir de ahi NO se vuelve a llamar", len(red.llamadas) == antes, len(red.llamadas))
    check("pero lo cacheado se sigue sirviendo",
          ns["aidb_consultar"]("1.1.1.1")[1] == "cache")

    # --- 8) la clave no aparece nunca en la pagina ---
    ns["aidb_restantes"] = lambda: 900
    ns["aidb_restantes_bloque"] = lambda: 100
    pag = ns["reputacion_page"](res=[("1.1.1.1", d, "cache", "")])
    check("la clave NO se filtra al HTML", "CLAVE-DE-PRUEBA-NO-REAL" not in pag)
    check("la pagina muestra las categorias en castellano", "SSH" in pag and "Escaneo de puertos" in pag)
    check("y que suele haber detras", "Que suele haber detras" in pag)
    check("y cuanta cuota queda", "900" in pag)

    # --- 9) una RED entera: UNA peticion cubre todas sus direcciones ---
    tmp3 = tempfile.mkdtemp(); red3 = Red(); ns3 = entorno(tmp3, red3)
    ns3["aidb_set"]("K")
    BLOQUE = {"data": {"networkAddress": "200.0.0.0", "netmask": "255.255.255.0",
                       "numPossibleHosts": 256, "addressSpaceDesc": "Public",
                       "reportedAddress": [
                           {"ipAddress": "200.0.0.7", "numReports": 90,
                            "abuseConfidenceScore": 100, "mostRecentReport": "2026-09-21T10:00:00+00:00",
                            "countryCode": "EC"},
                           {"ipAddress": "200.0.0.9", "numReports": 3,
                            "abuseConfidenceScore": 22, "mostRecentReport": "2026-09-19T10:00:00+00:00",
                            "countryCode": "EC"}]}}
    red3.guion.append(BLOQUE)
    d9, o9, e9 = ns3["aidb_consultar_red"]("200.0.0.0/24")
    check("una /24 se resuelve con UNA sola peticion, no 256",
          len(red3.llamadas) == 1 and o9 == "api", (len(red3.llamadas), o9, e9))
    check("se usa el endpoint de bloques", "check-block" in red3.llamadas[0]["url"], red3.llamadas[0]["url"])
    check("dice cuantas direcciones tiene la red", d9.get("hosts") == 256, d9)
    check("y cuales estan denunciadas", d9.get("n_den") == 2, d9)
    check("ordenadas de peor a mejor", d9["denunciadas"][0][0] == "200.0.0.7", d9["denunciadas"])
    check("gasta la cuota de REDES, no la de IPs",
          ns3["aidb_restantes_bloque"]() == ns3["AIDB_CUOTA_BLOQUE"] - 1
          and ns3["aidb_restantes"]() == ns3["AIDB_CUOTA"], 
          (ns3["aidb_restantes_bloque"](), ns3["aidb_restantes"]()))
    n9 = len(red3.llamadas)
    _d, o9b, _e = ns3["aidb_consultar_red"]("200.0.0.0/24")
    check("repetirla sale de cache", o9b == "cache" and len(red3.llamadas) == n9, o9b)

    # redes que NO se consultan
    for mala, porque in (("10.0.0.0/8", "privada"), ("192.168.0.0/16", "privada"),
                         ("200.0.0.0/8", "demasiado grande"), ("no-es-red/24", "invalida")):
        n = len(red3.llamadas)
        _d, _o, err = ns3["aidb_consultar_red"](mala)
        check("la red %s no se consulta (%s)" % (mala, porque),
              len(red3.llamadas) == n and err, err)

    # el 402 del plan se explica en vez de salir como error generico
    red3.guion.append(urllib.error.HTTPError("https://api.abuseipdb.com/", 402, "x", {}, None))
    _d, _o, err402 = ns3["aidb_consultar_red"]("200.1.0.0/20")
    check("si el plan no llega a ese tamaño, se dice", "plan" in (err402 or ""), err402)

    # --- 10) el repartidor: mezcla de IPs y redes en el mismo cuadro ---
    tmp4 = tempfile.mkdtemp(); red4 = Red(); ns4 = entorno(tmp4, red4)
    ns4["aidb_set"]("K")
    red4.guion.extend([BLOQUE, FICHA])
    lote, aviso = ns4["aidb_lote"]("200.0.0.0/24, 1.1.1.1")
    check("se pueden mezclar redes e IPs", len(lote) == 2 and not aviso, (len(lote), aviso))
    check("la red va al endpoint de bloques y la IP al de siempre",
          "check-block" in red4.llamadas[0]["url"] and "check?" in red4.llamadas[1]["url"],
          [c["url"][:60] for c in red4.llamadas])
    check("la red se marca como tal para pintarla distinto",
          lote[0][1].get("tipo") == "red" and lote[1][1].get("tipo") != "red", lote[0][1].get("tipo"))
    n4 = len(red4.llamadas)
    ns4["aidb_lote"]("1.1.1.1 1.1.1.1 1.1.1.1")
    check("una IP repetida en el mismo pegado no se consulta 3 veces",
          len(red4.llamadas) == n4, len(red4.llamadas))

    # --- 11) la vuelta: mirar una direccion de una red no puede dejarte encallado ----
    # Fallo dos veces: primero porque la consulta iba por POST (Atras pedia reenviar el
    # formulario) y luego porque el enlace de vuelta quedaba encima de un bloque largo,
    # o sea fuera de la pantalla.
    pag_red = ns["reputacion_page"](res=[("200.0.0.0/24",
                                          {"tipo": "red", "red": "200.0.0.0/24", "hosts": 256,
                                           "n_den": 1, "ts": 0,
                                           "denunciadas": [["200.0.0.7", 38, 11, "2026-09-19", "EC"]]},
                                          "cache", "")], texto="200.0.0.0/24")
    check("el formulario va por GET, para que el boton Atras funcione",
          "method=get" in pag_red and "method=post action='/reputacion'" not in pag_red)
    check("cada direccion de la red recuerda de donde viene",
          "volver=200.0.0.0/24" in pag_red, pag_red[pag_red.find("ver que hace") - 200:][:200])

    pag_ip = ns["reputacion_page"](res=[("200.0.0.7", d, "cache", "")],
                                   texto="200.0.0.7", volver="200.0.0.0/24")
    check("al mirar una direccion hay boton de vuelta a su red",
          "Volver a 200.0.0.0/24" in pag_ip)
    check("se dice CUANDO se verifico, no de donde salio el dato",
          "ultima verificacion" in pag_ip and "de cache" not in pag_ip, "")
    check("y la vuelta va ANTES del resultado, no al final de la pagina",
          pag_ip.index("Volver a 200.0.0.0/24") < pag_ip.index("Confianza de abuso"),
          (pag_ip.index("Volver a 200.0.0.0/24"), pag_ip.index("Confianza de abuso")))
    check("sin red de origen igual hay vuelta",
          "Volver a Consultar IP" in ns["reputacion_page"](res=[("1.1.1.1", d, "cache", "")]))
    check("y sin consulta no se pinta ninguna vuelta",
          "class=volver" not in ns["reputacion_page"]())

    # --- interfaz: ni cajones enormes ni titulos repetidos ---
    ns["cargar_routers"] = lambda: [{"id": "r1", "nombre": "MikroTik"}]
    ns["guardar_publicas_de"]("r1", "200.0.0.0/24")
    adm = ns["reputacion_page"](es_admin=True)
    check("las IPs declaradas se ven como fichas, no en un textarea",
          "pchip" in adm and "<textarea" not in adm, "textarea=%s" % ("<textarea" in adm))
    check("se agregan de una en una, en un campo pequeño",
          "action='/publicas/agregar'" in adm and "size=20" in adm)
    check("y cada ficha se puede quitar", "action='/publicas/quitar'" in adm)
    check("el titulo 'Tus IPs publicas' no sale dos veces",
          adm.count("Tus IPs publicas") == 1, adm.count("Tus IPs publicas"))
    check("el buscador es un campo pequeño en la cabecera, no una seccion",
          "name=ips size=22" in adm and "class=busca" in adm, "")
    check("ya no hay una seccion aparte 'Consultar cualquier IP o red'",
          "Consultar cualquier IP" not in adm)
    # dos controles llamados casi igual en la misma tarjeta confundian: uno abre el
    # detalle y el otro refresca de verdad
    check("solo hay UN 'Revisar ahora'",
          adm.lower().count("revisar ahora") == 1, adm.lower().count("revisar ahora"))
    check("y el enlace del detalle dice lo que hace", "ver detalle" in adm)

    # --- 12) una clave rechazada no se confunde con 'sin red' ---
    tmp2 = tempfile.mkdtemp(); red2 = Red(); ns2 = entorno(tmp2, red2)
    ns2["aidb_set"]("MALA")
    red2.guion.append(http(401))
    _d8, _o8, err8 = ns2["aidb_consultar"]("1.1.1.1")
    check("una clave rechazada se dice tal cual", "rechazo la clave" in (err8 or ""), err8)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
