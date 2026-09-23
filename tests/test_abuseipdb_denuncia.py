# -*- coding: utf-8 -*-
"""Denunciar atacantes a AbuseIPDB: las barreras antes de publicar nada.

Es la unica funcion del panel que publica hacia fuera y con el nombre del usuario, asi
que lo que se protege aqui son los frenos:

  - viene APAGADA: sin activarla no se llama a nadie;
  - nunca se denuncia una IP propia (denunciar tu rango te mete a VOS en las listas);
  - ni una privada, ni una de la lista 'Nunca bloquear';
  - el comentario no lleva NINGUNA IP (ni la del atacante ni la de la victima);
  - la misma IP no se repite antes de 24 h;
  - y las categorias salen de la firma de Suricata, no de un valor fijo.
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

PIEZAS = ("FEEDS_CONF", "AIDB_CACHE", "AIDB_ESTADO", "AIDB_CUOTA", "AIDB_RESERVA_MANUAL",
          "AIDB_MAX_CACHE", "AIDB_TTL_LIMPIA", "AIDB_TTL_SUCIA", "_AIDB_LOCK", "AIDB_CATS",
          "AIDB_DENUNCIAS", "AIDB_REDENUNCIA", "PANEL_FLAGS", "AIDB_FIRMA_CAT",
          "_feeds_conf_get", "_feeds_conf_set", "aidb_key", "aidb_configurada", "aidb_set",
          "aidb_ip_valida", "aidb_reportar_activo", "aidb_set_reportar", "publicar_flags",
          "aidb_cats_de_firma", "aidb_comentario", "_aidb_denuncias",
          "_aidb_guardar_denuncias", "aidb_denunciar")

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
        r = self.guion.pop(0) if self.guion else {"data": {"abuseConfidenceScore": 42}}
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


def entorno(tmp, red, mias=("10.", "1.1.1."), nunca=()):
    ns = {"json": json, "os": os, "re": re, "time": __import__("time"),
          "threading": __import__("threading"), "ipaddress": __import__("ipaddress"),
          "urllib": types.SimpleNamespace(request=red, error=urllib.error, parse=urllib.parse),
          "es_mi_cpe": lambda ip: any(ip.startswith(m) for m in mias),
          "nunca_bloquear": lambda ip: ip in nunca,
          "bitacora": lambda *a, **k: None}
    for n in ARBOL.body:
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["FEEDS_CONF"] = os.path.join(tmp, "feeds.conf")
    ns["AIDB_DENUNCIAS"] = os.path.join(tmp, "denuncias.json")
    ns["PANEL_FLAGS"] = os.path.join(tmp, "flags.json")
    return ns


def main():
    tmp = tempfile.mkdtemp()
    red = Red()
    ns = entorno(tmp, red)
    ns["aidb_set"]("CLAVE-DE-PRUEBA-NO-REAL")

    # --- 1) apagada de fabrica ---
    check("las denuncias vienen APAGADAS", ns["aidb_reportar_activo"]() is False)
    ok, det = ns["aidb_denunciar"]("1.1.1.1", firma="ET SCAN portscan")
    check("apagada, no se llama a nadie", red.llamadas == [] and not ok, (red.llamadas, det))
    check("y se dice donde se activa", "Ajustes" in det, det)

    ns["aidb_set_reportar"](True)
    check("se puede activar", ns["aidb_reportar_activo"]() is True)
    flags = json.load(open(ns["PANEL_FLAGS"], encoding="utf-8"))
    check("y se publica para el reporte", flags.get("aidb_reportar") is True, flags)
    check("el archivo publicado NO lleva la clave",
          "CLAVE-DE-PRUEBA-NO-REAL" not in open(ns["PANEL_FLAGS"], encoding="utf-8").read())

    # --- 2) lo que NUNCA se denuncia ---
    # el caso que de verdad importa: tu propio rango PUBLICO de NAT. Denunciarlo te mete
    # a VOS en las listas negras, asi que tiene que frenarse aunque sea una IP publica.
    ok, det = ns["aidb_denunciar"]("1.1.1.1", firma="x")
    check("una IP PUBLICA que es tuya (tu NAT) no se denuncia",
          not ok and red.llamadas == [], det)
    check("y se explica por que", "TUS redes" in det, det)
    ok, det = ns["aidb_denunciar"]("10.6.1.165", firma="x")
    check("una IP de abonado tampoco", not ok and red.llamadas == [], det)
    ok, det = ns["aidb_denunciar"]("192.168.1.1", firma="x")
    check("una IP privada tampoco", not ok and red.llamadas == [], det)
    ns2 = entorno(tempfile.mkdtemp(), red, nunca=("9.9.9.9",))
    ns2["aidb_set"]("K"); ns2["aidb_set_reportar"](True)
    ok, det = ns2["aidb_denunciar"]("9.9.9.9", firma="x")
    check("una IP de 'Nunca bloquear' tampoco", not ok and red.llamadas == [], det)

    # --- 3) denuncia buena ---
    ok, det = ns["aidb_denunciar"]("8.8.8.8", firma="ET SCAN Potential SSH Scan from 203.0.113.9",
                                   dport="22", proto="TCP", n=140, quien="operador1")
    check("una IP publica ajena SI se denuncia", ok and len(red.llamadas) == 1, (ok, det))
    cuerpo = urllib.parse.parse_qs((red.llamadas[0]["data"] or b"").decode("utf-8"))
    check("la clave viaja en la cabecera Key",
          red.llamadas[0]["headers"].get("Key") == "CLAVE-DE-PRUEBA-NO-REAL")
    check("se manda la IP denunciada", cuerpo.get("ip") == ["8.8.8.8"], cuerpo)
    cats = (cuerpo.get("categories") or [""])[0]
    check("con las categorias que tocan: un 'SSH Scan' es SSH y escaneo, NO fuerza bruta",
          cats == "22,14", cats)
    com = (cuerpo.get("comment") or [""])[0]
    check("el comentario dice de donde sale", com.startswith("Suricata IDS"), com)
    check("NO lleva ninguna IP (ni la tuya ni la del atacante)",
          not re.search(r"\d{1,3}(?:\.\d{1,3}){3}", com), com)
    check("pero si el puerto y el volumen", "22/tcp" in com and "140 alertas" in com, com)

    # --- 4) no se repite antes de 24 h ---
    antes = len(red.llamadas)
    ok2, det2 = ns["aidb_denunciar"]("8.8.8.8", firma="ET SCAN otra vez")
    check("la misma IP no se redenuncia enseguida", not ok2 and len(red.llamadas) == antes, det2)
    check("y dice cuando se denuncio", "24 h" in det2, det2)

    # --- 5) las categorias salen de la firma, no de un valor fijo ---
    casos = [("ET SCAN SSH brute force attempt", "", [22, 14, 18]),
             ("ET SCAN Nmap Scripting Engine", "", [14]),
             ("ET WEB_SERVER SQL Injection attempt", "", [16, 21]),
             ("ET EXPLOIT Mirai telnet", "", [23, 15]),
             ("ET VOIP asterisk friendly-scanner", "", [14, 8]),
             ("firma que nadie reconoce", "", [15]),
             ("", "22", [18, 22])]
    for firma, dp, esperado in casos:
        got = ns["aidb_cats_de_firma"](firma, dp)
        check("categorias de %r" % (firma or ("puerto " + dp)), got == esperado, got)

    # --- 6) el comentario aguanta basura ---
    sucio = ns["aidb_comentario"]("ataque desde 10.6.1.165 y 2001:db8::1 <script>x</script>", "", "", 0)
    check("se limpian IPv4, IPv6 y caracteres raros",
          not re.search(r"\d{1,3}(?:\.\d{1,3}){3}", sucio) and "2001:db8" not in sucio
          and "<" not in sucio, sucio)

    # --- 7) un 429 no se traga ---
    red.guion.append(urllib.error.HTTPError("https://api.abuseipdb.com/", 429, "x", {}, None))
    ok3, det3 = ns["aidb_denunciar"]("9.9.9.9", firma="ET SCAN x")
    check("si se agota la cuota de denuncias, se dice", not ok3 and "cuota" in det3, det3)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
