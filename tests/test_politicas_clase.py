# -*- coding: utf-8 -*-
"""Politicas por clase de abuso: que hacer depende de QUE hace el CPE, no solo de cuanto puntua.

Lo que se protege:
  - herencia: una caja con ALTO=cuarentena y sin POL_<CLASE> sigue haciendo lo mismo en
    todas las clases (nada cambia en produccion por actualizar); 'dns' contaba como corte;
  - la decision: 'alto' corta solo en ALTO, 'medio' en MEDIO y ALTO, 'siempre' en todas,
    'notificar' avisa, 'nada' nada;
  - aplicar_politicas manda a la lista de la CLASE (no a la heredada), guarda clase y lista
    en el registro, y libera de la lista guardada, no de la que tocaria hoy;
  - un CPE de clase P2P con politica 'nada' no se corta aunque su riesgo sea ALTO;
  - el barrido rapido se rige por la politica de botnet, no por POL_ALTO;
  - el formulario tiene un select por clase con su lista al lado, y la ruta guarda
    POL_<CLASE> ignorando valores que no sean de la lista.
"""
import ast
import json
import os
import sys
import tempfile

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
    ns = {"json": json, "os": os, "time": __import__("time"), "html": __import__("html")}
    ns.update(extra or {})
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


BASE = ("CAT_CPE", "CAT_OTROS", "POL_CLASE", "POL_CLASE_VALORES", "_BANDA_NIVEL", "_POL_UMBRAL",
        "_politica_heredada", "politica_de_clase", "accion_para", "categoria_de_cats")


def main():
    ns = piezas(BASE, {"_mk_globales": lambda: {}})
    pdc = ns["politica_de_clase"]; acc = ns["accion_para"]

    # --- herencia desde las bandas ----------------------------------------------------
    viejo = {"POL_BAJO": "nada", "POL_MEDIO": "nada", "POL_ALTO": "cuarentena"}
    check("ALTO=cuarentena sin POL_<CLASE> -> 'alto' en todas las clases (P2P incluido)",
          all(pdc(c, viejo) == "alto" for c, *_ in ns["CAT_CPE"] + [ns["CAT_OTROS"]]), "")
    check("MEDIO=cuarentena -> 'medio'", pdc("botnet", {"POL_MEDIO": "cuarentena"}) == "medio", "")
    check("BAJO=dns (era una cuarentena a la lista DNS) -> 'siempre'",
          pdc("dns", {"POL_BAJO": "dns"}) == "siempre", "")
    check("solo notificar en alguna banda -> 'notificar'", pdc("spam", {"POL_ALTO": "notificar"}) == "notificar", "")
    check("nada de nada -> 'nada'", pdc("spam", {}) == "nada", "")
    check("y POL_<CLASE> manda sobre lo heredado",
          pdc("p2p", {"POL_ALTO": "cuarentena", "POL_P2P": "nada"}) == "nada"
          and pdc("botnet", {"POL_ALTO": "cuarentena", "POL_P2P": "nada"}) == "alto", "")
    check("un valor raro en POL_<CLASE> se ignora y cae a lo heredado",
          pdc("botnet", {"POL_ALTO": "cuarentena", "POL_BOTNET": "zzz"}) == "alto", "")

    # --- la decision --------------------------------------------------------------------
    for pol, esperado in (("alto", {"BAJO": "nada", "MEDIO": "nada", "ALTO": "cuarentena"}),
                          ("medio", {"BAJO": "nada", "MEDIO": "cuarentena", "ALTO": "cuarentena"}),
                          ("siempre", {"BAJO": "cuarentena", "MEDIO": "cuarentena", "ALTO": "cuarentena"}),
                          ("notificar", {"BAJO": "notificar", "MEDIO": "notificar", "ALTO": "notificar"}),
                          ("nada", {"BAJO": "nada", "MEDIO": "nada", "ALTO": "nada"})):
        got = {b: acc("botnet", b, {"POL_BOTNET": pol}) for b in ("BAJO", "MEDIO", "ALTO")}
        check("politica '%s' decide bien por banda" % pol, got == esperado, got)
    check("banda desconocida nunca corta", acc("botnet", "", {"POL_BOTNET": "siempre"}) == "nada", "")

    # --- aplicar_politicas con dobles ---------------------------------------------------
    td = tempfile.mkdtemp()
    cq = {"top_riesgo": [
        {"ip": "10.0.0.7", "router": "", "riesgo": 85, "banda": "ALTO", "cats_top": {"Botnet CnC": 20}},
        {"ip": "10.0.0.8", "router": "", "riesgo": 80, "banda": "ALTO", "cats_top": {"BitTorrent / P2P": 90}},
        {"ip": "10.0.0.9", "router": "", "riesgo": 50, "banda": "MEDIO", "cats_top": {"Fuerza bruta": 30}},
        {"ip": "10.0.0.10", "router": "", "riesgo": 45, "banda": "MEDIO", "cats_top": {"Spam": 30}},
    ]}
    json.dump(cq, open(os.path.join(td, "cuarentena.json"), "w"))
    m = {"ENABLED": "1", "POL_AUTO": "1", "POL_BOTNET": "alto", "POL_P2P": "nada",
         "POL_FUERZA": "medio", "POL_SPAM": "notificar", "POL_ALTO": "cuarentena"}
    anadidos = []; quitados = []; logs = []
    envs = {"sent": {"r0|10.0.0.99": {"pol": True, "lista": "lista-vieja", "router": ""}}, "dns": {}}
    def mk_add(ip, comment="", lista="", ttl="", router=None):
        anadidos.append((ip, lista)); return True, ""
    def mk_remove(ip, lista="", router=None):
        quitados.append((ip, lista)); return True
    def cargar_enviados(path):
        return dict(envs["sent"] if path == "SENT" else envs["dns"])
    def guardar_enviados(env, path):
        envs["sent" if path == "SENT" else "dns"] = env
    extra = {"_mk_globales": lambda: m, "cargar_mk": lambda: m, "mk_configurado": lambda: True,
             "LOGDIR": td, "POL_NOTIF": os.path.join(td, "notif.json"),
             "clave_cpe": lambda ip, rid: ("r0|" + ip), "ip_de": lambda k: k.split("|")[-1],
             "router_de_clave": lambda k: {"id": "r0"}, "cargar_mk_de": lambda r: {"ENABLED": "1", "LIST": "heredada"},
             "lista_de_categoria": lambda c: "clientes-" + c, "mk_add": mk_add, "mk_remove": mk_remove,
             "cargar_enviados": cargar_enviados, "guardar_enviados": guardar_enviados,
             "MK_SENT": "SENT", "MK_SENT_DNS": "DNS", "_motivo_bloqueo": lambda k: {},
             "notificar_cuarentena": lambda *a, **k: None, "_suf_nodo": lambda k: "",
             "mk_log": lambda accion, ip, quien, det="": logs.append((accion, ip, det))}
    ns2 = piezas(BASE + ("aplicar_politicas",), extra)
    ns2["aplicar_politicas"]()
    check("la botnet ALTA va a la lista de SU clase, no a la heredada",
          ("10.0.0.7", "clientes-botnet") in anadidos, anadidos)
    check("la fuerza bruta MEDIA tambien (politica 'medio')", ("10.0.0.9", "clientes-fuerza") in anadidos, anadidos)
    check("el P2P ALTO con politica 'nada' NO se corta", not any(ip == "10.0.0.8" for ip, _l in anadidos), anadidos)
    check("el spam 'notificar' no se corta y deja bitacora",
          not any(ip == "10.0.0.10" for ip, _l in anadidos)
          and any(a == "POLITICA-NOTIFICAR" and ip == "10.0.0.10" and "clase=spam" in d for a, ip, d in logs), logs)
    e7 = envs["sent"].get("r0|10.0.0.7", {})
    check("el registro guarda clase y lista", e7.get("categoria") == "botnet" and e7.get("lista") == "clientes-botnet"
          and e7.get("pol") is True, e7)
    check("el que ya no califica sale de la lista GUARDADA, no de la de hoy",
          ("10.0.0.99", "lista-vieja") in quitados and "r0|10.0.0.99" not in envs["sent"], quitados)
    check("nadie va a la lista heredada", not any(l == "heredada" for _ip, l in anadidos), anadidos)

    # --- barrido rapido: se rige por la politica de botnet ------------------------------
    br = DASH[DASH.index("def barrido_alto_rapido"):]
    br = br[:br.index("\ndef ", 10)]
    check("el barrido rapido mira la politica de botnet, no POL_ALTO",
          'politica_de_clase("botnet", m) not in _POL_UMBRAL' in br and "POL_ALTO" not in br, "")
    check("y ya no exige la lista heredada", 'lst = m.get("LIST", "")' not in br, "")

    # --- formulario y ruta ---------------------------------------------------------------
    ns3 = piezas(BASE + ("_card_politicas",), {"_mk_globales": lambda: {}, "lista_de_categoria": lambda c: "clientes-" + c})
    h = ns3["_card_politicas"]({"POL_ALTO": "cuarentena", "POL_P2P": "nada", "POL_AUTO": "1"})
    check("un select por clase (8)", h.count("<select name='pol_") == 8, h.count("<select name='pol_"))
    check("con la lista de la clase al lado", "clientes-botnet" in h and "clientes-p2p" in h, "")
    check("P2P sale en 'nada' y botnet heredado en 'alto'",
          "<option value='nada' selected>" in h[h.index("pol_p2p"):]
          and "<option value='alto' selected>" in h[h.index("pol_botnet"):h.index("pol_dns")], "")
    check("ya no hay selects por banda", "pol_bajo" not in h and "pol_alto'" not in h and "Riesgo BAJO" not in h, "")
    ruta = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta = ruta[:ruta.index('if ruta == "/routers/')]
    check("la ruta guarda POL_<CLASE> validando contra la lista",
          '_v in POL_CLASE_VALORES' in ruta and 'm["POL_" + _cat.upper()] = _v' in ruta
          and 'm["POL_ALTO"] =' not in ruta, "")
    check("la documentacion explica el por que",
          "politicas por clase de abuso" in SRC and "el riesgo mide <i>cuanto</i>, no <i>que</i>" in SRC, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
