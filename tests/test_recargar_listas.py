# -*- coding: utf-8 -*-
"""Las IPs en cuarentena, entre el panel y las address-lists del MikroTik.

De donde sale:
  - el user pidio un boton para volver a cargar en el router las IPs del panel si las
    listas se vacian ("si estan, perfecto, lo omite");
  - al mirarlo salio un fallo: la sincronizacion de cada 5 minutos comparaba TODO con la
    lista vieja unica (LIST). Un CPE en clientes-botnet no estaba ahi, asi que se soltaba
    del registro aunque siguiera bloqueado: el panel lo olvidaba, el liberador ya no podia
    sacarlo y la politica lo volvia a mandar en el ciclo siguiente.

Lo que se protege:
  - sync: cada entrada contra SU lista; lo que esta, se marca en el router;
  - sync: una entrada permanente que falta en el router NO se olvida, queda "falta en el
    router"; una con TTL que falta se suelta (caduco); lo desconocido se registra con su
    lista; un router que no responde no toca lo suyo;
  - recargar: carga SOLO las que faltan, omite las que estan y las de "nunca bloquear",
    con una conexion, respetando la permanencia (politica sin TTL), y las marca en el router.
"""
import ast
import json
import os
import sys
import tempfile
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "tests"))
import test_acciones_router as base          # RouterFalso: la API de RouterOS de mentira

SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_mk_ips_listas_en", "_mk_ips_listas", "_rid_entrada", "mk_sync_enviados", "recargar_listas",
          "cargar_enviados", "_ttl_efectivo", "ACCIONES_POR_CAT")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(cfg=None, nunca=()):
    rt = base.RouterFalso()
    td = tempfile.mkdtemp()
    conex = []
    bit = []
    m = {"HOST": "192.0.2.1", "USER": "u", "PASS": "p", "ENABLED": "1", "LIST": "suricata-cuarentena",
         "TTL": "", "AUTO_MANTENER": "1"}
    m.update(cfg or {})

    def guardar(d, path):
        json.dump(d, open(path, "w", encoding="utf-8"))

    ns = {"json": json, "os": os, "time": time, "_ENV_LOCK": threading.RLock(),
          "MK_SENT": os.path.join(td, "env.json"), "MK_SENT_DNS": os.path.join(td, "envd.json"),
          "cargar_routers": lambda: [dict(m, id="r1")], "cargar_mk_de": lambda r: dict(m),
          "mk_conectar": lambda d, timeout=6: (conex.append(1), rt)[1],
          "_mk_send": lambda s_, words: s_.enviar(words), "_mk_reply": lambda s_: s_.responder(),
          "lista_de_categoria": lambda c: "clientes-" + c,
          "clave_cpe": lambda ip, rid: (rid + "|" + ip) if rid else ip,
          "rid_de": lambda k: k.split("|")[0] if "|" in k else "", "ip_de": lambda k: k.split("|")[-1],
          "nunca_bloquear": lambda ip: ip in nunca, "bitacora": lambda a, d="", quien=None, ip=None: bit.append((a, d)),
          "guardar_enviados": lambda d, path=None: guardar(d, path)}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n), ns)
    return ns, rt, conex, bit


def al(rt, lista, ip):
    rt.t["/ip/firewall/address-list"].append({".id": rt._id(), "list": lista, "address": ip})


def main():
    # ===================== sync =====================
    ns, rt, conex, _b = entorno()
    al(rt, "clientes-botnet", "10.0.0.5")
    al(rt, "clientes-spam", "10.0.0.77")                      # puesta a mano en el router
    json.dump({"10.0.0.5": {"lista": "clientes-botnet", "router": "r1", "categoria": "botnet", "pol": True},
               "10.0.0.6": {"lista": "clientes-botnet", "router": "r1", "categoria": "botnet", "pol": True},
               "10.0.0.9": {"lista": "clientes-escaneo", "router": "r1", "categoria": "escaneo"}},
              open(ns["MK_SENT"], "w"))
    ns["mk_sync_enviados"]()
    env = json.load(open(ns["MK_SENT"]))
    check("sync: el CPE que esta en clientes-botnet NO se suelta (antes se comparaba con LIST)",
          "10.0.0.5" in env and env["10.0.0.5"]["en_router"] is True, env.get("10.0.0.5"))
    check("sync: una entrada permanente que falta en el router se queda, marcada 'falta'",
          env.get("10.0.0.6", {}).get("en_router") is False and env["10.0.0.6"].get("falta_desde"), env.get("10.0.0.6"))
    check("  y sin TTL configurado (auto-mantener), la manual que falta tambien se queda",
          env.get("10.0.0.9", {}).get("en_router") is False, env.get("10.0.0.9"))
    check("sync: lo que esta en una lista del panel y el panel no conoce, se registra con su lista",
          env.get("10.0.0.77", {}).get("lista") == "clientes-spam" and env["10.0.0.77"]["manual"] is True, env.get("10.0.0.77"))
    check("sync: una conexion por router (no una por lista)", len(conex) <= 2, len(conex))   # LIST y LIST_DNS

    # con TTL (sin auto-mantener): la manual que falta CADUCO -> se suelta, como siempre
    ns2, rt2, _c2, _b2 = entorno({"TTL": "1d", "AUTO_MANTENER": "0"})
    json.dump({"10.0.0.9": {"lista": "clientes-escaneo", "router": "r1"},
               "10.0.0.6": {"lista": "clientes-botnet", "router": "r1", "pol": True}}, open(ns2["MK_SENT"], "w"))
    ns2["mk_sync_enviados"]()
    env2 = json.load(open(ns2["MK_SENT"]))
    check("sync: con TTL, la que falta se da por caducada y se suelta", "10.0.0.9" not in env2, env2)
    check("  pero la de politica (va sin TTL) se queda aunque haya TTL", env2.get("10.0.0.6", {}).get("en_router") is False, env2)

    # router caido: no se toca nada
    ns3, rt3, _c3, _b3 = entorno()
    json.dump({"10.0.0.6": {"lista": "clientes-botnet", "router": "r1", "pol": True}}, open(ns3["MK_SENT"], "w"))
    def _caido(d, timeout=6):
        raise IOError("sin respuesta")
    ns3["mk_conectar"] = _caido
    ns3["mk_sync_enviados"]()
    check("sync: si el router no responde no se toca su registro",
          json.load(open(ns3["MK_SENT"])) == {"10.0.0.6": {"lista": "clientes-botnet", "router": "r1", "pol": True}}, "")

    # ===================== recargar =====================
    ns, rt, conex, bit = entorno({"TTL": "1d", "AUTO_MANTENER": "0"}, nunca=("10.0.0.8",))
    al(rt, "clientes-botnet", "10.0.0.5")
    json.dump({"10.0.0.5": {"lista": "clientes-botnet", "router": "r1", "categoria": "botnet", "pol": True},
               "10.0.0.6": {"lista": "clientes-botnet", "router": "r1", "categoria": "botnet", "pol": True,
                            "en_router": False, "falta_desde": 1},
               "10.0.0.7": {"lista": "clientes-spam", "router": "r1", "categoria": "spam"},
               "10.0.0.8": {"lista": "clientes-spam", "router": "r1", "categoria": "spam"}},
              open(ns["MK_SENT"], "w"))
    ok, msg = ns["recargar_listas"]({"id": "r1"}, quien="admin")
    ips = {(f["list"], f["address"]): f for f in rt.t["/ip/firewall/address-list"]}
    check("recargar: carga las que faltan", ("clientes-botnet", "10.0.0.6") in ips and ("clientes-spam", "10.0.0.7") in ips, list(ips))
    check("  la que ya estaba se omite (no se duplica)",
          sum(1 for f in rt.t["/ip/firewall/address-list"] if f["address"] == "10.0.0.5") == 1, "")
    check("  la que ahora esta en 'nunca bloquear' no se carga", ("clientes-spam", "10.0.0.8") not in ips, "")
    check("  la de politica va permanente; la manual, con el TTL configurado",
          "timeout" not in ips[("clientes-botnet", "10.0.0.6")] and ips[("clientes-spam", "10.0.0.7")].get("timeout") == "1d",
          (ips[("clientes-botnet", "10.0.0.6")], ips[("clientes-spam", "10.0.0.7")]))
    check("  con UNA conexion", len(conex) == 1, len(conex))
    env = json.load(open(ns["MK_SENT"]))
    check("  y quedan marcadas en el router", env["10.0.0.6"]["en_router"] is True and "falta_desde" not in env["10.0.0.6"]
          and env["10.0.0.7"]["en_router"] is True, (env["10.0.0.6"], env["10.0.0.7"]))
    check("  el mensaje dice cuantas se cargaron y cuantas ya estaban, por lista",
          ok and "2 IP(s) cargadas" in msg and "1 ya estaban" in msg and "clientes-spam: 1 cargada(s)" in msg
          and "nunca bloquear" in msg, msg)
    check("  y queda en la bitacora", bit and bit[-1][0] == "LISTAS-RECARGADAS", bit)
    ok2, msg2 = ns["recargar_listas"]({"id": "r1"}, quien="admin")
    check("recargar otra vez: no falta nada, no carga nada", ok2 and msg2.startswith("No faltaba nada")
          and len(rt.t["/ip/firewall/address-list"]) == 3, msg2)
    ns_v, _rt, _c, _bb = entorno()
    okv, msgv = ns_v["recargar_listas"]({"id": "r1"})
    check("sin IPs en cuarentena lo dice y no conecta", okv and "no hay nada que cargar" in msgv and not _c, msgv)

    # ===================== lo que se ve =====================
    check("el boton esta en Ajustes > MikroTik, con confirmacion propia (no confirm())",
          "listasRecargar()" in DASH and "Recargar las listas en el router" in DASH
          and "_accResultado('/mikrotik/listas/recargar'" in DASH, "")
    i = DASH.index('if ruta == "/mikrotik/listas/recargar":')
    check("la ruta es solo de admin", "self._admin()" in DASH[i:i + 300], "")
    check("en el desplegable de listas y en Cuarentena se ve 'falta en el router'",
          "falta en el router</span>" in DASH and "FALTA en el router" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
