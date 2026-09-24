# -*- coding: utf-8 -*-
"""Enviar y quitar de cuarentena respetando la identidad (router, IP).

El registro de enviados, los candidatos del reporte y el Top usan la IDENTIDAD del
CPE, que con varios MikroTik es "router|IP". Las rutas de ENVIO guardaban en cambio la
IP pelada, asi que:

  - el Top y la pestana Cuarentena mostraban "sin enviar" un CPE ya bloqueado
    (la marca se busca por identidad y estaba guardada por IP);
  - el bloqueo salia siempre hacia el router por defecto, no hacia el del abonado;
  - y al querer liberarlo, "router|IP" se rechazaba como "IP invalida".

Este archivo ejecuta las rutas reales contra un MikroTik de mentira.
"""
import ast
import json
import os
import sys
import tempfile
import textwrap

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("MK_SENT", "MK_SENT_DNS", "MK_LOG", "ROUTERS_CONF", "ROUTERS_MAP",
          "CAMPOS_ROUTER", "IFACE_BASE", "_ENV_LOCK",
          "_router_vacio", "_mk_globales", "cargar_routers", "publicar_routers_map",
          "router_por_id", "router_defecto", "cargar_mk", "cargar_mk_de",
          "mk_configurado", "mk_listo", "_ttl_efectivo",
          "clave_cpe", "ip_de", "rid_de", "router_de_clave", "_suf_nodo",
          "_motivo_bloqueo", "cargar_enviados", "guardar_enviados", "quitar_enviados")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def cuerpo_ruta(ruta):
    for n in ast.walk(ARBOL):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and getattr(n.test.left, "id", "") == "ruta" and n.test.comparators
                and getattr(n.test.comparators[0], "value", "") == ruta):
            ls = DASH.split("\n")[n.body[0].lineno - 1:n.body[-1].end_lineno]
            return textwrap.dedent("\n".join(ls))
    raise SystemExit("no se encontro la ruta " + ruta)


def entorno(tmp):
    """Las piezas reales del panel, con los archivos apuntando a un directorio de prueba."""
    ns = {"json": json, "os": os, "html": __import__("html"), "time": __import__("time"),
          "threading": __import__("threading"), "ipaddress": __import__("ipaddress"),
          "_up": __import__("urllib.parse", fromlist=["parse"])}
    piezas = [(getattr(n, "name", None) or (getattr(n.targets[0], "id", "")
               if isinstance(n, ast.Assign) and n.targets else ""), n)
              for n in ARBOL.body]
    piezas = [(nom, n) for nom, n in piezas if nom in PIEZAS]
    # 1) constantes, 2) se reescriben las rutas de archivo, 3) funciones: asi los
    #    argumentos por defecto (path=MK_SENT) quedan apuntando al directorio de prueba
    for nom, n in piezas:
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns.update({"MK_SENT": os.path.join(tmp, "enviados.json"),
               "MK_SENT_DNS": os.path.join(tmp, "dns-enviados.json"),
               "MK_LOG": os.path.join(tmp, "cuarentena.log"),
               "MK_CONF": os.path.join(tmp, "mikrotik.conf"),
               "ROUTERS_CONF": os.path.join(tmp, "routers.json"),
               "ROUTERS_MAP": os.path.join(tmp, "map.json"),
               "LOGDIR": tmp})
    for nom, n in piezas:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


class Mikrotik:
    """MikroTik de mentira: apunta a que router y a que lista fue cada orden."""
    def __init__(self):
        self.add = []      # (ip, lista, router_id)
        self.rem = []

    def add_fn(self, ip, comment="", lista=None, ttl=None, router=None):
        self.add.append((ip, lista, (router or {}).get("id", "")))
        return True, ""

    def rem_fn(self, ip, lista=None, router=None):
        self.rem.append((ip, lista, (router or {}).get("id", "")))
        return True, "quitado"


def llamar(ns, mk, ruta, campos, operador=True):
    """Ejecuta el cuerpo de una ruta y devuelve lo que se le respondio al usuario."""
    visto = {}
    class Self:
        def _operador(self): return operador
        def _deny(self): return visto.update({"deny": True})
        def _redirect(self, u): return visto.update({"redirect": u})
        def _json(self, d, code=200): return visto.update({"json": d})
        def send_response(self, *a): pass
        def send_header(self, *a): pass
        def end_headers(self, *a): pass
        wfile = type("W", (), {"write": lambda self, b: visto.update({"texto": b.decode("utf-8")})})()
    class Ctx:
        user = "operador1"
        ip = "192.0.2.9"
    # los dobles van en el MISMO espacio de nombres donde se definieron las piezas del
    # panel: guardar_enviados() y compania resuelven ahi sus propias dependencias
    ns2 = ns
    ns2.update({"self": Self(), "q": {k: [v] for k, v in campos.items()}, "CTX": Ctx(),
                "mk_add": mk.add_fn, "mk_remove": mk.rem_fn,
                "mk_log": lambda *a, **k: None, "bitacora": lambda *a, **k: None,
                "notificar_cuarentena": lambda *a, **k: None,
                "enviar_telegram": lambda *a, **k: None,
                "pedir_regen": lambda *a, **k: None,
                "es_mi_cpe": lambda ip: ip.startswith("10."),
                "es_publica_declarada": lambda ip: "",
                "nunca_bloquear": lambda ip: False})
    exec(compile("def _f():\n" + textwrap.indent(cuerpo_ruta(ruta), "    "), "<r>", "exec"), ns2)
    ns2["_f"]()
    return visto


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    open(ns["MK_CONF"], "w", encoding="utf-8").write("ENABLED=1\nAUTO_MANTENER=0\n")
    json.dump({"routers": [
        {"id": "r1", "nombre": "Nodo Sur", "iface": "ids-mon", "HOST": "192.0.2.1",
         "USER": "api", "PASS": "x", "LIST": "cuar-sur", "TTL": "1h", "ENABLED": "1"},
        {"id": "r2", "nombre": "Nodo Norte", "iface": "ids-mon2", "HOST": "192.0.2.2",
         "USER": "api", "PASS": "x", "LIST": "cuar-norte", "TTL": "1h", "ENABLED": "1"},
    ]}, open(ns["ROUTERS_CONF"], "w", encoding="utf-8"))
    # dos CPEs DISTINTOS con la misma IP, uno en cada nodo: el caso que rompia todo
    json.dump({"candidatos": [
        {"ip": "10.6.1.165", "router": "r1", "riesgo": 73, "banda": "ALTO",
         "confianza": "alta", "alertas_cnc": 8, "firmas_cnc": 2, "firma": "Mirai del sur",
         "destinos_ip": ["198.51.100.7"]},
        {"ip": "10.6.1.165", "router": "r2", "riesgo": 91, "banda": "ALTO",
         "confianza": "alta", "alertas_cnc": 40, "firmas_cnc": 3, "firma": "Cobalt del norte",
         "destinos_ip": ["203.0.113.9"]},
    ], "dns_candidatos": [], "top_riesgo": []},
        open(os.path.join(tmp, "cuarentena.json"), "w", encoding="utf-8"))

    mk = Mikrotik()

    # --- 1) enviar el CPE del nodo Norte ---
    v = llamar(ns, mk, "/cuarentena/enviar", {"ajax": "1", "ip": "r2|10.6.1.165", "score": "91"})
    check("se acepta la identidad 'router|IP' (antes: 'IP invalida')",
          v.get("texto", "").startswith("OK"), v)
    check("el bloqueo sale hacia SU router y a la lista de ESE router",
          mk.add[-1:] == [("10.6.1.165", "cuar-norte", "r2")], mk.add)

    reg = ns["cargar_enviados"](ns["MK_SENT"])
    check("queda registrado por identidad, no por IP pelada",
          list(reg.keys()) == ["r2|10.6.1.165"], list(reg.keys()))
    check("y por eso el Top lo marca 'En cuarentena'",
          ns["clave_cpe"]("10.6.1.165", "r2") in reg, list(reg.keys()))
    check("el CPE del OTRO nodo con la misma IP sigue sin bloquear",
          ns["clave_cpe"]("10.6.1.165", "r1") not in reg, list(reg.keys()))
    e = reg.get("r2|10.6.1.165") or {}
    check("se guarda el motivo del CPE correcto, no el del vecino",
          (e.get("motivo") or {}).get("firma") == "Cobalt del norte", e.get("motivo"))
    check("no se rotula como manual: era candidato del reporte",
          e.get("manual") is False, e)

    # --- 2) el mismo CPE del nodo Sur es otro abonado ---
    llamar(ns, mk, "/cuarentena/enviar", {"ajax": "1", "ip": "r1|10.6.1.165", "score": "73"})
    reg = ns["cargar_enviados"](ns["MK_SENT"])
    check("el del sur va a SU router, no al del norte",
          mk.add[-1:] == [("10.6.1.165", "cuar-sur", "r1")], mk.add)
    check("y conviven los dos en el registro", len(reg) == 2, list(reg.keys()))

    # --- 3) liberar uno no libera al otro ---
    v = llamar(ns, mk, "/cuarentena/quitar", {"ip": "r2|10.6.1.165"})
    check("quitar acepta la identidad (antes: 'IP invalida')",
          "invalida" not in v.get("redirect", ""), v)
    check("se quita del router correcto y de su lista",
          mk.rem[-1:] == [("10.6.1.165", "cuar-norte", "r2")], mk.rem)
    reg = ns["cargar_enviados"](ns["MK_SENT"])
    check("sale del registro el del norte", "r2|10.6.1.165" not in reg, list(reg.keys()))
    check("y el del sur sigue bloqueado", "r1|10.6.1.165" in reg, list(reg.keys()))

    # --- 4) una instalacion de un solo nodo no cambia en nada ---
    tmp1 = tempfile.mkdtemp()
    ns1 = entorno(tmp1)
    open(ns1["MK_CONF"], "w", encoding="utf-8").write("ENABLED=1\nAUTO_MANTENER=0\n")
    json.dump({"routers": [
        {"id": "r1", "nombre": "MikroTik", "iface": "ids-mon", "HOST": "192.0.2.1",
         "USER": "api", "PASS": "x", "LIST": "suricata-cuarentena", "TTL": "1h", "ENABLED": "1"}]},
        open(ns1["ROUTERS_CONF"], "w", encoding="utf-8"))
    json.dump({"candidatos": [{"ip": "10.6.4.61", "router": "", "riesgo": 73,
                               "confianza": "alta", "firma": "unica"}],
               "dns_candidatos": [], "top_riesgo": []},
              open(os.path.join(tmp1, "cuarentena.json"), "w", encoding="utf-8"))
    mk1 = Mikrotik()
    v = llamar(ns1, mk1, "/cuarentena/enviar", {"ajax": "1", "ip": "10.6.4.61", "score": "73"})
    reg1 = ns1["cargar_enviados"](ns1["MK_SENT"])
    check("con un solo nodo la clave sigue siendo la IP pelada",
          list(reg1.keys()) == ["10.6.4.61"], list(reg1.keys()))
    check("y se envia igual que siempre",
          mk1.add == [("10.6.4.61", "suricata-cuarentena", "r1")], mk1.add)
    llamar(ns1, mk1, "/cuarentena/quitar", {"ip": "10.6.4.61"})
    check("y se quita igual que siempre",
          ns1["cargar_enviados"](ns1["MK_SENT"]) == {}, ns1["cargar_enviados"](ns1["MK_SENT"]))

    # --- 5) un nodo en dry-run no recibe nada ---
    rs = json.load(open(ns["ROUTERS_CONF"], encoding="utf-8"))
    rs["routers"][1]["ENABLED"] = "0"
    json.dump(rs, open(ns["ROUTERS_CONF"], "w", encoding="utf-8"))
    n_antes = len(mk.add)
    v = llamar(ns, mk, "/cuarentena/enviar", {"ajax": "1", "ip": "r2|10.6.1.165", "score": "91"})
    check("a un nodo deshabilitado no se le manda nada", len(mk.add) == n_antes, mk.add)
    check("y se dice por que", "HABILITA" in v.get("texto", ""), v)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
