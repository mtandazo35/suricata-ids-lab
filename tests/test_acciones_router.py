# -*- coding: utf-8 -*-
"""Politicas de accion por categoria: las reglas se ponen en el router por la API.

Contra un RouterOS de mentira que habla el protocolo de la API (print con proplist y
filtros, add, set, remove, .id). Lo que se protege:
  - las plantillas generan lo que dicen (cortar, solo-web con su cadena y jump, sin correo,
    redirigir con y sin IP, limitar solo con limite, nada vacio);
  - aplicar respalda las tablas ANTES del primer cambio y el archivo queda en 600;
  - aplicar dos veces: la segunda no hace nada (ni respaldo ni ordenes);
  - una regla ajena (otro comment) no se toca nunca, ni al quitar;
  - cambiar de plantilla corrige (set) y quita lo que sobra; el jump va delante de la
    primera regla de prerouting (place-before);
  - quitar deja solo lo ajeno; la vista previa dice exactamente lo que se hara;
  - si el router rechaza una orden se para y lo dice; sin respaldo no se toca nada;
  - guardar_mk conserva ACCION_*.
"""
import ast
import json
import os
import re
import stat
import sys
import tempfile
import time

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


PIEZAS = ("ACCIONES", "ACCIONES_POR_CAT", "ACCION_DEFECTO", "T_RAW", "T_NAT", "T_MANGLE", "T_QUEUE", "T_FILTER",
          "_RSC_TABLA", "REGLAS_DIR", "_RE_KV", "_CADENAS_BASE", "_ACCIONES_TABLA", "_TERMINALES", "_NO_CRITERIO",
          "_PROTO_CON_PUERTO", "_LISTAS_IF_SISTEMA", "verificar_reglas", "_mk_contar", "verificar_en_router", "lineas_verificacion", "_RE_FIND_COMMENT", "_RE_FIND_CHAIN", "DNS_PROTEGIDO_DEFECTO", "reglas_desde_rsc", "cargar_reglas_propias", "guardar_reglas_propias",
          "_TABLA_RSC", "_PROPS_TABLA", "RESPALDOS_MK", "accion_de_clase", "reglas_de_accion",
          "_com_regla", "_prefijo_regla", "_rsc_val", "rsc_de", "_reglas_nuestras", "_params_accion",
          "_plan", "_plan_en", "plan_reglas", "_mk_print_todo", "_mk_print", "respaldar_firewall", "aplicar_reglas",
          "quitar_reglas", "guardar_mk", "_mk_globales")


class RouterFalso(object):
    """Lo justo de la API de RouterOS: tablas con .id, print/add/set/remove."""
    def __init__(self):
        self.t = {"/ip/firewall/raw": [], "/ip/firewall/nat": [], "/ip/firewall/filter": [],
                  "/ip/firewall/mangle": [], "/queue/tree": [],
                  "/interface/list": [{".id": "*L1", "name": "WAN"}], "/ip/firewall/address-list": []}
        self.n = 0; self.ordenes = []; self.fallar = None; self.pend = None

    def _id(self):
        self.n += 1; return "*%X" % self.n

    def enviar(self, words):
        self.pend = words

    def responder(self):
        w = self.pend; self.pend = None
        cmd = w[0]; args = w[1:]
        tabla, op = cmd.rsplit("/", 1)
        self.ordenes.append((op, tabla, tuple(args)))
        if self.fallar and self.fallar(op, tabla, args):
            return (False, [["!trap", "=message=rechazado por el router"], ["!done"]], "rechazado por el router")
        filas = self.t[tabla]
        if op == "print":
            props = None; filtros = {}
            for a in args:
                if a.startswith("=.proplist="):
                    props = a[len("=.proplist="):].split(",")
                elif a.startswith("?"):
                    k, v = a[1:].split("=", 1); filtros[k] = v
            out = []
            for f in filas:
                if all(f.get(k) == v for k, v in filtros.items()):
                    campos = props or list(f.keys())
                    out.append(["!re"] + ["=%s=%s" % (k, f[k]) for k in campos if k in f])
            return (True, out + [["!done"]], "")
        kv = {}
        for a in args:
            if a.startswith("="):
                k, v = a[1:].split("=", 1); kv[k] = v
        if op == "add":
            fila = {".id": self._id()}; pb = kv.pop("place-before", None); fila.update(kv)
            if pb:
                i = next((i for i, f in enumerate(filas) if f[".id"] == pb), len(filas))
                filas.insert(i, fila)
            else:
                filas.append(fila)
            return (True, [["!done", "=ret=" + fila[".id"]]], "")
        if op == "set":
            rid = kv.pop(".id"); f = next(f for f in filas if f[".id"] == rid); f.update(kv)
            return (True, [["!done"]], "")
        if op == "remove":
            rid = kv[".id"]; filas[:] = [f for f in filas if f[".id"] != rid]
            return (True, [["!done"]], "")
        raise AssertionError(cmd)

    def reglas(self, tabla, pref="Suricata:"):
        return [f for f in self.t[tabla] if (f.get("comment") or "").startswith(pref)]


def entorno():
    rt = RouterFalso()
    logs = []
    m = {"HOST": "192.0.2.1", "USER": "u", "PASS": "p", "ENABLED": "1"}
    ns = {"re": re, "os": os, "json": json, "time": time,
          "mk_conectar": lambda d, timeout=6: rt,
          "_mk_send": lambda s_, words: s_.enviar(),
          "_mk_reply": lambda s_: s_.responder(),
          "cargar_mk_de": lambda r: dict(m), "lista_de_categoria": lambda c: "clientes-" + c,
          "mk_log": lambda a, ip, q, det="": logs.append((a, det)), "MK_CONF": None}
    # _mk_send recibe las palabras: el doble necesita verlas
    ns["_mk_send"] = lambda s_, words: s_.enviar(words)
    for n in ARBOL.body:
        noms = set()
        if getattr(n, "name", None):
            noms.add(n.name)
        elif isinstance(n, ast.Assign):
            for tg in n.targets:          # tambien 'A, B, C = ...' (las tablas van asi)
                for el in (tg.elts if isinstance(tg, ast.Tuple) else [tg]):
                    if isinstance(el, ast.Name):
                        noms.add(el.id)
        if noms & set(PIEZAS):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["_mk_globales"] = lambda: m
    td = tempfile.mkdtemp(); ns["RESPALDOS_MK"] = os.path.join(td, "backups")
    return ns, rt, m, logs, td


def main():
    ns, rt, m, logs, td = entorno()
    R = ns["reglas_de_accion"]
    T_RAW, T_NAT, T_MANGLE, T_QUEUE = ns["T_RAW"], ns["T_NAT"], ns["T_MANGLE"], ns["T_QUEUE"]

    # ---------- plantillas ----------
    c = R("botnet", "cortar", "clientes-botnet")
    check("cortar = un drop en raw prerouting por la lista, arriba del todo",
          c == [(T_RAW, {"chain": "prerouting", "action": "drop", "src-address-list": "clientes-botnet", "_arriba": "1"})], c)
    w = R("botnet", "solo-web", "clientes-botnet")
    check("solo-web = cadena propia (DNS udp/tcp, 80/443) + drop + jump desde prerouting",
          len(w) == 5 and [x[1]["action"] for x in w] == ["return", "return", "return", "drop", "jump"]
          and w[4][1]["jump-target"] == "SURICATA-BOTNET" and w[2][1]["dst-port"] == "80,443", w)
    sc = R("spam", "sin-correo", "clientes-spam")
    check("sin-correo = drop tcp 25,465,587,2525 (como la del ISP)", sc[0][1]["dst-port"] == "25,465,587,2525" and sc[0][1]["protocol"] == "tcp", sc)
    rd = R("dns", "redirigir-dns", "clientes-dns-malware", {"dns_ip": ""})
    check("redirigir sin IP = redirect al propio router, udp y tcp",
          [x[1]["action"] for x in rd] == ["redirect", "redirect"] and {x[1]["protocol"] for x in rd} == {"udp", "tcp"}, rd)
    rd2 = R("dns", "redirigir-dns", "l", {"dns_ip": "192.0.2.53"})
    check("redirigir con IP = dst-nat a esa IP", rd2[0][1]["action"] == "dst-nat" and rd2[0][1]["to-addresses"] == "192.0.2.53", rd2)
    check("limitar sin limite no genera nada", R("p2p", "limitar", "l", {"limite": ""}) == [], "")
    li = R("p2p", "limitar", "clientes-p2p", {"limite": "2M"})
    check("limitar con limite = marca de conexion + marca de paquete + cola", [x[0] for x in li] == [T_MANGLE, T_MANGLE, T_QUEUE]
          and li[2][1]["max-limit"] == "2M" and li[1][1]["new-packet-mark"] == "suricata-p2p", li)
    check("nada = vacio", R("otros", "nada", "l") == [], "")
    check("los defectos son las reglas probadas del ISP: botnet solo-web, dns protegido, escaneo frenado",
          ns["accion_de_clase"]("botnet", {}) == "solo-web" and ns["accion_de_clase"]("dns", {}) == "dns-protegido"
          and ns["accion_de_clase"]("escaneo", {}) == "frenar-escaneo" and ns["accion_de_clase"]("p2p", {}) == "nada"
          and ns["accion_de_clase"]("spam", {}) == "sin-correo", "")

    # ---------- las plantillas que salen de las reglas del ISP ----------
    dp = R("dns", "dns-protegido", "clientes-dns-malware", {"dns_ip": "", "wan": "WAN"})
    check("DNS protegido: 7 reglas (2 nat, 2 drop DoT, cadena de tope de 2 y su jump)", len(dp) == 7
          and [x[0] for x in dp] == [T_NAT, T_NAT, T_RAW, T_RAW, T_RAW, T_RAW, T_RAW], [x[0] for x in dp])
    check("  el 53 va a Quad9 por defecto, con !WAN", dp[0][1]["to-addresses"] == "9.9.9.9"
          and dp[0][1]["in-interface-list"] == "!WAN" and dp[0][1]["action"] == "dst-nat", dp[0])
    check("  corta DoT/DoQ y puertos alternativos como la del ISP",
          dp[2][1]["dst-port"] == "853,8853,9953" and dp[3][1]["dst-port"] == "784,853,8853,9953", (dp[2], dp[3]))
    check("  tope de 50/s por cliente con rafaga 100", dp[4][1]["dst-limit"] == "50,100,src-address/10s", dp[4])
    dp2 = R("dns", "dns-protegido", "l", {"dns_ip": "192.0.2.53", "wan": ""})
    check("  con IP propia y sin lista WAN: a esa IP y sin la condicion",
          dp2[0][1]["to-addresses"] == "192.0.2.53" and all("in-interface-list" not in x[1] for x in dp2), dp2[0])
    fe = R("escaneo", "frenar-escaneo", "clientes-escaneo", {"wan": "WAN"})
    check("frenar escaneo: tope de 30 SYN/s (rafaga 60) y jump con syn,!ack y !WAN",
          fe[0][1]["dst-limit"] == "30,60,src-address/10s" and fe[2][1]["tcp-flags"] == "syn,!ack"
          and fe[2][1]["in-interface-list"] == "!WAN" and fe[2][1]["jump-target"] == "SURICATA-ESCANEO-TOPE", fe)
    pa = ns["_params_accion"]("dns", {})
    check("la lista WAN por defecto es 'WAN'; 'ninguna' la quita",
          pa["wan"] == "WAN" and ns["_params_accion"]("dns", {"ACCION_WAN_LIST": "ninguna"})["wan"] == "", pa)
    check("una accion que no es de esa clase cae al defecto", ns["accion_de_clase"]("otros", {"ACCION_OTROS": "limitar"}) == "nada", "")
    check("rsc entrecomilla lo que lo necesita", 'src-address-list="Cliente Virus"' in ns["rsc_de"](T_RAW, {"src-address-list": "Cliente Virus"})
          and "src-address-list=clientes-botnet" in ns["rsc_de"](T_RAW, {"src-address-list": "clientes-botnet"}, "Suricata:botnet:01"), "")

    # ---------- aplicar: respaldo antes, idempotente, lo ajeno intacto ----------
    rt.t[T_RAW].append({".id": rt._id(), "chain": "prerouting", "action": "accept", "comment": "mio: gestion"})
    router = {"id": "r1"}
    m["ACCION_BOTNET"] = "cortar"          # el defecto ya es solo-web: aqui se prueba cortar
    ok, msg, plan = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("aplicar 'cortar' en botnet: ok", ok is True, msg)
    nuestras = rt.reglas(T_RAW, "Suricata:botnet:")
    check("queda UNA regla nuestra con su comentario numerado", len(nuestras) == 1 and nuestras[0]["comment"] == "Suricata:botnet:01", nuestras)
    check("y se puso DELANTE de la regla ajena (place-before)", rt.t[T_RAW][0]["comment"] == "Suricata:botnet:01", [f.get("comment") for f in rt.t[T_RAW]])
    resp = os.listdir(ns["RESPALDOS_MK"])
    check("hay respaldo del firewall", len(resp) == 1 and resp[0].startswith("mikrotik-r1-"), resp)
    j = json.load(open(os.path.join(ns["RESPALDOS_MK"], resp[0]), encoding="utf-8"))
    check("el respaldo trae las tablas de ANTES (solo la regla ajena)", [f.get("comment") for f in j["tablas"][T_RAW]] == ["mio: gestion"], j["tablas"][T_RAW])
    if os.name != "nt":
        check("respaldo en 600", stat.S_IMODE(os.stat(os.path.join(ns["RESPALDOS_MK"], resp[0])).st_mode) == 0o600, "")
    i_resp = next(i for i, o in enumerate(rt.ordenes) if o[0] == "print" and "=.proplist" not in "".join(o[2]))
    i_add = next(i for i, o in enumerate(rt.ordenes) if o[0] == "add")
    check("el respaldo se leyo ANTES del primer add", i_resp < i_add, (i_resp, i_add))
    check("queda en la bitacora", any(a == "REGLAS-APLICADAS" and "clase=botnet" in d for a, d in logs), logs)

    n_ord = len(rt.ordenes)
    ok2, msg2, plan2 = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("aplicar otra vez: sin cambios", ok2 and "sin cambios" in msg2 and plan2["cambios"] == 0, msg2)
    check("y sin ordenes de escritura ni respaldo nuevo",
          all(o[0] == "print" for o in rt.ordenes[n_ord:]) and len(os.listdir(ns["RESPALDOS_MK"])) == 1, rt.ordenes[n_ord:])

    # ---------- cambiar de plantilla: set + add + remove ----------
    m["ACCION_BOTNET"] = "solo-web"
    plan3 = ns["plan_reglas"](router, "botnet")
    ops = [a[0] for a in plan3["acciones"]]
    check("vista previa de cortar->solo-web: 1 set (la :01) y 4 add", ops.count("set") == 1 and ops.count("add") == 4 and "remove" not in ops, ops)
    check("la vista previa es RSC legible", any("jump-target=SURICATA-BOTNET" in l for l in plan3["rsc"]), plan3["rsc"])
    ok3, msg3, _ = ns["aplicar_reglas"](router, "botnet", quien="admin")
    nuestras = rt.reglas(T_RAW, "Suricata:botnet:")
    cadena = [f["action"] for f in nuestras if f.get("chain") == "SURICATA-BOTNET"]
    pre = [f.get("comment") for f in rt.t[T_RAW] if f.get("chain") == "prerouting"]
    check("ahora hay 5 reglas nuestras: la cadena en orden (3 return + drop)", len(nuestras) == 5
          and cadena == ["return", "return", "return", "drop"], [f["action"] for f in nuestras])
    check("y el jump va el PRIMERO de prerouting, delante de la regla ajena",
          pre and pre[0] == "Suricata:botnet:05" and "mio: gestion" in pre, pre)
    check("la ajena sigue intacta", any(f.get("comment") == "mio: gestion" and f["action"] == "accept" for f in rt.t[T_RAW]), "")
    m["ACCION_BOTNET"] = "cortar"
    ok4, msg4, plan4 = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("volver a cortar: corrige la :01 y quita las otras 4", "4 quitada" in msg4 and len(rt.reglas(T_RAW, "Suricata:botnet:")) == 1
          and rt.reglas(T_RAW, "Suricata:botnet:")[0]["action"] == "drop", msg4)

    # ---------- quitar: solo lo nuestro ----------
    ok5, msg5, _ = ns["quitar_reglas"](router, "botnet", quien="admin")
    check("quitar deja solo lo ajeno", ok5 and rt.reglas(T_RAW) == [] and len(rt.t[T_RAW]) == 1, rt.t[T_RAW])

    # ---------- limitar sin limite: no se aplica y se dice ----------
    m["ACCION_P2P"] = "limitar"
    ok6, msg6, plan6 = ns["aplicar_reglas"](router, "p2p", quien="admin")
    check("limitar sin limite no toca nada y avisa", ok6 is False and "Falta el limite" in msg6 and rt.t[T_MANGLE] == [], msg6)
    m["ACCION_LIMITE_P2P"] = "2M"
    ok7, msg7, _ = ns["aplicar_reglas"](router, "p2p", quien="admin")
    check("con limite, marcas y cola", ok7 and len(rt.t[T_MANGLE]) == 2 and rt.t[T_QUEUE][0]["max-limit"] == "2M", msg7)

    # ---------- el router rechaza: se para y se dice ----------
    m["ACCION_SPAM"] = "sin-correo"
    rt.fallar = lambda op, tabla, args: op == "add"
    ok8, msg8, _ = ns["aplicar_reglas"](router, "spam", quien="admin")
    check("si el router rechaza, falla con el motivo y el respaldo", ok8 is False and "rechazado" in msg8 and "respaldo" in msg8.lower(), msg8)
    check("y queda en la bitacora como error", any(a == "REGLAS-ERROR" for a, _d in logs), "")
    rt.fallar = None

    # ---------- sin respaldo no se toca ----------
    ns["RESPALDOS_MK"] = os.path.join(td, "noexiste", "x" * 300)   # ruta imposible
    antes = len(rt.t[T_RAW])
    ok9, msg9, _ = ns["aplicar_reglas"](router, "spam", quien="admin")
    check("si el respaldo falla, no se toca nada", ok9 is False and "respaldar" in msg9 and len(rt.t[T_RAW]) == antes, msg9)

    # ---------- reglas PROPIAS: el bloque que pega el usuario ----------
    PEGADO = """/ip firewall raw
add action=return chain=BOTNET-CUARENTENA comment="Permite consultas DNS UDP 53" dst-port=53 protocol=udp
add action=return chain=BOTNET-CUARENTENA comment="Permite consultas DNS TCP 53" dst-port=53 protocol=tcp
add action=return chain=BOTNET-CUARENTENA comment="Permite navegacion" dst-port=80,443 protocol=tcp
add action=drop chain=BOTNET-CUARENTENA comment="Bloquea el resto"
add action=jump chain=prerouting comment="Restringe clientes botnet" jump-target=BOTNET-CUARENTENA place-before=0 src-address-list={LISTA}
"""
    pr = ns["reglas_desde_rsc"](PEGADO, "clientes-botnet")
    check("el bloque pegado parsea en 5 reglas raw", len(pr) == 5 and all(tb == T_RAW for tb, _p in pr), pr)
    check("el comment pegado se descarta (lo pone el panel) y {LISTA} se sustituye",
          all("comment" not in p for _t, p in pr) and pr[4][1]["src-address-list"] == "clientes-botnet", pr[4])
    check("place-before=0 pasa a 'la primera de su cadena'", pr[4][1].get("_arriba") == "1" and "place-before" not in pr[4][1], pr[4])
    check("los valores entrecomillados y las listas de puertos se respetan", pr[2][1]["dst-port"] == "80,443", pr[2])
    try:
        ns["reglas_desde_rsc"]("/ip route\nadd dst-address=0.0.0.0/0", "l"); mal = ""
    except ValueError as ex:
        mal = str(ex)
    check("una tabla que no se maneja es un error con la linea", "linea 1" in mal and "no soportada" in mal, mal)
    try:
        ns["reglas_desde_rsc"]("add chain=prerouting action=drop", "l"); mal2 = ""
    except ValueError as ex:
        mal2 = str(ex)
    check("un add sin tabla delante es un error", "falta la tabla" in mal2, mal2)
    check("la marca interna no sale en el RSC de la vista previa, place-before si",
          "_arriba" not in ns["rsc_de"](T_RAW, pr[4][1], "Suricata:botnet:05") and "place-before=0" in ns["rsc_de"](T_RAW, pr[4][1]), "")

    ns["REGLAS_DIR"] = os.path.join(td, "reglas")
    n_g = ns["guardar_reglas_propias"]("botnet", PEGADO)
    check("guardar valida y cuenta las reglas", n_g == 5 and ns["cargar_reglas_propias"]("botnet").startswith("/ip firewall raw"), n_g)
    try:
        ns["guardar_reglas_propias"]("botnet", "/ip route\nadd x=1"); g_mal = ""
    except ValueError as ex:
        g_mal = str(ex)
    check("un bloque invalido NO se guarda", "no soportada" in g_mal and "/ip route" not in ns["cargar_reglas_propias"]("botnet"), g_mal)

    rt2 = RouterFalso(); rt2.t[T_RAW].append({".id": rt2._id(), "chain": "prerouting", "action": "accept", "comment": "mio"})
    ns["mk_conectar"] = lambda d, timeout=6: rt2
    ns["RESPALDOS_MK"] = os.path.join(td, "backups2")
    m["ACCION_BOTNET"] = "propias"
    okp, msgp, planp = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("aplicar las reglas propias: ok, 5 nuevas", okp and "5 nueva" in msgp, msgp)
    pre2 = [f.get("comment") for f in rt2.t[T_RAW] if f.get("chain") == "prerouting"]
    check("el jump pegado con place-before=0 queda el primero de prerouting", pre2[0] == "Suricata:botnet:05" and "mio" in pre2, pre2)
    okp2, msgp2, planp2 = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("segunda vez: sin cambios (los campos propios tambien se comparan)", okp2 and planp2["cambios"] == 0, (msgp2, [a[0] for a in planp2["acciones"]]))
    m["ACCION_ESCANEO"] = "propias"
    oke, msge, plane = ns["aplicar_reglas"](router, "escaneo", quien="admin")
    check("propias sin bloque pegado: no toca nada y lo dice", oke is False and "No hay reglas propias" in msge, msge)

    # ---------- las reglas REALES del ISP (2026-10-09), pegadas tal cual ----------
    DNS_ISP = """/ip firewall nat
add action=dst-nat chain=dstnat comment="Fuerza DNS UDP" dst-port=53 in-interface-list=!WAN protocol=udp src-address-list={LISTA} to-addresses=9.9.9.9 to-ports=53 place-before=0
add action=dst-nat chain=dstnat comment="Fuerza DNS TCP" dst-port=53 in-interface-list=!WAN protocol=tcp src-address-list={LISTA} to-addresses=9.9.9.9 to-ports=53 place-before=0

/ip firewall raw
add action=drop chain=prerouting comment="DoT TCP" dst-port=853,8853,9953 in-interface-list=!WAN protocol=tcp src-address-list={LISTA}
add action=drop chain=prerouting comment="DoT UDP" dst-port=784,853,8853,9953 in-interface-list=!WAN protocol=udp src-address-list={LISTA}

/ip firewall raw
add action=return chain=DNS-MALWARE-LIMIT comment="hasta 50/s" dst-limit=50,100,src-address/10s
add action=drop chain=DNS-MALWARE-LIMIT comment="exceso"
add action=jump chain=prerouting comment="tope" dst-port=53 in-interface-list=!WAN jump-target=DNS-MALWARE-LIMIT place-before=0 protocol=udp src-address-list={LISTA}
"""
    rd_isp = ns["reglas_desde_rsc"](DNS_ISP, "clientes-dns-malware")
    check("el bloque DNS del ISP parsea entero (7 reglas, nat y raw)", len(rd_isp) == 7
          and [x[0] for x in rd_isp].count(T_NAT) == 2, [x[0] for x in rd_isp])
    check("  !WAN y dst-limit llegan tal cual", rd_isp[0][1]["in-interface-list"] == "!WAN"
          and rd_isp[4][1]["dst-limit"] == "50,100,src-address/10s", (rd_isp[0], rd_isp[4]))
    ESC_ISP = """/ip firewall raw
add action=return chain=ESCANEO-CONTROL comment="30/s" dst-limit=30,60,src-address/10s
add action=drop chain=ESCANEO-CONTROL comment="exceso"
add action=jump chain=prerouting comment="Controla SYN" in-interface-list=!WAN jump-target=ESCANEO-CONTROL place-before=[find where chain=prerouting comment="Drop Malware"] protocol=tcp src-address-list={LISTA} tcp-flags=syn,!ack
"""
    re_isp = ns["reglas_desde_rsc"](ESC_ISP, "clientes-escaneo")
    j = re_isp[2][1]
    check("place-before=[find ...] NO se parte: la cadena sigue siendo prerouting y no se cuela 'where'",
          j["chain"] == "prerouting" and "where" not in j and j.get("_antes_de") == "Drop Malware"
          and j.get("_antes_cadena") == "prerouting" and j["tcp-flags"] == "syn,!ack", j)
    check("y la vista previa lo escribe como en la consola",
          'place-before=[find where chain=prerouting comment="Drop Malware"]' in ns["rsc_de"](T_RAW, j), ns["rsc_de"](T_RAW, j))
    try:
        ns["reglas_desde_rsc"]("/ip firewall raw\nadd chain=prerouting action=drop place-before=[find where dynamic=yes]", "l"); m_pb = ""
    except ValueError as ex:
        m_pb = str(ex)
    check("un place-before que no se sabe resolver es un error con su linea", "linea 2" in m_pb and "place-before" in m_pb, m_pb)

    # aplicar el de escaneo en un router CON la regla 'Drop Malware'
    rt3 = RouterFalso()
    for c_ in ("mio: gestion", "Drop Malware", "mio: final"):
        rt3.t[T_RAW].append({".id": rt3._id(), "chain": "prerouting", "action": "accept" if c_ != "Drop Malware" else "drop", "comment": c_})
    ns["mk_conectar"] = lambda d, timeout=6: rt3
    ns["RESPALDOS_MK"] = os.path.join(td, "backups3")
    ns["REGLAS_DIR"] = os.path.join(td, "reglas3")
    ns["guardar_reglas_propias"]("escaneo", ESC_ISP)
    m["ACCION_ESCANEO"] = "propias"
    p3 = ns["plan_reglas"](router, "escaneo")
    check("con 'Drop Malware' en el router, la vista previa no avisa", "Drop Malware" not in p3["aviso"], p3["aviso"])
    ok_e, msg_e, _ = ns["aplicar_reglas"](router, "escaneo", quien="admin")
    pre3 = [f.get("comment") for f in rt3.t[T_RAW] if f.get("chain") == "prerouting"]
    check("el jump queda justo DELANTE de 'Drop Malware', no arriba del todo",
          ok_e and pre3 == ["mio: gestion", "Suricata:escaneo:03", "Drop Malware", "mio: final"], pre3)

    # ... y en un router SIN esa regla: aviso en la vista previa y va la primera
    rt4 = RouterFalso(); rt4.t[T_RAW].append({".id": rt4._id(), "chain": "prerouting", "action": "accept", "comment": "mio"})
    ns["mk_conectar"] = lambda d, timeout=6: rt4
    p4 = ns["plan_reglas"](router, "escaneo")
    check("sin 'Drop Malware', la vista previa lo avisa ANTES de aplicar", "no hay ninguna regla 'Drop Malware'" in p4["aviso"], p4["aviso"])
    ok4b, _m4, _ = ns["aplicar_reglas"](router, "escaneo", quien="admin")
    pre4 = [f.get("comment") for f in rt4.t[T_RAW] if f.get("chain") == "prerouting"]
    check("  y el jump va el primero de prerouting", ok4b and pre4[0] == "Suricata:escaneo:03", pre4)

    # orden: varias 'arriba' conservan su orden (antes salian al reves)
    ORDEN = """/ip firewall raw
add chain=prerouting action=accept protocol=tcp dst-port=587 src-address-list={LISTA} place-before=0
add chain=prerouting action=drop protocol=tcp dst-port=587 place-before=0
add chain=prerouting action=drop protocol=tcp dst-port=25
"""
    rt5 = RouterFalso(); rt5.t[T_RAW].append({".id": rt5._id(), "chain": "prerouting", "action": "accept", "comment": "mio"})
    ns["mk_conectar"] = lambda d, timeout=6: rt5
    ns["guardar_reglas_propias"]("spam", ORDEN)
    m["ACCION_SPAM"] = "propias"
    ns["aplicar_reglas"](router, "spam", quien="admin")
    pre5 = [f.get("comment") for f in rt5.t[T_RAW] if f.get("chain") == "prerouting"]
    check("dos reglas 'arriba' conservan su orden (accept antes que drop) y lo que no dice posicion va al final",
          pre5 == ["Suricata:spam:01", "Suricata:spam:02", "mio", "Suricata:spam:03"], pre5)

    # ---------- guardar_mk conserva ACCION_* ----------
    ns["MK_CONF"] = os.path.join(td, "mk.conf")
    ns["guardar_mk"]({"HOST": "h", "ACCION_BOTNET": "solo-web", "ACCION_DNS_IP": "192.0.2.53", "ACCION_LIMITE_P2P": "2M"})
    # _mk_globales real, no el doble
    for n in ARBOL.body:
        if getattr(n, "name", None) == "_mk_globales":
            exec(ast.get_source_segment(DASH, n), ns)
    g = ns["_mk_globales"]()
    check("guardar_mk conserva ACCION_*", g.get("ACCION_BOTNET") == "solo-web" and g.get("ACCION_DNS_IP") == "192.0.2.53" and g.get("ACCION_LIMITE_P2P") == "2M", g)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
