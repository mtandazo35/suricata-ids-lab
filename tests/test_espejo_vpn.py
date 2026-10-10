# -*- coding: utf-8 -*-
"""Ajustes > VPN: el espejo por la VPN se monta desde la web, sin consola.

Lo que se protege:
  - el comando del instalador se construye del estado real de la VPN: -t -e vpn, -m con las
    IPs de los MikroTik EN EL TUNEL (en el orden de sus interfaces: el que ya esta dado de
    alta conserva la suya), -n con sus redes (o el HOME_NET de ahora si no tienen);
  - -a viene prerrellenado con la IP que LLEGA al sensor (con proxy, la del proxy): el
    firewall de solo-tunel cerraria la web a quien esta entrando. Se valida, y la basura
    se rechaza antes de construir nada; NUNCA se pasa -P (las claves se conservan);
  - el lanzamiento: respaldo antes (sin respaldo no se lanza), instalador en /root, unidad
    propia de systemd, sin shell, y la marca FIN rc=N al final (se ejecuta de verdad);
  - el avance sale de esa marca, y el JS aguanta el corte del reinicio y sigue;
  - montar el espejo en un MikroTik: solo conectado y dado de alta; la vista previa no
    respalda ni toca; aplicar respalda ANTES; las credenciales van en un archivo 600 en
    /root que se borra aunque falle, y la clave no va en la linea de comandos;
  - dar de alta su API: HOST = IP del tunel, envio apagado, la clave fuera de la bitacora;
  - las rutas son solo de admin.
"""
import ast
import html
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import types

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = {
    "OVPN_SH", "OVPN_ETC", "OVPN_SRV", "OVPN_CCD", "OVPN_LOG", "OVPN_BACKUPS", "_RE_OVPN_USER", "_RE_ANSI",
    "_ovpn_conf", "_ovpn_conectados", "ovpn_instalando", "ovpn_estado", "_router_vacio", "IFACE_BASE",
    "_REPO_RAW2", "_card_vpn", "_VPN_UI", "_mb",
    "MK_INIT_BIN", "MK_INIT_MARCA", "CRED_DIR", "SURI_YAML", "IDS_FW_BIN", "EVEBOX_YAML", "INSTALADOR_LOCAL",
    "ESPEJO_LOG", "ESPEJO_UNIDAD", "TZSP_PORT_DEF", "ESPEJO_RESPALDAR", "mkinit_asegurar", "mkinit_correr",
    "_systemctl_env", "_lista_csv", "sensor_modo", "_slot_iface", "espejo_vpn_origenes",
    "espejo_vpn_red_operador", "espejo_vpn_a_defecto", "espejo_vpn_n_defecto", "_redes_validas",
    "espejo_vpn_args", "espejo_vpn_comando", "_url_vpn", "espejo_vpn_plan", "espejo_vpn_corriendo",
    "espejo_vpn_respaldo", "espejo_vpn_bajar_instalador", "espejo_vpn_lanzar", "espejo_vpn_avance",
    "_router_libre", "router_de_ip", "vpn_mk_alta", "vpn_mk_espejo", "_vpn_celda_espejo",
    "_vpn_bloque_sensor"}

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)[:400]))
    if not c:
        fallos += 1


class Sub(object):
    """subprocess de mentira. Recuerda cada orden y contesta lo que se le pida."""
    SubprocessError = subprocess.SubprocessError
    TimeoutExpired = subprocess.TimeoutExpired

    def __init__(self, orden):
        self.orden = orden          # lista compartida: en que orden pasan las cosas
        self.env = ""               # salida de systemctl show tzsp-decap
        self.fw = True              # suricata-ids-fw activo
        self.corriendo = False      # hay una unidad suricata-espejo-vpn-* activa
        self.mk_salida = b"VISTA PREVIA\n"
        self.mk_rc = 0
        self.mk_lanza = None        # excepcion a lanzar al ejecutar suricata-mikrotik-init
        self.mk_visto = []          # [(argv, contenido del archivo de credenciales, su modo)]
        self.systemd_run = []

    def call(self, cmd, **k):
        if "suricata-ids-fw" in cmd:
            return 0 if self.fw else 3
        return 0

    def run(self, cmd, **k):
        txt = k.get("text")
        def r(out="", rc=0):
            o = out if txt else out.encode("utf-8")
            return types.SimpleNamespace(returncode=rc, stdout=o, stderr="" if txt else b"")
        if cmd[:3] == ["systemctl", "show", "tzsp-decap"]:
            return r(self.env)
        if cmd[:2] == ["systemctl", "list-units"]:
            activo = self.corriendo and any("suricata-espejo-vpn" in x for x in cmd)
            return r("suricata-espejo-vpn-1.service loaded active running\n" if activo else "")
        if cmd and cmd[0] == "systemd-run":
            self.systemd_run.append(list(cmd))
            self.orden.append("systemd-run")
            return r()
        if cmd and cmd[0].endswith("suricata-mikrotik-init"):
            cred = cmd[cmd.index("-k") + 1]
            self.mk_visto.append((list(cmd), open(cred, encoding="utf-8").read(), os.stat(cred).st_mode, cred))
            self.orden.append("mkinit" + (" plan" if "--plan" in cmd else ""))
            if self.mk_lanza:
                raise self.mk_lanza
            return types.SimpleNamespace(returncode=self.mk_rc, stdout=self.mk_salida, stderr=b"")
        return r()


def entorno():
    td = tempfile.mkdtemp()
    etc = os.path.join(td, "etc", "openvpn")
    srv = os.path.join(etc, "server")
    ccd = os.path.join(etc, "open-vpn")
    os.makedirs(srv)
    os.makedirs(ccd)
    open(os.path.join(srv, "server.conf"), "w").write(
        "local 192.0.2.10\nport 1194\nproto tcp\ndev tun\nserver 100.64.0.0 255.255.255.0\n")
    open(os.path.join(ccd, "vpnaaaaaaaaaaaa"), "w").write(
        "ifconfig-push 100.64.0.2 255.255.255.0\niroute 10.20.0.0 255.255.0.0\n")
    open(os.path.join(ccd, "vpnbbbbbbbbbbbb"), "w").write(
        "ifconfig-push 100.64.0.3 255.255.255.0\niroute 172.30.0.0 255.255.0.0\n")
    open(os.path.join(srv, "openvpn-status.log"), "w").write(
        "TITLE,OpenVPN 2.6\n"
        "CLIENT_LIST,vpnaaaaaaaaaaaa,198.51.100.7:51234,100.64.0.2,,5242880,1048576,2026-10-10 17:00:00,1791669600,vpnaaaaaaaaaaaa\n")
    orden = []
    sub = Sub(orden)
    bit = []
    routers = [{"id": "r1", "nombre": "", "iface": "ids-mon", "HOST": "", "USER": "", "PASS": "", "ENABLED": "0"}]
    ns = {"os": os, "re": re, "time": time, "json": json, "html": html, "hashlib": __import__("hashlib"),
          "ipaddress": ipaddress, "subprocess": sub,
          "urllib": types.SimpleNamespace(request=None),
          "bitacora": lambda a, d="", quien=None, ip=None: bit.append((a, d)),
          "CFG": {"PORT": "5637"}, "CTX": types.SimpleNamespace(ip="203.0.113.5", peer="203.0.113.5")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n), ns)
    mkbin = os.path.join(td, "suricata-mikrotik-init")
    open(mkbin, "w").write("#!/usr/bin/env python3\n# --sin-registrar --plan\n")
    resp = os.path.join(td, "respaldar")
    os.makedirs(resp)
    for f in ("suricata.yaml", "tzsp-decap.service"):
        open(os.path.join(resp, f), "w").write("# " + f + "\n")
    ns.update(OVPN_SH=os.path.join(td, "openvpn.sh"), OVPN_ETC=etc, OVPN_SRV=srv, OVPN_CCD=ccd,
              OVPN_LOG=os.path.join(td, "ovpn.log"), OVPN_BACKUPS=os.path.join(td, "backups"),
              MK_INIT_BIN=mkbin, CRED_DIR=td, SURI_YAML=os.path.join(td, "suricata.yaml"),
              IDS_FW_BIN=os.path.join(td, "suricata-ids-fw"), EVEBOX_YAML=os.path.join(td, "evebox.yaml"),
              INSTALADOR_LOCAL=os.path.join(td, "install-suricata.sh"),
              ESPEJO_LOG=os.path.join(td, "espejo.log"),
              ESPEJO_RESPALDAR=(os.path.join(resp, "suricata.yaml"), os.path.join(resp, "tzsp-decap.service"),
                                os.path.join(resp, "no-existe")))
    open(ns["OVPN_SH"], "w").write("#!/bin/bash\nagregar_redes() { :; }\n")

    def cargar_routers():
        return [dict(r) for r in routers]

    def guardar_routers(lst):
        routers[:] = [dict(r) for r in lst]
        return routers
    ns.update(cargar_routers=cargar_routers, guardar_routers=guardar_routers,
              cargar_mk_de=lambda r: dict(r or {}))
    return ns, td, sub, bit, routers, orden


def main():
    ns, td, sub, bit, routers, orden = entorno()
    est = ns["ovpn_estado"]()

    # ======================= 1) el comando del instalador =======================
    sub.env = ("Environment=TZSP_PORT=37008 TZSP_OUT_IF=ids-in TZSP_ALLOW=192.0.2.1 "
               "TZSP_MAP=192.0.2.1=ids-in TZSP_BYTES=0\n")
    sub.fw = False
    open(ns["SURI_YAML"], "w").write('vars:\n  address-groups:\n    HOME_NET: "[10.0.0.0/8,192.168.0.0/16]"\n')
    open(ns["EVEBOX_YAML"], "w").write("http:\n  host: \"0.0.0.0\"\n  port: 5636\n")
    modo = ns["sensor_modo"]()
    check("modo actual: origenes, recorte, HOME_NET y firewall (local, sin solo-tunel)",
          modo["allow"] == ["192.0.2.1"] and modo["bytes"] == 0 and modo["home_net"] == ["10.0.0.0/8", "192.168.0.0/16"]
          and modo["modo"] == "local" and modo["puerto"] == 37008 and modo["web"] and modo["evebox_puerto"] == "5636", modo)

    orig = ns["espejo_vpn_origenes"](est, ns["cargar_routers"]())
    check("-m: las IPs de los MikroTik EN EL TUNEL, una interfaz por cada uno",
          [(o["ip"], o["iface"]) for o in orig] == [("100.64.0.2", "ids-mon"), ("100.64.0.3", "ids-mon2")], orig)
    # el que ya esta dado de alta con SU interfaz la conserva aunque la VPN lo liste antes
    rs = [{"id": "r1", "iface": "ids-mon", "HOST": "192.0.2.1"},
          {"id": "r2", "iface": "ids-mon2", "HOST": "100.64.0.2", "nombre": "Nodo Norte"}]
    orig2 = ns["espejo_vpn_origenes"](est, rs)
    check("  el que ya esta dado de alta conserva su interfaz (sus alertas siguen siendo suyas)",
          [(o["ip"], o["iface"]) for o in orig2] == [("100.64.0.3", "ids-mon"), ("100.64.0.2", "ids-mon2")]
          and orig2[1]["router"] == "Nodo Norte", orig2)

    a_def = ns["espejo_vpn_a_defecto"](modo, est, "203.0.113.5")
    n_def = ns["espejo_vpn_n_defecto"](est, modo)
    check("-a prerrellenado con la IP de quien entra ahora", a_def == ["203.0.113.5/32"], a_def)
    check("-n prerrellenado con las redes de los MikroTik", n_def == ["10.20.0.0/16", "172.30.0.0/16"], n_def)
    check("  entrando por la VPN (o desde la propia caja) no hace falta -a",
          ns["espejo_vpn_red_operador"]("100.64.0.9", est) == "" and ns["espejo_vpn_red_operador"]("127.0.0.1", est) == "", "")
    modo_g = dict(modo, gestion=["203.0.113.0/24"])
    check("  las redes que ya tenia -a se conservan (y no se repite la que ya cubren)",
          ns["espejo_vpn_a_defecto"](modo_g, est, "203.0.113.5") == ["203.0.113.0/24"]
          and ns["espejo_vpn_a_defecto"](modo_g, est, "198.51.100.4") == ["203.0.113.0/24", "198.51.100.4/32"], "")
    sin_redes = {"usuarios": [{"usuario": "x", "ip": "100.64.0.2", "redes": []}]}
    check("  sin redes en la VPN, -n conserva el HOME_NET de ahora",
          ns["espejo_vpn_n_defecto"](sin_redes, modo) == ["10.0.0.0/8", "192.168.0.0/16"], "")

    args, err, av = ns["espejo_vpn_args"](orig, ",".join(n_def), ",".join(a_def), modo)
    check("argumentos: -t -e vpn -m <tunel> -n <redes> -a <operador>",
          args == ["-t", "-e", "vpn", "-m", "100.64.0.2,100.64.0.3", "-n", "10.20.0.0/16,172.30.0.0/16",
                   "-a", "203.0.113.5/32"] and not err, (args, err))
    check("  NUNCA -P: las claves de la web se conservan", "-P" not in args, args)
    for basura in ("203.0.113.5; rm -rf /", "0.0.0.0/0", "hola", "$(reboot)", "10.0.0.0/7"):
        a2, e2, _ = ns["espejo_vpn_args"](orig, "10.20.0.0/16", basura, modo)
        check("  -a con basura se rechaza antes de construir nada: %r" % basura, e2 and a2 == [], (a2, e2))
    a3, e3, _ = ns["espejo_vpn_args"](orig, "", "203.0.113.5/32", modo)
    check("  -n vacio se rechaza", e3 and not a3, e3)
    a4, e4, _ = ns["espejo_vpn_args"]([], "10.20.0.0/16", "", modo)
    check("  sin MikroTik en la VPN no hay comando", e4 and not a4, e4)
    a5, _e, _ = ns["espejo_vpn_args"](orig, "10.20.0.0/16", "", dict(modo, bytes=20000, web=False))
    check("  conserva el recorte elegido a mano y no instala EveBox donde no lo habia",
          a5[-3:] == ["-b", "20000", "-W"] and "-a" not in a5, a5)
    a6, _e, _ = ns["espejo_vpn_args"](orig, "10.20.0.0/16", "", dict(modo, evebox_puerto="8443"))
    check("  y el puerto de EveBox si no era el de siempre", a6[-2:] == ["-p", "8443"], a6)

    # vista previa: lo que se va a ejecutar, con el aviso de quedarse fuera
    p = ns["espejo_vpn_plan"](",".join(n_def), "", "203.0.113.5", est=est, modo=modo,
                              routers=ns["cargar_routers"]())
    check("vista previa sin -a: avisa que perderas la web y como entrar luego",
          p["ok"] and "NO esta en -a" in p["avisos"][0] and "http://100.64.0.1:5637" in p["avisos"][0]
          and "NADIE" in p["confirmar"], p)
    check("  y avisa del origen que deja de aceptarse y del cambio de HOME_NET",
          any("192.0.2.1" in x for x in p["avisos"]) and any("HOME_NET pasa de" in x for x in p["avisos"]), p["avisos"])
    check("  el comando ensenado es el de los argumentos (instalador en /root)",
          p["cmd"] == "bash %s %s" % (ns["INSTALADOR_LOCAL"], " ".join(p["args"])) and "/tmp" not in p["cmd"], p["cmd"])
    p2 = ns["espejo_vpn_plan"](",".join(n_def), "203.0.113.5/32", "203.0.113.5", est=est, modo=modo,
                               routers=ns["cargar_routers"]())
    check("  con su IP en -a no hay aviso de quedarse fuera, y la confirmacion lo dice",
          not any("NO esta en -a" in x for x in p2["avisos"]) and "203.0.113.5/32" in p2["confirmar"], p2)
    p3 = ns["espejo_vpn_plan"]("10.20.0.0/16", "basura", "203.0.113.5", est=est, modo=modo, routers=[])
    check("  con basura no hay plan", not p3["ok"] and "basura" in p3["msg"], p3)

    # la tarjeta: detras de un proxy, -a lleva al PROXY (es lo que ve el firewall)
    ns["CTX"] = types.SimpleNamespace(ip="198.51.100.20", peer="192.0.2.50")
    b = ns["_vpn_bloque_sensor"](est, modo, ns["cargar_routers"]())
    va = re.search(r'id=vpn_a value="([^"]*)"', b)
    check("tarjeta: -a prerrellenado con la IP del proxy si se entra por proxy",
          va and va.group(1) == "192.0.2.50/32" and "proxy" in b and "198.51.100.20" in b, va and va.group(1))
    check("  y -n con las redes de la VPN", 'id=vpn_n value="10.20.0.0/16,172.30.0.0/16"' in b, "")
    ns["CTX"] = types.SimpleNamespace(ip="100.64.0.6", peer="100.64.0.6")
    b = ns["_vpn_bloque_sensor"](est, modo, ns["cargar_routers"]())
    check("  entrando por la VPN, -a vacio y lo dice",
          'id=vpn_a value=""' in b and "no necesitas <code>-a</code>" in b, "")

    # ======================= 2) lanzar: respaldo, /root, unidad propia, FIN =======================
    INST = b"#!/usr/bin/env bash\n# instalador\ncat > /usr/local/bin/suricata-dashboard <<'DASH'\nDASH\n"

    class Resp(object):
        def __init__(self, b_):
            self.b = b_

        def read(self):
            return self.b
    ns["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(urlopen=lambda u, timeout=0: Resp(INST)))
    ok, msg = ns["espejo_vpn_lanzar"](args + ["-P", "x"], quien="admin")
    check("lanzar con -P se niega", not ok and not sub.systemd_run, msg)
    resp_antes = ns["espejo_vpn_respaldo"]
    ns["espejo_vpn_respaldo"] = lambda: (_ for _ in ()).throw(OSError("disco lleno"))
    ok, msg = ns["espejo_vpn_lanzar"](args, quien="admin")
    check("sin respaldo no se lanza nada", not ok and "no se toca nada" in msg and not sub.systemd_run, msg)
    ns["espejo_vpn_respaldo"] = resp_antes
    ok, msg = ns["espejo_vpn_lanzar"](args, quien="admin")
    check("lanzar: en marcha", ok and len(sub.systemd_run) == 1, msg)
    bk = [f for f in os.listdir(ns["OVPN_BACKUPS"]) if f.startswith("espejo-vpn-")]
    nombres = tarfile.open(os.path.join(ns["OVPN_BACKUPS"], bk[0])).getnames() if bk else []
    check("  antes se respaldo lo que se va a reescribir (lo que existe)",
          bk and any(n.endswith("suricata.yaml") for n in nombres) and any(n.endswith("tzsp-decap.service") for n in nombres),
          nombres)
    check("  el instalador quedo en /root (aqui, su doble) tal cual se bajo",
          open(ns["INSTALADOR_LOCAL"], "rb").read() == INST, "")
    c = sub.systemd_run[0]
    i = c.index("/bin/bash")
    check("  unidad propia de systemd, con log y sin shell para los argumentos",
          c[1] == "--unit" and c[2].startswith("suricata-espejo-vpn-")
          and "StandardOutput=append:" + ns["ESPEJO_LOG"] in c and c[i + 1] == "-c"
          and c[i + 3] == ns["INSTALADOR_LOCAL"] and c[i + 4:] == args and "-P" not in c, c)
    check("  bitacora: quien, con que opciones, huella del instalador y respaldo",
          bit and bit[-1][0] == "ESPEJO-VPN" and "-m 100.64.0.2,100.64.0.3" in bit[-1][1]
          and "sha256=" in bit[-1][1] and "espejo-vpn-" in bit[-1][1], bit[-1:])
    # el envoltorio de verdad: pasa los argumentos tal cual (con espacios) y deja la marca
    falso = os.path.join(td, "falso.sh")
    io.open(falso, "w", encoding="utf-8", newline="\n").write('printf "ARG[%s]\\n" "$@"; exit 3\n')
    rb = subprocess.run(["bash", "-c", c[i + 2], falso.replace("\\", "/"), "-n", "10.0.0.0/8", "a b"],
                        capture_output=True, text=True)
    check("  el envoltorio pasa los argumentos intactos y termina con FIN rc=<codigo>",
          "ARG[-n]\nARG[10.0.0.0/8]\nARG[a b]\n" in rb.stdout and rb.stdout.rstrip().endswith("FIN rc=3"), rb.stdout)
    sub.corriendo = True
    ok, msg = ns["espejo_vpn_lanzar"](args, quien="admin")
    check("  dos a la vez no", not ok and "en marcha" in msg and len(sub.systemd_run) == 1, msg)
    ns["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(urlopen=lambda u, timeout=0: Resp(b"<html>404</html>")))
    sub.corriendo = False
    ok, msg = ns["espejo_vpn_lanzar"](args, quien="admin")
    check("  si lo bajado no es el instalador, no se ejecuta", not ok and len(sub.systemd_run) == 1, msg)

    # el avance
    open(ns["ESPEJO_LOG"], "w").write("Recibir el espejo\n\x1b[32m[+]\x1b[0m Suricata instalado\n")
    sub.corriendo = True
    l = ns["espejo_vpn_avance"]()
    check("avance: en marcha mientras no aparece la marca FIN", l["corriendo"] and l["rc"] is None, l)
    open(ns["ESPEJO_LOG"], "a").write("FIN rc=0\n")
    sub.corriendo = False
    l = ns["espejo_vpn_avance"]()
    check("  terminado: rc de la marca y sin colores de terminal", l["rc"] == 0 and not l["corriendo"]
          and "\x1b[" not in l["log"], l)

    # ======================= 3) el espejo en el MikroTik =======================
    ns["respaldar_firewall"] = lambda r, s_=None: (orden.append("respaldo"), "/root/backups/x.json")[1]
    ns["mk_conectar"] = lambda d, timeout=6: types.SimpleNamespace(close=lambda: None)
    ok, msg = ns["vpn_mk_espejo"]("vpnbbbbbbbbbbbb", aplicar=True, quien="admin")
    check("sin conectar a la VPN no se toca el router, y dice por que",
          not ok and "no esta conectado" in msg and not orden[-1:] == ["respaldo"] and not sub.mk_visto, msg)
    ok, msg = ns["vpn_mk_espejo"]("vpnaaaaaaaaaaaa", aplicar=False, quien="admin")
    check("sin dar de alta su API, lo pide", not ok and "Dar de alta su API" in msg, msg)

    # alta de la API desde la fila
    ok, msg = ns["vpn_mk_alta"]("vpnaaaaaaaaaaaa", "Nodo <Norte>", "ids", "S3creta!", "", False, quien="admin")
    r1 = routers[0]
    check("alta: el nodo vacio de un sensor nuevo se usa, con HOST = IP del tunel",
          ok and len(routers) == 1 and r1["HOST"] == "100.64.0.2" and r1["iface"] == "ids-mon"
          and r1["PORT"] == "8728" and r1["USER"] == "ids" and r1["PASS"] == "S3creta!", (msg, routers))
    check("  el envio a cuarentena queda apagado y el nombre sin marcas",
          r1["ENABLED"] == "0" and r1["nombre"] == "Nodo Norte", r1)
    check("  la clave no va a la bitacora ni vuelve en el mensaje",
          bit[-1][0] == "CONFIG-NODO" and "S3creta" not in bit[-1][1] and "S3creta" not in msg, (bit[-1], msg))
    check("  y prueba la API al guardar", "La API responde" in msg, msg)
    ok, msg = ns["vpn_mk_alta"]("vpnaaaaaaaaaaaa", "", "ids", "x", "", False)
    check("  dos veces el mismo, no", not ok and "ya esta dado de alta" in msg, msg)
    ok, msg = ns["vpn_mk_alta"]("vpnbbbbbbbbbbbb", "", "ids", "x\nHOST=203.0.113.9", "", False)
    check("  una clave con salto de linea se rechaza (meteria otra clave en el archivo)", not ok, msg)
    routers.append({"id": "r3", "iface": "ids-mon3", "HOST": "192.0.2.77", "USER": "u", "PASS": "p"})
    ok, msg = ns["vpn_mk_alta"]("vpnbbbbbbbbbbbb", "", "ids", "otra", "8729", True)
    nuevo = routers[-1]
    check("  el siguiente va aparte, con un id e interfaz libres (no pisa a nadie)",
          ok and nuevo["HOST"] == "100.64.0.3" and nuevo["id"] == "r2" and nuevo["iface"] == "ids-mon2"
          and nuevo["TLS"] == "1" and nuevo["PORT"] == "8729", routers)
    routers.pop()          # vuelve a ser un sensor con un solo MikroTik dado de alta
    routers.pop()

    # vista previa: ni respaldo ni cambios; credenciales en archivo temporal
    del orden[:]
    sub.mk_salida = b"VISTA PREVIA: no se ha tocado nada.\n  /ip firewall mangle add action=sniff-tzsp\n"
    ok, msg = ns["vpn_mk_espejo"]("vpnaaaaaaaaaaaa", aplicar=False, quien="admin")
    argv, cont, modo_c, cred = sub.mk_visto[-1]
    check("vista previa: --plan y --sin-registrar, sensor = su IP EN EL TUNEL, -e vpn, sus redes",
          ok and "--plan" in argv and "--sin-registrar" in argv and argv[argv.index("-s") + 1] == "100.64.0.1"
          and argv[argv.index("-e") + 1] == "vpn" and argv[argv.index("-r") + 1] == "10.20.0.0/16"
          and argv[argv.index("-p") + 1] == "37008", argv)
    check("  no respalda ni toca: solo mira", orden == ["mkinit plan"], orden)
    check("  devuelve lo que se haria y avisa si el sensor aun no lo recibe",
          "VISTA PREVIA" in msg and "Recibir el espejo por la VPN" in msg, msg)
    check("  la clave va en el archivo, nunca en la linea de comandos",
          "PASS=S3creta!" in cont and "HOST=100.64.0.2" in cont and not any("S3creta" in x for x in argv), (argv, cont))
    check("  el archivo esta en /root (aqui, su doble), no en /tmp", os.path.dirname(cred) == ns["CRED_DIR"], cred)
    if os.name == "posix":
        check("  con permisos 600 (modo real)", (modo_c & 0o077) == 0, oct(modo_c))
    else:
        check("  con permisos 600 (no medible en Windows: se comprueba la intencion)",
              "os.chmod(cred, 0o600)" in DASH, "")
    check("  y se borra al terminar", not os.path.exists(cred), cred)

    # aplicar: respaldo ANTES; si falla el respaldo, no se toca
    del orden[:]
    sub.mk_salida = b"regla 'espejo IDS (ida)': crear: hecho\n"
    ok, msg = ns["vpn_mk_espejo"]("vpnaaaaaaaaaaaa", aplicar=True, quien="admin")
    argv = sub.mk_visto[-1][0]
    check("aplicar: respaldo del firewall del router ANTES de tocarlo", ok and orden == ["respaldo", "mkinit"], orden)
    check("  sin --plan y sin registrar de nuevo (no pisa la configuracion del panel)",
          "--plan" not in argv and "--sin-registrar" in argv, argv)
    check("  bitacora con el router, el sensor y el respaldo",
          bit[-1][0] == "ESPEJO-MIKROTIK" and "100.64.0.2" in bit[-1][1] and "sensor=100.64.0.1" in bit[-1][1]
          and "respaldo=" in bit[-1][1], bit[-1])
    ns["respaldar_firewall"] = lambda r, s_=None: (_ for _ in ()).throw(IOError("router caido"))
    n_antes = len(sub.mk_visto)
    ok, msg = ns["vpn_mk_espejo"]("vpnaaaaaaaaaaaa", aplicar=True, quien="admin")
    check("  sin respaldo no se toca el router", not ok and "no se toca nada" in msg and len(sub.mk_visto) == n_antes, msg)
    # credenciales borradas aunque la herramienta falle
    sub.mk_lanza = subprocess.TimeoutExpired("suricata-mikrotik-init", 150)
    rc, out = ns["mkinit_correr"](routers[0], ["--plan"])
    cred = sub.mk_visto[-1][3]
    check("si la herramienta revienta (timeout), el archivo de credenciales se borra igual",
          rc == 1 and not os.path.exists(cred), (rc, out))
    sub.mk_lanza = None
    restos = [f for f in os.listdir(ns["CRED_DIR"]) if f.endswith(".cred")]
    check("  no queda ningun archivo de credenciales", not restos, restos)

    # la herramienta vieja (sin --sin-registrar) se renueva sola antes de usarla
    open(ns["MK_INIT_BIN"], "w").write("#!/usr/bin/env python3\n# vieja\n")
    ns["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(
        urlopen=lambda u, timeout=0: Resp(SRC.encode("utf-8"))))
    ok, msg = ns["mkinit_asegurar"]()
    nueva = open(ns["MK_INIT_BIN"], encoding="utf-8").read()
    prog = SRC.split("<<'MKINIT'\n", 1)[1].split("\nMKINIT\n", 1)[0] + "\n"
    check("herramienta vieja: se baja del instalador publicado y se instala tal cual",
          ok and nueva == prog and "--sin-registrar" in nueva, msg)
    check("  y la vieja queda respaldada", any(f.startswith("suricata-mikrotik-init.bak-") for f in os.listdir(td)), "")
    # el boton Actualizar tambien la renueva (el trozo real del actualizador, con bash)
    upd = SRC.split("cat > /usr/local/bin/suricata-panel-update <<'UPDSH'\n", 1)[1].split("\nUPDSH\n", 1)[0]
    f_ini = upd.index("extraer() {")
    f_fin = upd.index("\n}\n", f_ini) + 3
    b_ini = upd.index("# suricata-mikrotik-init: Ajustes > VPN")
    b_fin = upd.index("\nfi\n", upd.index('log "no se renovo suricata-mikrotik-init"', b_ini)) + 4
    root2 = tempfile.mkdtemp().replace("\\", "/")
    io.open(root2 + "/instalador.sh", "w", encoding="utf-8", newline="\n").write(SRC)
    io.open(root2 + "/suricata-mikrotik-init", "w", encoding="utf-8", newline="\n").write("# vieja\n")
    trozo = ("set -u\nlog(){ echo \"LOG $*\"; }\nTMP=%s/instalador.sh\n" % root2 + upd[f_ini:f_fin]
             + upd[b_ini:b_fin]).replace("/usr/local/bin/suricata-mikrotik-init", root2 + "/suricata-mikrotik-init")
    ru = subprocess.run(["bash", "-s"], input=trozo, capture_output=True, text=True, encoding="utf-8")
    check("el actualizador renueva suricata-mikrotik-init (el programa, no la linea que lo busca)",
          ru.returncode == 0 and io.open(root2 + "/suricata-mikrotik-init", encoding="utf-8").read() == prog,
          (ru.stdout[-300:], ru.stderr[-300:]))

    # ======================= 4) tarjeta y rutas =======================
    ns["CTX"] = types.SimpleNamespace(ip="203.0.113.5", peer="203.0.113.5")
    c = ns["_card_vpn"]()
    check("tarjeta: el conectado y dado de alta ofrece montar el espejo; el otro dice por que no",
          "vpnEspejoPlan('vpnaaaaaaaaaaaa')" in c and "Conectalo primero a la VPN" in c, "")
    check("  y debajo, recibir el espejo por la VPN con -a y -n editables",
          "vpnSensorPlan()" in c and "id=vpn_a" in c and "id=vpn_n" in c, "")
    check("  sin dialogos nativos", not re.search(r"(?<![A-Za-z0-9_.])(confirm|alert|prompt)\s*\(", c), "")
    i = DASH.index('if ruta in ("/vpn/mk-alta", "/vpn/mk-espejo-plan", "/vpn/mk-espejo-aplicar",')
    check("las rutas nuevas son solo de admin", "if not self._admin():" in DASH[i:i + 500], "")
    j = DASH.index('if path == "/vpn/sensor-log":')
    check("  y el avance tambien", "if not self._admin():" in DASH[j:j + 200], "")
    check("  lo que se lanza se recalcula en el servidor (no viene hecho del navegador)",
          'espejo_vpn_lanzar(p["args"]' in DASH[i:i + 2500], "")
    check("la IP que llega al socket queda en el contexto (es la que ve el firewall)",
          "CTX.peer = self._peer_ip()" in DASH, "")

    # ======================= 5) el JS del avance aguanta el reinicio =======================
    if shutil.which("node"):
        script = re.search(r"<script>(.*)</script>", ns["_VPN_UI"], re.S).group(1)
        fjs = os.path.join(td, "vpnui.js")
        io.open(fjs, "w", encoding="utf-8").write(script)
        arnes = os.path.join(td, "arnes.js")
        io.open(arnes, "w", encoding="utf-8").write(ARNES_JS)
        rn = subprocess.run(["node", arnes, fjs], capture_output=True, text=True, encoding="utf-8")
        check("avance en el navegador: aguanta cortes y respuestas que no son JSON, y llega al final",
              rn.returncode == 0 and "FIN-OK" in rn.stdout, (rn.stdout[-400:], rn.stderr[-400:]))
        check("  mientras tanto dice que el panel se esta reiniciando",
              "REINICIANDO" in rn.stdout, rn.stdout[-300:])
    else:
        print("  aviso: node no esta instalado, se omite la prueba del avance en el navegador")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


# DOM minimo: la caja del modal y los elementos que vpnSensorLog crea en ella. fetch falla
# como falla de verdad un reinicio: red caida, 502 del proxy, la pagina de login (no JSON),
# y despues contesta. setTimeout no espera: el tiempo no es lo que se prueba.
ARNES_JS = r"""
const vm = require('vm');
const fs = require('fs');
const caja = {innerHTML: ''};
const els = {};
const estados = [];
function el(id) {
  if (!els[id]) {
    const e = {id: id, className: '', innerHTML: '', scrollTop: 0, scrollHeight: 0, style: {}};
    let t = '';
    Object.defineProperty(e, 'textContent', {get() { return t; }, set(v) { t = v; if (id === 'vpnst') estados.push(v); }});
    els[id] = e;
  }
  return els[id];
}
global.document = {
  getElementById(id) {
    if (id === 'vpnov') return {style: {}, querySelector() { return caja; }};
    return caja.innerHTML.indexOf('id=' + id) >= 0 ? el(id) : null;
  }
};
global.location = {hash: '', reload() {}};
global.window = global;
const respuestas = [
  () => Promise.reject(new TypeError('Failed to fetch')),
  () => Promise.resolve({ok: false, status: 502}),
  () => Promise.resolve({ok: true, json() { return Promise.reject(new SyntaxError('login')); }}),
  () => Promise.resolve({ok: true, json() { return Promise.resolve({corriendo: true, rc: null, log: 'instalando'}); }}),
  () => Promise.resolve({ok: true, json() { return Promise.resolve({corriendo: false, rc: 0, log: 'instalando\nFIN rc=0'}); }}),
];
let n = 0;
global.fetch = () => (respuestas[Math.min(n++, respuestas.length - 1)])();
global.setTimeout = (f) => setImmediate(f);
vm.runInThisContext(fs.readFileSync(process.argv[2], 'utf8'));
vpnSensorLog();
setTimeout = global.setTimeout;
const fin = Date.now() + 3000;
(function esperar() {
  const t = els['vpnlt'] ? els['vpnlt'].textContent : '';
  if (t.indexOf('Listo') === 0) {
    if (estados.some(s => s.indexOf('reiniciando') >= 0)) console.log('REINICIANDO');
    if (els['vpnsp'] && els['vpnsp'].className === 'vpnico' && n >= 5) console.log('FIN-OK');
    return;
  }
  if (Date.now() > fin) { console.log('no termino: ' + t + ' n=' + n); process.exit(1); }
  setImmediate(esperar);
})();
"""


if __name__ == "__main__":
    sys.exit(main())
