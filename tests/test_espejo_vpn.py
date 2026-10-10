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
    la interfaz, la que le dara -m (no la primera libre);
  - cada interfaz, de su router: el plan corrige los nodos (el de -m toma la suya; el que no
    esta en -m pierde la que pasa a otro y su envio a cuarentena) y se guarda al lanzar;
  - uno a la vez: dos Lanzar a la vez (dos hilos) lanzan UN instalador; unidad de nombre fijo;
  - el respaldo permite volver atras (programas, config del panel, EveBox...) y es 600;
  - el instalador reinicia el panel si ya corria; el log de la web va con las claves tapadas;
  - el actualizador respalda y restaura tambien suricata-mikrotik-init (con dash);
  - las rutas son solo de admin (ejecutando el handler con una sesion de solo lectura).
"""
import ast
import contextlib
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
import threading
import time
import types
import urllib.parse
from http.cookies import SimpleCookie

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
    "_vpn_bloque_sensor",
    "OVPN_UNIDAD", "OVPN_CERROJO", "ESPEJO_CERROJO", "_UnaVez", "_RE_CLAVE_LOG", "enmascarar_claves",
    "espejo_vpn_reasignar", "espejo_vpn_nodos_txt", "espejo_vpn_nodos_aplicar", "_iface_en_uso",
    "_iface_vpn", "rid_por_iface", "ovpn_instalar"}


class OsEspia(object):
    """os de verdad, pero apunta con que permisos se crea cada archivo (chmod y os.open).
    En Windows el modo real no se puede medir; asi se mide lo que el codigo PIDE, en el
    momento en que lo pide, en cualquier sistema."""

    def __init__(self):
        self.modos = {}      # ruta -> ultimo modo pedido (chmod u os.open)
        self.creado = {}     # ruta -> modo con el que se CREO por os.open (si se creo asi)

    def __getattr__(self, n):
        return getattr(os, n)

    @staticmethod
    def _k(p):
        return os.path.normcase(os.path.abspath(p))

    def chmod(self, p, m, *a, **k):
        self.modos[self._k(p)] = m
        return os.chmod(p, m, *a, **k)

    def open(self, p, flags, mode=0o777, *a, **k):
        if flags & os.O_CREAT:
            self.modos[self._k(p)] = mode
            self.creado.setdefault(self._k(p), mode)
        return os.open(p, flags, mode, *a, **k)

    def modo(self, p):
        return self.modos.get(self._k(p))

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
        self.systemd_rc = 0         # 1 = systemd-run falla (p.ej. la unidad ya existe)
        self.espia = None           # OsEspia: con que permisos se pidio cada archivo
        self.routers_al_lanzar = None   # los routers guardados en el momento de systemd-run
        self.leer_routers = None

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
            if self.leer_routers:
                self.routers_al_lanzar = self.leer_routers()
            if self.systemd_rc:
                return types.SimpleNamespace(returncode=self.systemd_rc, stdout="",
                                             stderr="Unit suricata-espejo-vpn.service already exists.")
            return r()
        if cmd and cmd[0].endswith("suricata-mikrotik-init"):
            cred = cmd[cmd.index("-k") + 1]
            pedido = self.espia.modo(cred) if self.espia else None
            self.mk_visto.append((list(cmd), open(cred, encoding="utf-8", newline="").read(),
                                  (pedido, os.stat(cred).st_mode), cred))
            self.orden.append("mkinit" + (" plan" if "--plan" in cmd else ""))
            if self.mk_lanza:
                raise self.mk_lanza
            return types.SimpleNamespace(returncode=self.mk_rc, stdout=self.mk_salida, stderr=b"")
        return r()


def entorno(routers0=None, usuarios=("a", "b")):
    td = tempfile.mkdtemp()
    etc = os.path.join(td, "etc", "openvpn")
    srv = os.path.join(etc, "server")
    ccd = os.path.join(etc, "open-vpn")
    os.makedirs(srv)
    os.makedirs(ccd)
    open(os.path.join(srv, "server.conf"), "w").write(
        "local 192.0.2.10\nport 1194\nproto tcp\ndev tun\nserver 100.64.0.0 255.255.255.0\n")
    if "a" in usuarios:
        open(os.path.join(ccd, "vpnaaaaaaaaaaaa"), "w").write(
            "ifconfig-push 100.64.0.2 255.255.255.0\niroute 10.20.0.0 255.255.0.0\n")
    if "b" in usuarios:
        open(os.path.join(ccd, "vpnbbbbbbbbbbbb"), "w").write(
            "ifconfig-push 100.64.0.3 255.255.255.0\niroute 172.30.0.0 255.255.0.0\n")
    open(os.path.join(srv, "openvpn-status.log"), "w").write(
        "TITLE,OpenVPN 2.6\n"
        "CLIENT_LIST,vpnaaaaaaaaaaaa,198.51.100.7:51234,100.64.0.2,,5242880,1048576,2026-10-10 17:00:00,1791669600,vpnaaaaaaaaaaaa\n")
    orden = []
    sub = Sub(orden)
    bit = []
    routers = [dict(r) for r in routers0] if routers0 is not None else [
        {"id": "r1", "nombre": "", "iface": "ids-mon", "HOST": "", "USER": "", "PASS": "", "ENABLED": "0"}]
    espia = OsEspia()
    sub.espia = espia
    ns = {"os": espia, "re": re, "time": time, "json": json, "html": html, "hashlib": __import__("hashlib"),
          "ipaddress": ipaddress, "subprocess": sub, "threading": threading,
          "urllib": types.SimpleNamespace(request=None, parse=urllib.parse),
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
              ESPEJO_CERROJO=os.path.join(td, "espejo.lock"), OVPN_CERROJO=os.path.join(td, "ovpn.lock"),
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
    sub.leer_routers = cargar_routers
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
    check("  unidad propia de systemd de nombre FIJO (systemd rechaza un segundo) y --collect, con log "
          "y sin shell para los argumentos",
          c[1] == "--unit" and c[2] == "suricata-espejo-vpn" and "--collect" in c[:i]
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
          'PASS="S3creta!"' in cont and "HOST=100.64.0.2" in cont and not any("S3creta" in x for x in argv), (argv, cont))
    check("  el archivo esta en /root (aqui, su doble), no en /tmp", os.path.dirname(cred) == ns["CRED_DIR"], cred)
    # lo que el codigo PIDE (medible en cualquier sistema) y, donde se puede, el modo real
    check("  con permisos 600 pedidos ANTES de ejecutar la herramienta", modo_c[0] == 0o600, modo_c)
    if os.name == "posix":
        check("  y en disco nadie mas lo puede leer (modo real)", (modo_c[1] & 0o077) == 0, oct(modo_c[1]))
    check("  y se borra al terminar", not os.path.exists(cred), cred)

    # hallazgo 10: la clave llega intacta a la herramienta (espacios y comillas en los bordes)
    i_mk = SRC.index("cat > /usr/local/bin/suricata-mikrotik-init <<'MKINIT'")
    prog_mk = SRC[i_mk:].split("\n", 1)[1].split("\nMKINIT\n", 1)[0]
    ns_mk = {"__name__": "prueba"}
    exec(compile(prog_mk, "<mkinit>", "exec"), ns_mk)
    for rara in (" empieza-con-espacio", "acaba-en-espacio ", '"entre-comillas"', "'simples'", 'a"b', "x'"):
        rr = dict(routers[0], PASS=rara)
        n0 = len(sub.mk_visto)
        ns["mkinit_correr"](rr, ["--plan"])
        cont_r = sub.mk_visto[n0][1] if len(sub.mk_visto) > n0 else ""
        fcred = os.path.join(td, "cred-prueba")
        io.open(fcred, "w", encoding="utf-8", newline="").write(cont_r)
        try:
            with contextlib.redirect_stdout(io.StringIO()):   # el aviso de permisos (en Windows siempre)
                leida = ns_mk["leer_credenciales"](fcred).get("PASS")
        except SystemExit as ex:
            leida = "SALIO: %s" % ex
        check("  clave %r: el panel la escribe y suricata-mikrotik-init la lee IGUAL" % rara, leida == rara,
              (leida, cont_r))
    n_r = len(routers)
    ok_a, msg_a = ns["vpn_mk_alta"]("vpnbbbbbbbbbbbb", "", "ids", " 'clave rara\" ", "", False)
    check("  y vpn_mk_alta acepta claves asi (no es un caso imposible) y las guarda tal cual",
          ok_a and routers[-1]["PASS"] == " 'clave rara\" ", (msg_a, routers[-1:]))
    del routers[n_r:]

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
    # el actualizador es #!/bin/sh: en Debian, dash. Se corre con dash si esta (bash si no), y
    # en bytes: con text=True, en Windows, el \n se convertiria y el trozo no seria el real
    shell = shutil.which("dash") or "bash"
    ru = subprocess.run([shell, "-s"], input=trozo.encode("utf-8"), capture_output=True)
    check("el actualizador renueva suricata-mikrotik-init (el programa, no la linea que lo busca) [%s]"
          % os.path.basename(shell),
          ru.returncode == 0 and io.open(root2 + "/suricata-mikrotik-init", encoding="utf-8").read() == prog,
          (ru.stdout[-300:], ru.stderr[-300:]))

    # hallazgo 12: el actualizador la respalda antes y la restaura en el rollback, como al resto
    root3 = tempfile.mkdtemp().replace("\\", "/")
    os.makedirs(root3 + "/bin")
    os.makedirs(root3 + "/bkp")
    for f in ("suricata-dashboard", "suricata-html-report", "suricata-panel-update", "suricata-mikrotik-init"):
        io.open(root3 + "/bin/" + f, "w", encoding="utf-8", newline="\n").write("# vieja " + f + "\n")
    b1 = upd.index('mkdir -p "$BKP"\n') + len('mkdir -p "$BKP"\n')
    b2 = upd.index("\ndone\n", b1) + 6
    r1_ = upd.index("for f in", upd.index("ROLLBACK desde"))
    r2_ = upd.index("\n  done\n", r1_) + 8
    resp_sh = ("set -e\nBKP=%s/bkp\n" % root3 + upd[b1:b2]
               + "for f in %s/bin/*; do echo '# nueva' > \"$f\"; done\n" % root3
               + upd[r1_:r2_] + "echo FIN\n").replace("/usr/local/bin/", root3 + "/bin/")
    rr_ = subprocess.run([shell, "-s"], input=resp_sh.encode("utf-8"), capture_output=True)
    check("el actualizador respalda suricata-mikrotik-init antes de renovarla [%s]" % os.path.basename(shell),
          os.path.isfile(root3 + "/bkp/suricata-mikrotik-init")
          and io.open(root3 + "/bkp/suricata-mikrotik-init", encoding="utf-8").read() == "# vieja suricata-mikrotik-init\n",
          (rr_.stdout[-200:], rr_.stderr[-200:]))
    check("  y el rollback la restaura con el resto (y sigue aunque falte algun programa)",
          b"FIN" in rr_.stdout
          and io.open(root3 + "/bin/suricata-mikrotik-init", encoding="utf-8").read() == "# vieja suricata-mikrotik-init\n"
          and io.open(root3 + "/bin/suricata-dashboard", encoding="utf-8").read() == "# vieja suricata-dashboard\n",
          (rr_.stdout[-200:], rr_.stderr[-200:]))

    # ======================= 4) tarjeta y rutas =======================
    ns["CTX"] = types.SimpleNamespace(ip="203.0.113.5", peer="203.0.113.5")
    c = ns["_card_vpn"]()
    check("tarjeta: el conectado y dado de alta ofrece montar el espejo; el otro dice por que no",
          "vpnEspejoPlan('vpnaaaaaaaaaaaa')" in c and "Conectalo primero a la VPN" in c, "")
    check("  y debajo, recibir el espejo por la VPN con -a y -n editables",
          "vpnSensorPlan()" in c and "id=vpn_a" in c and "id=vpn_n" in c, "")
    check("  sin dialogos nativos", not re.search(r"(?<![A-Za-z0-9_.])(confirm|alert|prompt)\s*\(", c), "")
    prueba_rutas()
    prueba_nodos()
    prueba_uno_a_la_vez()
    prueba_respaldo_y_reinicio()
    prueba_claves_en_el_log()

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


INSTALADOR_FALSO = b"#!/usr/bin/env bash\n# instalador\ncat > /usr/local/bin/suricata-dashboard <<'DASH'\nDASH\n"


class RespFalsa(object):
    def __init__(self, b_):
        self.b = b_

    def read(self):
        return self.b


def _bajar(ns, cuerpo=INSTALADOR_FALSO, antes=None):
    def urlopen(u, timeout=0):
        if antes:
            antes()
        return RespFalsa(cuerpo)
    ns["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(urlopen=urlopen), parse=urllib.parse)


def _lanzar(ns, args, nodos):
    """espejo_vpn_lanzar con las correcciones del plan (el codigo viejo no las aceptaba)."""
    try:
        return ns["espejo_vpn_lanzar"](args, quien="admin", nodos=nodos)
    except TypeError:
        return ns["espejo_vpn_lanzar"](args, quien="admin")


MODO_LOCAL = {"tzsp": True, "allow": ["192.0.2.1"], "bytes": 0, "puerto": 37008, "home_net": ["10.0.0.0/8"],
              "fw": False, "gestion": [], "web": True, "evebox_puerto": "5636", "modo": "local"}
ENV_LOCAL = "Environment=TZSP_PORT=37008 TZSP_ALLOW=192.0.2.1 TZSP_MAP=192.0.2.1=ids-in TZSP_BYTES=0\n"


def _cada_interfaz_de_su_router(ns, mapa, nombre):
    """Tras lanzar: la alerta que entre por la interfaz de cada origen de -m se atribuye al router
    con ESE HOST (o a ninguno si ese MikroTik no esta dado de alta), nunca a otro."""
    rs = ns["cargar_routers"]()
    por_id = {r["id"]: r for r in rs}
    malos = []
    for o in mapa:
        rid = ns["rid_por_iface"](o["iface"])
        if rid and por_id.get(rid, {}).get("HOST") != o["ip"]:
            malos.append((o["iface"], o["ip"], rid, por_id.get(rid, {}).get("HOST")))
        # router_por_iface no tiene el atajo de "un solo nodo": mira el registro tal cual
        r = next((x for x in rs if x.get("iface") == o["iface"]), None)
        if r and r.get("HOST") != o["ip"]:
            malos.append((o["iface"], o["ip"], r.get("id"), r.get("HOST")))
    check("%s: tras lanzar, cada interfaz de -m es del router con ese HOST (o de ninguno)" % nombre,
          not malos, malos)


def prueba_nodos():
    """Hallazgo 1: al pasar a modo VPN, ningun nodo se queda con la interfaz de otro."""
    local = {"id": "r1", "nombre": "Local", "iface": "ids-mon", "HOST": "192.0.2.1", "USER": "u",
             "PASS": "p", "ENABLED": "1"}
    otro = {"id": "r9", "nombre": "Otro local", "iface": "ids-mon2", "HOST": "192.0.2.9", "USER": "u",
            "PASS": "p", "ENABLED": "1"}

    # --- Escenario A: MikroTik local + dos MikroTik en la VPN SIN API (con uno y con dos nodos locales)
    for extra, nombre in (([], "A (un nodo local)"), ([otro], "A (dos nodos locales)")):
        ns, td, sub, bit, routers, orden = entorno([local] + extra)
        sub.env = ENV_LOCAL
        _bajar(ns)
        est = ns["ovpn_estado"]()
        p = ns["espejo_vpn_plan"]("10.20.0.0/16", "203.0.113.5/32", "203.0.113.5", est=est, modo=MODO_LOCAL,
                                  routers=ns["cargar_routers"]())
        txt = " ".join(p.get("nodos_txt") or [])
        check("%s: la vista previa ensena que el nodo local pierde ids-mon y su envio" % nombre,
              p["ok"] and "Local" in txt and "ids-mon" in txt and "cuarentena" in txt, p.get("nodos_txt"))
        check("  y no lleva claves (va al navegador)", "PASS" not in json.dumps(p) and '"p"' not in json.dumps(p.get("nodos")), "")
        ok, msg = _lanzar(ns, p["args"], p.get("nodos"))
        check("  lanzado", ok, msg)
        _cada_interfaz_de_su_router(ns, p["mapa"], nombre)
        r1 = next(r for r in ns["cargar_routers"]() if r["id"] == "r1")
        check("  el nodo local, que ya no manda espejo, queda sin interfaz y con el envio apagado",
              r1["iface"] == "" and r1["ENABLED"] == "0" and r1["PASS"] == "p", r1)
        check("  y se guardo ANTES de lanzar el instalador (con el respaldo hecho)",
              sub.routers_al_lanzar is not None
              and next(r for r in sub.routers_al_lanzar if r["id"] == "r1")["iface"] == "", sub.routers_al_lanzar)
        check("  la bitacora dice que nodos se corrigieron", "r1:ids-mon->-" in bit[-1][1], bit[-1:])

    # --- Escenario B: MikroTik local + "Dar de alta su API" de uno de la VPN (con uno y con dos en la VPN)
    for usuarios, nombre in ((("a",), "B (un MikroTik en la VPN)"), (("a", "b"), "B (dos en la VPN)")):
        ns, td, sub, bit, routers, orden = entorno([local], usuarios=usuarios)
        sub.env = ENV_LOCAL
        ns["mk_conectar"] = lambda d, timeout=6: types.SimpleNamespace(close=lambda: None)
        _bajar(ns)
        ok, msg = ns["vpn_mk_alta"]("vpnaaaaaaaaaaaa", "Nodo Norte", "ids", "x", "", False, quien="admin")
        est = ns["ovpn_estado"]()
        p = ns["espejo_vpn_plan"]("10.20.0.0/16", "203.0.113.5/32", "203.0.113.5", est=est, modo=MODO_LOCAL,
                                  routers=ns["cargar_routers"]())
        nuevo = next(r for r in routers if r.get("HOST") == "100.64.0.2")
        su_m = next(o["iface"] for o in p["mapa"] if o["ip"] == "100.64.0.2")
        check("%s: el alta le da la interfaz que le dara -m (%s), no la primera libre" % (nombre, su_m),
              ok and nuevo["iface"] == su_m, (nuevo.get("iface"), su_m, msg))
        ok, msg = _lanzar(ns, p["args"], p.get("nodos"))
        _cada_interfaz_de_su_router(ns, p["mapa"], nombre)
        check("  el nodo dado de alta recibe sus alertas", ok and ns["rid_por_iface"](su_m) == nuevo["id"], msg)

    # --- si el sensor YA recibe su espejo, el alta respeta esa interfaz (es la verdad de ahora)
    ns, td, sub, bit, routers, orden = entorno()
    sub.env = "Environment=TZSP_PORT=37008 TZSP_ALLOW=100.64.0.3,100.64.0.2 TZSP_MAP=100.64.0.3=ids-in,100.64.0.2=ids-in2\n"
    ns["mk_conectar"] = lambda d, timeout=6: types.SimpleNamespace(close=lambda: None)
    ok, msg = ns["vpn_mk_alta"]("vpnaaaaaaaaaaaa", "", "ids", "x", "", False)
    check("alta de uno que el sensor ya recibe: conserva la interfaz por la que llega (ids-mon2)",
          ok and routers[0]["iface"] == "ids-mon2", routers)

    # --- si systemd-run falla, los nodos vuelven a como estaban
    ns, td, sub, bit, routers, orden = entorno([local])
    sub.env = ENV_LOCAL
    sub.systemd_rc = 1
    _bajar(ns)
    p = ns["espejo_vpn_plan"]("10.20.0.0/16", "", "203.0.113.5", est=ns["ovpn_estado"](), modo=MODO_LOCAL,
                              routers=ns["cargar_routers"]())
    ok, msg = _lanzar(ns, p["args"], p.get("nodos"))
    check("si no se pudo lanzar, los nodos quedan como estaban",
          not ok and routers[0]["iface"] == "ids-mon" and routers[0]["ENABLED"] == "1", (msg, routers))


def prueba_uno_a_la_vez():
    """Hallazgo 2: dos Lanzar a la vez (dos hilos del panel) lanzan UN instalador."""
    ns, td, sub, bit, routers, orden = entorno()
    args = ["-t", "-e", "vpn", "-m", "100.64.0.2", "-n", "10.20.0.0/16"]
    dentro, soltar = threading.Event(), threading.Event()

    def frena():
        if not dentro.is_set():
            dentro.set()
            soltar.wait(8)
    _bajar(ns, antes=frena)
    res = {}
    open(ns["ESPEJO_LOG"], "w").write("lo que habia en el log\n")
    h1 = threading.Thread(target=lambda: res.__setitem__(1, ns["espejo_vpn_lanzar"](args, quien="uno")))
    h1.start()
    dentro.wait(8)
    res[2] = ns["espejo_vpn_lanzar"](args, quien="dos")          # el segundo, con el primero a medias
    log_entre = open(ns["ESPEJO_LOG"], encoding="utf-8").read()
    soltar.set()
    h1.join(10)
    check("dos a la vez (dos hilos): solo uno lanza el instalador",
          res.get(1, (False,))[0] and not res[2][0] and "en marcha" in res[2][1] and len(sub.systemd_run) == 1,
          (res, len(sub.systemd_run)))
    check("  y el rechazado no toca el log (antes lo truncaba)", log_entre == "lo que habia en el log\n", log_entre)
    ok3, msg3 = ns["espejo_vpn_lanzar"](args, quien="tres")
    check("  terminado el primero, el cerrojo queda libre (se suelta siempre)", ok3 and len(sub.systemd_run) == 2, msg3)
    ns["espejo_vpn_respaldo"], resp0 = (lambda: (_ for _ in ()).throw(OSError("disco lleno"))), ns["espejo_vpn_respaldo"]
    ns["espejo_vpn_lanzar"](args, quien="cuatro")
    ns["espejo_vpn_respaldo"] = resp0
    ok5, msg5 = ns["espejo_vpn_lanzar"](args, quien="cinco")
    check("  tambien tras un fallo a mitad (respaldo que revienta)", ok5, msg5)
    try:
        import fcntl
    except ImportError:
        fcntl = None
    if fcntl is not None:
        fd = os.open(ns["ESPEJO_CERROJO"], os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)        # otro proceso del panel lo tiene
        n = len(sub.systemd_run)
        ok6, msg6 = ns["espejo_vpn_lanzar"](args, quien="seis")
        os.close(fd)
        check("  y otro proceso con el cerrojo (flock en /run) tambien lo impide",
              not ok6 and len(sub.systemd_run) == n, msg6)
    else:
        print("  aviso: sin fcntl (Windows): el flock entre procesos se prueba en Linux")

    # OpenVPN tenia el mismo problema
    ns2, td2, sub2, _b, _r, _o = entorno()
    dentro2, soltar2 = threading.Event(), threading.Event()

    def respaldo_lento():
        if not dentro2.is_set():
            dentro2.set()
            soltar2.wait(8)
        return "/root/backups/x"
    ns2.update(_ovpn_conf=lambda: None, ovpn_asegurar_script=lambda: (True, ""), ovpn_respaldo=respaldo_lento,
               OVPN_ETC=td2)
    r2 = {}
    h2 = threading.Thread(target=lambda: r2.__setitem__(1, ns2["ovpn_instalar"](quien="uno")))
    h2.start()
    dentro2.wait(8)
    r2[2] = ns2["ovpn_instalar"](quien="dos")
    soltar2.set()
    h2.join(10)
    unidades = [c[c.index("--unit") + 1] for c in sub2.systemd_run]
    check("instalar OpenVPN dos a la vez: una sola instalacion, unidad de nombre fijo con --collect",
          r2.get(1, (False,))[0] and not r2[2][0] and unidades == ["suricata-ovpn-instalar"]
          and "--collect" in sub2.systemd_run[0], (r2, sub2.systemd_run))


def prueba_respaldo_y_reinicio():
    """Hallazgo 3: el respaldo permite volver atras (y es 600); el panel se reinicia de verdad."""
    ns, td, sub, bit, routers, orden = entorno()
    os.makedirs(os.path.join(td, "bin"))
    for f in ("suricata-dashboard", "suricata-mikrotik-init", "otra-cosa"):
        open(os.path.join(td, "bin", f), "w").write("# " + f + "\n")
    conf = os.path.join(td, "suricata-dashboard.conf")
    open(conf, "w").write("PORT=5637\n")
    ns["ESPEJO_RESPALDAR"] = (conf, os.path.join(td, "bin", "suricata-*"), os.path.join(td, "no-existe"))
    ruta = ns["espejo_vpn_respaldo"]()
    nombres = tarfile.open(ruta).getnames()
    check("respaldo: los programas suricata-* (comodin) y la config del panel; nada mas",
          any(n.endswith("bin/suricata-dashboard") for n in nombres)
          and any(n.endswith("bin/suricata-mikrotik-init") for n in nombres)
          and any(n.endswith("suricata-dashboard.conf") for n in nombres)
          and not any(n.endswith("otra-cosa") for n in nombres), nombres)
    check("  el tar NACE 600 (lleva las claves de los routers): no hay un instante legible por otros",
          sub.espia.creado.get(sub.espia._k(ruta + ".tmp")) == 0o600, sub.espia.creado)
    if os.name == "posix":
        check("  y en disco es 600 (modo real)", (os.stat(ruta).st_mode & 0o077) == 0, oct(os.stat(ruta).st_mode))
    real = {}
    for n in ARBOL.body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "ESPEJO_RESPALDAR":
            exec(ast.get_source_segment(DASH, n), real)
    faltan = [f for f in ("/usr/local/bin/suricata-*", "/etc/suricata-dashboard.conf",
                          "/etc/suricata-dashboard-users.json", "/etc/evebox/evebox.yaml",
                          "/etc/suricata-mikrotik.conf", "/etc/suricata-routers.json",
                          "/etc/suricata/suricata.yaml") if f not in real.get("ESPEJO_RESPALDAR", ())]
    check("  en el servidor se respalda todo lo que el instalador de main reescribe", not faltan, faltan)

    # el instalador: si el panel ya corria, se REINICIA (enable --now no lo hace)
    try:
        ini = SRC.index("# el panel: si ya corria, REINICIARLO")
        trozo = SRC[ini:SRC.index("\nfi\n", ini) + 4]
    except ValueError:
        trozo = next(l for l in SRC.splitlines() if l.startswith("systemctl enable --now suricata-dashboard")) + "\n"
    for activo, nombre in ((0, "ya corria"), (3, "no corria")):
        tdx = tempfile.mkdtemp().replace("\\", "/")
        guion = ("set -uo pipefail\nwarn(){ echo \"WARN $*\"; }\n"
                 "systemctl(){ echo \"$*\" >> %s/systemctl.log; [ \"$1\" = is-active ] && return %d; return 0; }\n"
                 % (tdx, activo)) + trozo
        rx = subprocess.run(["bash", "-s"], input=guion.encode("utf-8"), capture_output=True)
        log = open(tdx + "/systemctl.log").read() if os.path.exists(tdx + "/systemctl.log") else ""
        if activo == 0:
            check("instalador, panel que %s: se reinicia (si no, seguiria el codigo viejo)" % nombre,
                  rx.returncode == 0 and "restart suricata-dashboard" in log, (log, rx.stderr[-200:]))
        else:
            check("instalador, panel que %s: se habilita y arranca, sin reinicio de mas" % nombre,
                  rx.returncode == 0 and "enable --now suricata-dashboard" in log
                  and "restart" not in log, (log, rx.stderr[-200:]))


def prueba_claves_en_el_log():
    """Hallazgo 11: el resumen del instalador lleva claves y el log se ensena en la web."""
    ns, td, sub, bit, routers, orden = entorno()
    open(ns["ESPEJO_LOG"], "w", encoding="utf-8").write(
        "Recibir el espejo por la VPN\n"
        "[OK] Panel de estadisticas: http://192.0.2.10:5637  (usuario admin, clave Pz9secretoA)\n"
        "[OK] Clave del panel: puesta de nuevo (para poder entregarla al final).\n"
        "  Interfaz web (EveBox)\n    Usuario    : admin\n    Clave      : Qw7secretoB\n"
        "  Panel\n    Clave      : Zx5secretoC   (la misma que EveBox)\n"
        "evebox: username=admin, password=Rt3secretoD\n"
        "FIN rc=0\n")
    l = ns["espejo_vpn_avance"]()["log"]
    fugas = [s for s in ("Pz9secretoA", "Qw7secretoB", "Zx5secretoC", "Rt3secretoD") if s in l]
    check("el log que se ensena en la web no lleva ninguna clave", not fugas, (fugas, l))
    check("  y el resto se sigue leyendo (usuario, avisos, la marca de fin)",
          "Usuario    : admin" in l and "Clave del panel: puesta de nuevo" in l and "FIN rc=0" in l, l)


METODOS_H = ("_sid", "_peer_ip", "_proxy_confiable", "_client_ip", "_sesion", "_sesion_ok", "_rol", "_admin",
             "_operador", "_set_ctx", "_auth_ok", "_deny", "_seguro", "do_GET", "do_POST", "_post_mismo_origen",
             "_post", "_get")


def handler_real(ns_extra):
    """La clase H del panel con sus metodos REALES (los de sesion, rol y despacho) y lo de
    fuera de dobles. Devuelve una funcion que hace una peticion y dice que respondio."""
    import traceback
    cls = next(n for n in ARBOL.body if isinstance(n, ast.ClassDef) and n.name == "H")
    ns = {"urllib": urllib, "json": json, "time": time, "re": re, "html": html, "sys": sys,
          "traceback": traceback, "SimpleCookie": SimpleCookie, "PROXIES_OK": set(),
          "CTX": types.SimpleNamespace(), "ip_confiable": lambda ip: True,
          "cargar_usuarios": lambda: [{"usuario": "ana"}], "cargar_confianza": lambda: [],
          "bitacora": lambda *a, **k: None, "SESSIONS": {}}
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("origen_ajeno", "_host_puerto"):
            exec(ast.get_source_segment(DASH, n), ns)
    ns.update(ns_extra)
    metodos = {}
    for m in cls.body:
        if isinstance(m, ast.FunctionDef) and m.name in METODOS_H:
            exec(compile(ast.Module(body=[m], type_ignores=[]), "<H.%s>" % m.name, "exec"), ns)
            metodos[m.name] = ns[m.name]
    Clase = type("HPrueba", (object,), dict(metodos))

    def peticion(metodo, ruta, cuerpo="", rol="lectura", cabeceras=None, cliente="203.0.113.5"):
        ns["SESSIONS"].clear()
        ns["SESSIONS"]["tok"] = {"user": "ana", "role": rol, "exp": time.time() + 3600}
        p = Clase()
        data = cuerpo.encode("utf-8")
        p.headers = {"Content-Length": str(len(data)), "Cookie": "sid=tok", "Host": "192.0.2.10:5637"}
        p.headers.update(cabeceras or {})
        p.rfile = io.BytesIO(data)
        p.path, p.command, p.client_address = ruta, metodo, (cliente, 50000)
        p.close_connection = False
        p.resp = []
        p._html = lambda s, code=200: p.resp.append(("html", code, s))
        p._json = lambda obj, code=200: p.resp.append(("json", code, obj))
        p._redirect = lambda loc, cookie=None: p.resp.append(("redirect", 303, loc))
        (p.do_POST if metodo == "POST" else p.do_GET)()
        return p.resp
    return peticion, ns


def prueba_rutas():
    """Hallazgo 14: las rutas del espejo por la VPN, con el handler de verdad."""
    llamadas = []

    def doble(nombre, ret):
        return lambda *a, **k: (llamadas.append((nombre, a, k)), ret)[1]
    plan = {"ok": True, "args": ["-t", "-e", "vpn", "-m", "100.64.0.2", "-n", "10.20.0.0/16"],
            "nodos": [{"id": "r1", "nombre": "Local", "HOST": "192.0.2.1", "antes": "ids-mon", "despues": "",
                       "apagar": True}]}
    peticion, ns = handler_real({
        "vpn_mk_alta": doble("vpn_mk_alta", (True, "ok")), "vpn_mk_espejo": doble("vpn_mk_espejo", (True, "ok")),
        "espejo_vpn_plan": doble("espejo_vpn_plan", plan), "espejo_vpn_lanzar": doble("espejo_vpn_lanzar", (True, "ok")),
        "espejo_vpn_avance": doble("espejo_vpn_avance", {"corriendo": False, "rc": 0, "log": ""}),
        "ovpn_instalar": doble("ovpn_instalar", (True, "ok")), "ovpn_accion": doble("ovpn_accion", (True, "", {})),
        "ovpn_estado": doble("ovpn_estado", {"usuarios": [{"usuario": "vpnaaaaaaaaaaaa", "redes": []}]}),
        "ovpn_redes_validas": doble("ovpn_redes_validas", (["10.0.0.0/8"], [], [])),
        "ovpn_log": doble("ovpn_log", {"corriendo": False, "rc": 0, "log": ""})})
    rutas = ("/vpn/mk-alta", "/vpn/mk-espejo-plan", "/vpn/mk-espejo-aplicar", "/vpn/sensor-plan",
             "/vpn/sensor-aplicar", "/vpn/instalar", "/vpn/usuario", "/vpn/redes", "/vpn/quitar-redes", "/vpn/borrar")
    for rol in ("lectura", "operador"):
        malas = []
        for ruta in rutas:
            del llamadas[:]
            r = peticion("POST", ruta, "usuario=vpnaaaaaaaaaaaa&a=&n=10.20.0.0%2F16&user=x&pass=y", rol=rol)
            if r != [("redirect", 303, "/login")] or llamadas:
                malas.append((ruta, r, [c[0] for c in llamadas]))
        for ruta in ("/vpn/sensor-log", "/vpn/log"):
            del llamadas[:]
            r = peticion("GET", ruta, rol=rol)
            if r != [("redirect", 303, "/login")] or llamadas:
                malas.append((ruta, r, [c[0] for c in llamadas]))
        check("rutas de Ajustes > VPN con sesion de '%s': todas rechazadas y no se ejecuta nada" % rol,
              not malas, malas)
    del llamadas[:]
    r = peticion("POST", "/vpn/sensor-aplicar", "a=203.0.113.5%2F32&n=10.20.0.0%2F16&args=-P+x", rol="admin")
    lz = [c for c in llamadas if c[0] == "espejo_vpn_lanzar"]
    pl = [c for c in llamadas if c[0] == "espejo_vpn_plan"]
    check("admin: lo que se lanza sale del plan recalculado en el servidor (no del navegador), con sus nodos",
          r and r[0][0] == "json" and pl and pl[0][1][:3] == ("10.20.0.0/16", "203.0.113.5/32", "203.0.113.5")
          and lz and lz[0][1][0] == plan["args"] and lz[0][2].get("nodos") == plan["nodos"], (r, llamadas))
    del llamadas[:]
    r = peticion("GET", "/vpn/sensor-log", rol="admin")
    check("  y el avance si lo ve", r == [("json", 200, {"corriendo": False, "rc": 0, "log": ""})], r)
    ns["PROXIES_OK"] = {"192.0.2.50"}
    peticion("GET", "/vpn/sensor-log", rol="admin", cliente="192.0.2.50",
             cabeceras={"X-Forwarded-For": "198.51.100.20"})
    check("la IP que llega al socket queda en el contexto (es la que ve el firewall), aparte de la real",
          ns["CTX"].peer == "192.0.2.50" and ns["CTX"].ip == "198.51.100.20", vars(ns["CTX"]))


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
