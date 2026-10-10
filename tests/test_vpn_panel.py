# -*- coding: utf-8 -*-
"""Ajustes > VPN: la VPN de los MikroTik se administra desde la web, sin consola.

Lo que se protege:
  - el estado sale de los archivos de OpenVPN tal como los deja /root/openvpn.sh: puerto,
    red, IP del sensor en el tunel, cada MikroTik con su IP y sus redes, y si esta
    CONECTADO (status de OpenVPN, desde donde, cuanto);
  - las redes nuevas se validan antes de tocar nada: nada enorme (/0-/7), nada que pise el
    tunel, nada solapado con otro MikroTik; las repetidas no cuentan; avisa si la red
    incluye la puerta de enlace del servidor; normaliza "10.20.1.5/16" a 10.20.0.0/16;
  - cada cambio respalda /etc/openvpn antes (y sin respaldo no se toca nada);
  - la clave del MikroTik se devuelve UNA vez y NO va a la bitacora;
  - el avance de la instalacion sale de la marca FIN del registro;
  - la tarjeta: sin script / sin instalar / instalado con su tabla; todo escapado; sin
    dialogos nativos; las rutas son solo de admin; tras cada accion vuelve a abrir #vpn.
"""
import ast
import json
import os
import re
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

PIEZAS = ("OVPN_MARCA_CLI", "ovpn_script_al_dia", "ovpn_asegurar_script", "_REPO_RAW2", "OVPN_SH", "OVPN_ETC", "OVPN_SRV", "OVPN_CCD", "OVPN_LOG", "OVPN_BACKUPS", "_RE_OVPN_USER",
          "_RE_ANSI", "_ovpn_conf", "_ovpn_conectados", "ovpn_instalando", "ovpn_estado", "_ovpn_gw",
          "ovpn_redes_validas", "ovpn_respaldo", "ovpn_correr", "ovpn_accion", "ovpn_instalar",
          "ovpn_log", "_mb", "_card_vpn", "_VPN_UI",
          # la tarjeta ensena tambien el espejo de cada MikroTik y el modo del sensor
          "_vpn_celda_espejo", "_vpn_bloque_sensor", "sensor_modo", "_systemctl_env", "_lista_csv",
          "espejo_vpn_corriendo", "espejo_vpn_origenes", "_slot_iface", "espejo_vpn_a_defecto",
          "espejo_vpn_n_defecto", "espejo_vpn_red_operador", "_url_vpn", "TZSP_PORT_DEF", "SURI_YAML",
          "IDS_FW_BIN", "EVEBOX_YAML", "ESPEJO_UNIDAD")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class SubFalso(object):
    """subprocess de mentira: systemctl dice 'activo' y no hay instalacion en marcha."""
    SubprocessError = Exception

    def __init__(self):
        self.instalando = False

    def call(self, cmd, **k):
        return 0

    def run(self, cmd, **k):
        out = "suricata-ovpn-instalar-1.service loaded active running\n" if (self.instalando and "list-units" in cmd) else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")


def entorno():
    td = tempfile.mkdtemp()
    etc = os.path.join(td, "etc", "openvpn")
    srv = os.path.join(etc, "server")
    ccd = os.path.join(etc, "open-vpn")
    os.makedirs(srv)
    os.makedirs(ccd)
    sub = SubFalso()
    bit = []
    ns = {"os": os, "re": re, "time": time, "json": json, "html": __import__("html"),
          "hashlib": __import__("hashlib"), "urllib": types.SimpleNamespace(request=None),
          "ipaddress": __import__("ipaddress"), "subprocess": sub,
          "bitacora": lambda a, d="", quien=None, ip=None: bit.append((a, d)),
          "ask": None, "cargar_routers": lambda: [], "CFG": {"PORT": "5637"}, "IFACE_BASE": "ids-mon",
          "CTX": types.SimpleNamespace(ip="203.0.113.5", peer="203.0.113.5")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n), ns)
    ns.update(SURI_YAML=os.path.join(td, "no-hay.yaml"), IDS_FW_BIN=os.path.join(td, "no-hay-fw"),
              EVEBOX_YAML=os.path.join(td, "no-hay-evebox.yaml"))
    ns.update(OVPN_SH=os.path.join(td, "openvpn.sh"), OVPN_ETC=etc, OVPN_SRV=srv, OVPN_CCD=ccd,
              OVPN_LOG=os.path.join(td, "ovpn.log"), OVPN_BACKUPS=os.path.join(td, "backups"))
    return ns, td, srv, ccd, sub, bit


def main():
    ns, td, srv, ccd, sub, bit = entorno()

    # ---------- sin script / sin instalar ----------
    e = ns["ovpn_estado"]()
    check("sin /root/openvpn.sh: lo dice", not e["script"] and "Falta <code>/root/openvpn.sh</code>" in ns["_card_vpn"](), "")
    open(ns["OVPN_SH"], "w").write("#!/bin/bash\nagregar_redes() { :; }\n")
    c = ns["_card_vpn"]()
    check("sin instalar: ofrece instalar el servidor (con confirmacion propia)",
          "no esta instalado" in c and "vpnInstalar()" in c and "ask(this,'Instalar OpenVPN'" in c, "")

    # ---------- instalado, como lo deja el script ----------
    open(os.path.join(srv, "server.conf"), "w").write(
        "local 192.0.2.10\nport 1194\nproto tcp\ndev tun\nserver 100.64.0.0 255.255.255.0\n")
    open(os.path.join(ccd, "rutas.sh"), "w").write(
        "#!/usr/bin/env sh\n/sbin/ip route replace 10.20.0.0/16 via 100.64.0.2 # vpnaaaaaaaaaaaa 10.20.0.0/16\n")
    open(os.path.join(ccd, "vpnaaaaaaaaaaaa"), "w").write(
        "ifconfig-push 100.64.0.2 255.255.255.0\niroute 10.20.0.0 255.255.0.0\n")
    open(os.path.join(ccd, "vpnbbbbbbbbbbbb"), "w").write(
        "ifconfig-push 100.64.0.3 255.255.255.0\niroute 172.30.0.0 255.255.0.0\n")
    open(os.path.join(srv, "openvpn-status.log"), "w").write(
        "TITLE,OpenVPN 2.6\nHEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,"
        "Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username\n"
        "CLIENT_LIST,vpnaaaaaaaaaaaa,198.51.100.7:51234,100.64.0.2,,5242880,1048576,2026-10-10 17:00:00,1791669600,vpnaaaaaaaaaaaa\n")
    e = ns["ovpn_estado"]()
    check("instalado: puerto, protocolo, red y la IP del sensor en el tunel",
          e["instalado"] and e["puerto"] == "1194" and e["proto"] == "tcp" and e["red"] == "100.64.0.0/24"
          and e["servidor"] == "100.64.0.1" and e["activo"], e)
    us = {u["usuario"]: u for u in e["usuarios"]}
    check("  cada MikroTik con su IP y sus redes (rutas.sh no cuenta como usuario)",
          set(us) == {"vpnaaaaaaaaaaaa", "vpnbbbbbbbbbbbb"} and us["vpnaaaaaaaaaaaa"]["ip"] == "100.64.0.2"
          and us["vpnaaaaaaaaaaaa"]["redes"] == ["10.20.0.0/16"], us)
    check("  y si esta conectado: desde donde, desde cuando y cuanto",
          us["vpnaaaaaaaaaaaa"]["conexion"] == {"real": "198.51.100.7", "ip": "100.64.0.2", "rx": 5242880,
                                                "tx": 1048576, "desde": 1791669600}
          and us["vpnbbbbbbbbbbbb"]["conexion"] is None, us)
    c = ns["_card_vpn"]()
    check("la tarjeta: tabla con conectado / sin conectar, redes con quitar y agregar",
          "conectado" in c and "sin conectar" in c and "vpnQuitarRed('vpnaaaaaaaaaaaa','10.20.0.0/16')" in c
          and "vpnRedes('vpnbbbbbbbbbbbb')" in c and "+ Agregar un MikroTik" in c and "100.64.0.1" in c, "")
    check("  sin dialogos nativos del navegador", "confirm(" not in c and "alert(" not in c and "prompt(" not in c, "")

    # ---------- validar redes ----------
    V = lambda t, u="vpnaaaaaaaaaaaa", gw="": ns["ovpn_redes_validas"](t, u, e, gw=gw)
    n, er, av = V("10.40.1.5/16, 192.168.60.0/24\n10.40.0.0/16")
    check("redes: normaliza, separa por coma/espacio/linea y no repite",
          n == ["10.40.0.0/16", "192.168.60.0/24"] and not er, (n, er))
    check("  una red enorme (/0 a /7) se rechaza", V("0.0.0.0/0")[1] and V("10.0.0.0/7")[1] and not V("10.0.0.0/8")[1], "")
    check("  la que pisa el tunel se rechaza", V("100.64.0.0/16")[1], "")
    check("  la que se solapa con otro MikroTik se rechaza (dos routers, misma red no)",
          any("vpnbbbbbbbbbbbb" in x for x in V("172.30.5.0/24")[1]), V("172.30.5.0/24"))
    check("  la que ya era suya no cuenta (aviso)", V("10.20.0.0/16")[0] == [] and V("10.20.0.0/16")[2], "")
    check("  avisa si incluye la puerta de enlace del servidor",
          any("puerta de enlace" in x for x in V("10.0.0.0/8", gw="10.0.0.4")[2]), "")
    check("  lo que no es una red se dice", V("hola")[1], "")

    # ---------- acciones: respaldo, clave fuera de la bitacora ----------
    salida = ("IPVPN=100.64.0.4\nUSUARIO=vpncccccccccccc\nCLAVE=0123456789abcdef0123456789abcdef\nCONECTAR=192.0.2.10\n"
              "MT7=/interface ovpn-client add connect-to=192.0.2.10 user=vpncccccccccccc password=0123456789abcdef0123456789abcdef\n"
              "MT6=/interface ovpn-client add cipher=aes256\n")
    llamadas = []
    ns["ovpn_correr"] = lambda args, timeout=240: (llamadas.append(list(args)), (0, salida))[1]
    ok, msg, datos = ns["ovpn_accion"]("usuario", quien="admin")
    check("usuario: devuelve sus datos y comandos UNA vez",
          ok and datos["USUARIO"] == "vpncccccccccccc" and datos["CLAVE"].startswith("0123") and "MT7" in datos, datos)
    check("  la clave NO va a la bitacora",
          bit and bit[-1][0] == "VPN-USUARIO" and "0123456789abcdef" not in bit[-1][1], bit[-1:])
    resp = [f for f in os.listdir(ns["OVPN_BACKUPS"]) if f.endswith(".tar.gz")]
    check("  y antes se respaldo /etc/openvpn",
          resp and "etc/openvpn/server/server.conf" in tarfile.open(os.path.join(ns["OVPN_BACKUPS"], resp[0])).getnames(), resp)
    ok, msg, _d = ns["ovpn_accion"]("redes", "vpnaaaaaaaaaaaa", ["10.40.0.0/16"], quien="admin")
    check("redes: llama al script con el usuario y las redes ya validadas",
          llamadas[-1] == ["--redes", "vpnaaaaaaaaaaaa", "10.40.0.0/16"] and bit[-1][0] == "VPN-REDES", llamadas[-1])
    ok, msg, _d = ns["ovpn_accion"]("borrar", "x; rm -rf /", quien="admin")
    check("un usuario raro no llega al script", not ok and llamadas[-1][0] != "--borrar", llamadas[-1])
    ns["ovpn_respaldo"] = lambda: (_ for _ in ()).throw(OSError("disco lleno"))
    n_antes = len(llamadas)
    ok, msg, _d = ns["ovpn_accion"]("borrar", "vpnaaaaaaaaaaaa", quien="admin")
    check("sin respaldo no se toca nada", not ok and "no se toca nada" in msg and len(llamadas) == n_antes, msg)

    # ---------- renovar el script viejo (primera actualizacion por boton) ----------
    ns2, td2, _s2, _c2, _sub2, bit2 = entorno()
    open(ns2["OVPN_SH"], "w").write("#!/bin/bash\n# version vieja, solo menu\n")
    class Resp(object):
        def __init__(self, b):
            self.b = b
        def read(self):
            return self.b
    ns2["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(urlopen=lambda u, timeout=0: Resp(SRC.encode("utf-8"))))
    ok, msg = ns2["ovpn_asegurar_script"]()
    nuevo = open(ns2["OVPN_SH"], encoding="utf-8").read()
    check("script viejo: se baja del instalador publicado, se verifica y se instala",
          ok and "agregar_redes()" in nuevo and nuevo == SRC.split("<<'OVPNSH'\n", 1)[1].split("\nOVPNSH\n", 1)[0] + "\n", msg)
    check("  y el viejo queda respaldado", any(".bak-" in f for f in os.listdir(td2)), os.listdir(td2))
    check("  al dia: no se vuelve a bajar", ns2["ovpn_asegurar_script"]() == (True, ""), "")
    open(ns2["OVPN_SH"], "w").write("#!/bin/bash\n")
    trucado = SRC.replace("agregar_redes() {", "agregar_redes() { rm -rf / ;", 1)
    ns2["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(urlopen=lambda u, timeout=0: Resp(trucado.encode("utf-8"))))
    ok, msg = ns2["ovpn_asegurar_script"]()
    check("  si no coincide con su huella, NO se instala", not ok and "huella" in msg
          and open(ns2["OVPN_SH"]).read() == "#!/bin/bash\n", msg)

    # ---------- avance de la instalacion ----------
    open(ns["OVPN_LOG"], "w").write("Instalando OpenVPN\n[OK] algo\n")
    sub.instalando = True
    l = ns["ovpn_log"]()
    check("instalacion: en marcha mientras no aparece la marca FIN", l["corriendo"] and l["rc"] is None, l)
    open(ns["OVPN_LOG"], "a").write("\x1b[1;32m[OK]\x1b[0m OpenVPN instalado\nFIN rc=0\n")
    sub.instalando = False
    l = ns["ovpn_log"]()
    check("  terminada: rc de la marca FIN y sin colores de terminal",
          not l["corriendo"] and l["rc"] == 0 and "\x1b[" not in l["log"], l)

    # ---------- rutas y apertura ----------
    i = DASH.index('if ruta in ("/vpn/instalar", "/vpn/usuario", "/vpn/redes", "/vpn/quitar-redes", "/vpn/borrar"):')
    check("las rutas de la VPN son solo de admin", "if not self._admin():" in DASH[i:i + 300], "")
    j = DASH.index('if path == "/vpn/log":')
    check("  y el avance tambien", "if not self._admin():" in DASH[j:j + 120], "")
    check("tras cada accion se recarga y se vuelve a abrir el apartado (#vpn)",
          "location.hash='vpn';location.reload();" in DASH
          and "if(h&&h!=='cuenta'&&h!=='clave'&&document.getElementById('m-'+h)){openm(h);" in DASH, "")
    check("el mosaico VPN esta en Ajustes, solo para admin",
          '_tile("vpn", "VPN", _IC_VPN, bool(card_vpn))' in DASH and 'card_vpn = _card_vpn() if (es_admin and yo) else ""' in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
