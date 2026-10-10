# -*- coding: utf-8 -*-
"""Detectar del MikroTik: que traiga TUS publicas y no las de otros.

Dos casos reales que esto protege:

1. Al pulsar el boton aparecieron 1.1.1.1, 9.9.9.9 y 208.67.220.123 entre las "IPs
   publicas del cliente". Son resolutores de Cloudflare, Quad9 y OpenDNS. La deteccion
   leia el `to-addresses` de TODAS las reglas NAT: en srcnat ese campo es por donde sales
   -tuyo-, pero en dstnat es a donde REDIRIGES -de otro-. Los ISP suelen forzar el DNS de
   sus clientes con un dstnat.

2. Un ISP numera las LAN de sus abonados con rangos que PARECEN privados y no lo son
   (172.168.x, 182.168.x, mal copiados de 172.16 y 192.168). La deteccion tomaba las
   direcciones de TODAS las interfaces y solo tiraba lo RFC1918, asi que esas LAN entraban
   como "IPs publicas" del cliente y el panel vigilaba en las listas negras redes que
   nunca salen a internet.

Lo que se protege:
  - solo cuentan las direcciones de las interfaces WAN: la interface-list WAN mas la
    interfaz de la ruta por defecto activa (v7 immediate-gw, v6 gateway-status, PPPoE);
  - nada que caiga dentro del src-address de un srcnat (eso es la LAN que se NATea);
  - si no se sabe cual es la WAN NO se cae a "todas": solo los pools y un aviso;
  - solo el to-addresses de srcnat, nunca el de dstnat;
  - y lo privado nunca entra.
"""
import ast
import ipaddress
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_a_cidr", "_params_accion", "_ifaces_de_ruta", "_redes_de",
          "mk_publicas_detectadas")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


# --- el router de mentira: una tabla por comando, como contesta la API ----------------
LISTA_WAN = [{"list": "WAN", "interface": "ether1"},
             {"list": "LAN", "interface": "bridge-lan"}]

DIRECCIONES = [
    {"address": "198.51.100.2/30", "interface": "ether1"},       # la WAN de verdad
    # LAN de abonados en rangos "casi privados": is_global dice que son publicos
    {"address": "172.168.1.1/24", "interface": "bridge-lan"},
    {"address": "182.168.11.1/24", "interface": "bridge-lan"},
    {"address": "10.0.0.1/24", "interface": "bridge-lan"},       # privada de las de siempre
]

NAT = [
    # lo tuyo: por aqui sales a internet
    {"chain": "srcnat", "action": "masquerade", "src-address": "172.168.0.0/16"},
    {"chain": "srcnat", "action": "src-nat", "src-address": "10.0.0.0/8",
     "to-addresses": "203.0.113.0/29", "comment": "SALIDA A INTERNET"},
    # lo de otros: a donde rediriges el DNS de tus clientes
    {"chain": "dstnat", "to-addresses": "1.1.1.1", "comment": "forzar DNS"},
    {"chain": "dstnat", "to-addresses": "9.9.9.9", "comment": "forzar DNS"},
    {"chain": "dstnat", "to-addresses": "208.67.220.123", "comment": "OpenDNS familia"},
    {"chain": "dstnat", "to-addresses": "192.0.2.53", "comment": "DNS propio del ISP"},
]

RUTA_V7 = [{"dst-address": "0.0.0.0/0", "gateway": "198.51.100.1",
            "immediate-gw": "198.51.100.1%ether1", "active": "true"},
           {"dst-address": "10.20.0.0/16", "gateway": "10.0.0.2",
            "immediate-gw": "10.0.0.2%bridge-lan", "active": "true"}]
RUTA_V6 = [{"dst-address": "0.0.0.0/0", "gateway": "198.51.100.1",
            "gateway-status": "198.51.100.1 reachable via  ether1", "active": "true"},
           {"dst-address": "10.20.0.0/16", "gateway": "10.0.0.2",
            "gateway-status": "10.0.0.2 reachable via  bridge-lan", "active": "true"}]


class Router(object):
    """Contesta a cada comando con su tabla, y apunta lo que se le pidio."""
    def __init__(self, tablas):
        self.tablas = tablas
        self.pedidos = []

    def close(self):
        pass


def _ipaddress_con_documentacion():
    """Una copia PROPIA del modulo ipaddress en la que los rangos de documentacion (RFC
    5737) cuentan como publicos.

    Las pruebas no pueden llevar IPs reales, y las de documentacion son justo las que
    is_global descarta: sin esto la deteccion las tiraria todas por "privadas" y no se
    probaria nada. Es una copia aparte, no un parche al modulo de verdad, y solo cambian
    esos tres /24: RFC1918, CGNAT y el resto siguen siendo lo que son."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("ipaddress_prueba", ipaddress.__file__)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    fuera = {"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
    m._IPv4Constants._private_networks = [
        n for n in m._IPv4Constants._private_networks if str(n) not in fuera]
    assert m.ip_network("198.51.100.0/30").is_global and not m.ip_address("10.0.0.1").is_global
    return m


IPADDRESS = _ipaddress_con_documentacion()


def entorno(router, conf=None):
    conf = dict(conf or {})
    conf.setdefault("HOST", "192.0.2.1")
    ns = {"ipaddress": IPADDRESS, "re": re,
          "cargar_mk": lambda: conf,
          "cargar_mk_de": lambda r: conf,
          "mk_conectar": lambda d, timeout=6: router,
          "_mk_send": lambda s, w: s.pedidos.append(w),
          "_mk_reply": lambda s: (True, [["!re"] + ["=%s=%s" % kv for kv in f.items()]
                                         for f in s.tablas.get(s.pedidos[-1][0], [])], "")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def detectar(tablas, conf=None):
    """(lista, aviso). Tolera la forma vieja (solo lista) para que la prueba FALLE por lo
    que devuelve y no por como lo devuelve."""
    r = entorno(Router(tablas), conf)["mk_publicas_detectadas"]()
    return r if isinstance(r, tuple) else (r, "")


def tablas(lista=LISTA_WAN, rutas=RUTA_V7, dirs=DIRECCIONES, nat=NAT):
    return {"/interface/list/member/print": lista, "/ip/route/print": rutas,
            "/ip/address/print": dirs, "/ip/firewall/nat/print": nat}


ESPERADO = ["198.51.100.0/30", "203.0.113.0/29"]


def sin_lan(res):
    return not any(x.startswith(("172.168.", "182.168.", "10.", "192.168.")) for x in res)


def main():
    # --- 1. lista WAN + ruta v7: lo de siempre ---------------------------------------------
    res, aviso = detectar(tablas())
    check("v7: la direccion de la WAN entra (de ahi sale el masquerade)",
          "198.51.100.0/30" in res, res)
    check("  y el pool de srcnat tambien", "203.0.113.0/29" in res, res)
    check("  las LAN 172.168.x / 182.168.x NO, aunque is_global las de por publicas",
          sin_lan(res), res)
    check("  exactamente eso, sin repetir nada", res == ESPERADO, res)
    check("  y sin aviso: la WAN se encontro", aviso == "", aviso)

    # --- 2. lo de otros no entra --------------------------------------------------------------
    for ajena, quien in (("1.1.1.1", "Cloudflare"), ("9.9.9.9", "Quad9"),
                         ("208.67.220.123", "OpenDNS")):
        check("no se declara %s como tuya (%s, dstnat)" % (ajena, quien),
              ajena not in res, res)
    check("ni el resolutor propio al que rediriges, que no es por donde sales",
          "192.0.2.53" not in res, res)

    # --- 3. sin lista WAN: basta la ruta por defecto (v7 y v6) ---------------------------------
    res, aviso = detectar(tablas(lista=[]))
    check("sin lista WAN, la interfaz de la ruta por defecto v7 (immediate-gw) vale",
          res == ESPERADO and aviso == "", (res, aviso))
    res, aviso = detectar(tablas(lista=[], rutas=RUTA_V6))
    check("sin lista WAN, la de la ruta por defecto v6 (gateway-status) vale",
          res == ESPERADO and aviso == "", (res, aviso))
    res, aviso = detectar(tablas(rutas=RUTA_V6), {"ACCION_WAN_LIST": "ninguna"})
    check("con la lista desactivada en Ajustes (\"ninguna\") manda la ruta",
          res == ESPERADO and aviso == "", (res, aviso))
    # la lista se llama como diga Ajustes, no siempre WAN
    res, aviso = detectar(tablas(lista=[{"list": "SALIDAS", "interface": "ether1"}], rutas=[]),
                          {"ACCION_WAN_LIST": "SALIDAS"})
    check("la interface-list es la de Ajustes (ACCION_WAN_LIST), no siempre 'WAN'",
          res == ESPERADO and aviso == "", (res, aviso))

    # --- 4. PPPoE, ECMP y rutas de respaldo -------------------------------------------------------
    pppoe_dirs = DIRECCIONES + [{"address": "203.0.113.77/32", "interface": "pppoe-out1"},
                                {"address": "198.51.100.6/30", "interface": "ether2"}]
    res, _ = detectar(tablas(lista=[], dirs=pppoe_dirs, rutas=[
        {"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1",
         "gateway-status": "pppoe-out1 reachable", "active": "true"},
        # la de respaldo, inactiva: no es por donde sales ahora
        {"dst-address": "0.0.0.0/0", "gateway": "198.51.100.5",
         "gateway-status": "198.51.100.5 reachable via  ether2", "active": "false"}]))
    check("PPPoE (gateway=pppoe-out1): su direccion entra tal cual",
          "203.0.113.77" in res, res)
    check("  y la ruta por defecto inactiva no cuenta", "198.51.100.4/30" not in res, res)
    res, _ = detectar(tablas(lista=[], dirs=pppoe_dirs, rutas=[
        {"dst-address": "0.0.0.0/0", "gateway": "198.51.100.1,198.51.100.5",
         "gateway-status": "198.51.100.1 reachable via  ether1,198.51.100.5 reachable via  ether2",
         "active": "true"}]))
    check("v6 con dos salidas (ECMP): las dos WAN entran",
          "198.51.100.0/30" in res and "198.51.100.4/30" in res and sin_lan(res), res)

    # --- 5. red de seguridad: la LAN metida en la lista WAN por error ------------------------------
    res, _ = detectar(tablas(lista=LISTA_WAN + [{"list": "WAN", "interface": "bridge-lan"}]))
    check("lo que cae en el src-address de un srcnat es LAN aunque este en la lista WAN",
          "172.168.1.0/24" not in res and "198.51.100.0/30" in res, res)
    # un srcnat que lo NATea todo (src-address=0.0.0.0/0) no dice que es LAN
    res, _ = detectar(tablas(nat=NAT + [{"chain": "srcnat", "action": "masquerade",
                                         "src-address": "0.0.0.0/0"}]))
    check("  y un srcnat de 0.0.0.0/0 no tacha la WAN ni los pools", res == ESPERADO, res)

    # --- 6. sin WAN ninguna: solo pools, y se avisa ------------------------------------------------
    res, aviso = detectar(tablas(lista=[], rutas=[]))
    check("sin lista WAN ni ruta por defecto NO se toman todas las direcciones",
          "198.51.100.0/30" not in res and sin_lan(res), res)
    check("  solo los pools de srcnat", res == ["203.0.113.0/29"], res)
    check("  y se le dice al usuario que cree la lista o revise la ruta",
          "WAN" in aviso and "ruta por defecto" in aviso, aviso)
    check("  sin colar el DNS de otros tampoco aqui", "1.1.1.1" not in res, res)

    # --- 7. lo privado nunca ----------------------------------------------------------------------
    res, _ = detectar(tablas(dirs=[{"address": "10.255.0.2/30", "interface": "ether1"},
                                   {"address": "100.64.0.2/30", "interface": "ether1"}]))
    check("una WAN privada o CGNAT no es una publica por la que te baneen",
          res == ["203.0.113.0/29"], res)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
