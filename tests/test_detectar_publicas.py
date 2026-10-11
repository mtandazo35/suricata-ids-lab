# -*- coding: utf-8 -*-
"""Detectar del MikroTik: que traiga TUS publicas y no las de otros.

Dos casos reales que esto protege:

1. Al pulsar el boton aparecieron 1.1.1.1, 9.9.9.9 y 208.67.220.123 entre las "IPs
   publicas del cliente". Son resolutores de Cloudflare, Quad9 y OpenDNS. La deteccion
   leia el `to-addresses` de TODAS las reglas NAT: en srcnat ese campo es por donde sales
   -tuyo-, pero en dstnat es a donde REDIRIGES -de otro-. Los ISP suelen forzar el DNS de
   sus clientes con un dstnat.

2. Hay ISP que numeran las LAN de sus abonados con bloques que NO son privados (un rango
   mal copiado de 172.16 o 192.168, o uno que no es suyo). La deteccion tomaba las
   direcciones de TODAS las interfaces y solo tiraba lo RFC1918, asi que esas LAN entraban
   como "IPs publicas" del cliente y el panel vigilaba en las listas negras redes que
   nunca salen a internet. Aqui esa LAN es 192.0.2.0/24 (documentacion, que esta prueba
   trata como global: ver _ipaddress_con_documentacion).

3. Detectar solo anadia: lo que una version anterior declaro mal se quedaba para
   siempre. Ahora se avisa de las que ya no salen y se dejan marcadas, sin borrar nada.

4. El resultado viajaba como TEXTO en la URL (/reputacion?msg=...) y el panel lo pintaba
   en su modal oficial: phishing con el logo del panel. Ahora es un codigo de un uso.

5. Una lectura del router que fallaba (timeout, usuario sin permiso) se tomaba por una
   tabla vacia: con /ip/address/print fallido y la WAN encontrada, todas las WAN declaradas
   antes salian "ya no detectadas" y llegaban PRE-MARCADAS para quitar. Ahora el resultado
   se da por parcial, se avisa y no se marca nada (tampoco si no vino ninguna publica).

Lo que se protege:
  - solo cuentan las direcciones de las interfaces WAN: la interface-list WAN mas la
    interfaz de la ruta por defecto activa (v7 immediate-gw, v6 gateway-status, PPPoE);
  - nada que caiga dentro del src-address de un srcnat, ni de su src-address-list
    (eso es la LAN que se NATea); las srcnat deshabilitadas no cuentan;
  - una ruta por defecto solo cuenta si esta activa (active=true, o sin 'active' y sin
    inactive=true);
  - si no se sabe cual es la WAN NO se cae a "todas": solo los pools y un aviso;
  - solo el to-addresses de srcnat, nunca el de dstnat;
  - y lo privado nunca entra.
"""
import ast
import ipaddress
import json
import os
import re
import sys
import time
import types
import urllib.parse

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_a_cidr", "_params_accion", "_ifaces_de_ruta", "_redes_de",
          "mk_publicas_detectadas", "publicas_ya_no_detectadas",
          "_REP_AVISOS", "_REP_AVISOS_TTL", "rep_aviso_guardar", "rep_aviso_tomar",
          "rep_aviso_url")

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
    # LAN de abonados en un bloque que NO es privado: is_global dice que es publico.
    # Una mitad se NATea por src-address y la otra por src-address-list.
    {"address": "192.0.2.1/25", "interface": "bridge-lan"},
    {"address": "192.0.2.129/25", "interface": "bridge-lan"},
    {"address": "10.0.0.1/24", "interface": "bridge-lan"},       # privada de las de siempre
]

NAT = [
    # lo tuyo: por aqui sales a internet
    {"chain": "srcnat", "action": "masquerade", "src-address": "192.0.2.0/25"},
    {"chain": "srcnat", "action": "masquerade", "src-address-list": "LAN-ABONADOS"},
    {"chain": "srcnat", "action": "src-nat", "src-address": "10.0.0.0/8",
     "to-addresses": "203.0.113.0/29", "comment": "SALIDA A INTERNET"},
    # una srcnat DESHABILITADA: ni su pool es tuyo ahora ni su src-address dice nada
    {"chain": "srcnat", "action": "src-nat", "src-address": "198.51.100.0/24",
     "to-addresses": "198.51.100.200", "disabled": "true", "comment": "pool viejo"},
    # lo de otros: a donde rediriges el DNS de tus clientes
    {"chain": "dstnat", "to-addresses": "1.1.1.1", "comment": "forzar DNS"},
    {"chain": "dstnat", "to-addresses": "9.9.9.9", "comment": "forzar DNS"},
    {"chain": "dstnat", "to-addresses": "208.67.220.123", "comment": "OpenDNS familia"},
    {"chain": "dstnat", "to-addresses": "203.0.113.53", "comment": "DNS propio del ISP"},
]

# La address-list del router. Solo cuenta como LAN la que usa un srcnat, y sin las
# entradas deshabilitadas: "bloqueados" tapa la WAN entera y no tiene que tacharla.
LISTAS = [
    {"list": "LAN-ABONADOS", "address": "192.0.2.128/25"},
    {"list": "LAN-ABONADOS", "address": "198.51.100.0/24", "disabled": "true"},
    {"list": "bloqueados", "address": "198.51.100.0/24"},
    {"list": "bloqueados", "address": "203.0.113.0/24"},
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
    """Contesta a cada comando con su tabla, y apunta lo que se le pidio. Una tabla puede
    ser una excepcion (timeout) o Trap("motivo") (el router contesta !trap: sin permiso)."""
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


class Trap(object):
    def __init__(self, motivo):
        self.motivo = motivo


def _responder(s):
    """Lo que devolveria _mk_reply: (ok, frases, error), como la API de verdad."""
    t = s.tablas.get(s.pedidos[-1][0], [])
    if isinstance(t, BaseException):
        raise t
    if isinstance(t, Trap):
        return False, [["!trap", "=message=" + t.motivo], ["!done"]], t.motivo
    return True, [["!re"] + ["=%s=%s" % kv for kv in f.items()] for f in t] + [["!done"]], ""


def entorno(router, conf=None):
    conf = dict(conf or {})
    conf.setdefault("HOST", "192.0.2.1")
    import secrets
    ns = {"ipaddress": IPADDRESS, "re": re, "time": time, "secrets": secrets,
          "cargar_mk": lambda: conf,
          "cargar_mk_de": lambda r: conf,
          "mk_conectar": lambda d, timeout=6: router,
          "_mk_send": lambda s, w: s.pedidos.append(w),
          "_mk_reply": _responder}
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


def tablas(lista=LISTA_WAN, rutas=RUTA_V7, dirs=DIRECCIONES, nat=NAT, listas=LISTAS):
    return {"/interface/list/member/print": lista, "/ip/route/print": rutas,
            "/ip/address/print": dirs, "/ip/firewall/nat/print": nat,
            "/ip/firewall/address-list/print": listas}


ESPERADO = ["198.51.100.0/30", "203.0.113.0/29"]


def sin_lan(res):
    return not any(x.startswith(("192.0.2.", "10.", "192.168.")) for x in res)


class _Doble:
    """Se deja llamar y leer sin quejarse: lo del manejador que no interesa aqui."""
    def __call__(self, *a, **k):
        return _Doble()
    def __getattr__(self, _n):
        return _Doble()
    def __bool__(self):
        return False


class _Globales(dict):
    """Lo que falte es un doble... salvo lo de Python: con globales que no son un dict
    exacto, un nombre como `int` o `Exception` pasa por __missing__ ANTES que por los
    builtins, y el manejador leeria un cuerpo vacio sin decir nada."""
    def __missing__(self, k):
        import builtins
        if hasattr(builtins, k):
            return getattr(builtins, k)
        return _Doble()


class _Peticion:
    """El `self` del manejador: una peticion con su cuerpo, y lo que contesta."""
    def __init__(self, path, cuerpo=""):
        self.path = path
        self.headers = {"Content-Length": str(len(cuerpo.encode("utf-8")))}
        self.rfile = types.SimpleNamespace(read=lambda n=0: cuerpo.encode("utf-8"))
        self.salida = []
    def _auth_ok(self):
        return True
    def _admin(self):
        return True
    def _operador(self):
        return True
    def _redirect(self, u, cookie=None):
        self.salida.append(("redirect", u))
    def _html(self, x, code=200):
        self.salida.append(("html", x))
    def _deny(self):
        self.salida.append(("deny", 403))
    def __getattr__(self, _n):
        return _Doble()


def _metodo(nombre):
    for n in ast.walk(ARBOL):
        if isinstance(n, ast.ClassDef) and n.name == "H":
            for m in n.body:
                if isinstance(m, ast.FunctionDef) and m.name == nombre:
                    return m
    raise SystemExit("no se encontro H." + nombre)


def rutas_del_panel():
    """El boton de verdad: POST /publicas/detectar y el GET /reputacion al que redirige.

    Se ejecuta el manejador ENTERO (H._post / H._get) con el router y el disco de
    mentira, para probar lo que ve el usuario y no una funcion suelta."""
    ns = entorno(Router({}))
    disco = {"nodos": {}, "origen": {}}
    vio = {}

    def guardar_publicas_de(rid, texto, origen_nuevas=""):
        ok = [t for t in re.split(r"[\s,;]+", texto) if t]
        prev = disco["origen"].get(rid, {})
        disco["origen"][rid] = {e: prev.get(e, origen_nuevas) for e in ok
                                if prev.get(e) or (e not in disco["nodos"].get(rid, [])
                                                   and origen_nuevas)}
        disco["nodos"][rid] = ok
        return ok, [], []

    def reputacion_page(**k):
        vio.clear(); vio.update(k)
        return "pagina"

    deteccion = {"r": (["198.51.100.0/30", "203.0.113.0/29"], "")}

    def mk(r):
        if isinstance(deteccion["r"], Exception):
            raise deteccion["r"]
        if isinstance(deteccion["r"], dict):
            # la deteccion REAL contra un router de mentira (lo que contesta cada tabla)
            return entorno(Router(deteccion["r"]))["mk_publicas_detectadas"]()
        return deteccion["r"]

    g = _Globales({
        "re": re, "json": json, "time": time, "urllib": urllib, "_up": urllib.parse,
        "ipaddress": IPADDRESS, "BaseHTTPRequestHandler": object,
        "ip_confiable": lambda *a, **k: True, "cargar_confianza": lambda *a, **k: [],
        "router_por_id": lambda rid: {"id": rid} if rid == "r1" else None,
        "mk_publicas_detectadas": mk,
        "cargar_publicas": lambda: {k: list(v) for k, v in disco["nodos"].items()},
        "origen_publicas": lambda: {k: dict(v) for k, v in disco["origen"].items()},
        "guardar_publicas_de": guardar_publicas_de,
        "bitacora": lambda *a, **k: None,
        "threading": types.SimpleNamespace(Thread=lambda **k: types.SimpleNamespace(
            start=lambda: None)),
        "reputacion_page": reputacion_page,
    })
    for nom in ("publicas_ya_no_detectadas", "_REP_AVISOS", "_REP_AVISOS_TTL",
                "rep_aviso_guardar", "rep_aviso_tomar", "rep_aviso_url"):
        if nom in ns:
            g[nom] = ns[nom]
    for nombre in ("_post", "_get"):
        exec(compile(ast.Module(body=[_metodo(nombre)], type_ignores=[]), "<h>", "exec"), g)
    post, get = g["_post"], g["_get"]

    def pulsar_detectar():
        p = _Peticion("/publicas/detectar", "rid=r1")
        post(p)
        return p.salida[-1][1] if p.salida and p.salida[-1][0] == "redirect" else ""

    def abrir(url):
        p = _Peticion(url)
        vio.clear()
        get(p)
        return vio.get("msg", ""), vio.get("marcar") or {}

    # --- 8. phishing: un texto puesto a mano en la URL NO sale en el modal del panel ------
    cebo = "Tu sesion caduco. Vuelve a entrar en https://panel-falso.example/login"
    msg, _m = abrir("/reputacion?msg=" + urllib.parse.quote(cebo))
    check("/reputacion?msg=<texto inventado> no pinta ese texto en el modal",
          cebo not in msg and "panel-falso" not in msg, msg)

    # --- 9. Detectar avisa de lo que una deteccion anterior declaro mal, sin borrarlo ------
    disco["nodos"]["r1"] = ["198.51.100.0/30", "192.0.2.0/25", "203.0.113.53",
                            "198.51.100.77", "203.0.113.2"]
    disco["origen"]["r1"] = {"198.51.100.0/30": "mikrotik",
                             "192.0.2.0/25": "mikrotik",        # la LAN que se colo
                             "203.0.113.53": "mikrotik",        # el DNS de otro
                             "198.51.100.77": "manual",         # a mano: no se discute
                             "203.0.113.2": "mikrotik"}         # dentro del pool: sigue
    url = pulsar_detectar()
    check("Detectar redirige a /reputacion con un CODIGO, no con el texto",
          url.startswith("/reputacion?msg=") and " " not in urllib.parse.unquote(url)
          and "MikroTik" not in urllib.parse.unquote(url), url)
    msg, marcar = abrir(url)
    check("  y el GET traduce el codigo al mensaje del panel",
          "publica(s) nueva(s) del MikroTik" in msg, msg)
    check("  avisa de las 2 declaradas desde el MikroTik que ya no son de la WAN",
          "2 declarada(s) antes desde el MikroTik ya no son de la WAN" in msg
          and "192.0.2.0/25" in msg and "203.0.113.53" in msg, msg)
    check("  y dice como quitarlas (Quitar marcadas)", "Quitar marcadas" in msg, msg)
    check("  las de origen manual y las que caen en lo hallado no se ponen en duda",
          "198.51.100.77" not in msg and not re.search(r"203\.0\.113\.2(?![\d/])", msg), msg)
    check("  quedan MARCADAS en la pagina (solo esas dos)",
          sorted(marcar.get("r1", [])) == ["192.0.2.0/25", "203.0.113.53"], marcar)
    check("  y NO se borra nada solo",
          all(e in disco["nodos"]["r1"] for e in ("192.0.2.0/25", "203.0.113.53",
                                                  "198.51.100.77")), disco["nodos"]["r1"])
    msg2, _m = abrir(url)
    check("  el codigo es de un solo uso: recargar no repite el aviso", msg2 == "", msg2)

    # sin WAN el resultado es parcial: no se acusa a la WAN de "ya no detectada"
    deteccion["r"] = (["203.0.113.0/29"], "No se encontraron interfaces WAN en el MikroTik")
    msg, marcar = abrir(pulsar_detectar())
    check("sin WAN (resultado parcial) no se marca nada como 'ya no es de la WAN'",
          "ya no son de la WAN" not in msg and not marcar and "interfaces WAN" in msg,
          (msg, marcar))
    # nada publico: un vacio es mas facil que sea un fallo que una WAN sin publicas. Antes
    # se marcaban TODAS las declaradas desde el MikroTik para quitar
    deteccion["r"] = ([], "")
    msg, marcar = abrir(pulsar_detectar())
    check("deteccion vacia: no marca nada ni acusa a nadie de 'ya no es de la WAN'",
          not marcar and "ya no son de la WAN" not in msg
          and "ninguna direccion publica" in msg, (msg, marcar))

    # de punta a punta: la deteccion de verdad con /ip/address/print fallando (timeout)
    # y la WAN encontrada. Antes salia solo el pool y la WAN 198.51.100.0/30 llegaba
    # PRE-MARCADA para quitar
    antes = list(disco["nodos"]["r1"])
    for nombre, falla in (("timeout", TimeoutError("timed out")),
                          ("sin permiso (!trap)", Trap("not enough permissions (9)"))):
        deteccion["r"] = tablas(dirs=falla)
        msg, marcar = abrir(pulsar_detectar())
        check("lectura parcial (/ip/address/print: %s): no marca nada" % nombre,
              not marcar and "ya no son de la WAN" not in msg, (msg, marcar))
        check("  y avisa de que la lectura fue parcial y de cual fallo",
              "PARCIAL" in msg and "/ip/address/print" in msg, msg)
        check("  y no se borra nada", all(e in disco["nodos"]["r1"] for e in antes),
              disco["nodos"]["r1"])
    # el error del router llega igual, pero por codigo
    deteccion["r"] = RuntimeError("timeout")
    url = pulsar_detectar()
    msg, _m = abrir(url)
    check("un fallo del router se ve en el modal, sin viajar como texto en la URL",
          "No se pudo preguntar al MikroTik: timeout" in msg and "timeout" not in url,
          (url, msg))


def main():
    # --- 1. lista WAN + ruta v7: lo de siempre ---------------------------------------------
    res, aviso = detectar(tablas())
    check("v7: la direccion de la WAN entra (de ahi sale el masquerade)",
          "198.51.100.0/30" in res, res)
    check("  y el pool de srcnat tambien", "203.0.113.0/29" in res, res)
    check("  la LAN 192.0.2.x NO, aunque is_global la de por publica",
          sin_lan(res), res)
    check("  exactamente eso, sin repetir nada", res == ESPERADO, res)
    check("  y sin aviso: la WAN se encontro", aviso == "", aviso)

    # --- 2. lo de otros no entra --------------------------------------------------------------
    for ajena, quien in (("1.1.1.1", "Cloudflare"), ("9.9.9.9", "Quad9"),
                         ("208.67.220.123", "OpenDNS")):
        check("no se declara %s como tuya (%s, dstnat)" % (ajena, quien),
              ajena not in res, res)
    check("ni el resolutor propio al que rediriges, que no es por donde sales",
          "203.0.113.53" not in res, res)
    check("una srcnat DESHABILITADA no declara su pool (198.51.100.200)",
          "198.51.100.200" not in res, res)

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

    # --- 4b. rutas de estado dudoso: solo cuenta la que el router da por activa -------------------
    def _sale_por_ether2(ruta):
        r_, _a = detectar(tablas(lista=[], dirs=pppoe_dirs, rutas=RUTA_V7 + [ruta]))
        return "198.51.100.4/30" in r_
    check("v7: una ruta sin 'active' y con inactive=true no cuenta",
          not _sale_por_ether2({"dst-address": "0.0.0.0/0", "gateway": "198.51.100.5",
                                "immediate-gw": "198.51.100.5%ether2", "inactive": "true"}), "")
    check("v7: con active=true si cuenta",
          _sale_por_ether2({"dst-address": "0.0.0.0/0", "gateway": "198.51.100.5",
                            "immediate-gw": "198.51.100.5%ether2", "active": "true"}), "")
    check("v6: 'active' vacio (estado desconocido) no se da por activa",
          not _sale_por_ether2({"dst-address": "0.0.0.0/0", "gateway": "198.51.100.5",
                                "gateway-status": "198.51.100.5 reachable via  ether2",
                                "active": ""}), "")
    check("v6: deshabilitada no cuenta aunque diga active=true",
          not _sale_por_ether2({"dst-address": "0.0.0.0/0", "gateway": "198.51.100.5",
                                "gateway-status": "198.51.100.5 reachable via  ether2",
                                "active": "true", "disabled": "true"}), "")
    check("v6: sin 'active' ni inactive ni disabled cuenta (el router no manda el campo)",
          _sale_por_ether2({"dst-address": "0.0.0.0/0", "gateway": "198.51.100.5",
                            "gateway-status": "198.51.100.5 reachable via  ether2"}), "")

    # --- 5. red de seguridad: la LAN metida en la lista WAN por error ------------------------------
    con_lan = LISTA_WAN + [{"list": "WAN", "interface": "bridge-lan"}]
    res, _ = detectar(tablas(lista=con_lan))
    check("la LAN metida en la lista WAN no entra: src-address Y src-address-list la tachan",
          res == ESPERADO, res)
    # el router se pregunta solo por la lista que usa el srcnat, no por todas
    rt = Router(tablas(lista=con_lan))
    entorno(rt)["mk_publicas_detectadas"]()
    pedidas = [w for w in rt.pedidos if w[0] == "/ip/firewall/address-list/print"]
    check("  la address-list se pide filtrada (?list=LAN-ABONADOS), no entera",
          pedidas and all("?list=LAN-ABONADOS" in w for w in pedidas), pedidas)
    # "!LISTA" es "todos menos esa": no dice cual es la LAN
    res, _ = detectar(tablas(lista=con_lan, nat=NAT + [
        {"chain": "srcnat", "action": "masquerade", "src-address-list": "!bloqueados"}]))
    check("  un src-address-list negado (!bloqueados) no tacha la WAN", res == ESPERADO, res)
    # LIMITE CONOCIDO, documentado tambien en el panel: una LAN que se NATea sin
    # src-address ni src-address-list (masquerade solo por out-interface) no hay forma de
    # reconocerla. Si su interfaz esta en la lista WAN, entra. Si algun dia se cubre,
    # cambia esta comprobacion y el parrafo de la Documentacion.
    res, _ = detectar(tablas(lista=con_lan, nat=[
        {"chain": "srcnat", "action": "masquerade", "out-interface": "ether1"}]))
    check("  limite conocido: sin src-address ni src-address-list la LAN en la lista WAN entra",
          res == ["192.0.2.0/25", "192.0.2.128/25", "198.51.100.0/30"], res)
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

    # --- 6b. una lectura que falla no es una tabla vacia ------------------------------------------
    for nombre, falla in (("timeout", TimeoutError("timed out")),
                          ("sin permiso (!trap)", Trap("not enough permissions (9)"))):
        res, aviso = detectar(tablas(dirs=falla))
        check("/ip/address/print falla (%s) con la WAN encontrada: aviso de lectura parcial"
              % nombre, "PARCIAL" in aviso and "/ip/address/print" in aviso, aviso)
        check("  y trae lo que si pudo leer (los pools)", res == ["203.0.113.0/29"], res)
    res, aviso = detectar(tablas(nat=Trap("not enough permissions (9)")))
    check("si falla la lectura del NAT tambien se avisa (faltan pools y el filtro de LAN)",
          "PARCIAL" in aviso and "/ip/firewall/nat/print" in aviso, aviso)
    res, aviso = detectar(tablas(lista=[], rutas=TimeoutError("timed out")))
    check("sin WAN porque fallo la ruta: dice las dos cosas",
          "PARCIAL" in aviso and "/ip/route/print" in aviso and "interfaces WAN" in aviso, aviso)

    # --- 7. lo privado nunca ----------------------------------------------------------------------
    res, _ = detectar(tablas(dirs=[{"address": "10.255.0.2/30", "interface": "ether1"},
                                   {"address": "100.64.0.2/30", "interface": "ether1"}]))
    check("una WAN privada o CGNAT no es una publica por la que te baneen",
          res == ["203.0.113.0/29"], res)

    rutas_del_panel()

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
