# -*- coding: utf-8 -*-
"""Detectar del MikroTik: que traiga TUS publicas y no las de otros.

El caso real: al pulsar el boton aparecieron 1.1.1.1, 9.9.9.9 y 208.67.220.123 entre las
"IPs publicas del cliente". Son resolutores de Cloudflare, Quad9 y OpenDNS.

De donde salian: la deteccion leia el `to-addresses` de TODAS las reglas NAT. En srcnat
ese campo es por donde sales -tuyo-, pero en dstnat es a donde REDIRIGES -de otro-. Los
ISP suelen forzar el DNS de sus clientes con un dstnat, asi que el boton acababa
declarando los resolutores publicos como propios y el panel se ponia a vigilar la
reputacion de Cloudflare.

Lo que se protege:
  - que solo cuente el to-addresses de srcnat;
  - que se sigan cogiendo las direcciones de las interfaces, que es de donde sale el
    masquerade;
  - y que lo privado nunca entre: no es una IP publica por la que te puedan banear.
"""
import ast
import ipaddress
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_a_cidr", "mk_publicas_detectadas")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


DIRECCIONES = [{"address": "181.78.242.150/27"},
               {"address": "10.0.0.1/24"},          # privada: no es publica de nadie
               {"address": "192.168.88.1/24"}]

NAT = [
    # lo tuyo: por aqui sales a internet
    {"chain": "srcnat", "to-addresses": "181.78.242.151", "comment": "SALIDA A INTERNET"},
    {"chain": "srcnat", "to-addresses": "181.78.242.157", "comment": "IESS"},
    # lo de otros: a donde rediriges el DNS de tus clientes
    {"chain": "dstnat", "to-addresses": "1.1.1.1", "comment": "forzar DNS"},
    {"chain": "dstnat", "to-addresses": "9.9.9.9", "comment": "forzar DNS"},
    {"chain": "dstnat", "to-addresses": "208.67.220.123", "comment": "OpenDNS familia"},
    {"chain": "dstnat", "to-addresses": "205.235.3.8", "comment": "DNS propio del ISP"},
]


class Sock(object):
    def close(self):
        pass


def entorno():
    ns = {"ipaddress": ipaddress,
          "cargar_mk": lambda: {"HOST": "192.0.2.1"},
          "cargar_mk_de": lambda r: {"HOST": "192.0.2.1"},
          "mk_conectar": lambda d, timeout=6: Sock(),
          "_mk_send": lambda s, w: ns_pedido.append(w),
          "_mk_reply": lambda s: (True, _respuesta(), "")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


ns_pedido = []


def _respuesta():
    """Contesta segun lo ultimo que se pidio, como haria el router."""
    cmd = ns_pedido[-1][0] if ns_pedido else ""
    filas = DIRECCIONES if "address" in cmd and "firewall" not in cmd else NAT
    return [["!re"] + ["=%s=%s" % (k, v) for k, v in f.items()] for f in filas]


def main():
    ns = entorno()
    res = ns["mk_publicas_detectadas"]()

    # --- lo de otros no entra ----------------------------------------------------------
    for ajena, quien in (("1.1.1.1", "Cloudflare"), ("9.9.9.9", "Quad9"),
                         ("208.67.220.123", "OpenDNS")):
        check("no se declara %s como tuya (%s, dstnat)" % (ajena, quien),
              ajena not in res, res)
    check("ni el resolutor propio al que rediriges, que no es por donde sales",
          "205.235.3.8" not in res, res)

    # --- lo tuyo si -----------------------------------------------------------------------
    check("la direccion de la interfaz entra (de ahi sale el masquerade)",
          "181.78.242.128/27" in res, res)
    check("y el to-addresses de srcnat tambien", "181.78.242.151" in res, res)
    check("incluido el de una regla con nombre propio", "181.78.242.157" in res, res)

    # --- lo privado nunca -------------------------------------------------------------------
    check("una direccion privada no es una publica por la que te baneen",
          not any(x.startswith(("10.", "192.168.")) for x in res), res)

    check("y no se repite nada", len(res) == len(set(res)), res)

    # --- el filtro esta escrito donde se lee -------------------------------------------------
    fuente = ast.get_source_segment(DASH, next(
        n for n in ARBOL.body
        if getattr(n, "name", "") == "mk_publicas_detectadas")) or ""
    # El filtro correcto es por CADENA. Una lista negra de resolutores conocidos tapa el
    # sintoma y falla con el primer ISP que redirija a un DNS que no este en la lista.
    # Se quita el docstring con el AST: ahi se nombran esas IPs justamente para explicar
    # el fallo, y buscarlas en el texto crudo daria un falso positivo.
    fn = next(n for n in ARBOL.body
              if getattr(n, "name", "") == "mk_publicas_detectadas")
    cuerpo = fn.body[1:] if (isinstance(fn.body[0], ast.Expr)
                             and isinstance(fn.body[0].value, ast.Constant)) else fn.body
    codigo = "".join(ast.unparse(x) for x in cuerpo)
    check("se filtra por la cadena de la regla",
          "chain" in codigo and "srcnat" in codigo, "")
    # Una lista negra de resolutores conocidos tapa el sintoma y falla con el primer ISP
    # que redirija a un DNS que no este en la lista.
    check("y no por una lista de resolutores conocidos, que tapa el sintoma",
          "9.9.9.9" not in codigo and "208.67" not in codigo, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
