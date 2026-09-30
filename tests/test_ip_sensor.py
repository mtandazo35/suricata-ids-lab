# -*- coding: utf-8 -*-
"""La IP del sensor va puesta en los comandos que se copian al MikroTik.

De donde sale: el panel imprimia `streaming-server=IP_DEL_SENSOR:37008` tal cual. Quien lo
copia pega en el router un nombre que no existe, el espejo no llega a ninguna parte y el
sensor se queda ciego — y el panel sigue diciendo exactamente lo mismo, "El espejo NO esta
enviando", sin ninguna pista de que el problema fue eso.

Lo que se prueba:
  - que se elija la IP con la que se llega A ESE router y no una cualquiera. Estas cajas
    tienen varias interfaces (gestion, tunel, red del cliente) y con varios nodos la buena
    cambia segun el nodo: acertar por casualidad con una sola interfaz no demuestra nada.
  - que ante la duda devuelva el hueco en vez de inventarse una IP. Una IP equivocada
    manda el espejo a otra caja y nadie se entera; el hueco al menos se ve.
  - que nunca salga una direccion de loopback ni 0.0.0.0, que romperian el espejo en
    silencio igual.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class SocketFalso(object):
    """Imita lo justo: connect() fija la ruta y getsockname() dice por donde saldria."""

    def __init__(self, rutas, fallan=()):
        self.rutas = rutas          # destino -> IP local con la que se sale
        self.fallan = set(fallan)   # destinos sin ruta
        self.pedidos = []

    def socket(self, *a, **k):
        return self

    def connect(self, par):
        dst = par[0]
        self.pedidos.append(dst)
        if dst in self.fallan or dst not in self.rutas:
            raise OSError("sin ruta a " + dst)

    def getsockname(self):
        return (self.rutas[self.pedidos[-1]], 0)

    def close(self):
        pass


AF_INET = 2
SOCK_DGRAM = 2


def entorno(sock, mk_host=""):
    ns = {"_socket": sock, "cargar_mk": lambda: {"HOST": mk_host}}
    sock.AF_INET, sock.SOCK_DGRAM = AF_INET, SOCK_DGRAM
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name == "ip_del_sensor":
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns["ip_del_sensor"]


def main():
    # --- con varios nodos, cada router ve una IP distinta de este mismo sensor ---------
    sk = SocketFalso({"10.87.87.1": "10.87.87.3",        # router del cliente A
                      "172.19.1.1": "172.19.1.3",        # router del cliente B, otro tunel
                      "192.0.2.1": "203.0.113.9"})       # salida por defecto
    ip = entorno(sk, mk_host="10.87.87.1")
    check("da la IP con la que se llega a ESE router", ip("10.87.87.1") == "10.87.87.3",
          ip("10.87.87.1"))
    check("y con otro nodo da la otra, no la primera", ip("172.19.1.1") == "172.19.1.3",
          ip("172.19.1.1"))

    # Sin nodo concreto cae al router configurado; solo si tampoco hay, a la salida por
    # defecto. El orden importa: la salida por defecto suele ser la de internet, que no es
    # por donde el router del cliente alcanza al sensor.
    check("sin nodo concreto usa el router configurado", ip() == "10.87.87.3", ip())
    ip2 = entorno(SocketFalso({"192.0.2.1": "203.0.113.9"}), mk_host="")
    check("y sin router configurado, la salida por defecto", ip2() == "203.0.113.9", ip2())

    # --- ante la duda, el hueco: una IP equivocada es peor que ninguna ------------------
    ip3 = entorno(SocketFalso({}, fallan=["192.0.2.1"]))
    check("sin ninguna ruta devuelve el hueco, no una IP inventada",
          ip3() == "IP_DEL_SENSOR", ip3())

    # Un loopback rompe el espejo igual que un nombre inexistente, y encima parece valido.
    ip4 = entorno(SocketFalso({"10.87.87.1": "127.0.0.1", "192.0.2.1": "0.0.0.0"}))
    check("nunca devuelve loopback ni 0.0.0.0",
          ip4("10.87.87.1") == "IP_DEL_SENSOR", ip4("10.87.87.1"))

    # Un router inalcanzable no puede dejar sin respuesta al resto del diagnostico.
    ip5 = entorno(SocketFalso({"192.0.2.1": "203.0.113.9"}, fallan=["10.9.9.1"]),
                  mk_host="")
    check("si ese router no responde, sigue probando", ip5("10.9.9.1") == "203.0.113.9",
          ip5("10.9.9.1"))

    # --- y que el hueco no haya vuelto a los comandos ----------------------------------
    check("el espejo del diagnostico ya no lleva el hueco",
          "streaming-server=%s:37008" in DASH and "streaming-server=IP_DEL_SENSOR" not in DASH,
          "")
    check("los dos schedulers tampoco",
          "IP_DEL_SENSOR:PUERTO" not in DASH, "")
    check("ni el ejemplo de mangle de la documentacion",
          "sniff-target=IP_IDS" not in DASH, "")
    # el hueco sigue existiendo como ultimo recurso, que es lo que hace segura la funcion
    check("pero se conserva como valor de respaldo",
          'return "IP_DEL_SENSOR"' in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
