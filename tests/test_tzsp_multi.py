# -*- coding: utf-8 -*-
"""Receptor TZSP con varios MikroTik: cada espejo a SU interfaz.

Es la pieza de la que depende todo el multi-nodo: si el espejo de dos routers cae en
la misma interfaz, Suricata no puede decir de cual vino cada alerta, dos nodos que
usan el mismo rango privado se confunden y el bloqueo puede acabar en el router
equivocado. Tambien se comprueba que una instalacion de UN router siga igual.
"""
import ast
import ipaddress
import os
import socket
import sys

# El receptor corre en Linux; en Windows la constante no existe pero aqui solo se
# usa para elegir el socket falso, asi que basta con definirla.
if not hasattr(socket, "AF_PACKET"):
    socket.AF_PACKET = 17

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/tzsp-decap.py <<'")
_m = SRC[_i:].split("<<'", 1)[1].split("'", 1)[0]
DECAP = SRC[_i:].split("\n", 1)[1].split("\n" + _m + "\n", 1)[0]

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class SocketFalso:
    """Sustituye a AF_PACKET: anota que trama fue a que interfaz."""
    def __init__(self, registro):
        self.reg = registro
        self.iface = None

    def bind(self, par):
        self.iface = par[0]
        self.reg.setdefault(self.iface, [])

    def send(self, datos):
        self.reg[self.iface].append(datos)

    def setsockopt(self, *a):
        pass

    def recvfrom(self, n):
        raise SystemExit("fin")


def montar(env):
    """Ejecuta el modulo del receptor con el entorno dado y devuelve su espacio."""
    ns = {"__name__": "prueba"}
    os.environ.update({"TZSP_MAP": "", "TZSP_ALLOW": "", "TZSP_OUT_IF": "ids-in"})
    os.environ.update(env)
    exec(compile(DECAP, "<tzsp-decap>", "exec"), ns)
    return ns


def correr(env, paquetes):
    """Monta el receptor y le pasa (ip_origen, trama) simulados. Devuelve
    {interfaz: [tramas]} y cuantos se rechazaron."""
    ns = montar(env)
    registro = {}
    rechazados = {"n": 0}

    # trama ethernet minima valida envuelta en TZSP v1/tipo1/proto1 con tag END
    def tzsp(carga):
        return bytes([1, 1, 0, 1, 0x01]) + carga

    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + b"x" * 40

    import socket as _s
    real_socket = _s.socket
    pend = list(paquetes)

    class RX:
        def setsockopt(self, *a): pass
        def bind(self, *a): pass
        def recvfrom(self, n):
            if not pend:
                raise SystemExit("fin")
            ip, carga = pend.pop(0)
            return tzsp(carga), (ip, 1234)

    def fabrica(fam, tipo):
        if fam == _s.AF_INET:
            return RX()
        return SocketFalso(registro)

    _s.socket = fabrica
    permitido_real = ns["permitido"]

    def permitido(ip):
        ok = permitido_real(ip)
        if not ok:
            rechazados["n"] += 1
        return ok
    ns["permitido"] = permitido
    try:
        ns["main"]()
    except SystemExit:
        pass
    finally:
        _s.socket = real_socket
    return registro, rechazados["n"], eth


def main():
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + b"x" * 40

    # --- tres routers, cada uno a su interfaz ---
    reg, rej, _ = correr(
        {"TZSP_MAP": "10.0.0.1=ids-in,10.9.9.1=ids-in2,192.0.2.1=ids-in3"},
        [("10.0.0.1", eth), ("10.9.9.1", eth), ("192.0.2.1", eth), ("10.0.0.1", eth)])
    check("cada router entrega en SU interfaz",
          [len(reg.get(i, [])) for i in ("ids-in", "ids-in2", "ids-in3")] == [2, 1, 1], reg)
    check("no se mezcla el trafico de un nodo con el de otro",
          all(len(v) > 0 for v in reg.values()) and rej == 0, (reg, rej))

    # --- un origen no autorizado no entra a ninguna interfaz ---
    reg, rej, _ = correr(
        {"TZSP_MAP": "10.0.0.1=ids-in,10.9.9.1=ids-in2"},
        [("10.0.0.1", eth), ("203.0.113.9", eth)])
    check("un origen ajeno se rechaza (nadie inyecta tramas forjadas)", rej == 1, rej)
    check("y no llega a ninguna interfaz",
          sum(len(v) for v in reg.values()) == 1, reg)

    # --- rangos por CIDR ---
    reg, _, _ = correr({"TZSP_MAP": "10.0.0.0/24=ids-in,10.9.9.0/24=ids-in2"},
                       [("10.0.0.7", eth), ("10.9.9.7", eth)])
    check("acepta rangos, no solo IPs sueltas",
          len(reg.get("ids-in", [])) == 1 and len(reg.get("ids-in2", [])) == 1, reg)

    # --- compatibilidad: instalacion de UN router, como hasta ahora ---
    reg, rej, _ = correr({"TZSP_ALLOW": "10.87.87.1", "TZSP_OUT_IF": "ids-in"},
                         [("10.87.87.1", eth), ("10.87.87.2", eth)])
    check("sin TZSP_MAP sigue funcionando con una sola interfaz",
          len(reg.get("ids-in", [])) == 1, reg)
    check("y mantiene el filtro de origen", rej == 1, rej)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
