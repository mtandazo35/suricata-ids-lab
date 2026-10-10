# -*- coding: utf-8 -*-
"""Conexion TLS a la API del MikroTik (api-ssl).

De donde sale: "Aplicar" daba "No se hizo: TLS handshake fallo ([SSL: SSLV3_ALERT_
HANDSHAKE_FAILURE] ...)" mientras la etiqueta de estado, contra el mismo router, conectaba
bien. Aplicar abria cuatro logins seguidos y cada uno probaba hasta tres cifrados, cada
intento con su conexion TCP: hasta doce contra la API en dos segundos. Y el mensaje solo
traia el fallo del ULTIMO intento (los cifrados por defecto de Python, que RouterOS
rechaza siempre), que tapaba el motivo real.

Lo que se protege:
  - el cifrado que funciono con un router se prueba PRIMERO la siguiente vez (una sola
    conexion TCP en vez de hasta tres);
  - si fallan todos, el mensaje trae el motivo de CADA intento, y se olvida el recordado;
  - aplicar y quitar usan UNA conexion para plan, respaldo, cambios y relectura.
"""
import ast
import os
import sys
import types

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "tests"))
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


class Raw(object):
    def close(self):
        pass


def entorno(acepta):
    """acepta: conjunto de cifrados con los que el 'router' completa el handshake."""
    tcp = []
    probados = []

    class Ctx(object):
        def __init__(self):
            self.ciphers = None
            self.check_hostname = True
            self.verify_mode = None

        def set_ciphers(self, c):
            self.ciphers = c

        def wrap_socket(self, raw, server_hostname=None):
            probados.append(self.ciphers)
            if self.ciphers in acepta:
                return "SOCKET-TLS"
            raise OSError("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] fallo con %s" % self.ciphers)

    ssl_falso = types.SimpleNamespace(create_default_context=Ctx, CERT_NONE=0,
                                      TLSVersion=types.SimpleNamespace(TLSv1=1))
    sock_falso = types.SimpleNamespace(create_connection=lambda *a, **k: (tcp.append(1), Raw())[1])
    ns = {"_ssl": ssl_falso, "_socket": sock_falso}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) else "")
        if nom in ("_MK_TLS_OK", "_mk_tls_wrap"):
            exec(ast.get_source_segment(DASH, n), ns)
    return ns, tcp, probados


def main():
    # router con certificado: ADH falla, DEFAULT:@SECLEVEL=0 funciona
    ns, tcp, probados = entorno({"DEFAULT:@SECLEVEL=0"})
    w = ns["_mk_tls_wrap"]
    check("primera vez: prueba en orden hasta el que funciona", w("192.0.2.1", 8729, 3) == "SOCKET-TLS"
          and probados == ["ADH:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0"], probados)
    del tcp[:], probados[:]
    w("192.0.2.1", 8729, 3)
    check("la siguiente: empieza por el que funciono (UNA conexion TCP, no dos)",
          probados == ["DEFAULT:@SECLEVEL=0"] and len(tcp) == 1, (probados, len(tcp)))
    del tcp[:], probados[:]
    w("192.0.2.2", 8729, 3)
    check("  y es por router: otro router empieza por el orden de siempre", probados[0] == "ADH:@SECLEVEL=0", probados)

    # ningun cifrado vale: el mensaje trae los tres motivos, no solo el ultimo
    ns2, _tcp2, _p2 = entorno(set())
    ns2["_MK_TLS_OK"][("192.0.2.9", 8729)] = "ADH:@SECLEVEL=0"
    try:
        ns2["_mk_tls_wrap"]("192.0.2.9", 8729, 3); msg = ""
    except IOError as ex:
        msg = str(ex)
    check("si fallan todos, dice el motivo de CADA intento",
          "3 cifrados" in msg and "ADH:@SECLEVEL=0:" in msg and "DEFAULT:@SECLEVEL=0:" in msg
          and "cifrados por defecto:" in msg, msg)
    check("  y olvida el recordado (la proxima vez vuelve a probar todos)",
          ("192.0.2.9", 8729) not in ns2["_MK_TLS_OK"], ns2["_MK_TLS_OK"])

    # aplicar/quitar: una conexion para todo
    import test_acciones_router as base
    nsb, rt, m, logs, td = base.entorno()
    rt.t["/interface/list"] = [{".id": "*1", "name": "WAN"}]
    conexiones = []
    nsb["mk_conectar"] = lambda d, timeout=6: (conexiones.append(1), rt)[1]
    ok, msg, _p = nsb["aplicar_reglas"]({"id": "r1"}, "botnet", quien="admin")
    check("aplicar: plan + respaldo + cambios + relectura con UNA conexion",
          ok and "Verificado" in msg and len(conexiones) == 1, (len(conexiones), msg))
    del conexiones[:]
    ok, msg, _p = nsb["quitar_reglas"]({"id": "r1"}, "botnet", quien="admin")
    check("quitar: tambien UNA", ok and len(conexiones) == 1, (len(conexiones), msg))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
