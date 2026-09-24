# -*- coding: utf-8 -*-
"""Una address-list por categoria de abuso, no un unico cajon.

Meter en la misma lista al que tiene una botnet y al que usa BitTorrent obliga a darles
el mismo trato en el firewall, y no es el mismo problema: la botnet se corta, el P2P se
encola, el DNS se redirige al resolutor propio.

Lo que se protege aqui es la clasificacion. Si un CPE cae en la lista equivocada, o se
corta a quien no habia que cortar, o se deja suelto a quien si.
"""
import ast
import json
import os
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("CAT_CPE", "CAT_OTROS", "_CPES_CACHE", "_cpes_de_reporte",
          "lista_de_categoria", "nombre_categoria", "categoria_cpe", "listas_cpe_reglas")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp, globales=None):
    ns = {"json": json, "os": os, "time": __import__("time"),
          "LOGDIR": tmp,
          "clave_cpe": lambda ip, rid: (rid + "|" + ip) if rid else ip,
          "_mk_globales": lambda: dict(globales or {})}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


REPORTE = {"candidatos": [], "dns_candidatos": [], "top_riesgo": [
    {"ip": "10.0.0.1", "router": "", "cats_top": {"Botnet CnC": 90, "BitTorrent / P2P": 900}},
    {"ip": "10.0.0.2", "router": "", "cats_top": {"BitTorrent / P2P": 5000}},
    {"ip": "10.0.0.3", "router": "", "cats_top": {"DNS sospechoso": 40}},
    {"ip": "10.0.0.4", "router": "", "cats_top": {"Escaneo SSH": 700}},
    {"ip": "10.0.0.5", "router": "", "cats_top": {"Spam": 1200}},
    {"ip": "10.0.0.6", "router": "", "cats_top": {"Criptomineria": 30}},
    {"ip": "10.0.0.7", "router": "", "cats_top": {"Fuerza bruta": 200}},
    {"ip": "10.0.0.8", "router": "", "cats_top": {"Anomalia TLS/SSL": 400}},
]}


def main():
    tmp = tempfile.mkdtemp()
    json.dump(REPORTE, open(os.path.join(tmp, "cuarentena.json"), "w", encoding="utf-8"))
    ns = entorno(tmp)

    # --- cada CPE a su categoria ---
    casos = [("10.0.0.2", "p2p"), ("10.0.0.3", "dns"), ("10.0.0.4", "escaneo"),
             ("10.0.0.5", "spam"), ("10.0.0.6", "minado"), ("10.0.0.7", "fuerza"),
             ("10.0.0.8", "otros")]
    for ip, esperada in casos:
        check("%s -> %s" % (ip, esperada), ns["categoria_cpe"](ip) == esperada,
              ns["categoria_cpe"](ip))

    # el caso que decide el diseño: uno que hace las dos cosas
    check("quien tiene botnet Y P2P es un CPE con BOTNET, no un CPE de P2P",
          ns["categoria_cpe"]("10.0.0.1") == "botnet", ns["categoria_cpe"]("10.0.0.1"))
    check("aunque el P2P tenga diez veces mas alertas", True)

    check("un CPE que no esta en el reporte cae en 'otros'",
          ns["categoria_cpe"]("10.9.9.9") == "otros")

    # --- nombres de lista ---
    check("la botnet va a clientes-botnet",
          ns["lista_de_categoria"]("botnet") == "clientes-botnet", ns["lista_de_categoria"]("botnet"))
    check("el DNS de malware a clientes-dns-malware",
          ns["lista_de_categoria"]("dns") == "clientes-dns-malware")
    check("el P2P a clientes-p2p", ns["lista_de_categoria"]("p2p") == "clientes-p2p")
    check("una categoria desconocida cae en la de otros",
          ns["lista_de_categoria"]("inventada") == "clientes-otros")

    # se pueden renombrar, por si el ISP ya tiene su nomenclatura
    ns2 = entorno(tmp, globales={"LISTA_BOTNET": "abusivos-botnet"})
    check("el nombre se puede cambiar desde la configuracion",
          ns2["lista_de_categoria"]("botnet") == "abusivos-botnet",
          ns2["lista_de_categoria"]("botnet"))
    check("y las que no se cambian siguen con el suyo",
          ns2["lista_de_categoria"]("p2p") == "clientes-p2p")

    # --- las reglas: cada lista con SU trato ---
    reg = ns["listas_cpe_reglas"]()
    check("la botnet se corta entera",
          "src-address-list=clientes-botnet action=drop" in reg, reg[:200])
    check("al de spam solo se le cierra el correo, no internet",
          "clientes-spam" in reg and "dst-port=25,465,587" in reg
          and "src-address-list=clientes-spam action=drop" not in reg, "")
    check("el DNS de malware se redirige al resolutor propio, no se corta",
          "clientes-dns-malware" in reg and "action=redirect" in reg
          and "src-address-list=clientes-dns-malware action=drop" not in reg, "")
    check("el P2P se encola, no se corta",
          "clientes-p2p" in reg and "queue" in reg
          and "src-address-list=clientes-p2p action=drop" not in reg, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
