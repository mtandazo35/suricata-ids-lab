# -*- coding: utf-8 -*-
"""Bloquear destinos de mala reputacion: solo publicas, y solo lo que se sostiene.

Es la otra direccion del problema. La cuarentena corta al CPE; esto corta el DESTINO, que
es lo que mantiene vivo al equipo infectado: sin canal de control la botnet no manda nada,
y vale para todos los abonados a la vez sin identificar a ninguno.

Los dos errores caros y por eso se prueban primero:
  - bloquear una IP PRIVADA como destino: seria de la propia red y dejaria a los abonados
    sin verse entre si;
  - bloquear por un feed flojo: una IP que alguna vez escaneo a alguien puede alojar
    ademas algo legitimo, y el abonado se queda sin servicio sin haber hecho nada.
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

PIEZAS = ("DESTINOS_FILE", "MK_SENT_DST", "DST_CONFIABLES", "cargar_destinos_malos",
          "destino_bloqueable", "destinos_malos", "destinos_reglas")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp, enviados=(), confiables=()):
    ns = {"json": json, "os": os, "ipaddress": __import__("ipaddress"),
          "time": __import__("time"),
          # como en produccion: MIS_REDES puede incluir rangos PUBLICOS (el NAT de salida)
          "es_mi_cpe": lambda ip: ip.startswith("10.") or ip.startswith("190.0.2."),
          "cargar_enviados": lambda path=None: {k: 1 for k in enviados},
          "_dest_ok_set": lambda: set(confiables)}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["DESTINOS_FILE"] = os.path.join(tmp, "destinos.json")
    return ns


DESTINOS = {
    # C2 activo: es lo que es, se bloquea
    "1.1.1.1": {"alertas": 800, "cpes": 12, "fuente": "feodo", "categoria": "c2-activo",
                "pais": "NL", "firma": "ET CNC Feodo checkin"},
    # red secuestrada: tambien
    "8.8.8.8": {"alertas": 40, "cpes": 3, "fuente": "spamhaus-drop",
                "categoria": "infra-delictiva", "pais": "RU", "firma": ""},
    # feed flojo: alguna vez escaneo a alguien. NO se propone: puede alojar algo legitimo
    "9.9.9.9": {"alertas": 5000, "cpes": 40, "fuente": "cins",
                "categoria": "atacante-observado", "pais": "US", "firma": ""},
    # una IP de la propia red que se cuele: jamas
    "10.6.1.10": {"alertas": 900, "cpes": 1, "fuente": "feodo", "categoria": "c2-activo",
                  "pais": "EC", "firma": ""},
    # rango de documentacion: no es publica
    "203.0.113.5": {"alertas": 700, "cpes": 4, "fuente": "feodo", "categoria": "c2-activo",
                    "pais": "XX", "firma": ""},
}


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    json.dump({"destinos": DESTINOS}, open(ns["DESTINOS_FILE"], "w", encoding="utf-8"))

    # --- lo que NUNCA se bloquea como destino ---
    ok, porque = ns["destino_bloqueable"]("10.6.1.10")
    check("una IP de abonado no se puede bloquear como destino", not ok, porque)
    check("y se dice que no es publica", "publica" in porque, porque)
    # el caso que de verdad importa: una IP PUBLICA que es TUYA (tu rango de NAT).
    # Pasa el filtro de "es publica" y aun asi hay que frenarla.
    ok2, porque2 = ns["destino_bloqueable"]("190.0.2.7")
    check("una IP PUBLICA que es tuya tampoco se bloquea", not ok2, porque2)
    check("y ahi si se dice que es de tus redes", "tus redes" in porque2, porque2)
    check("una privada cualquiera tampoco", not ns["destino_bloqueable"]("192.168.1.1")[0])
    check("un rango de documentacion tampoco (no es publica)",
          not ns["destino_bloqueable"]("203.0.113.5")[0])
    check("una cadena que no es IP tampoco", not ns["destino_bloqueable"]("basura")[0])
    check("una publica ajena si", ns["destino_bloqueable"]("1.1.1.1")[0])

    # --- que se propone ---
    lst = {x["ip"]: x for x in ns["destinos_malos"]()}
    check("se propone el C2 activo", "1.1.1.1" in lst, list(lst))
    check("y la red secuestrada", "8.8.8.8" in lst, list(lst))
    check("NO se propone lo que viene de un feed flojo (podria ser legitimo)",
          "9.9.9.9" not in lst, list(lst))
    check("ni la IP de tus redes", "10.6.1.10" not in lst, list(lst))
    check("ni el rango de documentacion", "203.0.113.5" not in lst, list(lst))
    check("se dice cuantos CPEs lo contactan, que es lo que mide el daño",
          lst["1.1.1.1"]["cpes"] == 12, lst["1.1.1.1"])
    check("y de que feed viene", lst["1.1.1.1"]["fuente"] == "feodo", lst["1.1.1.1"])

    # con el filtro flojo abierto, entra todo lo publico
    todos = {x["ip"] for x in ns["destinos_malos"](solo_confiables=False)}
    check("si se pide, se puede ver tambien lo de los feeds flojos", "9.9.9.9" in todos, todos)
    check("pero las privadas siguen fuera", "10.6.1.10" not in todos, todos)

    # --- lo ya marcado como falso positivo no se vuelve a proponer ---
    ns2 = entorno(tmp, confiables=("1.1.1.1",))
    json.dump({"destinos": DESTINOS}, open(ns2["DESTINOS_FILE"], "w", encoding="utf-8"))
    check("un destino marcado confiable desaparece de la lista",
          "1.1.1.1" not in {x["ip"] for x in ns2["destinos_malos"]()})

    # --- los ya bloqueados salen marcados y al final ---
    ns3 = entorno(tmp, enviados=("1.1.1.1",))
    json.dump({"destinos": DESTINOS}, open(ns3["DESTINOS_FILE"], "w", encoding="utf-8"))
    r3 = ns3["destinos_malos"]()
    check("los ya bloqueados salen marcados", any(x["enviado"] for x in r3), r3)
    check("y van al final, para que arriba quede lo que falta decidir",
          not r3[0]["enviado"] and r3[-1]["enviado"], [(x["ip"], x["enviado"]) for x in r3])

    # --- la regla: es de DESTINO, no de origen ---
    reg = ns["destinos_reglas"]("suricata-destinos-malos")
    check("la regla usa dst-address-list, no src", "dst-address-list=" in reg and
          "src-address-list=" not in reg, reg)
    check("cubre forward y tambien raw, que es mas barato con muchas entradas",
          "/ip firewall filter" in reg and "/ip firewall raw" in reg)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
