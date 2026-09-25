# -*- coding: utf-8 -*-
"""Historial persistente: lo ya contado no se pierde ni se cuenta dos veces.

Lo que protege, en orden de importancia:

  - que el historial SOBREVIVA a que desaparezcan los logs. Es el motivo de que exista:
    logrotate parte eve.json y borra los rotados viejos, asi que la historia duraba lo
    que durase el disco. Aqui se vacia el log a proposito y el informe tiene que seguir
    contestando.
  - que un reinicio no duplique. La ingesta acumula (alertas = alertas + nuevas); si la
    marca de agua no se respetara, reingerir el mismo log doblaria todos los numeros y
    nadie lo notaria: los graficos saldrian igual de bonitos, solo que mintiendo.
  - que tampoco pierda: lo escrito despues de la marca tiene que entrar entero.
  - que la poda recorte la cola larga y no lo mas consultado.
"""
import ast
import json
import os
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("HIST_DB", "HIST_DIAS", "HIST_TOP", "HIST_CADA", "CONDUCTA_DIAS",
          "CONDUCTA_TOPE", "_cd_abrir", "_CD_TS", "_cd_ts", "_cd_top",
          "_hist_con", "hist_marca", "hist_ingerir", "hist_podar", "hist_conducta")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    import glob as _glob
    ns = {"json": json, "os": os, "time": time, "glob": _glob, "sys": sys,
          "LOGDIR": tmp,
          "es_mi_cpe": lambda ip: ip.startswith("192.168.")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["HIST_DB"] = os.path.join(tmp, "historial.db")
    return ns


def ev(ip, hace_min, tipo="alert", **kw):
    t = time.time() - hace_min * 60
    d = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000", time.localtime(t)),
         "src_ip": ip, "event_type": tipo}
    d.update(kw)
    return json.dumps(d) + "\n"


def escribir(tmp, lineas, modo="w"):
    with open(os.path.join(tmp, "eve.json"), modo, encoding="utf-8") as f:
        f.writelines(lineas)


def alertas_de(ns, ip):
    for f in ns["hist_conducta"](3)["filas"]:
        if f["ip"] == ip:
            return f["alertas"]
    return None


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    escribir(tmp, [ev("192.168.1.10", 30, dest_ip="8.8.8.8", dest_port=53,
                      alert={"signature": "ET MALWARE Botnet CnC"}) for _ in range(5)]
             + [ev("192.168.1.11", 20, tipo="dns", dest_ip="8.8.8.8",
                   dns={"rrname": "malo.example.com"})])
    ns["hist_ingerir"]()

    check("lo ingerido se puede consultar", alertas_de(ns, "192.168.1.10") == 5,
          alertas_de(ns, "192.168.1.10"))

    # --- LO IMPORTANTE: el log desaparece y el historial sigue -----------------------
    open(os.path.join(tmp, "eve.json"), "w").close()      # logrotate se lo llevo
    check("el historial sobrevive a que se vacie el log",
          alertas_de(ns, "192.168.1.10") == 5, alertas_de(ns, "192.168.1.10"))
    check("y el CPE de DNS tambien sigue ahi",
          any(f["ip"] == "192.168.1.11" for f in ns["hist_conducta"](3)["filas"]))

    # --- reinicio: reingerir no puede duplicar ---------------------------------------
    escribir(tmp, [ev("192.168.1.10", 30, dest_ip="8.8.8.8", dest_port=53,
                      alert={"signature": "ET MALWARE Botnet CnC"}) for _ in range(5)])
    ns2 = entorno(tmp)                    # conexion nueva = proceso nuevo tras reiniciar
    ns2["HIST_DB"] = ns["HIST_DB"]
    ns2["hist_ingerir"]()
    check("tras un reinicio, reingerir lo mismo NO duplica",
          alertas_de(ns2, "192.168.1.10") == 5, alertas_de(ns2, "192.168.1.10"))

    # --- lo nuevo si entra ------------------------------------------------------------
    escribir(tmp, [ev("192.168.1.10", 0.2, dest_ip="1.1.1.1", dest_port=443,
                      alert={"signature": "ET SCAN generico"}) for _ in range(3)], modo="a")
    ns2["hist_ingerir"]()
    check("lo escrito despues de la marca entra entero",
          alertas_de(ns2, "192.168.1.10") == 8, alertas_de(ns2, "192.168.1.10"))

    f10 = [f for f in ns2["hist_conducta"](3)["filas"] if f["ip"] == "192.168.1.10"][0]
    check("las firmas se acumulan por tipo", len(f10["firmas"]) == 2, f10["firmas"])
    check("y los destinos tambien", f10["destinos_n"] == 2, f10["destinos"])
    check("el mas ruidoso encabeza el informe",
          ns2["hist_conducta"](3)["filas"][0]["ip"] == "192.168.1.10")

    # --- la marca de agua avanza y se guarda -----------------------------------------
    c = ns2["_hist_con"]()
    try:
        marca = ns2["hist_marca"](c)
    finally:
        c.close()
    check("la marca de agua queda guardada en la base", marca > 0, marca)
    check("y no adelanta al futuro", marca <= time.time() + 1, marca)

    # --- poda: recorta la cola larga, no lo mas visto ---------------------------------
    escribir(tmp, [ev("192.168.2.30", 0.1, dest_ip="10.0.0.%d" % i, dest_port=443,
                      alert={"signature": "ET SCAN generico"})
                   for i in range(1, 40) for _ in range(1 if i > 3 else 9)])
    ns2["hist_ingerir"]()
    c = ns2["_hist_con"]()
    try:
        n = c.execute("SELECT COUNT(*) FROM detalle WHERE cpe='192.168.2.30' "
                      "AND tipo='destino'").fetchone()[0]
        quedan = [r[0] for r in c.execute(
            "SELECT clave FROM detalle WHERE cpe='192.168.2.30' AND tipo='destino'")]
    finally:
        c.close()
    check("la poda acota cuantas claves guarda por CPE", n <= ns2["HIST_TOP"], n)
    check("y conserva las mas frecuentes, no las primeras que llegaron",
          "10.0.0.1" in quedan and "10.0.0.39" not in quedan, quedan)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
