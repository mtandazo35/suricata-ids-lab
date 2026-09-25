# -*- coding: utf-8 -*-
"""Reporte de varios dias: que hizo cada CPE.

Lo que protege:
  - que se lean los ROTADOS. logrotate parte los logs cada dia, asi que "3 dias" no
    esta nunca en un solo archivo: si solo se mirara eve.json, el reporte de 3 dias
    seria en realidad el de hoy, y nadie lo notaria porque la tabla sale llena igual.
  - que un evento mas viejo que la ventana NO cuente.
  - que solo entren TUS abonados. Si entrara internet, el reporte tendria mas filas de
    servidores ajenos que de clientes y no serviria para decidir a quien cortar.
  - que el CSV escape los separadores: una firma trae ';' y comillas a menudo, y sin
    escapar corre las columnas y el cliente lee el dato de otro CPE.
"""
import ast
import gzip
import io
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

PIEZAS = ("CONDUCTA_FILE", "CONDUCTA_DIAS", "CONDUCTA_TOPE", "CONDUCTA_MAX",
          "CONDUCTA_CADA", "_CD_TS", "_cd_abrir", "_cd_ts", "_cd_top", "_cd_podar",
          "conducta_recolectar", "conducta_csv", "guardar_conducta", "cargar_conducta",
          "_TRAD", "traducir", "CAT_CPE", "CAT_OTROS", "nombre_categoria",
          "CONDUCTA_GUIA", "conducta_categoria", "_CD_COLORES", "conducta_barras",
          "PUERTO_NOMBRE", "nombre_puerto", "_cd_agrupa", "_cd_minibarras")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    import glob as _glob
    mias = ("192.168.", "172.17.")
    ns = {"json": json, "os": os, "time": time, "glob": _glob, "io": io, "gzip": gzip,
          "sys": sys, "html": __import__("html"), "LOGDIR": tmp,
          "re": __import__("re"),
          "es_mi_cpe": lambda ip: any(ip.startswith(m) for m in mias)}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["CONDUCTA_FILE"] = os.path.join(tmp, "conducta.json")
    return ns


def ev(ip, hace_dias, tipo="alert", **kw):
    t = time.time() - hace_dias * 86400
    d = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000", time.localtime(t)),
         "src_ip": ip, "event_type": tipo}
    d.update(kw)
    return json.dumps(d) + "\n"


def main():
    tmp = tempfile.mkdtemp()

    # eve.json de hoy
    hoy = [
        ev("192.168.1.10", 0.1, dest_ip="8.8.8.8", dest_port=53,
           alert={"signature": 'ET MALWARE "raro"; con punto y coma'}),
        ev("192.168.1.10", 0.2, dest_ip="1.1.1.1", dest_port=443,
           alert={"signature": "ET SCAN generico"}),
        ev("192.168.1.10", 0.3, tipo="flow", dest_ip="1.1.1.1",
           flow={"bytes_toserver": 5000}),
        ev("172.17.0.9", 0.1, dest_ip="9.9.9.9", dest_port=22,
           alert={"signature": "ET SCAN SSH"}),
        # internet: NO es un abonado y no debe aparecer
        ev("203.0.113.5", 0.1, dest_ip="192.168.1.10", dest_port=445,
           alert={"signature": "ET ATTACK entrante"}),
        # mas viejo que la ventana: fuera
        ev("192.168.1.99", 9, dest_ip="8.8.4.4", alert={"signature": "ET VIEJO"}),
    ]
    with open(os.path.join(tmp, "eve.json"), "w", encoding="utf-8") as f:
        f.writelines(hoy)

    # rotado de AYER, comprimido: la parte que se olvida siempre
    ayer = [ev("192.168.1.10", 1.5, dest_ip="5.5.5.5", dest_port=8080,
               alert={"signature": "ET AYER"}),
            ev("192.168.2.20", 1.2, tipo="dns", dest_ip="8.8.8.8",
               dns={"rrname": "malo.example.com"})]
    with gzip.open(os.path.join(tmp, "eve.json.1.gz"), "wt", encoding="utf-8") as f:
        f.writelines(ayer)

    ns = entorno(tmp)
    r = ns["conducta_recolectar"](3)
    por_ip = {f["ip"]: f for f in r["filas"]}

    check("entran los abonados que hicieron algo",
          set(por_ip) == {"192.168.1.10", "172.17.0.9", "192.168.2.20"}, sorted(por_ip))
    check("una IP de internet NO es un CPE y queda fuera", "203.0.113.5" not in por_ip)
    check("lo mas viejo que la ventana no cuenta", "192.168.1.99" not in por_ip)

    a = por_ip["192.168.1.10"]
    check("se leyo el rotado .gz de ayer, no solo el log de hoy",
          any(d == "5.5.5.5" for d, _ in a["destinos"]), a["destinos"])
    check("cuenta solo las alertas como alertas, no todo evento",
          a["alertas"] == 3 and a["eventos"] == 4, (a["alertas"], a["eventos"]))
    check("suma los bytes de los eventos de flujo", a["bytes"] == 5000, a["bytes"])
    check("cuenta los destinos distintos", a["destinos_n"] == 3, a["destinos_n"])
    check("y los dias en los que estuvo activo", a["dias"] == 2, a["dias"])

    b = por_ip["192.168.2.20"]
    check("las consultas DNS quedan como dominios",
          b["dominios"] == [["malo.example.com", 1]], b["dominios"])

    check("el mas ruidoso va primero", r["filas"][0]["ip"] == "192.168.1.10",
          r["filas"][0]["ip"])

    # --- CSV ---
    csv = ns["conducta_csv"](r).decode("utf-8")
    check("el CSV abre bien en Excel (lleva BOM)", csv.startswith("﻿"))
    cab, *cuerpo = csv.lstrip("﻿").split("\n")
    check("una firma con ';' va entrecomillada y no corre las columnas",
          all(l.count(";") == cab.count(";") or '"' in l for l in cuerpo if l), cuerpo)
    linea = [l for l in cuerpo if l.startswith("192.168.1.10")][0]
    check("y las comillas de dentro se duplican, no se comen",
          '""raro""' in linea, linea)
    check("hay una fila por CPE", len([l for l in cuerpo if l]) == 3, cuerpo)

    # --- guardar y cargar ---
    ns["guardar_conducta"](r)
    check("el reporte se guarda y se relee igual",
          ns["cargar_conducta"]()["filas"][0]["ip"] == "192.168.1.10")

    # --- la poda no puede inventar ni perder el top ---
    d = {"destinos": {str(i): i for i in range(50)}, "puertos": {}, "firmas": {},
         "dominios": {}}
    ns["_cd_podar"](d, 10)
    check("al podar se queda con los mas frecuentes, no con los primeros",
          d["destinos"].get("49") == 49 and "0" not in d["destinos"], d["destinos"])

    # --- clasificacion por categoria de abuso ------------------------------------
    # El informe se agrupa por categoria, asi que una firma mal clasificada manda al
    # abonado a la seccion equivocada: al de P2P se le corta y al infectado se le encola.
    def cat(*firmas):
        return ns["conducta_categoria"]({"firmas": [[f, 1] for f in firmas]})

    check("una firma de botnet cae en botnet", cat("ET MALWARE Botnet CnC checkin") == "botnet",
          cat("ET MALWARE Botnet CnC checkin"))
    check("un escaneo SSH cae en escaneo", cat("ET SCAN Potential SSH Scan") == "escaneo",
          cat("ET SCAN Potential SSH Scan"))
    check("BitTorrent cae en p2p", cat("ET P2P BitTorrent DHT ping request") == "p2p",
          cat("ET P2P BitTorrent DHT ping request"))
    check("quien tiene botnet Y P2P va a la seccion de BOTNET",
          cat("ET P2P BitTorrent DHT ping request", "ET MALWARE Botnet CnC checkin") == "botnet",
          cat("ET P2P BitTorrent DHT ping request", "ET MALWARE Botnet CnC checkin"))
    check("una firma que no encaja cae en otros",
          cat("ET INFO Observed DNS Query to .life TLD") in ("otros", "dns"),
          cat("ET INFO Observed DNS Query to .life TLD"))
    check("sin firmas, tambien otros", cat() == "otros", cat())

    check("la gravedad nunca va solo en el color: lleva su nombre escrito",
          all(len(v) == 4 and v[3] for v in ns["CONDUCTA_GUIA"].values()),
          {k: v[3:] for k, v in ns["CONDUCTA_GUIA"].items()})
    check("lo que hay que cortar comparte etiqueta de gravedad",
          ns["CONDUCTA_GUIA"]["botnet"][3] == ns["CONDUCTA_GUIA"]["escaneo"][3]
          == ns["CONDUCTA_GUIA"]["fuerza"][3] != ns["CONDUCTA_GUIA"]["p2p"][3])
    check("toda categoria tiene su explicacion y su color en la guia",
          all(c in ns["CONDUCTA_GUIA"] for c, _n, _cs, _l in ns["CAT_CPE"])
          and ns["CAT_OTROS"][0] in ns["CONDUCTA_GUIA"])
    check("lo que hay que cortar va en rojo y el consumo no",
          ns["CONDUCTA_GUIA"]["botnet"][2] == ns["CONDUCTA_GUIA"]["escaneo"][2]
          != ns["CONDUCTA_GUIA"]["p2p"][2])

    # --- el CSV lleva la categoria ------------------------------------------------
    csv2 = ns["conducta_csv"](r).decode("utf-8").lstrip("\ufeff").split("\n")
    check("el CSV trae la columna Categoria justo despues de la IP",
          csv2[0].split(";")[:2] == ["IP", "Categoria"], csv2[0])

    # --- el grafico de atacantes --------------------------------------------------
    barras = ns["conducta_barras"]([{"ip": "192.168.1.1", "alertas": 100},
                                    {"ip": "192.168.1.2", "alertas": 25}], "T")
    check("la barra mas alta ocupa el 100%", "width:100.0%" in barras, barras)
    check("y el resto va en proporcion, no todas iguales",
          "width:25.0%" in barras, barras)
    check("un CPE sin alertas no pinta barra",
          ns["conducta_barras"]([{"ip": "192.168.1.3", "alertas": 0}], "T") == "")

    # --- que la ficha se entienda sin ser de redes --------------------------------
    # El caso real que lo motivo: la ficha mostraba "DNS sospechoso" seis veces con
    # numeros distintos. Son firmas crudas distintas que significan lo mismo, y el
    # abonado leia seis problemas donde hay uno.
    crudas = [["ET MALWARE Known Malicious Domain A", 797],
              ["ET MALWARE Known Malicious Domain B", 34],
              ["ET MALWARE Known Malicious Domain C", 23],
              ["ET SCAN Potential SSH Scan", 39]]
    ag = ns["_cd_agrupa"](crudas, ns["traducir"])
    etiquetas = [k for k, _v in ag]
    check("lo que significa lo mismo se suma en una sola linea",
          len(etiquetas) == len(set(etiquetas)), etiquetas)
    check("y el total es la suma, no el mayor",
          dict(ag).get(ns["traducir"]("ET MALWARE Known Malicious Domain A")) == 854,
          ag)
    check("ordenado de mas a menos", [v for _k, v in ag] == sorted(
          [v for _k, v in ag], reverse=True), ag)

    check("un puerto conocido se dice en castellano",
          "navegacion" in ns["nombre_puerto"]("443"), ns["nombre_puerto"]("443"))
    check("y sigue mostrando el numero, para el ISP",
          "443" in ns["nombre_puerto"]("443"))
    _desc = lambda p_: ns["nombre_puerto"](p_).split(" (")[0]
    check("el correo saliente se llama igual en sus tres puertos",
          _desc("25") == _desc("465") == _desc("587") == "envio de correo",
          [_desc(x) for x in ("25", "465", "587")])
    check("un puerto raro no inventa un nombre",
          ns["nombre_puerto"]("47231") == "puerto 47231", ns["nombre_puerto"]("47231"))

    mb = ns["_cd_minibarras"]([["navegacion segura (443)", 9690],
                                       ["consultas de DNS (53)", 2329]])
    check("la barra mayor ocupa el 100%", "width:100.0%" in mb, mb[:200])
    check("todas las barras del bloque llevan el mismo tono, no uno por puesto",
          "background" not in mb, mb[:200])
    check("los miles se separan para poder leerlos", "9.690" in mb, mb[:300])
    check("sin datos no se pinta una caja vacia sin explicar",
          "Nada que destacar" in ns["_cd_minibarras"]([]))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
