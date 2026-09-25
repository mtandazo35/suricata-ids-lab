# -*- coding: utf-8 -*-
"""Feedback TP/FP: la base de verdad propia del operador.

Un IDS no se mide solo por lo que detecta, tambien por cuanto se equivoca. Pero el
dato solo sirve si se recoge bien:

  - por (CPE, firma) y no por firma a secas: la misma firma puede ser un ataque real en
    un abonado y un falso positivo en otro, y mezclarlos da un porcentaje que no
    significa nada;
  - votar otra vez CORRIGE, no acumula: si alguien se equivoco, el dato malo no puede
    quedarse contando para siempre;
  - con uno o dos votos no se publica un porcentaje, porque seria ruido presentado como
    medida.
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

PIEZAS = ("HIST_DB", "HIST_DIAS", "HIST_TOP", "_hist_con", "VEREDICTOS",
          "veredicto_guardar", "veredictos_de", "firmas_ruidosas", "veredicto_botones")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"json": json, "os": os, "time": time, "html": __import__("html")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["HIST_DB"] = os.path.join(tmp, "historial.db")
    return ns


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    G = ns["veredicto_guardar"]

    check("se guarda un veredicto", G("192.168.1.10", "ET SCAN x", "falso", "admin"))
    check("y se puede releer",
          ns["veredictos_de"]("192.168.1.10") == {"ET SCAN x": "falso"},
          ns["veredictos_de"]("192.168.1.10"))

    # --- corregir, no acumular ---------------------------------------------------------
    G("192.168.1.10", "ET SCAN x", "amenaza", "admin")
    check("votar otra vez corrige el voto anterior, no suma otro",
          ns["veredictos_de"]("192.168.1.10") == {"ET SCAN x": "amenaza"},
          ns["veredictos_de"]("192.168.1.10"))

    # --- la misma firma en otro CPE es otro voto --------------------------------------
    G("192.168.1.11", "ET SCAN x", "falso", "admin")
    check("la misma firma en otro abonado no pisa la anterior",
          ns["veredictos_de"]("192.168.1.10") == {"ET SCAN x": "amenaza"}
          and ns["veredictos_de"]("192.168.1.11") == {"ET SCAN x": "falso"})

    # --- validacion ---------------------------------------------------------------------
    check("un veredicto inventado se rechaza", not G("192.168.1.12", "f", "cualquiera"))
    check("sin CPE no se guarda nada", not G("", "ET SCAN x", "falso"))
    check("sin firma tampoco", not G("192.168.1.12", "", "falso"))

    # --- ranking de firmas ruidosas ------------------------------------------------------
    for i in range(20):
        G("192.168.2.%d" % i, "ET INFO dominio .top", "falso", "admin")
    G("192.168.2.99", "ET INFO dominio .top", "amenaza", "admin")
    for i in range(5):
        G("192.168.3.%d" % i, "ET MALWARE Botnet CnC", "amenaza", "admin")

    r = {x["firma"]: x for x in ns["firmas_ruidosas"](minimo=3)}
    check("la firma ruidosa sale con su porcentaje de fallo",
          abs(r["ET INFO dominio .top"]["fp_pct"] - 95.2) < 0.3,
          r.get("ET INFO dominio .top"))
    check("la firma buena sale con 0% de fallo",
          r["ET MALWARE Botnet CnC"]["fp_pct"] == 0.0, r.get("ET MALWARE Botnet CnC"))
    check("la mas ruidosa va primero: es la que hay que mirar",
          ns["firmas_ruidosas"](minimo=3)[0]["firma"] == "ET INFO dominio .top")

    check("con pocos votos no se publica un porcentaje, que seria ruido",
          all(x["firma"] != "ET SCAN x" for x in ns["firmas_ruidosas"](minimo=3)),
          [x["firma"] for x in ns["firmas_ruidosas"](minimo=3)])
    check("bajando el minimo si aparece",
          any(x["firma"] == "ET SCAN x" for x in ns["firmas_ruidosas"](minimo=2)))

    check("'actividad permitida' cuenta como no-amenaza, igual que el falso positivo",
          all(v in ("amenaza", "falso", "permitido") for v, _t, _c in ns["VEREDICTOS"]))

    # --- los botones ----------------------------------------------------------------------
    b = ns["veredicto_botones"]("192.168.1.10", "ET SCAN x", "amenaza", 3, "hola")
    check("se marca el voto ya emitido", "vb act" in b, b[:200])
    check("se conserva la pagina, para no volver al principio tras votar",
          "value='3'" in b, "")
    check("y el filtro activo", "value='hola'" in b, "")
    check("hay una opcion por cada veredicto", b.count("<button") == 3, b.count("<button"))
    peligrosa = ns["veredicto_botones"]("192.168.1.10", "<script>x</script>", None)
    check("una firma con HTML no se cuela en la pagina",
          "<script>" not in peligrosa, peligrosa[:160])

    # --- el bloque que convierte el feedback en algo accionable ------------------
    ns2 = entorno(tmp)
    ns2["HIST_DB"] = ns["HIST_DB"]
    ns2["traducir"] = lambda f: f
    ns2["firmas_ruidosas"] = ns["firmas_ruidosas"]
    for n in ARBOL.body:
        if getattr(n, "name", "") == "ruidosas_html":
            exec(ast.get_source_segment(DASH, n), ns2)
    h = ns2["ruidosas_html"]()
    check("el ranking de firmas ruidosas se pinta",
          "Firmas que mas se equivocan" in h, h[:120])
    check("la que mas falla se marca en rojo", "fp alto" in h, h[:300])
    check("y la que acierta, en verde", "fp bajo" in h, "")
    check("se ve cuantas acerto y cuantas fallo, no solo el porcentaje",
          "Acertadas" in h and "Falladas" in h)
    check("sin firmas que mostrar no se pinta una tabla vacia",
          ns2["ruidosas_html"](tope=0) == "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
