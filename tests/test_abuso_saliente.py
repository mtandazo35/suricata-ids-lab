# -*- coding: utf-8 -*-
"""La tendencia del abuso saliente: el numero que hay que poder enseñar.

Los reportes HTML se podan a los 3 dias, asi que la tendencia NO se puede reconstruir
desde ellos. Se acumula aparte, y de forma incremental: recontar la ventana daria mal el
total del dia en cuanto alguien la baje de 24 h, y lo haria sin avisar.

Lo que se protege aqui es que los contadores sumen bien entre corridas, que un dia sin
datos se vea como hueco y no como un dia tranquilo, y que la pagina calcule la tendencia
como toca.
"""
import ast
import json
import os
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
_d = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_d:].split("\n", 1)[1].split("\nDASH\n", 1)[0]

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(fuente, nombres, extra=None):
    arbol = ast.parse(fuente)
    ns = {"json": json, "os": os, "time": time, "html": __import__("html"),
          "glob": __import__("glob"), "threading": __import__("threading")}
    ns.update(extra or {})
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(fuente, n) or "", ns)
    return ns


def dia(delta):
    return time.strftime("%Y-%m-%d", time.localtime(time.time() + delta * 86400))


def main():
    # ---------- generador: fusion incremental ----------
    g = piezas(GEN, ("METRICAS_DIAS", "METRICAS_MAX_CPES", "fusionar_metricas"))
    fus = g["fusionar_metricas"]

    hoy = dia(0)
    r1 = fus({}, {hoy: {"sal": 100, "ent": 5, "cpes": {"10.0.0.1", "10.0.0.2"},
                        "puertos": {"25/tcp": 80}, "cats": {"Spam": 80}, "nodos": {}}},
             1000, False)
    check("primera corrida: se guarda el dia", r1["dias"][hoy]["sal"] == 100, r1["dias"][hoy])
    check("y la marca de hasta donde se conto", r1["ultimo_ts"] == 1000, r1["ultimo_ts"])

    r2 = fus(r1, {hoy: {"sal": 40, "ent": 2, "cpes": {"10.0.0.2", "10.0.0.9"},
                        "puertos": {"25/tcp": 30, "22/tcp": 10}, "cats": {"Spam": 30}, "nodos": {}}},
             2000, False)
    check("segunda corrida: SUMA, no reemplaza", r2["dias"][hoy]["sal"] == 140, r2["dias"][hoy]["sal"])
    check("los entrantes tambien suman", r2["dias"][hoy]["ent"] == 7, r2["dias"][hoy]["ent"])
    check("los CPEs distintos se unen sin duplicar", r2["dias"][hoy]["cpes_n"] == 3,
          r2["dias"][hoy]["cpes_n"])
    check("los puertos suman y aparecen los nuevos",
          r2["dias"][hoy]["puertos"] == {"25/tcp": 110, "22/tcp": 10}, r2["dias"][hoy]["puertos"])

    # un dia con corte de datos queda marcado
    r3 = fus(r2, {hoy: {"sal": 1, "ent": 0, "cpes": set(), "puertos": {}, "cats": {}, "nodos": {}}},
             3000, True)
    check("un corte de datos deja el dia marcado", r3["dias"][hoy].get("hueco") is True, r3["dias"][hoy])

    # retencion y colapso de la lista de CPEs
    viejo = dia(-10)
    antiguo = dia(-500)
    base = {"dias": {viejo: {"sal": 9, "ent": 0, "cpes": ["10.0.0.7"], "cpes_n": 1,
                             "puertos": {}, "cats": {}, "nodos": {}},
                     antiguo: {"sal": 5, "ent": 0, "cpes_n": 1, "puertos": {}, "cats": {}, "nodos": {}}}}
    r4 = fus(base, {}, 4000, False)
    check("de los dias viejos se guarda el numero, no la lista de CPEs",
          "cpes" not in r4["dias"][viejo] and r4["dias"][viejo]["cpes_n"] == 1, r4["dias"][viejo])
    check("y lo mas viejo que la retencion se cae", antiguo not in r4["dias"], list(r4["dias"]))

    # ---------- panel: contadores de accion y pagina ----------
    tmp = tempfile.mkdtemp()
    d = piezas(DASH, ("ACCIONES_FILE", "ACCIONES_DIAS", "_ACC_LOCK", "cargar_acciones",
                      "contar_accion", "METRICAS_FILE", "cargar_metricas", "_serie",
                      "_media", "_grafico", "historico_page"),
               extra={"BASE_CSS": "", "nav": lambda a="": "<!--nav-->",
                      "wrap": lambda b, refresh=True, active="": b, "LOGDIR": tmp})
    d["ACCIONES_FILE"] = os.path.join(tmp, "acciones.json")
    d["METRICAS_FILE"] = os.path.join(tmp, "metricas.json")

    d["contar_accion"]("ENVIADO"); d["contar_accion"]("ENVIADO"); d["contar_accion"]("QUITADO")
    acc = d["cargar_acciones"]()
    check("las acciones se cuentan por dia", acc[hoy] == {"ENVIADO": 2, "QUITADO": 1}, acc)

    # serie con un dia flojo y otro fuerte para que la tendencia se note
    dias = {}
    for i in range(14, 7, -1):
        dias[dia(-i)] = {"sal": 1000, "ent": 0, "cpes_n": 20, "puertos": {}, "cats": {}}
    for i in range(7, 0, -1):
        dias[dia(-i)] = {"sal": 500, "ent": 0, "cpes_n": 10,
                         "puertos": {"25/tcp": 400}, "cats": {"Spam": 400}}
    dias[hoy] = {"sal": 123, "ent": 4, "cpes_n": 7, "puertos": {"22/tcp": 100},
                 "cats": {"Escaneo SSH": 100}}
    json.dump({"dias": dias}, open(d["METRICAS_FILE"], "w", encoding="utf-8"))

    pag = d["historico_page"](30)
    check("sale el dato de hoy", "123" in pag, "")
    check("y la tendencia a la baja, en verde", "&darr;" in pag and "#3a9d5d" in pag,
          "flecha=%s" % ("&darr;" in pag))
    check("se cuentan las cuarentenas del periodo", "puestos en cuarentena" in pag)
    check("se dice por que atacan", "Spam" in pag and "Escaneo SSH" in pag)
    check("y por que puerto salen", "25/tcp" in pag and "22/tcp" in pag)
    check("hay grafico sin librerias externas", "<svg" in pag and "cdn" not in pag.lower())
    check("los reportes guardados siguen listandose", "Reportes guardados" in pag)

    vacia = d["historico_page"](30)
    json.dump({"dias": {}}, open(d["METRICAS_FILE"], "w", encoding="utf-8"))
    vacia = d["historico_page"](30)
    check("sin historico se explica, no se muestra un cero enganoso",
          "Todavia no hay historico" in vacia)

    # un dia con hueco se pinta distinto
    json.dump({"dias": {hoy: {"sal": 10, "hueco": True, "cpes_n": 1}}},
              open(d["METRICAS_FILE"], "w", encoding="utf-8"))
    ph = d["historico_page"](7)
    check("un dia con datos incompletos no se pinta como bueno",
          "#c8ccd1" in ph and "sensor estuvo parado" in ph)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
