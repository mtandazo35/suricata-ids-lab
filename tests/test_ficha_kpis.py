# -*- coding: utf-8 -*-
"""Lo que se le ensena al operador antes de cortarle el internet a un abonado.

Dos sitios donde la presentacion tapaba el dato en vez de mostrarlo:

  - **La ficha de evidencia** sacaba una fila por alerta. Una firma que dispara ocho veces
    llenaba la ficha con ocho filas identicas que solo cambiaban en el `flow_id`. La
    insignia decia "Confirmado - 3 pruebas" y la tabla no dejaba ver ninguna de las tres:
    lo que decide un corte no es cuantas alertas hay, sino cuantas cosas DISTINTAS apuntan
    al mismo abonado.
  - **El cuadro de tendencia** dividia por la media de los 7 dias anteriores en cuanto
    fuera mayor que cero. Con un solo dia de datos viejos salia "333.749 %", que ademas no
    cabia en el cuadro. No es que el abuso se multiplicara por tres mil: es que no habia
    con que comparar, y eso hay que decirlo en vez de disfrazarlo de medicion.
"""
import ast
import os
import sys
import time

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


def pieza(nombre):
    ns = {"time": time}
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name == nombre:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns[nombre]


def prueba(sid, sig, ts, dst="", dport=None, rrname="", flow="", rev="4"):
    return {"sid": sid, "rev": rev, "sig": sig, "ts": ts, "dst": dst,
            "dport": dport, "rrname": rrname, "flow_id": flow}


def main():
    agrupar = pieza("agrupar_pruebas")
    tend = pieza("tendencia_txt")

    # =====================================================================================
    # La ficha: una fila por firma
    # =====================================================================================
    # El caso real: la misma firma ocho veces en dos minutos, distinto flow_id cada vez.
    t0 = 1790000000
    ocho = [prueba("2014169", "ET DNS Query for .su TLD", t0 + i * 20,
                   rrname="dontworry.su", flow="115559325752856%d" % i)
            for i in range(8)]
    g = agrupar(ocho)
    check("ocho alertas de la misma firma son UNA fila", len(g) == 1, len(g))
    check("y dicen cuantas veces fue", g[0]["n"] == 8, g[0])
    check("con el rango de tiempo, no solo la ultima",
          g[0]["ini"] == t0 and g[0]["fin"] == t0 + 140, (g[0]["ini"], g[0]["fin"]))
    check("el dominio consultado no se repite ocho veces",
          g[0]["dst"] == ["dontworry.su"], g[0]["dst"])
    check("y queda un flow_id como referencia para buscarlo en EveBox",
          g[0]["flow"].startswith("1155593257528560"), g[0]["flow"])

    # --- lo que de verdad justifica "Confirmado": firmas DISTINTAS --------------------
    mezcla = ocho + [prueba("2019876", "ET MALWARE Botnet CnC Checkin", t0 + 300,
                            dst="198.51.100.7", dport=8080)]
    g = agrupar(mezcla)
    check("dos firmas distintas son dos filas", len(g) == 2, len(g))
    check("y la mas frecuente va primero", g[0]["sid"] == "2014169" and g[1]["n"] == 1,
          [(x["sid"], x["n"]) for x in g])
    check("a una conexion si se le pone el puerto",
          g[1]["dst"] == ["198.51.100.7:8080"], g[1]["dst"])
    # A un dominio no: se consulta, no se conecta. Escribir "dontworry.su:53" sugeriria
    # que el CPE habla con ese dominio por el 53, que no es lo que paso.
    check("a un dominio consultado NO se le pega el puerto",
          ":" not in g[0]["dst"][0], g[0]["dst"])

    # --- varios destinos de la misma firma se listan una vez cada uno -----------------
    varios = [prueba("2019876", "ET MALWARE CnC", t0 + i, dst="198.51.100.%d" % i,
                     dport=443) for i in range(1, 4)]
    g = agrupar(varios)
    check("los destinos distintos se conservan todos",
          len(g[0]["dst"]) == 3 and g[0]["n"] == 3, g[0]["dst"])

    # --- a igualdad de veces, el orden no puede bailar entre recargas -----------------
    par = [prueba("1111", "A", t0), prueba("2222", "B", t0 + 1)]
    check("con el mismo numero de veces, manda el orden de aparicion",
          [x["sid"] for x in agrupar(par)] == ["1111", "2222"],
          [x["sid"] for x in agrupar(par)])

    check("sin pruebas no revienta", agrupar([]) == [] and agrupar(None) == [], "")

    # =====================================================================================
    # El cuadro de tendencia
    # =====================================================================================
    # Lo que salia en pantalla: 67.247 de media contra un periodo anterior casi vacio.
    val, hint = tend(67247.0, 20.0, 1, 14)
    check("con un solo dia anterior NO se inventa un porcentaje",
          "%" not in val and "&times;" not in val, val)
    check("y se dice por que", "casi no tiene datos" in hint, hint)

    val, hint = tend(500.0, 0.0, 0, 5)
    check("sin 14 dias, lo dice tal cual", "hacen falta 14 dias" in hint, hint)

    # --- el caso normal ---------------------------------------------------------------
    val, hint = tend(120.0, 100.0, 7, 20)
    check("una subida normal sale en porcentaje", "20&nbsp;%" in val, val)
    check("con el espacio duro, para que el % no caiga a la linea de abajo",
          " %" not in val.replace("&nbsp;%", ""), val)
    check("y con flecha arriba", "&uarr;" in val, val)
    val, _ = tend(80.0, 100.0, 7, 20)
    check("una bajada va en verde y con flecha abajo",
          "&darr;" in val and "#3a9d5d" in val, val)

    # --- una subida real pero enorme: veces, no un porcentaje de cinco cifras ----------
    val, hint = tend(10000.0, 100.0, 7, 20)
    check("una subida enorme se dice en veces", "&times;100" in val, val)
    check("sin porcentaje, que ahi ya no se lee", "%" not in val, val)

    # =====================================================================================
    # Y que la fila de cuadros quede cuadrada
    # =====================================================================================
    check("los cuadros van en rejilla de columnas iguales",
          "grid-template-columns:repeat(auto-fit,minmax(180px,1fr))" in DASH, "")
    check("un numero largo no se parte en dos lineas",
          ".kpi .kv{" in DASH and "white-space:nowrap" in DASH, "")
    check("las aclaraciones quedan al fondo, a la misma altura en todos",
          "margin-top:auto" in DASH, "")
    # el de tendencia usaba su propia estructura y metia la aclaracion DENTRO del hueco
    # del numero, asi que salia en grande y por encima de la etiqueta
    check("el cuadro de tendencia se arma como los demas",
          '_kpi(var_val, "tendencia", var_hint)' in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
