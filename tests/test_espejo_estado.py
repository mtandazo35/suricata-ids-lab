# -*- coding: utf-8 -*-
"""suricata-espejo: el comando que responde "estoy leyendo trafico?".

Lo que protege es el VEREDICTO, que es lo unico que se lee de verdad. Los numeros
sueltos ya estaban en cuatro archivos; el valor esta en decir que hacer.

El caso que dio origen a media prueba: la primera version sacaba el desperdicio del
contador ACUMULADO del receptor. Despues de arreglar el router en produccion seguia
diciendo "el MikroTik manda sin filtrar, el 91% se tira" mientras en vivo entraban
21 Mbps y llegaban 16. Un diagnostico que no se entera de que ya lo arreglaste es peor
que no tenerlo: manda a tocar un router que estaba bien.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-espejo <<'ESPEJO'")
PROG = SRC[_i:].split("\n", 1)[1].split("\nESPEJO\n", 1)[0]
ARBOL = ast.parse(PROG)

PIEZAS = ("MINIMO_MEDIBLE", "DESPERDICIO_AVISO", "MUDO", "veredicto")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno():
    ns = {}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(PROG, n) or "", ns)
    return ns


def main():
    ns = entorno()
    v = ns["veredicto"]
    SANO = dict(receptor=True, suri=True, vistos={"10.0.0.1": 3},
                rechazados={}, aceptados={"10.0.0.1": 100},
                entra=21.0, llega=16.0, desperdicio=0.24, alertas=297, minutos=5)

    def con(**cambios):
        d = dict(SANO); d.update(cambios)
        return v(**d)

    # --- todo bien -----------------------------------------------------------------------
    n, t = con()
    check("con todo sano dice que estas leyendo", n == "verde", (n, t))

    # --- lo que deja el sensor inutil, por orden -------------------------------------------
    n, t = con(receptor=False)
    check("receptor caido es rojo y dice como arrancarlo",
          n == "rojo" and "tzsp-decap" in t, (n, t))
    n, t = con(suri=False)
    check("suricata parado tambien", n == "rojo" and "suricata" in t.lower(), (n, t))
    n, t = con(vistos={})
    check("sin ningun origen: nadie espeja hacia aqui",
          n == "rojo" and "sniff-target" in t, (n, t))
    n, t = con(rechazados={"203.0.113.9": 50}, aceptados={})
    check("si todo llega de un origen no autorizado, se dice cual",
          n == "rojo" and "203.0.113.9" in t, (n, t))
    n, t = con(vistos={"10.0.0.1": 3000})
    check("si el origen lleva 50 min callado, el router dejo de espejar",
          n == "rojo" and "dejo de espejar" in t, (n, t))
    n, t = con(entra=40.0, llega=0.0)
    check("entra trafico y no llega nada: la captura esta rota",
          n == "rojo" and "veth" in t, (n, t))

    # --- el fallo que motivo esta prueba ----------------------------------------------------
    # 21 Mbps entrando y 16 llegando es sano. Si el veredicto mirase el acumulado del
    # receptor (91% recortado de hace horas) mandaria a tocar un router ya arreglado.
    n, t = con(desperdicio=0.24)
    check("un 24% de diferencia en vivo es normal y NO acusa al router", n == "verde",
          (n, t))
    n, t = con(desperdicio=0.91)
    check("un 91% EN VIVO si acusa al router, con la regla concreta",
          n == "ambar" and "connection-bytes=0-10000" in t, (n, t))
    check("y el umbral no esta pegado al ruido: exige mas de la mitad",
          0.5 <= ns["DESPERDICIO_AVISO"] <= 0.8, ns["DESPERDICIO_AVISO"])
    fuente = ast.get_source_segment(PROG, next(
        n_ for n_ in ARBOL.body if getattr(n_, "name", "") == "veredicto")) or ""
    check("el veredicto no mira el contador acumulado del receptor",
          "acumulado" not in fuente.replace("acumulado del receptor", ""), "")

    # --- lo que degrada sin romper ------------------------------------------------------------
    n, t = con(alertas=0)
    check("sin alertas avisa, pero no lo da por roto",
          n == "ambar" and "test-alerts" in t, (n, t))

    # --- las prioridades no se cruzan ----------------------------------------------------------
    # Un receptor caido no puede reportarse como "poco trafico": lo primero es lo que
    # deja el sensor inutil.
    n, t = con(receptor=False, alertas=0, desperdicio=0.99)
    check("lo que deja el sensor inutil manda sobre lo que solo lo degrada",
          "tzsp-decap" in t, (n, t))

    # --- sin medida no se inventa un diagnostico -------------------------------------------------
    n, t = con(desperdicio=None, entra=None, llega=0.0, alertas=12)
    check("sin poder medir el caudal no se acusa a nadie", n == "verde", (n, t))
    check("y el minimo medible es explicito", ns["MINIMO_MEDIBLE"] > 0, ns["MINIMO_MEDIBLE"])
    check("igual que el silencio de un origen", ns["MUDO"] >= 300, ns["MUDO"])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
