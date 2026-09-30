# -*- coding: utf-8 -*-
"""La insignia que dice si un abonado esta confirmado, y con cuantas pruebas.

Por que se cambio el texto: la etiqueta decia "Alta confianza", y en castellano un
cliente de confianza es alguien FIABLE. O sea que la insignia que marca al abonado mas
comprometido se podia leer como lo contrario de lo que significa. Estos informes los lee
gente que no es de redes, asi que la ambiguedad no es un detalle de estilo.

Lo que se protege:
  - que no vuelva la palabra "confianza" a una insignia que significa lo contrario;
  - que salga CUANTAS pruebas hay, porque lo que decide no es el volumen de alertas sino
    cuantas cosas DISTINTAS apuntan al mismo abonado: una firma ruidosa que dispara mil
    veces sigue siendo una sola prueba;
  - y que el umbral siga siendo 2 pruebas independientes, no una.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(piezas):
    ns = {}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in piezas:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def main():
    ns = entorno(("_cfb", "CONFIANZA"))
    cfb = ns["_cfb"]

    # --- la insignia -------------------------------------------------------------------
    h = cfb("alta", 3)
    check("un abonado con varias pruebas sale como Confirmado", "Confirmado" in h, h)
    check("y dice cuantas son", "3 pruebas" in h, h)
    check("nunca dice 'confianza', que se lee al reves",
          "confianza" not in h.lower(), h)

    h1 = cfb("sospechoso", 1)
    check("con una sola pista, Sin confirmar", "Sin confirmar" in h1, h1)
    check("y se dice que es una", "1 pista" in h1, h1)
    check("tampoco aqui aparece 'confianza'", "confianza" not in h1.lower(), h1)

    check("sin nivel no se pinta insignia", cfb("", 0) == "" and cfb(None, 0) == "")
    check("si no se sabe cuantas pruebas, se omite el numero y no se inventa un cero",
          "0" not in cfb("alta", 0), cfb("alta", 0))

    # --- la escala del informe de 3 dias --------------------------------------------------
    textos = [t for _u, _k, t in ns["CONFIANZA"]]
    check("la escala del informe tampoco habla de confianza",
          not any("confianza" in t.lower() for t in textos), textos)
    check("el nivel maximo se llama Confirmado", textos[0] == "Confirmado", textos)
    check("y hay un escalon intermedio, para no saltar de indicio a confirmado",
          "Probable" in textos, textos)

    # --- el umbral no se movio ---------------------------------------------------------------
    # El texto cambia; la regla no. Dos pruebas independientes siguen siendo el minimo para
    # decir que algo esta confirmado, y una sola nunca basta.
    check("hacen falta 2 pruebas independientes para confirmar",
          'confianza = "alta" if n_ev >= 2 else "sospechoso"' in GEN,
          [l.strip() for l in GEN.splitlines() if "n_ev >=" in l])
    check("y la evidencia se cuenta por TIPOS distintos, no por volumen",
          "aqui se cuentan solo TIPOS distintos" in GEN, "")

    # --- lo que ve el operador antes de cortar a lo bruto --------------------------------------
    check("el boton masivo habla de confirmados, no de confianza",
          "Enviar confirmados (" in DASH and "Enviar alta confianza" not in DASH, "")
    check("y al confirmar dice por que son confirmados",
          "2 o mas pruebas independientes" in DASH, "")

    # --- la fila tiene que dejar comparar dos candidatos sin hacer scroll -------------
    # La celda del motivo apilaba recuento, firma partida en dos lineas, lista con vinetas
    # y un boton: 190 px por fila. Y aqui se decide a quien se le corta el internet
    # comparando unos con otros, asi que el alto de la fila no es un detalle estetico.
    check("las evidencias van en linea, no en una lista con vinetas",
          "class='evp'" in DASH and "<ul class='evlist'>" not in DASH, "")
    check("la firma ocupa una sola linea",
          "text-overflow:ellipsis" in DASH and ".fw{" in DASH, "")
    # recortarla a 70 se comia el final, que es donde la firma dice de que familia habla;
    # ahora va entera y el corte lo hace el navegador, con el texto completo en el title
    check("y va entera en el title, no cortada a 70 caracteres",
          "or '')[:70]" not in DASH, "")
    check("ver evidencia es un enlace, no un boton en bloque",
          "class=evlink" in DASH and "evbtn" not in DASH, "")
    check("la columna de alertas aclara que es el total del CPE",
          "no solo las de esta categoria" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
