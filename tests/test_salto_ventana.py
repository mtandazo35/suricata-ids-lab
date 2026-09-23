# -*- coding: utf-8 -*-
"""Saltar al inicio de la ventana sin perderse eventos.

De donde sale: en un nodo real, dns.json pesaba 1,8 GB y eve.json 246 MB, y cada corrida
del generador los leia ENTEROS para descartar casi todo por antiguo. Nueve minutos de CPU
al 100 % por corrida, con "En vivo" a media hora de retraso.

El riesgo de optimizar esto es el peor de todos: que el salto se pase y se pierdan
eventos EN SILENCIO. Nadie se enteraria: el panel seguiria pintando, solo que con menos
datos. Por eso lo que se prueba aqui no es que sea rapido, sino que NO se pierde nada de
lo que cae dentro de la ventana.
"""
import ast
import os
import re
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
ARBOL = ast.parse(GEN)

PIEZAS = ("opener", "_RE_TS_LINEA", "abrir_desde", "parse_ts", "TZ_EC")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas():
    ns = {"io": __import__("io"), "os": os, "re": re, "gzip": __import__("gzip"),
          "time": time, "datetime": __import__("datetime").datetime,
          "timezone": __import__("datetime").timezone,
          "timedelta": __import__("datetime").timedelta}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(GEN, n) or "", ns)
    return ns


def escribir_log(ruta, n, t0, paso=1.0, relleno=600):
    """Un log tipo eve.json: n lineas ordenadas por tiempo, con relleno para que pese."""
    with open(ruta, "w", encoding="utf-8") as f:
        for i in range(n):
            ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000-0500",
                               time.localtime(t0 + i * paso))
            f.write('{"timestamp":"%s","n":%d,"x":"%s"}\n' % (ts, i, "z" * relleno))
    return ruta


def main():
    ns = piezas()
    abrir_desde = ns["abrir_desde"]
    tmp = tempfile.mkdtemp()

    ahora = time.time()
    # 20.000 lineas, una por segundo hacia atras: ~5,5 h de historia, ~12 MB
    n = 20000
    t0 = ahora - n
    p = escribir_log(os.path.join(tmp, "eve.json"), n, t0)
    tam = os.path.getsize(p)
    check("el archivo de prueba es lo bastante grande para que el salto actue",
          tam > 8 * 1024 * 1024, "%d bytes" % tam)

    def leer(corte, margen=1024 * 1024):
        ns_i = []
        with abrir_desde(p, corte, margen) as f:
            for ln in f:
                m = re.search(r'"n":(\d+)', ln)
                if m:
                    ns_i.append(int(m.group(1)))
        return ns_i

    # --- lo esencial: no se pierde NADA de dentro de la ventana ---
    for horas in (0.5, 1, 2, 5):
        corte = ahora - horas * 3600
        esperados = [i for i in range(n) if t0 + i >= corte]
        leidos = leer(corte)
        falta = [i for i in esperados if i not in set(leidos)]
        check("ventana de %sh: no se pierde ningun evento" % horas, not falta,
              "faltan %d (el primero seria el %s)" % (len(falta), falta[:1]))
        # el ahorro solo se puede exigir cuando la ventana es una fraccion del archivo:
        # con 5 h sobre 5,5 h de historia, leerlo casi entero es lo CORRECTO
        if horas <= 2:
            check("ventana de %sh: y se lee bastante menos que el archivo entero" % horas,
                  len(leidos) < n * 0.75, "leidos %d de %d" % (len(leidos), n))
        check("ventana de %sh: nunca se lee mas de lo que hay" % horas, len(leidos) <= n)

    # --- casos que romperian el salto ---
    todo = leer(0)
    check("con corte 0 se lee el archivo entero", len(todo) == n, len(todo))

    corte_viejo = t0 - 86400
    check("si la ventana es anterior a todo el archivo, se lee entero",
          len(leer(corte_viejo)) == n, len(leer(corte_viejo)))

    corte_futuro = ahora + 86400
    check("si la ventana es posterior a todo, no revienta", isinstance(leer(corte_futuro), list))

    chico = escribir_log(os.path.join(tmp, "chico.json"), 50, t0)
    with abrir_desde(chico, ahora - 60) as f:
        ls = f.readlines()
    check("un archivo pequeño se lee entero, sin biseccion", len(ls) == 50, len(ls))

    # --- las lineas nunca salen cortadas por la mitad ---
    leidas = []
    with abrir_desde(p, ahora - 3600) as f:
        for ln in f:
            leidas.append(ln)
    check("ninguna linea sale truncada: todas son JSON completo",
          all(l.startswith('{"timestamp"') and l.rstrip().endswith("}") for l in leidas),
          [l[:40] for l in leidas[:1]])

    # --- un .gz no se posiciona, se abre como siempre ---
    import gzip
    gz = os.path.join(tmp, "eve.json.1.gz")
    with gzip.open(gz, "wt", encoding="utf-8") as f:
        for i in range(100):
            f.write('{"timestamp":"2026-01-01T00:00:00.000000-0500","n":%d}\n' % i)
    with abrir_desde(gz, ahora) as f:
        check("un .gz se lee entero aunque se pida un corte", len(f.readlines()) == 100)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
