#!/usr/bin/env python3
"""Saca de install-suricata.sh las piezas que se pueden probar sueltas.

Todo el proyecto es un unico script con programas en Python y JavaScript metidos
en heredocs, asi que no hay nada que importar: hay que extraerlo. Esto deja en un
directorio los artefactos que usan las pruebas:

  sort.js         ordenamiento de tablas (_SORT_JS)
  pos.js          posicion de la pagina al recargar (_POS_JS)
  masivo.js       script de la pagina de Cuarentena (seleccion y quitado masivo)
  mapa.js         mapa del reporte (mapa_ataques_section)
  ruta_uno.py     cuerpo de la ruta /cuarentena/quitar-uno
  ruta_masivo.py  cuerpo de la ruta /cuarentena/quitar-varios

Uso:  python3 tests/extraer.py <directorio_destino>
"""
import ast
import os
import re
import sys
import textwrap

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUENTE = os.path.join(RAIZ, "install-suricata.sh")


def heredoc(src, nombre):
    """Devuelve el cuerpo del heredoc que escribe /usr/local/bin/<nombre>."""
    i = src.index("cat > /usr/local/bin/%s <<'" % nombre)
    marca = src[i:].split("<<'", 1)[1].split("'", 1)[0]
    return src[i:].split("\n", 1)[1].split("\n" + marca + "\n", 1)[0]


def literal(nodo, sustituciones=None):
    """Evalua una concatenacion de literales de texto. Lo que no sea literal (datos
    embebidos con json.dumps, tablas) se sustituye por un marcador: a las pruebas les
    interesa el codigo, no los datos."""
    sustituciones = sustituciones or {}
    if isinstance(nodo, ast.Constant) and isinstance(nodo.value, str):
        return nodo.value
    if isinstance(nodo, ast.BinOp) and isinstance(nodo.op, ast.Add):
        return literal(nodo.left, sustituciones) + literal(nodo.right, sustituciones)
    if isinstance(nodo, ast.Name):
        return sustituciones.get(nodo.id, "")
    if isinstance(nodo, ast.Call) and getattr(nodo.func, "id", "") == "str":
        return "0"
    return "{}"


def asignacion(arbol, nombre):
    for n in ast.walk(arbol):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == nombre for t in n.targets):
            return n
    raise SystemExit("no se encontro la variable %s" % nombre)


def funcion(arbol, nombre):
    for n in ast.walk(arbol):
        if isinstance(n, ast.FunctionDef) and n.name == nombre:
            return n
    raise SystemExit("no se encontro la funcion %s" % nombre)


def cuerpo_ruta(fuente, arbol, ruta):
    """Devuelve el cuerpo del `if ruta == "<ruta>":` sin indentar, para ejecutarlo suelto."""
    for n in ast.walk(arbol):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and getattr(n.test.left, "id", "") == "ruta" and n.test.comparators
                and getattr(n.test.comparators[0], "value", "") == ruta):
            lineas = fuente.split("\n")[n.body[0].lineno - 1:n.body[-1].end_lineno]
            return textwrap.dedent("\n".join(lineas))
    raise SystemExit("no se encontro la ruta %s" % ruta)


def main():
    destino = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(destino, exist_ok=True)
    src = open(FUENTE, encoding="utf-8").read()

    dash = heredoc(src, "suricata-dashboard")
    arbol = ast.parse(dash)
    escritos = []

    def escribir(nombre, texto):
        with open(os.path.join(destino, nombre), "w", encoding="utf-8") as f:
            f.write(texto)
        escritos.append("%s (%d bytes)" % (nombre, len(texto)))

    for var, archivo in (("_SORT_JS", "sort.js"), ("_POS_JS", "pos.js")):
        js = literal(asignacion(arbol, var).value)
        escribir(archivo, js.replace("<script>", "").replace("</script>", ""))

    pag = funcion(arbol, "cuarentena_page")
    cuerpo = [x for x in ast.walk(pag) if isinstance(x, ast.Assign)
              and any(getattr(t, "id", "") == "body" for t in x.targets)][-1]
    scripts = re.findall(r"<script>(.*?)</script>", literal(cuerpo.value), re.S)
    escribir("masivo.js", scripts[0])

    for ruta, archivo in (("/cuarentena/quitar-uno", "ruta_uno.py"),
                          ("/cuarentena/quitar-varios", "ruta_masivo.py")):
        escribir(archivo, cuerpo_ruta(dash, arbol, ruta))

    rep = ast.parse(heredoc(src, "suricata-html-report"))
    fn = funcion(rep, "mapa_ataques_section")
    ret = [n for n in ast.walk(fn) if isinstance(n, ast.Return)][-1]
    # tablas de paises reducidas: las pruebas solo necesitan unos pocos
    html = literal(ret.value, {"_MAP_NUM2ISO": "{840:'US',528:'NL',466:'ML'}",
                               "_MAP_NAMES": "{US:'Estados Unidos',NL:'Paises Bajos'}"})
    js = [s for s in re.findall(r"<script>(.*?)</script>", html, re.S) if "(function(){" in s]
    if not js:
        raise SystemExit("no se encontro el script del mapa")
    escribir("mapa.js", js[0])

    print("extraidos en %s:" % destino)
    for e in escritos:
        print("  " + e)


if __name__ == "__main__":
    main()
