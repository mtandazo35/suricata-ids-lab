# -*- coding: utf-8 -*-
"""Ninguna ruta del panel puede reventar por un nombre sin definir.

De donde sale esta prueba: `_up` estaba como `import urllib.parse as _up` DENTRO de dos
ramas del manejador GET. Eso convierte a `_up` en variable LOCAL de todo el metodo, y esas
dos ramas hacen `return`, asi que cualquier ruta POSTERIOR que usara `_up` moria con
UnboundLocalError. Le paso a /documentacion: el hilo moria, la conexion se cerraba sin
responder y el proxy devolvia un "502 Bad Gateway" mudo. Nadie lo vio hasta produccion
porque las pruebas llamaban a documentacion_page() directamente, nunca a la RUTA.

Aqui se ejecuta el manejador ENTERO, ruta por ruta, con todo lo de fuera stubbeado. No
comprueba que cada pagina sea correcta -de eso hay otras pruebas- sino que ninguna se cae
antes de llegar a generarla.
"""
import ast
import glob
import html
import ipaddress
import json
import os
import re
import sys
import time
import types
import urllib.error
import urllib.parse
import urllib.request

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


class Cualquiera:
    """Un doble que se deja llamar, indexar y recorrer sin quejarse."""
    def __call__(self, *a, **k):
        return Cualquiera()
    def __getattr__(self, _n):
        return Cualquiera()
    def __getitem__(self, _k):
        return Cualquiera()
    def __iter__(self):
        return iter(())
    def __contains__(self, _x):
        return False
    def __str__(self):
        return ""
    def __bool__(self):
        return False
    def get(self, _k, d=None):
        return d if d is not None else Cualquiera()


class Globales(dict):
    """Todo lo que la funcion no encuentre se convierte en un doble. Asi se puede ejecutar
    el manejador sin arrastrar las 7.000 lineas del panel... pero un UnboundLocalError
    (nombre LOCAL usado antes de asignarse) NO se puede tapar asi: sigue explotando, que
    es justo lo que se quiere detectar."""
    def __missing__(self, k):
        return Cualquiera()


def metodo(nombre):
    for n in ast.walk(ARBOL):
        if isinstance(n, ast.ClassDef) and n.name == "H":
            for m in n.body:
                if isinstance(m, ast.FunctionDef) and m.name == nombre:
                    return m
    raise SystemExit("no se encontro H." + nombre)


def rutas_de(fn, var):
    """Las rutas literales que compara el manejador (if path == "..." / in (...))."""
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare) and getattr(n.left, "id", "") == var:
            for c in n.comparators:
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    out.append(c.value)
                elif isinstance(c, (ast.Tuple, ast.List)):
                    for e in c.elts:
                        if isinstance(e, ast.Constant) and isinstance(e.value, str):
                            out.append(e.value)
    vistas = []
    for r in out:
        if r not in vistas:
            vistas.append(r)
    return vistas


class Self:
    def __init__(self, path):
        self.path = path
        self.command = "GET"
        self.headers = {}
        self.close_connection = False
        self.rfile = types.SimpleNamespace(read=lambda n=0: b"")
        self.wfile = types.SimpleNamespace(write=lambda b: None)
        self.salida = []

    def _auth_ok(self):
        return True
    def _admin(self):
        return True
    def _operador(self):
        return True
    def _set_ctx(self):
        return None
    def _html(self, x, code=200):
        self.salida.append(("html", code))
    def _redirect(self, u, cookie=None):
        self.salida.append(("redirect", u))
    def _deny(self):
        self.salida.append(("deny", 403))
    def _json(self, d, code=200):
        self.salida.append(("json", code))
    def _cookie_secure(self):
        return ""
    def send_response(self, code=200, *a):
        # /logo.png y /favicon.ico responden a mano, sin _html: tambien cuenta como
        # "esta ruta respondio"
        self.salida.append(("raw", code))
    def send_header(self, *a):
        pass
    def end_headers(self, *a):
        pass
    def __getattr__(self, _n):
        # lo que el manejador use y no este aqui arriba se stubbea: si no, un
        # AttributeError corta la ejecucion ANTES de llegar a la ruta y la prueba
        # pasaria sin haber probado nada (ya paso).
        return Cualquiera()


def preparar(fn):
    g = Globales({
        "re": re, "json": json, "os": os, "time": time, "html": html, "glob": glob,
        "ipaddress": ipaddress, "urllib": urllib, "_up": urllib.parse,
        "BaseHTTPRequestHandler": object,
        # las puertas de entrada tienen que ABRIR: con el doble por defecto (falsy) el
        # manejador devolvia 403 y no se llegaba a ninguna ruta
        "ip_confiable": lambda *a, **k: True,
        "cargar_confianza": lambda *a, **k: [],
    })
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<h>", "exec"), g)
    return g[fn.name]


def main():
    get = metodo("_get")
    fn = preparar(get)
    rutas = rutas_de(get, "path")
    check("se encontraron las rutas GET del panel", len(rutas) >= 10, len(rutas))

    # Rutas que TIENEN que poder ejecutarse con dobles. Las que faltan (/ y /detalle)
    # arman el resumen entero y desempaquetan tuplas, asi que con dobles tontos no se
    # pueden recorrer; se dicen aparte en vez de dejar que la prueba parezca completa.
    CRITICAS = ("/documentacion", "/historico", "/reputacion", "/cuarentena",
                "/cuarentena/ficha", "/ajustes", "/exclusiones", "/log", "/bitacora")
    malas = []; mudas = []; sin_cubrir = []
    for r in rutas:
        s = Self(r)
        try:
            fn(s)
        except (NameError, UnboundLocalError) as e:
            malas.append((r, "%s: %s" % (type(e).__name__, e)))
            continue
        except Exception:
            pass          # otros fallos son de los dobles, no del manejador
        # un 403 significa que una puerta corto antes de la ruta: tampoco se probo nada
        if not s.salida or s.salida[0] == ("html", 403):
            (mudas if r in CRITICAS else sin_cubrir).append(r)
    check("ninguna ruta GET usa un nombre sin definir", not malas, malas)
    # Si una ruta no respondio NADA es que no se llego a ella y la comprobacion de arriba
    # seria vacia. Paso de verdad: un AttributeError cortaba antes que cualquier ruta.
    check("las rutas criticas se ejecutaron de verdad", not mudas, mudas)
    if sin_cubrir:
        print("       (no cubiertas por los dobles: %s)" % ", ".join(sin_cubrir))

    # y con parametros, que es como se usan de verdad
    conq = ["/documentacion?embed=1", "/documentacion?p=todo", "/historico?d=90",
            "/cuarentena?msg=hola", "/cuarentena/ficha?ip=1.1.1.1&embed=1",
            "/reputacion", "/exclusiones?edit=0"]
    malas2 = []
    for r in conq:
        s = Self(r)
        try:
            fn(s)
        except (NameError, UnboundLocalError) as e:
            malas2.append((r, "%s: %s" % (type(e).__name__, e)))
        except Exception:
            pass
        if not s.salida or s.salida[0] == ("html", 403):
            malas2.append((r, "no se llego a la ruta: %s" % (s.salida,)))
    check("tampoco con parametros en la URL", not malas2, malas2)

    # la causa raiz, prohibida explicitamente: un import dentro de una rama solo vale para
    # esa rama, pero hace local el nombre en TODO el metodo
    dentro = []
    for nombre in ("_get", "_post"):
        m = metodo(nombre)
        for n in ast.walk(m):
            if isinstance(n, (ast.Import, ast.ImportFrom)) and n not in m.body:
                dentro.append((nombre, n.lineno,
                               ",".join(a.asname or a.name for a in n.names)))
    check("ningun import dentro de una rama del manejador", not dentro, dentro)

    post = metodo("_post")
    fnp = preparar(post)
    rutasp = rutas_de(post, "ruta")
    check("se encontraron las rutas POST", len(rutasp) >= 10, len(rutasp))
    malas3 = []
    for r in rutasp:
        s = Self(r); s.command = "POST"
        try:
            fnp(s)
        except (NameError, UnboundLocalError) as e:
            malas3.append((r, "%s: %s" % (type(e).__name__, e)))
        except Exception:
            pass
    check("ninguna ruta POST usa un nombre sin definir", not malas3, malas3)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
