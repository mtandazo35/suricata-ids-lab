# -*- coding: utf-8 -*-
"""El aviso de Cuarentena (y de Conducta) no pinta texto libre de la URL.

Las acciones de Cuarentena redirigian a /cuarentena?msg=<TEXTO> y la pagina pintaba ese
texto en su aviso oficial. Un enlace /cuarentena?msg=Tu+sesion+caduco,+entra+en+... era
phishing con el logo del panel (lo mismo que se arreglo en /reputacion). Ahora la URL
lleva un CODIGO de un solo uso que el servidor traduce; el quitado masivo (JS) vuelve con
dos numeros, y el texto lo compone el panel.

Se ejecutan los manejadores REALES (H._post y H._get) con dobles para lo de fuera:
  - un texto inventado en ?msg= no se pinta (ni en /cuarentena ni en /conducta);
  - el mensaje de una accion real (quitar varios, sin seleccion, refrescar Conducta) si;
  - el codigo es de un solo uso;
  - ?quitadas=N&errores=M pinta el resumen; con texto en vez de numeros, nada.
"""
import ast
import ipaddress
import json
import os
import re
import secrets
import sys
import time
import types
import urllib.parse

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

AVISOS = ("_REP_AVISOS", "_REP_AVISOS_TTL", "rep_aviso_guardar", "rep_aviso_tomar",
          "rep_aviso_url", "cuar_aviso_url")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)[:400]))
    if not c:
        fallos += 1


class _Doble:
    """Se deja llamar y leer sin quejarse: lo del manejador que no interesa aqui."""
    def __call__(self, *a, **k):
        return _Doble()

    def __getattr__(self, _n):
        return _Doble()

    def __bool__(self):
        return False


class _Globales(dict):
    """Lo que falte es un doble, salvo lo de Python (los builtins van primero)."""
    def __missing__(self, k):
        import builtins
        if hasattr(builtins, k):
            return getattr(builtins, k)
        return _Doble()


class _Peticion:
    def __init__(self, path, cuerpo=""):
        self.path = path
        self.headers = {"Content-Length": str(len(cuerpo.encode("utf-8")))}
        self.rfile = types.SimpleNamespace(read=lambda n=0: cuerpo.encode("utf-8"))
        self.salida = []

    def _auth_ok(self):
        return True

    def _admin(self):
        return True

    def _operador(self):
        return True

    def _redirect(self, u, cookie=None):
        self.salida.append(("redirect", u))

    def _html(self, x, code=200):
        self.salida.append(("html", x))

    def _deny(self):
        self.salida.append(("deny", 403))

    def __getattr__(self, _n):
        return _Doble()


def _metodo(nombre):
    cls = next(n for n in ARBOL.body if isinstance(n, ast.ClassDef) and n.name == "H")
    for m in cls.body:
        if isinstance(m, ast.FunctionDef) and m.name == nombre:
            return m
    raise SystemExit("no se encontro H." + nombre)


def main():
    vio = {}
    estado = {"cuar": {"10.6.1.89": {}, "10.6.2.82": {}}, "dns": {}}

    def pagina(nombre):
        def _p(*a, **k):
            vio.clear()
            vio.update(k)
            vio["_pagina"] = nombre
            return "pagina"
        return _p

    g = _Globales({
        "re": re, "json": json, "time": time, "secrets": secrets, "urllib": urllib,
        "_up": urllib.parse, "ipaddress": ipaddress, "BaseHTTPRequestHandler": object,
        "ip_confiable": lambda *a, **k: True, "cargar_confianza": lambda *a, **k: [],
        "bitacora": lambda *a, **k: None,
        "cuarentena_page": pagina("cuarentena"), "conducta_page": pagina("conducta"),
        # lo que usa /cuarentena/quitar-varios
        "MK_SENT": "cuar", "MK_SENT_DNS": "dns", "CTX": types.SimpleNamespace(user="ana"),
        "cargar_mk": lambda: {"LIST_DNS": "lista-dns"},
        "cargar_mk_de": lambda r: {"LIST_DNS": "lista-dns"},
        "cargar_enviados": lambda path="cuar": estado[path],
        "quitar_enviados": lambda ips, path="cuar": [i for i in ips
                                                     if estado[path].pop(i, None) is not None],
        "mk_remove": lambda ip, lista=None, router=None: ((False, "el router rechazo")
                                                         if ip == "10.6.2.82" else (True, "")),
        "mk_log": lambda *a, **k: None,
        "ip_de": lambda k: k.split("|", 1)[1] if "|" in k else k,
        "router_de_clave": lambda k: {"id": "r1"},
    })
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in AVISOS:
            exec(ast.get_source_segment(DASH, n) or "", g)
    for nombre in ("_post", "_get"):
        exec(compile(ast.Module(body=[_metodo(nombre)], type_ignores=[]), "<h>", "exec"), g)
    post, get = g["_post"], g["_get"]

    def pulsar(ruta, cuerpo=""):
        p = _Peticion(ruta, cuerpo)
        post(p)
        return p.salida[-1][1] if p.salida and p.salida[-1][0] == "redirect" else repr(p.salida)

    def abrir(url):
        vio.clear()
        get(_Peticion(url))
        return vio.get("msg", None), vio.get("_pagina")

    # --- 1. phishing: un texto puesto a mano en la URL no sale en el aviso del panel ------
    cebo = "Tu sesion caduco. Vuelve a entrar en https://panel-falso.example/login"
    msg, pag = abrir("/cuarentena?msg=" + urllib.parse.quote(cebo))
    check("/cuarentena?msg=<texto inventado> no pinta ese texto",
          pag == "cuarentena" and msg == "", (pag, msg))
    msg, pag = abrir("/conducta?msg=" + urllib.parse.quote(cebo))
    check("/conducta?msg=<texto inventado> tampoco", pag == "conducta" and msg == "", (pag, msg))
    msg, pag = abrir("/cuarentena?quitadas=" + urllib.parse.quote(cebo) + "&errores=1")
    check("?quitadas=<texto> (no un numero) no pinta nada", pag == "cuarentena" and msg == "",
          (pag, msg))

    # --- 2. el mensaje de una accion real si se ve ----------------------------------------
    url = pulsar("/cuarentena/quitar-varios", "sel=cuar%7C10.6.1.89&sel=cuar%7C10.6.2.82")
    check("quitar varios redirige a /cuarentena con un CODIGO, no con el texto",
          url.startswith("/cuarentena?msg=") and "entrada" not in urllib.parse.unquote(url)
          and " " not in urllib.parse.unquote(url), url)
    msg, pag = abrir(url)
    check("  y el GET lo traduce al resumen de la accion",
          pag == "cuarentena" and msg.startswith("1 entrada(s) quitada(s)")
          and "10.6.2.82 (el router rechazo)" in msg, msg)
    msg, _p = abrir(url)
    check("  el codigo es de un solo uso: recargar no repite el aviso", msg == "", msg)
    msg, _p = abrir(pulsar("/cuarentena/quitar-varios", ""))
    check("sin seleccion: el aviso del panel se ve", msg == "No seleccionaste ninguna IP", msg)
    url = pulsar("/conducta/refrescar")
    msg, pag = abrir(url)
    check("Conducta -> Refrescar: codigo en la URL y su mensaje en la pagina",
          url.startswith("/conducta?msg=") and "segundo" not in url
          and pag == "conducta" and "segundo plano" in msg, (url, msg))

    # --- 3. el quitado masivo (JS) vuelve con dos numeros -----------------------------------
    msg, _p = abrir("/cuarentena?quitadas=2&errores=1")
    check("?quitadas=2&errores=1 pinta el resumen que compone el panel",
          msg == "2 entrada(s) quitada(s); 1 con error", msg)
    msg, _p = abrir("/cuarentena?quitadas=3")
    check("  sin errores no los menciona", msg == "3 entrada(s) quitada(s)", msg)
    msg, _p = abrir("/cuarentena")
    check("sin parametros no hay aviso", msg == "", msg)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
