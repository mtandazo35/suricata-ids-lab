# -*- coding: utf-8 -*-
"""Seleccionar texto dentro de un modal no lo cierra.

El usuario arrastraba para seleccionar un valor dentro del formulario de MikroTik, soltaba
el raton fuera de la caja y el modal se cerraba (y con el, todo lo escrito). El navegador
dispara `click` en el elemento donde se SUELTA, y la capa de fondo cerraba con cualquier
click sobre si misma. Ahora cierra solo si el raton tambien se PULSO sobre la capa.

Lo que se protege: toda capa que cierre al pulsar fuera lleva la guarda (mousedown y click
en la misma capa); no queda ninguna con el cierre antiguo; y la guarda hace lo que dice
(se simula en un DOM minimo: pulsar dentro y soltar fuera no cierra; pulsar y soltar
fuera si cierra).
"""
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class Nodo(object):
    """Lo justo de un elemento para ejecutar los dos manejadores inline."""
    def __init__(self):
        self._dn = None
        self.cerrado = False

    def mousedown(self, target):
        self._dn = target          # onmousedown="this._dn=event.target"

    def click(self, target):       # onclick="if(event.target===this&&this._dn===this){cerrar}"
        if target is self and self._dn is self:
            self.cerrado = True


def main():
    viejos = re.findall(r'onclick=\\?"if\(event\.target===this\)(?!&&this\._dn===this)', SRC)
    check("ninguna capa cierra solo con el click (sin mirar donde se pulso)", not viejos, len(viejos))
    con_guarda = re.findall(
        r'onmousedown=\\?"this\._dn=event\.target\\?" onclick=\\?"if\(event\.target===this&&this\._dn===this\)\{', SRC)
    check("las capas que cierran al pulsar fuera llevan la guarda (hay %d)" % len(con_guarda),
          len(con_guarda) >= 11, len(con_guarda))
    for nombre in ("aptmodal", "fichamodal", "askov", "exmodal", "mmasivo", "mkwait", "ovlNew"):
        i = SRC.find("id=" + nombre) if ("id=" + nombre) in SRC else SRC.find(nombre)
        trozo = SRC[max(0, i - 40): i + 320]
        check("la capa %s lleva la guarda" % nombre, "this._dn===this" in trozo, trozo[:140])

    # la guarda, simulada: el navegador manda el click al elemento donde se SUELTA
    capa = Nodo(); caja = object()
    capa.mousedown(caja); capa.click(capa)        # pulsar dentro de la caja, soltar fuera
    check("pulsar dentro y soltar fuera NO cierra", capa.cerrado is False, "")
    capa = Nodo()
    capa.mousedown(capa); capa.click(capa)        # pulsar y soltar fuera
    check("pulsar y soltar fuera SI cierra", capa.cerrado is True, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
